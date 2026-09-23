#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Verify that a parallel topotest run produced a result for every test it was
# meant to run, measured against `pytest --collect-only`, not against itself.
#
# Background (BLO-35428): the parallel topotest step only ever asked "did
# pytest exit 0?".  pytest's exit code says nothing about tests that were
# never collected, never scheduled, or lost when an xdist worker died, and
# the failed-only serial rerun that follows can only re-verify failures the
# partial junit happens to record.  This check compares the junit against the
# full collection taken from the same image a few minutes earlier, so a run
# that silently narrowed -- a truncated run list, a resume that dropped a
# failing file, an interrupted session -- turns red instead of green.
#
# Two properties are checked:
#
#   run-list coverage  every collected ID whose file is in --run-list (or that
#                      is itself listed) has a testcase in --results;
#   plan coverage      every collected ID has a testcase in --results, OR a
#                      NON-failing outcome in the --prior junit(s) this attempt
#                      resumed from.  With no --prior (first attempt, or no
#                      usable prior results) that means this attempt alone must
#                      account for the whole collection.
#
# A skip counts as accounted for (the test was scheduled and reported) but is
# never counted as verified -- that distinction belongs to
# verify_rerun_coverage.py, which gates the serial rerun.  A prior FAILURE is
# deliberately not accounted: a failing test must produce a fresh result in
# this attempt, or a resume that dropped it would read as coverage.  A prior
# failure stays a failure when its serial rerun only skipped it: overlay()
# lets a later pass clear a failure, never a later skip.
#
# Every ambiguity fails closed: an empty collection, an empty run list, a
# run-list entry naming nothing collected, or an unreadable XML is an error,
# never a pass.

import argparse
import os
import sys
import xml.etree.ElementTree as ET

# Same directory; stdlib-only sibling.  testcase_id() is the single definition
# of "which test does this <testcase> name", shared with the rerun guard so
# the two checks cannot drift on spelling.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_rerun_coverage import testcase_id  # noqa: E402

PASSED = "passed"
SKIPPED = "skipped"
FAILED = "failed"


def split_id(node_id):
    """Split a pytest node ID into (file, test) with any class segments dropped.

    `a/test_b.py::TestC::test_d[x]` -> ("a/test_b.py", "test_d[x]").  The
    parametrization in brackets is kept whole even if it contains "::".  A
    bare file (no "::") returns (file, None).
    """
    fname, sep, rest = node_id.partition("::")
    if not sep:
        return fname, None
    bracket = rest.find("[")
    if bracket == -1:
        return fname, rest.split("::")[-1]
    return fname, rest[:bracket].split("::")[-1] + rest[bracket:]


def normalize(node_id):
    """`<file>::<test>`, so a class-based collected ID and its junit agree."""
    fname, test = split_id(node_id)
    return fname if test is None else fname + "::" + test


def read_list(path):
    """Non-empty, stripped lines of a file, order kept, duplicates dropped."""
    seen = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                seen.setdefault(line, None)
    return list(seen)


def _outcome(testcase):
    for child in testcase:
        if child.tag in ("failure", "error"):
            return FAILED
    if testcase.find("skipped") is not None:
        return SKIPPED
    return PASSED


def _junit_key(testcase, known_files):
    """Normalized node ID for one <testcase>, or None if it names no test.

    xunit2 junit (what topotests writes) has no `file` attribute, so
    testcase_id() derives the file from the dotted classname.  For a
    class-based test that classname carries the class too
    (`a.test_b.TestC`), which would give `a/test_b/TestC.py`; recover the
    real file by taking the longest classname prefix that names a collected
    file.  Anything unrecognised is returned as-is: it will match no expected
    ID, so it can only ever make the check stricter.
    """
    tid = testcase_id(testcase)
    if tid is None:
        return None
    fname, test = split_id(tid)
    if test is None or fname in known_files:
        return normalize(tid)
    parts = testcase.get("classname", "").split(".")
    for cut in range(len(parts) - 1, 0, -1):
        cand = "/".join(parts[:cut]) + ".py"
        if cand in known_files:
            return cand + "::" + test
    return normalize(tid)


def parse_outcomes(path, known_files):
    """Return {normalized ID: outcome} for one junit file.

    A test reported more than once (pytest writes a second testcase for a
    teardown error after a pass) keeps its worst outcome.  A module-level
    record with no test name keys to the bare file path.
    Raises ET.ParseError / OSError on an unreadable file; callers fail closed.
    """
    outcomes = {}
    for testcase in ET.parse(path).iter("testcase"):
        key = _junit_key(testcase, known_files)
        if key is None:
            continue
        new = _outcome(testcase)
        if outcomes.get(key) != FAILED:
            if new == FAILED or key not in outcomes:
                outcomes[key] = new
    return outcomes


def overlay(outcome_maps):
    """Merge per-attempt outcomes in order (initial, then its serial rerun).

    A later outcome replaces an earlier one, except that a SKIP never clears
    a FAILURE: only a later pass does.  This is verify_rerun_coverage.py's
    rule ("a skip is not a pass") carried across attempts.  The serial rerun
    of a test whose routers failed to start typically comes back skipped
    (`if tgen.routers_have_failure(): pytest.skip(...)`), and letting that
    skip win would drop the test from the resume list AND count it as
    accounted for by the prior attempt, so a failure that turned attempt 1
    red would be green on attempt 2 without ever passing.
    """
    merged = {}
    for m in outcome_maps:
        for key, outcome in m.items():
            if outcome == SKIPPED and merged.get(key) == FAILED:
                continue
            merged[key] = outcome
    return merged


def expected_for_run(collected, run_entries):
    """Collected IDs selected by a run list of files and/or node IDs.

    Returns (expected, unmatched_entries).
    """
    files = {}
    for cid in collected:
        files.setdefault(split_id(cid)[0], []).append(cid)
    collected_set = set(collected)
    expected = set()
    unmatched = []
    for entry in run_entries:
        fname, test = split_id(entry)
        if test is None and fname in files:
            expected.update(files[fname])
        elif test is not None and normalize(entry) in collected_set:
            expected.add(normalize(entry))
        else:
            unmatched.append(entry)
    return expected, unmatched


def check(collected, run_entries, results, priors=()):
    """Return a list of problems; empty means the run is fully accounted for.

    collected    iterable of collected node IDs (any spelling)
    run_entries  the run list handed to pytest (files and/or node IDs)
    results      {normalized ID: outcome} from this attempt's junit
    priors       {normalized ID: outcome} maps from the resumed attempt, in
                 overlay order
    """
    collected = sorted({normalize(c) for c in collected})
    if not collected:
        return ["the collection is empty; refusing to certify against nothing"]
    if not run_entries:
        return ["the run list is empty; an empty list runs the whole tree"]

    problems = []
    expected, unmatched = expected_for_run(collected, run_entries)
    for entry in unmatched:
        problems.append(
            "{}: is in the run list but names nothing --collect-only "
            "collected, so the run differs from the plan".format(entry)
        )
    if not expected:
        problems.append("the run list selects no collected test")

    accounted = set(results)
    for cid in sorted(expected - accounted):
        problems.append(
            "{}: was in this attempt's run list but has NO result in its "
            "junit (never scheduled, lost with a worker, or the session was "
            "interrupted)".format(cid)
        )

    prior_ok = {cid for cid, outcome in overlay(priors).items() if outcome != FAILED}
    for cid in sorted(set(collected) - accounted - prior_ok - expected):
        problems.append(
            "{}: is collected but accounted for neither by this attempt nor "
            "by a non-failing result in the prior attempt, so it was never "
            "verified".format(cid)
        )
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Fail unless a topotest junit accounts for every collected test "
            "it was meant to run (BLO-35428)."
        )
    )
    parser.add_argument(
        "--collected",
        required=True,
        help="pytest --collect-only node IDs, one per line",
    )
    parser.add_argument(
        "--run-list",
        required=True,
        help="the list handed to pytest this attempt (files or node IDs)",
    )
    parser.add_argument("--results", required=True, help="this attempt's junit XML")
    parser.add_argument(
        "--prior",
        action="append",
        default=[],
        help=(
            "junit the run list was resumed from; repeat in overlay order "
            "(initial, then its serial rerun).  Omit on a full run."
        ),
    )
    args = parser.parse_args(argv)

    try:
        collected = read_list(args.collected)
        run_entries = read_list(args.run_list)
        known_files = {split_id(c)[0] for c in collected}
        results = parse_outcomes(args.results, known_files)
        priors = [parse_outcomes(p, known_files) for p in args.prior]
    except (ET.ParseError, OSError) as e:
        print("ERROR: cannot read coverage inputs: {}".format(e), file=sys.stderr)
        return 1

    problems = check(collected, run_entries, results, priors)
    print(
        "Topotest coverage: {} collected, {} run-list entr{}, {} result(s) "
        "this attempt, {} prior junit(s).".format(
            len(collected),
            len(run_entries),
            "y" if len(run_entries) == 1 else "ies",
            len(results),
            len(priors),
        )
    )
    sys.stdout.flush()
    if problems:
        print(
            "ERROR: {} collected test(s) are not accounted for:".format(len(problems)),
            file=sys.stderr,
        )
        for problem in problems:
            print("  - " + problem, file=sys.stderr)
        print(
            "Treating the run as INCOMPLETE: a green exit code over tests "
            "that produced no result is not a pass.",
            file=sys.stderr,
        )
        sys.stderr.flush()
        return 1
    print("Topotest coverage OK: every collected test is accounted for.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
