#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Verify that a serial topotest rerun actually re-executed the tests it was
# asked to re-verify.
#
# Background: the topotest job reruns the parallel run's failures serially and
# treats pytest's exit code as the whole answer.  pytest exits 0 for
# "everything I collected passed", which is a strictly weaker claim than
# "every test you named passed".  When the two diverge -- a target that
# collects nothing, is never handed to pytest at all, or comes back skipped --
# the step printed "All rerun tests passed" over a genuinely red run.  This
# script closes that gap by comparing the set of test IDs that actually
# produced a result against the set that was requested.
#
# The ID construction below deliberately mirrors get_filtered() in
# tests/topotests/analyze.py, because the expected IDs are harvested with
# `analyze.py -r` and the two sides have to agree on spelling for the
# comparison to mean anything.  If that function's key format changes, this
# must change with it.

import argparse
import re
import sys
import xml.etree.ElementTree as ET

# pytest-xdist synthesises a testcase whose @name is the worker id (e.g. gw5)
# for collection errors; analyze.py skips those and so do we -- they name a
# worker, not a test.
XDIST_WORKER_RE = re.compile(r"^gw\d+$")


def testcase_id(testcase):
    """Build the analyze.py-compatible node ID for one <testcase> element.

    Returns None for elements that do not name a real test (xdist workers).
    """
    fname = testcase.get("file", "")
    cname = testcase.get("classname", "")
    name = testcase.get("name", "")

    if not fname and not cname:
        if not name or XDIST_WORKER_RE.match(name):
            return None
        # A module-level failure can land here with no file/classname.
        return name.replace(".", "/") + ".py"

    if not fname:
        fname = cname.replace(".", "/") + ".py"
    if not name:
        return fname
    return fname + "::" + name


def parse_results(path):
    """Return (executed, skipped) sets of node IDs found in a junit XML file."""
    tree = ET.parse(path)
    executed = set()
    skipped = set()
    for testcase in tree.iter("testcase"):
        tid = testcase_id(testcase)
        if tid is None:
            continue
        # A <skipped> child means the test was collected but never actually
        # exercised, so it cannot vindicate a failure from the parallel run.
        if testcase.find("skipped") is not None:
            skipped.add(tid)
        else:
            executed.add(tid)
    return executed, skipped


def parse_errored(path):
    """Return the set of node IDs the parallel run reported as <error>.

    An <error> is a setup/teardown failure, not a test verdict: the test body
    never ran.  That distinction is what makes an excused skip sound in
    verify() below.
    """
    errored = set()
    for testcase in ET.parse(path).iter("testcase"):
        tid = testcase_id(testcase)
        if tid is not None and testcase.find("error") is not None:
            errored.add(tid)
    return errored


def covers(expected, actual_ids):
    """True if `expected` was accounted for by some ID in `actual_ids`.

    A file-level expectation (no "::") is satisfied by any test from that
    file, since analyze.py emits a bare path when a whole module errors out.
    A full node ID must match exactly.
    """
    if expected in actual_ids:
        return True
    if "::" not in expected:
        prefix = expected + "::"
        return any(a.startswith(prefix) for a in actual_ids)
    return False


def parse_failures(path):
    """Return the set of node IDs that FAILED or ERRORED in a junit XML file."""
    tree = ET.parse(path)
    failed = set()
    for testcase in tree.iter("testcase"):
        tid = testcase_id(testcase)
        if tid is None:
            continue
        if testcase.find("failure") is not None or testcase.find("error") is not None:
            failed.add(tid)
    return failed


def unexpected_failures(expected_ids, failed):
    """Failures the harvested set does not account for, sorted.

    BLO-36708 made the rerun run whole FILES rather than node IDs, because a
    topotest module is a stateful sequence and a single node ID re-run out of
    order fails on an assertion the parallel run never reached.  The
    consequence (BLO-36839): the rerun can now fail on a test that was never
    in `rerun_tests`, and the step exits 1 -- correctly -- while the log shows
    only RERUN_TESTS/RERUN_FILES, neither of which need contain the culprit.
    Name it, so "Some rerun tests still failed" is actionable.

    A file and the tests in it account for each other in both directions, as
    in covers(): a bare-file expectation accounts for every failure in that
    file, and a bare-file failure -- a module-level error, see testcase_id()
    -- is accounted for by any expected test from that file.
    """
    return sorted(f for f in failed if not _accounted_for(f, expected_ids))


def _accounted_for(failure, expected_ids):
    if failure in expected_ids:
        return True
    if "::" in failure:
        return failure.split("::", 1)[0] in expected_ids
    prefix = failure + "::"
    return any(e.startswith(prefix) for e in expected_ids)


def verify(expected_ids, executed, skipped, parallel_errored=frozenset()):
    """Return a list of human-readable problems; empty means the rerun is trustworthy."""
    problems = []

    if not expected_ids:
        # Guard against the caller handing us an empty expectation set, which
        # would otherwise vacuously "pass" and re-open the hole.
        return ["no expected test IDs were supplied; refusing to certify the rerun"]

    if not executed and not skipped:
        problems.append(
            "the rerun produced ZERO test results -- pytest collected nothing. "
            "Requested targets: " + " ".join(sorted(expected_ids))
        )
        return problems

    for expected in sorted(expected_ids):
        if covers(expected, executed):
            continue
        if covers(expected, skipped):
            # BLO-36708: a skip only fails to vindicate a real FAILURE.  When
            # the parallel run reported this ID as an <error> the test body
            # never ran there either, so the rerun skipping it leaves it in
            # exactly the state a healthy parallel run would have: not run,
            # by its own choice.
            #
            # Without this, a module-scoped fixture failure was unclearable.
            # pytest errors EVERY item in the file, and every topotest file
            # carries a test_memory_leak that is skipped unconditionally in
            # CI (is_memleak_enabled() is false), so that ID entered the
            # expected set and could never come back executed however clean
            # the rerun was.  Run 36343914099 u22 s2: srv6_sid_manager hit
            # "error mounting new sysfs", all 7 items errored, the whole-file
            # rerun went 6 passed / 1 skipped in 3m26s, and the shard was
            # still failed over test_memory_leak.  Master had no green path.
            if covers(expected, parallel_errored):
                continue
            problems.append(
                "{}: was SKIPPED in the rerun, so the parallel-run failure is "
                "unverified (a skip is not a pass)".format(expected)
            )
        else:
            problems.append(
                "{}: was NEVER EXECUTED by the rerun -- it collected no tests "
                "and reported no error".format(expected)
            )
    return problems


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Fail when a serial topotest rerun did not execute every test ID "
            "harvested from the failing parallel run."
        )
    )
    parser.add_argument(
        "--expected",
        required=True,
        help="file of expected pytest node IDs, one per line (from analyze.py -r)",
    )
    parser.add_argument(
        "--results",
        required=True,
        help="junit XML written by the rerun (topotests.xml)",
    )
    parser.add_argument(
        "--parallel-results",
        help=(
            "junit XML from the parallel run.  Optional; when given, a target "
            "that ERRORED there may come back skipped from the rerun without "
            "failing this check (see verify())."
        ),
    )
    args = parser.parse_args()

    with open(args.expected) as f:
        expected_ids = {line.strip() for line in f if line.strip()}

    try:
        executed, skipped = parse_results(args.results)
        failed = parse_failures(args.results)
    except (ET.ParseError, OSError) as e:
        # An unreadable or truncated results file is itself a failure to
        # verify; never let it degrade into a pass.
        print(
            "ERROR: cannot read rerun results {}: {}".format(args.results, e),
            file=sys.stderr,
        )
        return 1

    parallel_errored = frozenset()
    if args.parallel_results:
        try:
            parallel_errored = parse_errored(args.parallel_results)
        except (ET.ParseError, OSError) as e:
            # Fail closed: without it we simply lose the excuse, so fall back
            # to the strict rule rather than dropping the whole check.
            print(
                "WARNING: cannot read parallel results {}: {} -- no skip will "
                "be excused".format(args.parallel_results, e),
                file=sys.stderr,
            )

    problems = verify(expected_ids, executed, skipped, parallel_errored)

    verified = len(expected_ids) - len(problems) if expected_ids else 0
    print(
        "Rerun coverage: {}/{} requested target(s) verified "
        "({} test result(s) in the rerun, {} skipped).".format(
            verified, len(expected_ids), len(executed), len(skipped)
        )
    )
    # Flush before writing to stderr so the summary is not reordered ahead of
    # or behind the problem list in the interleaved CI log.
    sys.stdout.flush()

    # Diagnosability, not a verdict: these do not make the rerun fail (pytest's
    # exit code already does that), they say WHICH test the caller's
    # "Some rerun tests still failed" is about when it is not one we asked for.
    outside = unexpected_failures(expected_ids, failed)
    if outside:
        print(
            "NOTE: the rerun also failed {} test(s) outside the harvested "
            "failure set -- it runs whole files, so these ran as siblings of a "
            "requested target:".format(len(outside)),
            file=sys.stderr,
        )
        for f in outside:
            print("  - " + f, file=sys.stderr)
        sys.stderr.flush()

    if problems:
        print(
            "ERROR: the serial rerun did not re-verify every failing test:",
            file=sys.stderr,
        )
        for problem in problems:
            print("  - " + problem, file=sys.stderr)
        print(
            "Treating this rerun as FAILED: passing tests that were never run "
            "cannot clear the parallel run's failures.",
            file=sys.stderr,
        )
        sys.stderr.flush()
        return 1

    print("Rerun coverage OK: every requested test ID produced a result.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
