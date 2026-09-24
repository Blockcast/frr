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


def verify(expected_ids, executed, skipped):
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
    args = parser.parse_args()

    with open(args.expected) as f:
        expected_ids = {line.strip() for line in f if line.strip()}

    try:
        executed, skipped = parse_results(args.results)
    except (ET.ParseError, OSError) as e:
        # An unreadable or truncated results file is itself a failure to
        # verify; never let it degrade into a pass.
        print(
            "ERROR: cannot read rerun results {}: {}".format(args.results, e),
            file=sys.stderr,
        )
        return 1

    problems = verify(expected_ids, executed, skipped)

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
