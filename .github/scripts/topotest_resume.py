#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Decide what a topotest leg runs on this attempt: the whole tree, or only the
# files that still failed in the previous attempt ("Re-run failed jobs").
#
# Why this exists (BLO-35428): the resume path in github-ci.yml looked for
# test-results-<id>/topotests.xml, but upload-artifact roots an artifact at
# the least common ancestor of the paths that exist.  A leg with failures
# uploads BOTH test-results-<id> and test-results-<id>-initial, so its
# artifact is laid out one level deeper than the check expected
# (test-results-<id>/test-results-<id>/topotests.xml; the downloaded
# artifacts of runs 35709500854, 35480015782 and 35409722977 are all nested
# this way).  The check therefore missed exactly the legs that had failures,
# so "Re-run failed jobs" after a real test failure re-ran the whole tree.
#
# The layout is now pinned (both directories always exist), the download goes
# to a directory the run step does not delete, and this script decides from
# it.  Every doubt resolves to the whole universe -- slower, never narrower:
#
#   * no previous results, or the cleared seed Build uploads   -> full run
#   * a prior junit that does not account for every collected
#     test (cap kill, interrupted session)                     -> full run
#   * a prior failure in a file that is not collected now      -> full run
#   * no failures left to resume (the job failed outside the
#     suite, e.g. a cap kill in the upload tail)                -> full run
#   * otherwise                   -> the files that still fail, sorted
#
# stdout is the run list, one entry per line, and is never empty.  The reason
# goes to stderr.  With --prior-out, the junit(s) the decision was based on
# are written there in overlay order (empty on a full run) so the coverage
# check can require every collected test to be accounted for by either the
# prior attempt or this one.

import argparse
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from topotest_coverage import (  # noqa: E402
    FAILED,
    normalize,
    overlay,
    parse_outcomes,
    read_list,
    split_id,
)


def locate(prev, rid):
    """Return (initial, final) junit paths under a downloaded artifact.

    final:   <prev>/test-results-<id>/topotests.xml -- the parallel run on a
             clean leg, the serial rerun on a leg that had failures;
             falls back to the legacy flat layout <prev>/topotests.xml.
    initial: <prev>/test-results-<id>-initial/topotests.xml -- the parallel
             run of a leg that had failures.
    Either is None when absent.
    """
    final = os.path.join(prev, "test-results-" + rid, "topotests.xml")
    if not os.path.isfile(final):
        legacy = os.path.join(prev, "topotests.xml")
        final = legacy if os.path.isfile(legacy) else None
    initial = os.path.join(prev, "test-results-" + rid + "-initial", "topotests.xml")
    if not os.path.isfile(initial):
        initial = None
    return initial, final


def decide(prev, rid, collected, universe):
    """Return (run_list, prior_paths, reason).

    run_list is never empty: every path that cannot justify a narrowed list
    returns the whole universe, in the order given.
    """
    universe = list(dict.fromkeys(universe))
    if not universe:
        raise ValueError("empty universe")

    def full(reason):
        return universe, [], "full run: " + reason

    if not os.path.isdir(prev):
        return full("no previous results were downloaded")

    initial, final = locate(prev, rid)
    whole = initial or final
    if whole is None:
        return full(
            "no topotests.xml in the previous results (the cleared seed from "
            "Build, or the prior attempt ended before gathering results)"
        )

    known_files = {split_id(c)[0] for c in collected}
    priors = [p for p in (initial, final) if p]
    try:
        maps = [parse_outcomes(p, known_files) for p in priors]
    except (ET.ParseError, OSError) as e:
        return full("previous junit unreadable: {}".format(e))

    whole_map = maps[0]
    missing = {normalize(c) for c in collected} - set(whole_map)
    if missing:
        return full(
            "previous junit {} accounts for only {} of {} collected tests "
            "(partial junit: cap kill, interrupted session, or an earlier "
            "narrowed attempt); e.g. {}".format(
                whole,
                len(collected) - len(missing),
                len(collected),
                sorted(missing)[0],
            )
        )

    merged = overlay(maps)
    failing = sorted(
        {split_id(cid)[0] for cid, outcome in merged.items() if outcome == FAILED}
    )
    if not failing:
        return full("the previous attempt left no failing test to resume")

    universe_set = set(universe)
    stray = [f for f in failing if f not in universe_set]
    if stray:
        return full(
            "previous failures name files outside the collected universe: "
            + " ".join(stray)
        )
    return (
        failing,
        priors,
        "resume: {} file(s) still failing in the previous attempt ({})".format(
            len(failing), " then ".join(priors)
        ),
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Print the topotest run list for this attempt (BLO-35428)."
    )
    parser.add_argument("--prev", required=True, help="downloaded artifact dir")
    parser.add_argument("--id", required=True, help="leg id, e.g. amd64_u22")
    parser.add_argument(
        "--collected", required=True, help="pytest --collect-only node IDs"
    )
    parser.add_argument(
        "--universe", required=True, help="every collected test file, one per line"
    )
    parser.add_argument(
        "--prior-out",
        help="write the junit path(s) a resume was based on here (empty = full)",
    )
    args = parser.parse_args(argv)

    collected = read_list(args.collected)
    universe = read_list(args.universe)
    if not collected or not universe:
        print(
            "ERROR: empty collection or universe; refusing to choose a run list",
            file=sys.stderr,
        )
        return 1

    run_list, priors, reason = decide(args.prev, args.id, collected, universe)
    print(reason, file=sys.stderr)
    if args.prior_out:
        with open(args.prior_out, "w") as f:
            f.writelines(p + "\n" for p in priors)
    sys.stdout.write("".join(entry + "\n" for entry in run_list))
    return 0


if __name__ == "__main__":
    sys.exit(main())
