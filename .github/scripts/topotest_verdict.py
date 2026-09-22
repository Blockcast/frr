#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# CI-Verdict: one stable check that says whether a github-ci run built and
# tested what it was supposed to (BLO-35428).
#
# Sharding the Test job turns one check per platform into one per shard, and
# a skipped or missing shard is not a red check on its own: GitHub renders a
# skipped job as neutral.  This job needs every gating job and reads their
# results plus the plan artifact each Test shard uploads, so "a shard never
# ran" and "the shards did not cover the tree" are red here.
#
#   topotest_verdict.py --needs-env NEEDS_JSON --plans DIR --shards N \
#       --platforms p1,p2 --event-name EVENT --actor ACTOR
#
# NEEDS_JSON names an environment variable holding `toJSON(needs)`.
#
# FAIL CLOSED.  The only two ways to pass without the full checks are the
# two cases where the workflow deliberately builds nothing, and each is
# matched exactly, never by exclusion:
#
#   * doc-only:  doc-path-filter.result == 'success' AND its non_doc output
#                is the string 'false'.  NOT `non_doc != 'true'`: a filter
#                job that failed, was cancelled, or lost its runner (arc-default
#                pods are preemptible; one was preempted in run 35776450503)
#                before writing outputs leaves non_doc empty, Build/Test are
#                then skipped, and an inequality test would pass a run that
#                built and tested nothing.
#   * mergify:   doc-path-filter.result == 'skipped' AND the event is
#                pull_request AND the actor is mergify[bot] -- the exact
#                condition doc-path-filter's own `if:` skips on.
#
# Both exemptions additionally require every other needed job to be
# 'skipped'; if anything ran, the exemption does not describe this run.
# Every other combination goes through the full checks:
#
#   * Build, Unit-Test and Test are each 'success';
#   * per platform, all N plan artifacts are present and complete, their
#     plans are pairwise disjoint, their universe.txt files are identical,
#     and the plans' union is that universe;
#   * every file in each shard's collected-files.txt is in exactly one plan
#     (planned-but-not-collected is allowed: a module-level skip collects
#     nothing);
#   * every collected test ID is in the accounted.txt of the shard whose plan
#     owns its file, and no ID is accounted by two shards.  accounted.txt is
#     written by topotest_coverage.py only when its check passed, so this is
#     what each shard actually executed (or carried over non-failing from the
#     attempt it resumed), not what it was meant to.
#
# Any unreadable input is a failure, never a pass.  Every failed rule is
# reported, not just the first.

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from topotest_coverage import normalize, split_id  # noqa: E402

FILTER_JOB = "doc-path-filter"
REQUIRED_JOBS = ("Build", "Unit-Test", "Test")
MERGIFY_ACTOR = "mergify[bot]"
PLAN_FILES = (
    "shard.txt",
    "plan.txt",
    "universe.txt",
    "collected-files.txt",
    "collected-ids.txt",
    "accounted.txt",
)


def artifact_name(platform, k):
    """The plan artifact name the Test job uploads (topotest-plan-${RESULT_ID})."""
    return "topotest-plan-{}-s{}".format(platform, k)


def _lines(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def job_rules(needs, event_name, actor, required=REQUIRED_JOBS):
    """Return (problems, exempt_reason).

    exempt_reason is a string when the run is one of the two no-build cases
    and every other job was skipped; the caller then skips the plan checks.
    """
    problems = []
    for job in (FILTER_JOB,) + tuple(required):
        entry = needs.get(job)
        if not isinstance(entry, dict) or not isinstance(entry.get("result"), str):
            problems.append(
                "needs.{} is missing or has no result: this job's `needs:` and "
                "the verdict's job list have drifted".format(job)
            )
    if problems:
        return problems, None

    filt = needs[FILTER_JOB]
    result = filt["result"]
    outputs = filt.get("outputs")
    non_doc = outputs.get("non_doc") if isinstance(outputs, dict) else None
    others = {job: needs[job]["result"] for job in required}

    exempt = None
    if result == "skipped":
        if event_name == "pull_request" and actor == MERGIFY_ACTOR:
            exempt = "mergify backport PR ({} skipped by its own `if:`)".format(
                FILTER_JOB
            )
        else:
            return [
                "{} was skipped, but this is not the mergify backport case "
                "(event {!r}, actor {!r}); nothing says this run may skip its "
                "build and tests".format(FILTER_JOB, event_name, actor)
            ], None
    elif result == "success":
        if non_doc == "false":
            exempt = "doc-only change ({} non_doc == 'false')".format(FILTER_JOB)
        elif non_doc != "true":
            return [
                "{} succeeded but its non_doc output is {!r}, neither 'true' "
                "nor 'false'; cannot tell whether this run had to build and "
                "test".format(FILTER_JOB, non_doc)
            ], None
    else:
        return [
            "{} concluded {!r} (non_doc {!r}): a filter that did not succeed "
            "cannot exempt anything, and the jobs behind it did not run".format(
                FILTER_JOB, result, non_doc
            )
        ], None

    if exempt is not None:
        ran = {job: r for job, r in others.items() if r != "skipped"}
        if ran:
            return [
                "exemption '{}' claimed, but {} did not skip; the exemption "
                "does not describe this run".format(
                    exempt,
                    ", ".join(
                        "{} is {!r}".format(j, r) for j, r in sorted(ran.items())
                    ),
                )
            ], None
        return [], exempt

    for job, r in others.items():
        if r != "success":
            problems.append("{} concluded {!r}, not 'success'".format(job, r))
    return problems, None


def plan_rules(plans_dir, platform, shards):
    """Return (problems, summary line) for one platform's plan artifacts."""
    problems = []
    data = {}
    for k in range(1, shards + 1):
        name = artifact_name(platform, k)
        d = os.path.join(plans_dir, name)
        if not os.path.isdir(d):
            problems.append(
                "{}: plan artifact {} is missing (shard never ran, or "
                "died before uploading it)".format(platform, name)
            )
            continue
        shard = {}
        for fname in PLAN_FILES:
            path = os.path.join(d, fname)
            try:
                shard[fname] = _lines(path)
            except OSError as e:
                problems.append("{}: {} unreadable: {}".format(name, fname, e))
                continue
            if not shard[fname]:
                problems.append("{}: {} is empty".format(name, fname))
        if len(shard) != len(PLAN_FILES):
            continue
        want = "platform={} shard={} shards={}".format(platform, k, shards)
        if shard["shard.txt"] != [want]:
            problems.append(
                "{}: shard.txt says {!r}, expected {!r}".format(
                    name, " ".join(shard["shard.txt"]), want
                )
            )
        data[k] = shard
    if problems:
        return problems, None

    owner = {}
    for k in sorted(data):
        for f in data[k]["plan.txt"]:
            if f in owner:
                problems.append(
                    "{}: {} is planned in both shard {} and shard {}".format(
                        platform, f, owner[f], k
                    )
                )
            else:
                owner[f] = k

    universe = data[1]["universe.txt"]
    for k in sorted(data):
        if data[k]["universe.txt"] != universe:
            problems.append(
                "{}: shard {}'s universe.txt differs from shard 1's; "
                "the shards were planned over different trees".format(platform, k)
            )
    uni = set(universe)
    for f in sorted(set(owner) - uni):
        problems.append(
            "{}: {} is planned in shard {} but is not in the universe".format(
                platform, f, owner[f]
            )
        )
    for f in sorted(uni - set(owner)):
        problems.append(
            "{}: {} is in the universe but in no shard's plan".format(platform, f)
        )

    for k in sorted(data):
        for f in data[k]["collected-files.txt"]:
            if f not in owner:
                problems.append(
                    "{}: {} was collected by shard {} but is in no "
                    "plan, so no shard ran it".format(platform, f, k)
                )

    accounted_by = {}
    for k in sorted(data):
        for cid in data[k]["accounted.txt"]:
            fname = split_id(cid)[0]
            if owner.get(fname) != k:
                problems.append(
                    "{}: shard {} accounts for {}, whose file is not "
                    "in its plan".format(platform, k, cid)
                )
            if cid in accounted_by:
                problems.append(
                    "{}: {} is accounted by shards {} and {}".format(
                        platform, cid, accounted_by[cid], k
                    )
                )
            else:
                accounted_by[cid] = k
    collected_ids = set()
    for k in sorted(data):
        for cid in data[k]["collected-ids.txt"]:
            collected_ids.add(normalize(cid))
    for cid in sorted(collected_ids - set(accounted_by)):
        f = split_id(cid)[0]
        problems.append(
            "{}: {} was collected but no shard accounted for it "
            "(planned in shard {})".format(platform, cid, owner.get(f))
        )

    summary = (
        "{}: {} shards, {} files planned of {} enumerated, {} collected IDs, "
        "{} accounted ({})".format(
            platform,
            shards,
            len(owner),
            len(uni),
            len(collected_ids),
            len(accounted_by),
            " + ".join(str(len(data[k]["accounted.txt"])) for k in sorted(data)),
        )
    )
    return problems, summary


def main(argv=None):
    parser = argparse.ArgumentParser(description="github-ci CI-Verdict (BLO-35428).")
    parser.add_argument(
        "--needs-env", required=True, help="env var holding toJSON(needs)"
    )
    parser.add_argument(
        "--plans",
        required=True,
        help="dir holding the downloaded topotest-plan-* artifacts",
    )
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--platforms", required=True, help="comma-separated")
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--actor", required=True)
    args = parser.parse_args(argv)

    problems = []
    platforms = [p for p in args.platforms.split(",") if p]
    if args.shards < 1 or not platforms:
        problems.append("--shards must be >= 1 and --platforms non-empty")

    raw = os.environ.get(args.needs_env, "")
    needs = None
    try:
        needs = json.loads(raw) if raw.strip() else None
    except ValueError as e:
        problems.append("{} is not JSON: {}".format(args.needs_env, e))
    if not problems and not isinstance(needs, dict):
        problems.append(
            "{} is unset, empty or not an object; cannot judge a run "
            "from nothing".format(args.needs_env)
        )

    exempt = None
    if not problems:
        job_problems, exempt = job_rules(needs, args.event_name, args.actor)
        problems += job_problems

    summaries = []
    if not problems and exempt is None:
        for platform in platforms:
            p, summary = plan_rules(args.plans, platform, args.shards)
            problems += p
            if summary:
                summaries.append(summary)

    for s in summaries:
        print(s)
    if problems:
        for p in problems:
            print("::error title=CI-Verdict::" + p)
        print("CI-Verdict: RED ({} problem(s)).".format(len(problems)), file=sys.stderr)
        return 1
    if exempt is not None:
        print("CI-Verdict: green by exemption: " + exempt)
    else:
        print(
            "CI-Verdict: green: Build, Unit-Test and every Test shard succeeded, "
            "and the shards covered the collection exactly once."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
