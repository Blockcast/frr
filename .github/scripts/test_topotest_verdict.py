#!/usr/bin/env python3
"""Fixtures pinning CI-Verdict (topotest_verdict.py), BLO-35428.

The property every case protects: the verdict can only be green when Build,
Build-LTTng, Unit-Test and every Test shard succeeded and the shards covered
the collection exactly once -- or in the two deliberately build-less cases,
each matched exactly.  A filter job that failed, was cancelled or lost its
runner (empty outputs) must be red, because the jobs behind it were skipped
and nothing was built or tested (critic blocker: the first draft passed on
`non_doc != 'true'`).  An empty change list (doc and non_doc both 'false')
is not doc-only, and Documentation-HTML must succeed whenever doc/ changed,
doc-only runs included (review findings on this stack).

Build-LTTng left Build's matrix so it no longer delays Test, and no other
job needs it, so the verdict is the only thing that turns its failure red
(critic: that must land in the same change, with a test).  doc-path-filter
defaults to building everything when its paths-filter step cannot decide;
TestBuildDecisionStep runs that inline script itself.

Stdlib only, no network (TestBuildDecisionStep runs bash).

Run: python3 -m unittest discover -s .github/scripts -p 'test_topotest_*.py'
"""

import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_SPEC = importlib.util.spec_from_file_location(
    "topotest_verdict", os.path.join(_HERE, "topotest_verdict.py")
)
verdict = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verdict)

PLATFORMS = ("amd64_u22", "amd64_u24")
SHARDS = 2
# Two shards over four files; a/ and b/ collect, c/ is planned in shard 2 and
# collects nothing (a module-level skip), d/ collects and is in shard 1.
PLANS = {
    1: ["a/test_a.py", "d/test_d.py"],
    2: ["b/test_b.py", "c/test_c.py"],
}
UNIVERSE = sorted(PLANS[1] + PLANS[2])
COLLECTED_IDS = [
    "a/test_a.py::test_one",
    "a/test_a.py::TestK::test_two",
    "b/test_b.py::test_three[x-y]",
    "d/test_d.py::test_four",
]


_DERIVE = object()


def needs(
    filt="success",
    build="true",
    doc=_DERIVE,
    non_doc=_DERIVE,
    docs=_DERIVE,
    outputs=True,
    **results
):
    """toJSON(needs) as GitHub renders it; results override Build etc.

    doc-path-filter's outputs: `build` and `docs` as its decide step writes
    them, and the raw paths-filter classification, which by default is
    doc-only when build is 'false' and a code change otherwise; docs is
    'false' exactly when doc is 'false'.  None leaves a key out.
    Documentation-HTML defaults to what its `if:` makes it: 'success' when
    the filter succeeded with docs 'true', 'skipped' otherwise.
    """
    doc_only = build == "false"
    if doc is _DERIVE:
        doc = "true" if doc_only else "false"
    if non_doc is _DERIVE:
        non_doc = "false" if doc_only else "true"
    if docs is _DERIVE:
        docs = "false" if doc == "false" else "true"
    filter_entry = {"result": filt, "outputs": {}}
    if outputs:
        o = {"build": build, "doc": doc, "non_doc": non_doc, "docs": docs}
        filter_entry["outputs"] = {k: v for k, v in o.items() if v is not None}
    n = {"doc-path-filter": filter_entry}
    for job in verdict.REQUIRED_JOBS:
        n[job] = {
            "result": results.get(job.replace("-", "_"), "success"),
            "outputs": {},
        }
    docs_ran = filt == "success" and outputs and docs == "true"
    n[verdict.DOCS_JOB] = {
        "result": results.get(
            "Documentation_HTML", "success" if docs_ran else "skipped"
        ),
        "outputs": {},
    }
    return n


def accounted_for(k):
    """What topotest_coverage.py --accounted-out writes for shard k."""
    return sorted(
        verdict.normalize(c) for c in COLLECTED_IDS if c.split("::")[0] in PLANS[k]
    )


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.plans = os.path.join(self._tmp.name, "plans")
        for p in PLATFORMS:
            for k in range(1, SHARDS + 1):
                self.write_plan(p, k)

    def tearDown(self):
        self._tmp.cleanup()

    def write_plan(self, platform, k, **override):
        d = os.path.join(self.plans, verdict.artifact_name(platform, k))
        os.makedirs(d, exist_ok=True)
        files = {
            "shard.txt": ["platform={} shard={} shards={}".format(platform, k, SHARDS)],
            "plan.txt": PLANS[k],
            "universe.txt": UNIVERSE,
            "collected-files.txt": sorted({c.split("::")[0] for c in COLLECTED_IDS}),
            "collected-ids.txt": COLLECTED_IDS,
            "accounted.txt": accounted_for(k),
        }
        files.update(override)
        for name, lines in files.items():
            path = os.path.join(d, name)
            if lines is None:
                if os.path.exists(path):
                    os.remove(path)
                continue
            with open(path, "w") as f:
                f.writelines(line + "\n" for line in lines)
        return d

    def run_verdict(
        self, needs_obj, event="pull_request", actor="someone", shards=SHARDS, raw=None
    ):
        env_name = "NEEDS_JSON_TEST"
        saved = os.environ.get(env_name)
        if raw is not None:
            os.environ[env_name] = raw
        elif needs_obj is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = json.dumps(needs_obj)
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = verdict.main(
                    [
                        "--needs-env",
                        env_name,
                        "--plans",
                        self.plans,
                        "--shards",
                        str(shards),
                        "--platforms",
                        ",".join(PLATFORMS),
                        "--event-name",
                        event,
                        "--actor",
                        actor,
                    ]
                )
        finally:
            if saved is None:
                os.environ.pop(env_name, None)
            else:
                os.environ[env_name] = saved
        self.out = out.getvalue()
        return rc

    def assertRed(self, *args, why=None, **kw):
        self.assertEqual(self.run_verdict(*args, **kw), 1, self.out)
        if why:
            self.assertRegex(self.out, why)

    def assertGreen(self, *args, **kw):
        self.assertEqual(self.run_verdict(*args, **kw), 0, self.out)


# Every job behind doc-path-filter skipped, as on a doc-only, mergify or
# filter-failed run.
SKIPPED = dict(
    Build="skipped", Build_LTTng="skipped", Unit_Test="skipped", Test="skipped"
)


class TestFullRun(Base):
    def test_all_green_with_complete_plans(self):
        self.assertGreen(needs())
        self.assertIn(
            "amd64_u22: 2 shards, 4 files planned of 4 enumerated, "
            "4 collected IDs, 4 accounted (3 + 1)",
            self.out,
        )
        self.assertIn("Build-LTTng", self.out)

    def test_planned_but_not_collected_is_allowed(self):
        """c/test_c.py is planned and collects nothing (module-level skip)."""
        self.assertGreen(needs())

    def test_build_failure_is_red(self):
        self.assertRed(needs(Build="failure"), why="Build concluded 'failure'")

    def test_unit_test_cancelled_is_red(self):
        self.assertRed(needs(Unit_Test="cancelled"), why="Unit-Test concluded")

    def test_test_failure_is_red(self):
        self.assertRed(needs(Test="failure"), why="Test concluded 'failure'")

    def test_test_skipped_is_red(self):
        """A skipped Test (e.g. every shard skipped) is not a pass."""
        self.assertRed(needs(Test="skipped"), why="Test concluded 'skipped'")

    def test_every_failed_rule_is_reported(self):
        self.assertRed(
            needs(
                Build="failure",
                Build_LTTng="failure",
                Unit_Test="failure",
                Test="failure",
            )
        )
        self.assertEqual(self.out.count("::error title=CI-Verdict::"), 4, self.out)


class TestLttngBuild(Base):
    """Critic: moving LTTng off the Test gate must keep its failure red.

    Build-LTTng is needed by no job but CI-Verdict, so these are the only
    cases that stand between an LTTng build failure and a green verdict --
    with Build, Unit-Test and every Test shard green, as they will be when
    only the LTTng configuration is broken.
    """

    def test_lttng_build_failure_is_red_while_everything_else_is_green(self):
        self.assertRed(
            needs(Build_LTTng="failure"), why="Build-LTTng concluded 'failure'"
        )
        self.assertEqual(self.out.count("::error title=CI-Verdict::"), 1, self.out)

    def test_lttng_build_cancelled_or_timed_out_is_red(self):
        """A `timeout-minutes` kill is stamped 'cancelled'."""
        self.assertRed(needs(Build_LTTng="cancelled"), why="Build-LTTng concluded")

    def test_lttng_build_skipped_on_a_code_change_is_red(self):
        self.assertRed(
            needs(Build_LTTng="skipped"), why="Build-LTTng concluded 'skipped'"
        )

    def test_lttng_build_missing_from_needs_is_red(self):
        n = needs()
        del n["Build-LTTng"]
        self.assertRed(n, why="needs.Build-LTTng is missing")

    def test_lttng_is_a_required_job(self):
        self.assertIn("Build-LTTng", verdict.REQUIRED_JOBS)


class TestFilterJob(Base):
    """The critic blocker: the filter's own failure must never exempt."""

    def test_filter_failed_with_empty_outputs_is_red(self):
        n = needs(filt="failure", outputs=False, **SKIPPED)
        self.assertRed(n, why="doc-path-filter concluded 'failure'")

    def test_filter_lost_its_runner_is_red(self):
        """Preempted pod: result failure/cancelled, outputs empty strings."""
        for result in ("failure", "cancelled"):
            n = needs(filt=result, build="", doc="", non_doc="", **SKIPPED)
            self.assertRed(n, why="doc-path-filter concluded")

    def test_filter_failed_after_deciding_doc_only_is_red(self):
        """e.g. the job died after its decide step wrote build=false."""
        n = needs(filt="failure", build="false", **SKIPPED)
        self.assertRed(n, why="doc-path-filter concluded 'failure'")

    def test_filter_cancelled_is_red(self):
        """Also a `timeout-minutes` kill of the folded MIB population."""
        n = needs(filt="cancelled", outputs=False, **SKIPPED)
        self.assertRed(n)

    def test_filter_success_with_empty_build_is_red(self):
        n = needs(build="", **SKIPPED)
        self.assertRed(n, why="neither 'true' nor 'false'")

    def test_filter_success_with_missing_build_is_red(self):
        """The workflow of item 3, whose filter had no build output."""
        n = needs(build=None, doc="true", non_doc="false", **SKIPPED)
        self.assertRed(n, why="neither 'true' nor 'false'")

    def test_filter_success_with_missing_outputs_is_red(self):
        n = needs(outputs=False, **SKIPPED)
        self.assertRed(n, why="neither 'true' nor 'false'")

    def test_build_is_compared_exactly(self):
        for value in ("False", "0", "no", "TRUE", "false ", "true\n"):
            with self.subTest(build=value):
                n = needs(build=value, doc="true", non_doc="false", **SKIPPED)
                self.assertRed(n)

    def test_build_false_needs_the_exact_doc_only_classification(self):
        """The verdict re-derives the decide step's one build=false case."""
        cases = (
            ("true", "true"),  # mixed change
            ("false", "false"),  # empty change list
            ("false", "true"),  # code-only change
            ("", ""),  # filter errored (continue-on-error)
            (None, None),  # outputs missing
            ("True", "false"),
            ("true", "False"),
        )
        for doc, non_doc in cases:
            with self.subTest(doc=doc, non_doc=non_doc):
                n = needs(build="false", doc=doc, non_doc=non_doc, **SKIPPED)
                self.assertRed(n, why="not exactly doc-only")

    def test_filter_that_could_not_decide_builds_and_is_judged_in_full(self):
        """paths-filter errored: build=true, empty classification, all ran."""
        self.assertGreen(needs(build="true", doc="", non_doc=""))
        self.assertIn("CI-Verdict: green: Build, Build-LTTng", self.out)
        self.assertRed(
            needs(build="true", doc="", non_doc="", **SKIPPED),
            why="Build concluded 'skipped'",
        )

    def test_doc_only_change_is_green(self):
        n = needs(build="false", **SKIPPED)
        self.assertGreen(n)
        self.assertIn("doc-only", self.out)

    def test_doc_only_does_not_need_plans(self):
        n = needs(build="false", **SKIPPED)
        import shutil

        shutil.rmtree(self.plans)
        self.assertGreen(n)

    def test_doc_only_claim_with_a_job_that_ran_is_red(self):
        for job in ("Build", "Build_LTTng", "Unit_Test", "Test"):
            with self.subTest(job=job):
                n = needs(build="false", **dict(SKIPPED, **{job: "failure"}))
                self.assertRed(n, why="did not skip")

    def test_empty_change_list_builds_and_is_judged_in_full(self):
        """Review finding: paths-filter says doc 'false', non_doc 'false' when
        it found no changed file (first push of a branch at a commit already
        on master).  That is not doc-only: the decide step builds it, so it
        is green only when everything ran, and red when anything was skipped
        or when build 'false' is claimed over it."""
        empty = dict(doc="false", non_doc="false")
        self.assertGreen(needs(build="true", **empty))
        self.assertRed(
            needs(build="true", **dict(empty, **SKIPPED)),
            why="Build concluded 'skipped'",
        )
        self.assertRed(
            needs(build="false", **dict(empty, **SKIPPED)),
            why="not exactly doc-only",
        )

    def test_doc_output_is_compared_exactly(self):
        for value in ("True", "TRUE", "", "1", None):
            with self.subTest(doc=value):
                n = needs(
                    build="false",
                    doc=value,
                    non_doc="false",
                    Documentation_HTML="success",
                    **SKIPPED
                )
                self.assertRed(n, why="not exactly doc-only")

    def test_mergify_backport_is_green(self):
        n = needs(filt="skipped", outputs=False, **SKIPPED)
        self.assertGreen(n, event="pull_request", actor="mergify[bot]")
        self.assertIn("mergify", self.out)

    def test_filter_skipped_for_anyone_else_is_red(self):
        n = needs(filt="skipped", outputs=False, **SKIPPED)
        self.assertRed(n, event="pull_request", actor="omar", why="not the mergify")
        self.assertRed(n, event="push", actor="mergify[bot]", why="not the mergify")

    def test_mergify_with_a_job_that_ran_is_red(self):
        for job in ("Build_LTTng", "Test"):
            with self.subTest(job=job):
                n = needs(
                    filt="skipped", outputs=False, **dict(SKIPPED, **{job: "failure"})
                )
                self.assertRed(
                    n, event="pull_request", actor="mergify[bot]", why="did not skip"
                )


class TestDocsJob(Base):
    """Review finding: the docs build is the one job a doc-only run builds.

    It was outside the verdict, so a broken Sphinx build left CI-Verdict
    green -- on a doc-only run usually before the docs job had finished, and
    on a mixed run with every other job green.
    """

    DOC_ONLY = dict(build="false", **SKIPPED)

    def test_doc_only_needs_the_docs_build_to_succeed(self):
        self.assertGreen(needs(**self.DOC_ONLY))
        for result in ("failure", "cancelled", "skipped"):
            with self.subTest(docs=result):
                n = needs(Documentation_HTML=result, **self.DOC_ONLY)
                self.assertRed(n, why="Documentation-HTML concluded")
                self.assertEqual(
                    self.out.count("::error title=CI-Verdict::"), 1, self.out
                )

    def test_mixed_change_with_docs_failed_is_red(self):
        n = needs(doc="true", Documentation_HTML="failure")
        self.assertRed(n, why="Documentation-HTML concluded 'failure'")
        self.assertEqual(self.out.count("::error title=CI-Verdict::"), 1, self.out)

    def test_mixed_change_with_docs_green_is_green(self):
        self.assertGreen(needs(doc="true"))

    def test_docs_ran_on_a_code_only_change_is_red(self):
        """doc 'false' makes its `if:` false; anything but skipped is drift."""
        n = needs(doc="false", Documentation_HTML="success")
        self.assertRed(n, why="should have been 'skipped'")

    def test_mergify_with_docs_ran_is_red(self):
        n = needs(
            filt="skipped", outputs=False, Documentation_HTML="failure", **SKIPPED
        )
        self.assertRed(
            n, event="pull_request", actor="mergify[bot]", why="should have been"
        )
        self.assertEqual(self.out.count("::error title=CI-Verdict::"), 1, self.out)

    def test_docs_missing_from_needs_is_red(self):
        n = needs(**self.DOC_ONLY)
        del n[verdict.DOCS_JOB]
        self.assertRed(n, why="needs.Documentation-HTML is missing")

    def test_filter_that_could_not_decide_must_build_the_docs(self):
        """Review finding: paths-filter errored (continue-on-error), so doc
        was empty and a docs job keyed on it was skipped while
        doc-path-filter concluded 'success' -- all green, docs never built.
        The decide step now writes docs=true there, so a skip is red."""
        undecided = dict(build="true", doc="", non_doc="")
        self.assertGreen(needs(**undecided))
        self.assertRed(
            needs(Documentation_HTML="skipped", **undecided),
            why="Documentation-HTML concluded 'skipped'",
        )
        self.assertRed(
            needs(docs="false", Documentation_HTML="skipped", **undecided),
            why="says docs 'false'",
        )

    def test_docs_output_is_compared_exactly(self):
        for value in ("", None, "True", "FALSE", "false ", "1"):
            with self.subTest(docs=value):
                self.assertRed(
                    needs(docs=value, Documentation_HTML="skipped"),
                    why="docs output is",
                )

    def test_docs_false_needs_the_raw_doc_false(self):
        for doc in ("true", "", None, "False"):
            with self.subTest(doc=doc):
                n = needs(doc=doc, docs="false", Documentation_HTML="skipped")
                self.assertRed(n, why="says docs 'false'")


class TestNeedsInput(Base):
    def test_unset_env_is_red(self):
        self.assertRed(None, why="unset, empty")

    def test_empty_env_is_red(self):
        self.assertRed(None, raw="  ", why="unset, empty")

    def test_invalid_json_is_red(self):
        self.assertRed(None, raw="{nope", why="not JSON")

    def test_non_object_is_red(self):
        self.assertRed(None, raw="[]", why="not an object")

    def test_missing_needed_job_is_red(self):
        n = needs()
        del n["Test"]
        self.assertRed(n, why="needs.Test is missing")

    def test_bad_shard_count_is_red(self):
        self.assertRed(needs(), shards=0)


class TestPlans(Base):
    def test_missing_plan_artifact_is_red(self):
        """A shard that was skipped or died before uploading its plan."""
        import shutil

        shutil.rmtree(os.path.join(self.plans, verdict.artifact_name("amd64_u24", 2)))
        self.assertRed(needs(), why="topotest-plan-amd64_u24-s2 is missing")

    def test_no_plans_downloaded_at_all_is_red(self):
        import shutil

        shutil.rmtree(self.plans)
        self.assertRed(needs(), why="is missing")

    def test_missing_accounted_file_is_red(self):
        """accounted.txt exists only once the shard's coverage check passed."""
        self.write_plan("amd64_u22", 1, **{"accounted.txt": None})
        self.assertRed(needs(), why="accounted.txt unreadable")

    def test_empty_plan_file_is_red(self):
        self.write_plan("amd64_u22", 2, **{"plan.txt": []})
        self.assertRed(needs(), why="plan.txt is empty")

    def test_wrong_shard_identity_is_red(self):
        self.write_plan(
            "amd64_u22", 2, **{"shard.txt": ["platform=amd64_u22 shard=1 shards=2"]}
        )
        self.assertRed(needs(), why="shard.txt says")

    def test_overlapping_plans_are_red(self):
        self.write_plan("amd64_u22", 2, **{"plan.txt": PLANS[2] + ["a/test_a.py"]})
        self.assertRed(
            needs(), why="a/test_a.py is planned in both shard 1 and shard 2"
        )

    def test_universe_mismatch_is_red(self):
        self.write_plan("amd64_u24", 2, **{"universe.txt": UNIVERSE + ["e/test_e.py"]})
        self.assertRed(needs(), why="universe.txt differs")

    def test_universe_file_in_no_plan_is_red(self):
        """The mutation check: one line deleted from a plan."""
        self.write_plan("amd64_u22", 1, **{"plan.txt": ["a/test_a.py"]})
        self.assertRed(needs(), why="d/test_d.py is in the universe but in no")

    def test_planned_file_outside_universe_is_red(self):
        self.write_plan("amd64_u22", 2, **{"plan.txt": PLANS[2] + ["z/test_z.py"]})
        self.assertRed(needs(), why="z/test_z.py is planned in shard 2 but is not")

    def test_collected_file_in_no_plan_is_red(self):
        extra = COLLECTED_IDS + ["x/test_x.py::test_x"]
        self.write_plan(
            "amd64_u24",
            1,
            **{
                "collected-files.txt": sorted({c.split("::")[0] for c in extra}),
                "collected-ids.txt": extra,
            }
        )
        self.assertRed(
            needs(), why="x/test_x.py was collected by shard 1 but is in no plan"
        )

    def test_collected_id_nobody_accounted_is_red(self):
        """A shard whose coverage certified less than its plan's collection."""
        self.write_plan("amd64_u22", 1, **{"accounted.txt": ["a/test_a.py::test_one"]})
        self.assertRed(needs(), why="d/test_d.py::test_four was collected but no shard")

    def test_accounting_outside_own_plan_is_red(self):
        self.write_plan(
            "amd64_u22",
            2,
            **{"accounted.txt": accounted_for(2) + ["a/test_a.py::test_one"]}
        )
        self.assertRed(needs(), why="shard 2 accounts for a/test_a.py::test_one")

    def test_accounted_by_two_shards_is_red(self):
        self.write_plan(
            "amd64_u22",
            2,
            **{"accounted.txt": accounted_for(2) + ["a/test_a.py::test_one"]}
        )
        self.assertRed(needs(), why="accounted by shards 1 and 2")


class TestWorkflowWiring(unittest.TestCase):
    """The verdict's constants must match the job that runs it."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(_HERE, os.pardir, "workflows", "github-ci.yml")
        with open(os.path.normpath(path)) as f:
            cls.workflow = f.read()
        m = re.search(
            r"\n  CI-Verdict:\n(.*?)(?=\n  [A-Za-z][\w-]*:\n|\Z)", cls.workflow, re.S
        )
        cls.job = m.group(1) if m else ""

    def test_verdict_job_exists_and_always_runs(self):
        self.assertIn("if: ${{ always() }}", self.job)

    def test_needs_are_the_filter_plus_the_required_jobs(self):
        m = re.search(r"^    needs: \[([^\]]*)\]", self.job, re.M)
        self.assertIsNotNone(m)
        listed = [x.strip() for x in m.group(1).split(",")]
        self.assertEqual(
            sorted(listed),
            sorted(
                [verdict.FILTER_JOB] + list(verdict.REQUIRED_JOBS) + [verdict.DOCS_JOB]
            ),
        )

    def test_docs_job_runs_exactly_when_the_verdict_expects_it(self):
        """The verdict wants the docs job iff the decided docs is 'true'."""
        m = re.search(
            r"\n  "
            + re.escape(verdict.DOCS_JOB)
            + r":\n(.*?)(?=\n  [A-Za-z][\w-]*:\n)",
            self.workflow,
            re.S,
        )
        self.assertIsNotNone(m)
        self.assertRegex(m.group(1), r"(?m)^    needs: doc-path-filter$")
        self.assertRegex(
            m.group(1),
            r"(?m)^    if: \$\{\{ needs\.doc-path-filter\.outputs\.docs "
            r"== 'true' \}\}$",
        )

    def test_mergify_exemption_mirrors_the_filter_jobs_own_if(self):
        self.assertIn(
            "if: ${{ github.event_name != 'pull_request' || github.actor != '"
            + verdict.MERGIFY_ACTOR
            + "' }}",
            self.workflow,
        )

    def test_needs_and_actor_go_through_env(self):
        self.assertIn("NEEDS_JSON: ${{ toJSON(needs) }}", self.job)
        self.assertIn("ACTOR: ${{ github.actor }}", self.job)
        self.assertIn("EVENT_NAME: ${{ github.event_name }}", self.job)
        run = self.job[self.job.index("run: |") :]
        self.assertNotIn("${{", run)

    def test_plan_download_is_advisory_and_the_script_decides(self):
        m = re.search(
            r"- name: Download topotest shard plans\n(.*?)(?=\n      - name:)",
            self.job,
            re.S,
        )
        self.assertIsNotNone(m)
        self.assertIn("continue-on-error: true", m.group(1))
        self.assertIn("pattern: topotest-plan-*", m.group(1))
        self.assertIn("path: plans", m.group(1))
        self.assertIn("--plans plans", self.job)


def _read_workflow():
    path = os.path.join(_HERE, os.pardir, "workflows", "github-ci.yml")
    with open(os.path.normpath(path)) as f:
        return f.read()


def _job(workflow, name):
    """One top-level job's block (without its key line); '' if absent."""
    m = re.search(
        r"\n  " + re.escape(name) + r":\n(.*?)(?=\n  [A-Za-z][\w-]*:\n|\Z)",
        workflow,
        re.S,
    )
    return m.group(1) if m else ""


def _code(text):
    """text without its YAML comment lines."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def _steps(job):
    """The job's step items, each starting at its `- ` line."""
    body = job[job.index("\n    steps:\n") :]
    return ["      - " + s for s in body.split("\n      - ")[1:]]


def _step(job, name):
    for s in _steps(job):
        if s.startswith("      - name: " + name + "\n"):
            return s
    return None


class TestGateWiring(unittest.TestCase):
    """BLO-35428 item 4: what gates Build, Unit-Test and Test.

    Every property here is one whose loss lets a run skip building or
    testing while the verdict does not notice, lets the verdict stop
    seeing a job that can fail, or puts the filter on the wrong runner
    pool for its event.
    """

    # Jobs the verdict does not judge by a success/skip rule of their own:
    # itself, and the filter, whose result and outputs it reads directly.
    # Documentation-HTML is judged (conditionally, see TestDocsJob).
    NOT_GATING = {"CI-Verdict", verdict.FILTER_JOB}

    @classmethod
    def setUpClass(cls):
        cls.workflow = _read_workflow()
        cls.filter = _job(cls.workflow, verdict.FILTER_JOB)

    def test_every_building_or_testing_job_is_in_the_verdict(self):
        """A new job that can fail must not be invisible to CI-Verdict."""
        jobs_section = self.workflow[self.workflow.index("\njobs:\n") :]
        jobs = set(re.findall(r"(?m)^  ([A-Za-z][\w-]*):$", jobs_section))
        self.assertIn("Build-LTTng", jobs)
        self.assertEqual(
            sorted(jobs - self.NOT_GATING),
            sorted(verdict.REQUIRED_JOBS + (verdict.DOCS_JOB,)),
        )

    def test_prepare_mib_cache_job_is_folded_into_the_filter(self):
        self.assertNotIn("\n  Prepare-MIB-Cache:\n", self.workflow)
        self.assertNotIn("needs: Prepare-MIB-Cache", self.workflow)

    def test_builds_key_on_the_decided_build_output(self):
        for name in ("Build", "Build-LTTng"):
            with self.subTest(job=name):
                job = _job(self.workflow, name)
                self.assertRegex(job, r"(?m)^    needs: doc-path-filter$")
                self.assertRegex(
                    job,
                    r"(?m)^    if: \$\{\{ needs\.doc-path-filter\.outputs\.build "
                    r"== 'true' \}\}$",
                )

    def test_nothing_is_gated_on_the_raw_non_doc_output(self):
        """Only the decided `build` output may skip a build."""
        for line in self.workflow.splitlines():
            if re.match(r"^\s*if:", line):
                self.assertNotIn("non_doc", line, line)

    def test_filter_outputs_build_from_its_decide_step(self):
        self.assertRegex(
            self.filter, r"(?m)^      build: \$\{\{ steps\.decide\.outputs\.build \}\}$"
        )

    def test_nothing_is_gated_on_the_raw_doc_output(self):
        """Review finding: continue-on-error leaves the raw doc output empty
        on a filter error, so a job keyed on it is silently skipped.  Only
        the decided `docs` output may skip the docs build."""
        for line in self.workflow.splitlines():
            if re.match(r"^\s*if:", line):
                self.assertNotRegex(line, r"outputs\.doc(?!s)\b", line)

    def test_filter_outputs_docs_from_its_decide_step(self):
        self.assertRegex(
            self.filter, r"(?m)^      docs: \$\{\{ steps\.decide\.outputs\.docs \}\}$"
        )

    def test_a_paths_filter_error_cannot_fail_or_decide(self):
        (filt,) = [s for s in _steps(self.filter) if "dorny/paths-filter@" in s]
        self.assertRegex(filt, r"(?m)^        id: filter$")
        self.assertRegex(filt, r"(?m)^        continue-on-error: true$")
        decide = _step(self.filter, "Decide whether this run builds")
        self.assertIsNotNone(decide)
        self.assertRegex(decide, r"(?m)^        id: decide$")
        self.assertIn("FILTER_OUTCOME: ${{ steps.filter.outcome }}", decide)
        self.assertNotRegex(decide, r"(?m)^        continue-on-error:")
        steps = _steps(self.filter)
        self.assertLess(steps.index(filt), steps.index(decide))

    def test_mib_population_runs_whenever_a_build_does(self):
        """Dockerfile:122 hashes mib-cache: a build must find it populated."""
        steps = _steps(self.filter)
        decide = steps.index(_step(self.filter, "Decide whether this run builds"))
        build_job = _job(self.workflow, "Build")
        for name in (
            "Ensure local MIB cache directory exists",
            "Restore cached MIB files",
            "Populate missing MIB cache files",
        ):
            with self.subTest(step=name):
                s = _step(self.filter, name)
                self.assertIsNotNone(s)
                self.assertGreater(steps.index(s), decide)
                self.assertRegex(
                    s,
                    r"(?m)^        if: "
                    r"\$\{\{ steps\.decide\.outputs\.build == 'true' \}\}$",
                )
                self.assertNotRegex(s, r"(?m)^        continue-on-error:")
        restore = _step(self.filter, "Restore cached MIB files")
        self.assertIn("uses: actions/cache@v", restore)
        for key in ("path: docker/ubuntu-ci/mib-cache", "key: mib-cache-v1-ubuntu24"):
            self.assertIn(key, restore)
            self.assertIn(key, _step(build_job, "Restore cached MIB files"))
        self.assertRegex(self.filter, r"(?m)^    timeout-minutes: 20$")

    def test_filter_checkout_is_skipped_only_on_pull_requests(self):
        co = _step(self.filter, "Checkout")
        self.assertIsNotNone(co)
        self.assertRegex(
            co, r"(?m)^        if: \$\{\{ github\.event_name != 'pull_request' \}\}$"
        )
        self.assertRegex(_code(co), r"(?m)^          fetch-depth: 2$")
        # A partial clone would lazily fetch `before`'s whole history
        # (see the comment on the step).
        self.assertNotRegex(_code(co), r"(?m)^\s+(filter|sparse-checkout):")
        self.assertRegex(self.filter, r"(?m)^      pull-requests: read$")

    def test_filter_runs_on_arc_light_for_every_event(self):
        """Seconds of work on every event now that push and workflow_dispatch
        check out shallow, so never on `default`, where it queued for hours
        before Build queued again (the comment on its runs-on has the
        numbers)."""
        (runs_on,) = re.findall(r"(?m)^    runs-on: (.*)$", self.filter)
        self.assertEqual(runs_on, "arc-light")

    def test_one_lost_build_leg_does_not_skip_the_other_platform(self):
        for name in ("Unit-Test", "Test"):
            with self.subTest(job=name):
                job = _job(self.workflow, name)
                self.assertRegex(job, r"(?m)^    needs: Build$")
                self.assertRegex(
                    job,
                    r"(?m)^    if: \$\{\{ !cancelled\(\) && "
                    r"needs\.Build\.result != 'skipped' \}\}$",
                )

    def test_build_exports_only_the_registry_image(self):
        build = _job(self.workflow, "Build")
        code = _code(build)
        self.assertNotIn("type=docker", code)
        self.assertNotIn("/tmp/frr-", code)
        self.assertIsNone(_step(build, "Upload docker image artifact"))
        self.assertRegex(
            build,
            r"(?m)^          outputs: \|\n"
            r"            type=image,name=registry\.blockcast\.net/cache/frr-ci:img-"
            r"\$\{\{ github\.sha \}\}-"
            r"\$\{\{ matrix\.cfg\.platform \}\},push=true\n          [a-z#]",
        )

    def test_no_workflow_reads_the_deleted_image_artifact(self):
        wf_dir = os.path.normpath(os.path.join(_HERE, os.pardir, "workflows"))
        for fname in sorted(os.listdir(wf_dir)):
            if not fname.endswith((".yml", ".yaml")):
                continue
            with open(os.path.join(wf_dir, fname)) as f:
                text = f.read()
            code = _code(text)
            with self.subTest(workflow=fname):
                self.assertNotRegex(code, r"(?m)name: [^\n]*\}-image\s*$")
                self.assertNotIn("docker load", code)


class TestBuildDecisionStep(unittest.TestCase):
    """Runs doc-path-filter's inline "Decide whether this run builds" script.

    It cannot be a repo script: on pull requests that job has no checkout.
    So the script is lifted out of github-ci.yml and executed the way
    GitHub runs a `shell: bash` step, over every classification the filter
    can hand it.  build=false for anything but a successful, exactly
    doc-only classification would let a code change skip Build, and
    docs=false for anything but a successful doc 'false' would let a filter
    error skip the docs build.
    """

    @classmethod
    def setUpClass(cls):
        step = _step(
            _job(_read_workflow(), verdict.FILTER_JOB), "Decide whether this run builds"
        )
        assert step is not None, "decide step not found"
        lines = step.split("\n")
        start = lines.index("        run: |") + 1
        body = []
        for line in lines[start:]:
            if line.strip() and not line.startswith(" " * 10):
                break
            body.append(line[10:])
        cls.script = "\n".join(body).strip() + "\n"
        cls.bash = shutil.which("bash")

    def outputs(self, **env):
        """Run the step; return what it wrote to GITHUB_OUTPUT, as a dict."""
        self.assertIsNotNone(self.bash, "bash is required to run the step")
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "step.sh")
            out = os.path.join(tmp, "github_output")
            with open(script, "w") as f:
                f.write(self.script)
            open(out, "w").close()
            full_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "GITHUB_OUTPUT": out,
            }
            full_env.update(env)
            proc = subprocess.run(
                [self.bash, "--noprofile", "--norc", "-eo", "pipefail", script],
                env=full_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(out) as f:
                written = [line for line in f.read().splitlines() if line]
        self.assertEqual(len(written), 2, written)
        self.assertRegex(written[0], r"^build=(true|false)$")
        self.assertRegex(written[1], r"^docs=(true|false)$")
        return dict(line.split("=", 1) for line in written)

    def decide(self, **env):
        return self.outputs(**env)["build"]

    def docs(self, **env):
        return self.outputs(**env)["docs"]

    def test_script_takes_its_inputs_from_env_only(self):
        self.assertIn('echo "build=${build}" >> "${GITHUB_OUTPUT}"', self.script)
        self.assertIn('echo "docs=${docs}" >> "${GITHUB_OUTPUT}"', self.script)
        self.assertNotIn("${{", self.script)

    def test_only_a_successful_doc_only_classification_skips_the_build(self):
        self.assertEqual(
            self.decide(FILTER_OUTCOME="success", DOC="true", NON_DOC="false"), "false"
        )

    def test_everything_else_builds(self):
        cases = (
            ("success", "false", "true"),  # code only
            ("success", "true", "true"),  # doc + code
            ("success", "false", "false"),  # empty change list
            ("failure", "true", "false"),  # errored, yet wrote doc-only outputs
            ("failure", "", ""),  # errored before writing outputs
            ("cancelled", "", ""),
            ("skipped", "", ""),
            ("", "true", "false"),
            ("success", "", ""),
            ("success", "True", "false"),
            ("success", "true", "False"),
            ("success", "true ", "false"),
        )
        for outcome, doc, non_doc in cases:
            with self.subTest(outcome=outcome, doc=doc, non_doc=non_doc):
                self.assertEqual(
                    self.decide(FILTER_OUTCOME=outcome, DOC=doc, NON_DOC=non_doc),
                    "true",
                )

    def test_unset_inputs_build(self):
        self.assertEqual(self.decide(), "true")
        self.assertEqual(self.decide(DOC="true", NON_DOC="false"), "true")

    def test_only_a_successful_doc_false_skips_the_docs(self):
        for non_doc in ("true", "false"):  # code only; empty change list
            with self.subTest(non_doc=non_doc):
                self.assertEqual(
                    self.docs(FILTER_OUTCOME="success", DOC="false", NON_DOC=non_doc),
                    "false",
                )

    def test_everything_else_builds_the_docs(self):
        """Review finding: an errored filter step must not skip the docs."""
        cases = (
            ("success", "true", "false"),  # doc only
            ("success", "true", "true"),  # doc + code
            ("failure", "false", "true"),  # errored, yet wrote outputs
            ("failure", "", ""),  # errored before writing outputs
            ("cancelled", "", ""),
            ("skipped", "", ""),
            ("", "false", "true"),
            ("success", "", ""),
            ("success", "False", "true"),
            ("success", "false ", "true"),
        )
        for outcome, doc, non_doc in cases:
            with self.subTest(outcome=outcome, doc=doc, non_doc=non_doc):
                self.assertEqual(
                    self.docs(FILTER_OUTCOME=outcome, DOC=doc, NON_DOC=non_doc),
                    "true",
                )
        self.assertEqual(self.docs(), "true")


if __name__ == "__main__":
    unittest.main()
