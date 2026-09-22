#!/usr/bin/env python3
"""Fixtures pinning CI-Verdict (topotest_verdict.py), BLO-35428.

The property every case protects: the verdict can only be green when Build,
Unit-Test and every Test shard succeeded and the shards covered the
collection exactly once -- or in the two deliberately build-less cases, each
matched exactly.  A filter job that failed, was cancelled or lost its runner
(empty outputs) must be red, because the jobs behind it were skipped and
nothing was built or tested (critic blocker: the first draft passed on
`non_doc != 'true'`).

Stdlib only, no network.

Run: python3 -m unittest discover -s .github/scripts -p 'test_topotest_*.py'
"""

import importlib.util
import io
import json
import os
import re
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


def needs(filt="success", non_doc="true", outputs=True, **results):
    """toJSON(needs) as GitHub renders it; results override Build etc."""
    filter_entry = {"result": filt, "outputs": {}}
    if outputs and non_doc is not None:
        filter_entry["outputs"] = {"doc": "false", "non_doc": non_doc}
    n = {"doc-path-filter": filter_entry}
    for job in verdict.REQUIRED_JOBS:
        n[job] = {
            "result": results.get(job.replace("-", "_"), "success"),
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


class TestFullRun(Base):
    def test_all_green_with_complete_plans(self):
        self.assertGreen(needs())
        self.assertIn(
            "amd64_u22: 2 shards, 4 files planned of 4 enumerated, "
            "4 collected IDs, 4 accounted (3 + 1)",
            self.out,
        )

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
        self.assertRed(needs(Build="failure", Unit_Test="failure", Test="failure"))
        self.assertEqual(self.out.count("::error title=CI-Verdict::"), 3, self.out)


class TestFilterJob(Base):
    """The critic blocker: the filter's own failure must never exempt."""

    def test_filter_failed_with_empty_outputs_is_red(self):
        n = needs(
            filt="failure",
            outputs=False,
            Build="skipped",
            Unit_Test="skipped",
            Test="skipped",
        )
        self.assertRed(n, why="doc-path-filter concluded 'failure'")

    def test_filter_lost_its_runner_is_red(self):
        """Preempted pod: result failure/cancelled, outputs empty strings."""
        for result in ("failure", "cancelled"):
            n = needs(
                filt=result,
                non_doc="",
                Build="skipped",
                Unit_Test="skipped",
                Test="skipped",
            )
            self.assertRed(n, why="doc-path-filter concluded")

    def test_filter_cancelled_is_red(self):
        n = needs(
            filt="cancelled",
            outputs=False,
            Build="skipped",
            Unit_Test="skipped",
            Test="skipped",
        )
        self.assertRed(n)

    def test_filter_success_with_empty_non_doc_is_red(self):
        n = needs(non_doc="", Build="skipped", Unit_Test="skipped", Test="skipped")
        self.assertRed(n, why="neither 'true' nor 'false'")

    def test_filter_success_with_missing_outputs_is_red(self):
        n = needs(outputs=False, Build="skipped", Unit_Test="skipped", Test="skipped")
        self.assertRed(n, why="neither 'true' nor 'false'")

    def test_non_doc_is_compared_exactly(self):
        for value in ("False", "0", "no", "TRUE"):
            n = needs(
                non_doc=value, Build="skipped", Unit_Test="skipped", Test="skipped"
            )
            self.assertRed(n)

    def test_doc_only_change_is_green(self):
        n = needs(non_doc="false", Build="skipped", Unit_Test="skipped", Test="skipped")
        self.assertGreen(n)
        self.assertIn("doc-only", self.out)

    def test_doc_only_does_not_need_plans(self):
        n = needs(non_doc="false", Build="skipped", Unit_Test="skipped", Test="skipped")
        import shutil

        shutil.rmtree(self.plans)
        self.assertGreen(n)

    def test_doc_only_claim_with_a_job_that_ran_is_red(self):
        n = needs(non_doc="false", Build="failure", Unit_Test="skipped", Test="skipped")
        self.assertRed(n, why="did not skip")

    def test_mergify_backport_is_green(self):
        n = needs(
            filt="skipped",
            outputs=False,
            Build="skipped",
            Unit_Test="skipped",
            Test="skipped",
        )
        self.assertGreen(n, event="pull_request", actor="mergify[bot]")
        self.assertIn("mergify", self.out)

    def test_filter_skipped_for_anyone_else_is_red(self):
        n = needs(
            filt="skipped",
            outputs=False,
            Build="skipped",
            Unit_Test="skipped",
            Test="skipped",
        )
        self.assertRed(n, event="pull_request", actor="omar", why="not the mergify")
        self.assertRed(n, event="push", actor="mergify[bot]", why="not the mergify")

    def test_mergify_with_a_job_that_ran_is_red(self):
        n = needs(
            filt="skipped",
            outputs=False,
            Build="skipped",
            Unit_Test="skipped",
            Test="failure",
        )
        self.assertRed(
            n, event="pull_request", actor="mergify[bot]", why="did not skip"
        )


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
            sorted(listed), sorted([verdict.FILTER_JOB] + list(verdict.REQUIRED_JOBS))
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


if __name__ == "__main__":
    unittest.main()
