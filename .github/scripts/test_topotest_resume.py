#!/usr/bin/env python3
"""Fixtures pinning the topotest resume decision and its workflow wiring.

"Re-run failed jobs" must re-run only the files that still failed, and must
fall back to the whole tree whenever the previous attempt cannot justify a
narrower list (BLO-35428).  The artifact layouts below are the ones actually
produced by upload-artifact: the nested one was read off the downloaded
artifacts of runs 35709500854, 35480015782 and 35409722977, and the flat one
is what a clean leg and Build's cleared seed upload.

Stdlib only, no network.

Run: python3 -m unittest discover -s .github/scripts -p 'test_topotest_*.py'
"""

import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_SPEC = importlib.util.spec_from_file_location(
    "topotest_resume", os.path.join(_HERE, "topotest_resume.py")
)
resume = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(resume)

from test_topotest_coverage import (  # noqa: E402
    MSDP_LEAK,
    MSDP_SA,
    SPIN,
    TTL,
    TTL_LEAK,
    cid,
    junit,
    write,
)

RID = "amd64_u22"
PAIRS = (SPIN, MSDP_SA, MSDP_LEAK, TTL, TTL_LEAK)
COLLECTED = [cid(p) for p in PAIRS]
UNIVERSE = sorted({c.split("::")[0] for c in COLLECTED})
MSDP_FILE = "msdp_topo4/test_msdp_topo4.py"
SPIN_FILE = "bgp_io_cpu_spin/test_bgp_io_cpu_spin.py"

INITIAL_WITH_FAILURES = [
    (SPIN, "error"),
    (MSDP_SA, "failure"),
    (MSDP_LEAK, "skipped"),
    (TTL, "pass"),
    (TTL_LEAK, "skipped"),
]


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.prev = os.path.join(self._tmp.name, "prev-results")
        os.makedirs(self.prev)

    def tearDown(self):
        self._tmp.cleanup()

    def nested(self, initial=None, final=None):
        """The layout when both result dirs are uploaded (a leg with failures,
        and every leg once the layout marker is in place)."""
        write(self.prev, "test-results-%s/layout.txt" % RID, "attempt 1\n")
        write(self.prev, "test-results-%s-initial/layout.txt" % RID, "attempt 1\n")
        if initial is not None:
            write(
                self.prev, "test-results-%s-initial/topotests.xml" % RID, junit(initial)
            )
        if final is not None:
            write(self.prev, "test-results-%s/topotests.xml" % RID, junit(final))

    def decide(self):
        return resume.decide(self.prev, RID, COLLECTED, UNIVERSE)


class TestDecision(Base):
    def test_nested_layout_resumes_only_still_failing_files(self):
        """The defect: this is the layout the old :606 check could not see."""
        rerun = [(SPIN, "pass"), (MSDP_SA, "failure")]
        self.nested(INITIAL_WITH_FAILURES, rerun)
        run, priors, reason = self.decide()
        self.assertEqual(run, [MSDP_FILE])
        self.assertEqual(len(priors), 2)
        self.assertTrue(priors[0].endswith("-initial/topotests.xml"))
        self.assertIn("resume", reason)

    def test_legacy_flat_layout_is_still_read(self):
        """A clean leg's (or pre-change) artifact has topotests.xml at its root."""
        rec = [(p, "failure" if p == MSDP_SA else "pass") for p in PAIRS]
        write(self.prev, "topotests.xml", junit(rec))
        run, priors, _ = self.decide()
        self.assertEqual(run, [MSDP_FILE])
        self.assertEqual(priors, [os.path.join(self.prev, "topotests.xml")])

    def test_initial_alone_when_rerun_was_killed(self):
        """Cap kill during the serial rerun: no final junit, initial is whole."""
        self.nested(INITIAL_WITH_FAILURES, None)
        run, _, _ = self.decide()
        self.assertEqual(run, sorted([MSDP_FILE, SPIN_FILE]))

    def test_initial_failure_absent_from_rerun_is_still_rerun(self):
        """A failure the serial rerun never re-verified stays failing."""
        self.nested(INITIAL_WITH_FAILURES, [(MSDP_SA, "pass")])
        run, _, _ = self.decide()
        self.assertEqual(run, [SPIN_FILE])

    def test_partial_junit_forces_a_full_run(self):
        self.nested([(SPIN, "failure"), (MSDP_SA, "pass")], None)
        run, priors, reason = self.decide()
        self.assertEqual(run, UNIVERSE)
        self.assertEqual(priors, [])
        self.assertIn("partial junit", reason)

    def test_cleared_results_only_forces_a_full_run(self):
        """Build's seed artifact: a single cleared-results.txt, flat."""
        write(self.prev, "cleared-results.txt", "")
        run, priors, _ = self.decide()
        self.assertEqual((run, priors), (UNIVERSE, []))

    def test_layout_markers_only_force_a_full_run(self):
        """An attempt that died before any junit uploads markers alone."""
        self.nested(None, None)
        self.assertEqual(self.decide()[0], UNIVERSE)

    def test_empty_failure_set_forces_a_full_run(self):
        """e.g. the leg was cap-killed in the upload tail after passing."""
        self.nested(INITIAL_WITH_FAILURES, [(SPIN, "pass"), (MSDP_SA, "pass")])
        run, priors, reason = self.decide()
        self.assertEqual((run, priors), (UNIVERSE, []))
        self.assertIn("no failing test", reason)

    def test_no_download_forces_a_full_run(self):
        os.rmdir(self.prev)
        self.assertEqual(self.decide()[0], UNIVERSE)

    def test_unreadable_junit_forces_a_full_run(self):
        write(
            self.prev,
            "test-results-%s/topotests.xml" % RID,
            junit(INITIAL_WITH_FAILURES)[:-30],
        )
        self.assertEqual(self.decide()[0], UNIVERSE)

    def test_failure_outside_universe_forces_a_full_run(self):
        stranger = ("gone_dir.test_gone", "test_x")
        self.nested(INITIAL_WITH_FAILURES + [(stranger, "failure")], None)
        run, _, reason = self.decide()
        self.assertEqual(run, UNIVERSE)
        self.assertIn("outside the collected universe", reason)

    def test_other_legs_artifact_is_not_read(self):
        write(
            self.prev,
            "test-results-amd64_u24/topotests.xml",
            junit(INITIAL_WITH_FAILURES),
        )
        self.assertEqual(self.decide()[0], UNIVERSE)


class TestCli(Base):
    def run_cli(self, universe=UNIVERSE):
        out, err = io.StringIO(), io.StringIO()
        prior_out = os.path.join(self._tmp.name, "prior.txt")
        argv = [
            "--prev",
            self.prev,
            "--id",
            RID,
            "--collected",
            write(self._tmp.name, "c.txt", "\n".join(COLLECTED) + "\n"),
            "--universe",
            write(self._tmp.name, "u.txt", "\n".join(universe) + "\n"),
            "--prior-out",
            prior_out,
        ]
        with redirect_stdout(out), redirect_stderr(err):
            rc = resume.main(argv)
        with open(prior_out) if os.path.exists(prior_out) else io.StringIO() as f:
            prior = f.read()
        return rc, out.getvalue(), err.getvalue(), prior

    def test_full_run_prints_universe_verbatim_and_empty_prior(self):
        """The workflow cmp's this against universe.txt byte for byte."""
        rc, out, err, prior = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertEqual(out, "".join(u + "\n" for u in UNIVERSE))
        self.assertEqual(prior, "")
        self.assertIn("full run", err)

    def test_resume_writes_priors_in_overlay_order(self):
        self.nested(INITIAL_WITH_FAILURES, [(SPIN, "pass"), (MSDP_SA, "failure")])
        rc, out, _, prior = self.run_cli()
        self.assertEqual((rc, out), (0, MSDP_FILE + "\n"))
        lines = prior.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].endswith("-initial/topotests.xml"))

    def test_empty_universe_is_an_error_not_an_empty_list(self):
        rc, out, _, _ = self.run_cli(universe=[])
        self.assertEqual((rc, out), (1, ""))


class TestWorkflowWiring(unittest.TestCase):
    """Plain-text assertions over github-ci.yml -- no YAML parser needed."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(_HERE, os.pardir, "workflows", "github-ci.yml")
        with open(os.path.normpath(path)) as f:
            cls.workflow = f.read()
        # Split into step blocks at the 6-space `- name:` / `- uses:` indent,
        # and at every job key / job-level key, so the last step of one job
        # never runs on into the next job's header.
        cls.steps = re.split(
            r"\n(?=      - (?:name|uses):|  [A-Za-z][\w-]*:|    [a-z][\w-]*:)",
            cls.workflow,
        )

    def step(self, name):
        found = [
            s
            for s in self.steps
            if re.match(r"\s*- name: " + re.escape(name) + r"\s*\n", s)
        ]
        self.assertEqual(len(found), 1, "expected exactly one step named " + name)
        return found[0]

    def test_no_python_helper_feeds_mapfile_through_process_substitution(self):
        """Critic (d): `mapfile < <(python3 ...)` hides the helper's exit status.

        A process substitution is not a pipeline component `set -e` inspects,
        so a helper that crashes after partial output would silently narrow
        the run.  Capture with `raw=$(python3 ...)` first.
        """
        self.assertNotRegex(self.workflow, r"mapfile[^\n]*<\s*<\([^\n]*python3")

    def test_resume_list_is_captured_by_command_substitution(self):
        self.assertRegex(
            self.workflow,
            r"\w+=\$\(python3 \.github/scripts/topotest_resume\.py",
        )

    def test_empty_run_list_is_refused(self):
        run = self.step("Run topotests")
        self.assertRegex(run, r"\[ \$\{#run_tests\[@\]\} -gt 0 \] \|\|")

    def test_full_run_is_asserted_equal_to_the_plan(self):
        """Critic (e): with no usable prior, run list == universe exactly."""
        run = self.step("Run topotests")
        self.assertIn("--prior-out", run)
        self.assertRegex(
            run,
            r"if \[ \$\{#prior_args\[@\]\} -eq 0 \] && ! cmp -s "
            r'"\$\{RUNNER_TEMP\}/run-list\.txt" "\$\{RUNNER_TEMP\}/universe\.txt"; then'
            r"(?:\n(?!\s*fi\b)[^\n]*)*\n\s*exit 1\n\s*fi",
            "the no-prior run list is not asserted equal to the universe",
        )

    def test_previous_results_download_survives_the_run_step_cleanup(self):
        fetch = self.step("Fetch previous results")
        path = re.search(r"^\s+path:\s*(\S+)", fetch, re.M).group(1)
        self.assertFalse(
            path.startswith("test-results-"),
            "prior results are downloaded into a dir the run step's "
            "`rm -rf test-results-*` deletes before reading it: " + path,
        )
        self.assertIn("--prev " + path, self.step("Run topotests"))

    def test_layout_marker_pins_both_dirs_and_is_not_hidden(self):
        gather = self.step("Gather results")
        for d in (
            "test-results-${{ matrix.cfg.platform }}/layout.txt",
            "test-results-${{ matrix.cfg.platform }}-initial/layout.txt",
        ):
            self.assertIn(d, gather)
        self.assertNotRegex(gather, r"/\.layout")

    def test_parallel_rc_is_gated_before_any_success_claim(self):
        run = self.step("Run topotests")
        self.assertIn("|| par_rc=$?", run)
        self.assertRegex(run, r"case \"\$\{par_rc\}\" in\s*\n\s*0\|1\) ;;")
        gate = run.index("0|1) ;;")
        coverage = run.index("topotest_coverage.py")
        claim = run.index('echo "All tests passed."')
        self.assertLess(gate, coverage)
        self.assertLess(coverage, claim)

    def test_every_per_leg_upload_overwrites(self):
        """Critic (b): artifacts are run-scoped across attempts, so a re-run
        leg re-uploading a same-named artifact 409s without overwrite."""
        uploads = [s for s in self.steps if "uses: actions/upload-artifact" in s]
        per_leg = [s for s in uploads if re.search(r"name: [^\n]*\$\{\{ matrix\.", s)]
        self.assertGreaterEqual(len(per_leg), 5)
        for s in per_leg:
            self.assertIn("overwrite: true", s, s.splitlines()[0])

    def test_footprint_upload_cannot_fail_the_leg(self):
        up = self.step("Upload topotest footprint samples")
        self.assertIn("continue-on-error: true", up)
        self.assertIn("overwrite: true", up)
        check = self.step("Check topotest footprint samples")
        self.assertIn("continue-on-error: true", check)

    def test_sampler_first_sample_keeps_stderr(self):
        run = self.step("Run topotests")
        first = re.search(r"docker stats --no-stream[^\n]*\n[^\n]*first sample", run)
        self.assertIsNotNone(first, "first footprint sample is not logged")
        self.assertNotIn("2>/dev/null", first.group(0))


if __name__ == "__main__":
    unittest.main()
