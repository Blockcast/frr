#!/usr/bin/env python3
"""Fixtures pinning the parallel-run coverage check (BLO-35428).

The hole this guards: the parallel topotest step trusted pytest's exit code,
and a junit that silently lost tests -- never scheduled, lost with a worker,
an interrupted session, a narrowed run list -- could still exit 0.  The check
compares the junit against `pytest --collect-only`.  Each test names the
property it protects.

The testcase records are cut from real artifacts: the classnames, names and
failure/error/skip shapes come from run 35709500854's amd64_u22 junit
(xunit2, so there is no `file` attribute and the file is derived from the
dotted classname).

Stdlib only, no network.

Run: python3 -m unittest discover -s .github/scripts -p 'test_topotest_*.py'
"""

import importlib.util
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_SPEC = importlib.util.spec_from_file_location(
    "topotest_coverage", os.path.join(_HERE, "topotest_coverage.py")
)
cov = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cov)

# Real (classname, name) pairs from run 35709500854 amd64_u22.
SPIN = ("bgp_io_cpu_spin.test_bgp_io_cpu_spin", "test_bgp_io_thread_not_spinning")
MSDP_SA = ("msdp_topo4.test_msdp_topo4", "test_msdp_sa_check")
MSDP_LEAK = ("msdp_topo4.test_msdp_topo4", "test_memory_leak")
TTL = (
    "bgp_local_as_dynamic_peer_ttl.test_bgp_local_as_dynamic_peer_ttl",
    "test_bgp_nonpg_neighbor_local_as_replace_as_ttl",
)
TTL_LEAK = (
    "bgp_local_as_dynamic_peer_ttl.test_bgp_local_as_dynamic_peer_ttl",
    "test_memory_leak",
)

KIND_XML = {
    "pass": "",
    "failure": '<failure message="AssertionError: multicast route should '
    'exist&#10;assert False">t</failure>',
    "error": '<error message="failed on teardown with &quot;Failed: New '
    'core[s] found&quot;">t</error>',
    "skipped": '<skipped type="pytest.skip" message="Memory leak test/report '
    'is disabled">t</skipped>',
}


def cid(pair):
    """The --collect-only spelling of a (classname, name) pair."""
    return pair[0].replace(".", "/") + ".py::" + pair[1]


def junit(records):
    """Render an xunit2 junit document from ((classname, name), kind) pairs."""
    body = "".join(
        '<testcase classname="{}" name="{}" time="1.0">{}</testcase>'.format(
            c, n, KIND_XML[kind]
        )
        for (c, n), kind in records
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?><testsuites>'
        '<testsuite name="pytest" tests="{}">{}</testsuite></testsuites>'
    ).format(len(records), body)


def write(tmp, name, text):
    path = os.path.join(tmp, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


COLLECTED = [cid(p) for p in (SPIN, MSDP_SA, MSDP_LEAK, TTL, TTL_LEAK)]
FILES = sorted({c.split("::")[0] for c in COLLECTED})


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def run_main(self, results, run_list=FILES, collected=COLLECTED, priors=()):
        args = [
            "--collected",
            write(self.tmp, "collected.txt", "\n".join(collected) + "\n"),
            "--run-list",
            write(self.tmp, "run.txt", "\n".join(run_list) + "\n"),
            "--results",
            write(self.tmp, "results.xml", junit(results)),
        ]
        for i, prior in enumerate(priors):
            args += ["--prior", write(self.tmp, "prior%d.xml" % i, junit(prior))]
        with open(os.devnull, "w") as devnull:
            saved = sys.stdout, sys.stderr
            sys.stdout = sys.stderr = devnull
            try:
                return cov.main(args)
            finally:
                sys.stdout, sys.stderr = saved


ALL_PASS = [(p, "pass") for p in (SPIN, MSDP_SA, MSDP_LEAK, TTL, TTL_LEAK)]


class TestFullRun(Base):
    def test_complete_junit_passes(self):
        self.assertEqual(self.run_main(ALL_PASS), 0)

    def test_missing_test_detected(self):
        """The core hole: a junit that lost one test must not read as complete."""
        lost = [r for r in ALL_PASS if r[0] != MSDP_LEAK]
        self.assertEqual(self.run_main(lost), 1)
        problems = cov.check(
            COLLECTED,
            FILES,
            cov.parse_outcomes(write(self.tmp, "x.xml", junit(lost)), set(FILES)),
        )
        self.assertEqual(len(problems), 1)
        self.assertIn(cid(MSDP_LEAK), problems[0])

    def test_skip_counts_as_accounted(self):
        """A skip was scheduled and reported; it is accounted, not missing."""
        rec = [
            (p, "skipped" if p in (MSDP_LEAK, TTL_LEAK) else "pass")
            for p, _ in ALL_PASS
        ]
        self.assertEqual(self.run_main(rec), 0)

    def test_failure_and_error_count_as_accounted(self):
        """Pass/fail is pytest's rc and the rerun guard's job, not this one's."""
        rec = [(SPIN, "error"), (MSDP_SA, "failure")] + ALL_PASS[2:]
        self.assertEqual(self.run_main(rec), 0)

    def test_xdist_worker_record_accounts_for_nothing(self):
        xml = junit(ALL_PASS[1:]).replace(
            "</testsuite>",
            '<testcase classname="" name="gw3"><error message="x">t</error>'
            "</testcase></testsuite>",
        )
        path = write(self.tmp, "gw.xml", xml)
        outcomes = cov.parse_outcomes(path, set(FILES))
        self.assertNotIn("gw3", " ".join(outcomes))
        self.assertEqual(len(cov.check(COLLECTED, FILES, outcomes)), 1)

    def test_empty_collection_refused(self):
        self.assertEqual(self.run_main(ALL_PASS, collected=[]), 1)

    def test_empty_run_list_refused(self):
        self.assertEqual(self.run_main(ALL_PASS, run_list=[]), 1)

    def test_run_list_entry_naming_nothing_collected_is_red(self):
        self.assertEqual(
            self.run_main(ALL_PASS, run_list=FILES + ["no_such/test_x.py"]), 1
        )

    def test_unreadable_results_is_red(self):
        args = [
            "--collected",
            write(self.tmp, "c.txt", "\n".join(COLLECTED)),
            "--run-list",
            write(self.tmp, "r.txt", "\n".join(FILES)),
            "--results",
            write(self.tmp, "trunc.xml", junit(ALL_PASS)[:-40]),
        ]
        with open(os.devnull, "w") as devnull:
            saved = sys.stdout, sys.stderr
            sys.stdout = sys.stderr = devnull
            try:
                self.assertEqual(cov.main(args), 1)
            finally:
                sys.stdout, sys.stderr = saved

    def test_narrowed_first_attempt_is_red_without_prior(self):
        """Critic (e): with no usable prior, the run must cover the whole plan.

        A resume or shard bug that narrows the list on a first attempt runs a
        subset whose junit is internally consistent; only the plan check sees
        the rest of the collection went unrun.
        """
        narrowed = [cid(MSDP_SA).split("::")[0]]
        rec = [(MSDP_SA, "pass"), (MSDP_LEAK, "pass")]
        self.assertEqual(self.run_main(rec, run_list=narrowed), 1)


class TestNormalization(unittest.TestCase):
    def test_class_based_collected_id_matches_junit(self):
        collected = ["a_dir/test_a.py::TestThing::test_one[1.2.3.4]"]
        files = {"a_dir/test_a.py"}
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(
                '<testsuites><testsuite><testcase classname="a_dir.test_a.TestThing"'
                ' name="test_one[1.2.3.4]"/></testsuite></testsuites>'
            )
        try:
            outcomes = cov.parse_outcomes(f.name, files)
        finally:
            os.unlink(f.name)
        self.assertEqual(list(outcomes), ["a_dir/test_a.py::test_one[1.2.3.4]"])
        self.assertEqual(cov.check(collected, ["a_dir/test_a.py"], outcomes), [])

    def test_brackets_may_contain_double_colon(self):
        self.assertEqual(
            cov.normalize("d/test_x.py::C::test_y[a::b]"), "d/test_x.py::test_y[a::b]"
        )

    def test_node_id_run_entry_selects_only_that_test(self):
        expected, unmatched = cov.expected_for_run(COLLECTED, [cid(MSDP_SA)])
        self.assertEqual(expected, {cid(MSDP_SA)})
        self.assertEqual(unmatched, [])

    def test_teardown_error_after_pass_keeps_worst_outcome(self):
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(junit([(SPIN, "pass"), (SPIN, "error")]))
        try:
            outcomes = cov.parse_outcomes(f.name, set(FILES))
        finally:
            os.unlink(f.name)
        self.assertEqual(outcomes[cid(SPIN)], cov.FAILED)


class TestResumedAttempt(Base):
    PRIOR = [(MSDP_SA, "failure")] + [
        (p, "pass") for p in (SPIN, MSDP_LEAK, TTL, TTL_LEAK)
    ]
    MSDP_FILE = ["msdp_topo4/test_msdp_topo4.py"]

    def test_prior_plus_this_attempt_covers_the_plan(self):
        now = [(MSDP_SA, "pass"), (MSDP_LEAK, "pass")]
        self.assertEqual(
            self.run_main(now, run_list=self.MSDP_FILE, priors=[self.PRIOR]), 0
        )

    def test_prior_failure_is_not_accounted(self):
        """A resume that DROPPED a still-failing file must not read as coverage.

        The prior junit records MSDP_SA (a failure), so a check that counted
        any prior record would pass a run that never retried it.
        """
        now = [(SPIN, "pass")]
        self.assertEqual(
            self.run_main(
                now,
                run_list=["bgp_io_cpu_spin/test_bgp_io_cpu_spin.py"],
                priors=[self.PRIOR],
            ),
            1,
        )

    def test_rerun_pass_overlays_initial_failure(self):
        """initial failed, its serial rerun passed: accounted by the overlay."""
        rerun = [(MSDP_SA, "pass")]
        now = [(TTL, "pass"), (TTL_LEAK, "pass")]
        self.assertEqual(
            self.run_main(
                now,
                run_list=[cid(TTL).split("::")[0]],
                priors=[self.PRIOR, rerun],
            ),
            0,
        )

    def test_partial_prior_leaves_gap(self):
        partial = [(SPIN, "pass"), (MSDP_SA, "failure")]
        now = [(MSDP_SA, "pass"), (MSDP_LEAK, "pass")]
        self.assertEqual(
            self.run_main(now, run_list=self.MSDP_FILE, priors=[partial]), 1
        )


if __name__ == "__main__":
    unittest.main()
