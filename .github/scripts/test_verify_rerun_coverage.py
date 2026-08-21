#!/usr/bin/env python3
"""Fixtures pinning the rerun-coverage guard for the serial topotest rerun.

The bug this guards against (BLO-29523) turned a red parallel run into a green
step: the rerun step trusted pytest's exit code, and pytest exits 0 when
everything it *collected* passed -- even if a requested target contributed no
tests at all.  Each test below names the property it protects.

Stdlib only, no network -- verify() is a pure function over parsed results.

Run: python3 -m unittest discover -s .github/scripts -p 'test_*.py'
"""

import importlib.util
import os
import re
import tempfile
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "verify_rerun_coverage",
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "verify_rerun_coverage.py"
    ),
)
guard = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(guard)

GRPC = "grpc_basic/test_basic_grpc.py"
PIM = "pim_dimt_forwarding_events/test_pim_dimt_forwarding_events.py"


def junit(cases):
    """Render a junit document from (file, name, kind) triples.

    kind is one of "pass", "skipped", "failure".
    """
    body = []
    for fname, name, kind in cases:
        attrs = 'file="{}" classname="{}" name="{}"'.format(
            fname, fname.replace("/", ".").removesuffix(".py"), name
        )
        if kind == "pass":
            body.append("<testcase {} />".format(attrs))
        else:
            body.append(
                '<testcase {}><{} message="x">t</{}></testcase>'.format(
                    attrs, kind, kind
                )
            )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        "<testsuites><testsuite name='pytest' tests='{}'>{}</testsuite></testsuites>"
    ).format(len(cases), "".join(body))


def parse(xml):
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
        path = f.name
    try:
        return guard.parse_results(path)
    finally:
        os.unlink(path)


class TestRun32421578651(unittest.TestCase):
    """Replay of the exact scenario in run 32421578651 / frr#66 @ 1e7809d0.

    The rerun was fed both files and ran only grpc_basic: 5 collected, 5
    passed, exit 0, "All rerun tests passed."  The two pim_dimt IDs never
    executed.  This is the regression that must come back RED.
    """

    def setUp(self):
        self.expected = {
            PIM + "::test_install_then_exactly_one_forwarding_ready",
            PIM + "::test_v1_only_consumer_ignores_and_advances",
            GRPC + "::test_shutdown_checks",
        }
        # Exactly what the rerun actually produced: the 5 grpc_basic tests.
        self.executed, self.skipped = parse(
            junit(
                [
                    (GRPC, "test_shutdown_checks", "pass"),
                    (GRPC, "test_add_config", "pass"),
                    (GRPC, "test_get_config", "pass"),
                    (GRPC, "test_capabilities", "pass"),
                    (GRPC, "test_validate_config", "pass"),
                ]
            )
        )

    def test_the_historical_green_becomes_red(self):
        problems = guard.verify(self.expected, self.executed, self.skipped)
        self.assertTrue(problems, "run 32421578651 must not certify as passing")

    def test_names_both_uncollected_pim_ids(self):
        problems = guard.verify(self.expected, self.executed, self.skipped)
        joined = "\n".join(problems)
        self.assertIn("test_install_then_exactly_one_forwarding_ready", joined)
        self.assertIn("test_v1_only_consumer_ignores_and_advances", joined)
        self.assertIn("NEVER EXECUTED", joined)

    def test_does_not_slander_the_test_that_did_run(self):
        problems = guard.verify(self.expected, self.executed, self.skipped)
        self.assertNotIn("test_shutdown_checks", "\n".join(problems))


class TestCoverage(unittest.TestCase):
    def test_genuinely_fixed_flake_still_passes(self):
        """The paired negative case: the guard must not turn every rerun red."""
        expected = {GRPC + "::test_shutdown_checks"}
        executed, skipped = parse(junit([(GRPC, "test_shutdown_checks", "pass")]))
        self.assertEqual(guard.verify(expected, executed, skipped), [])

    def test_still_failing_rerun_is_covered_not_flagged(self):
        """A test that reran and failed again IS verified; exit code catches it."""
        expected = {GRPC + "::test_shutdown_checks"}
        executed, skipped = parse(junit([(GRPC, "test_shutdown_checks", "failure")]))
        self.assertEqual(guard.verify(expected, executed, skipped), [])

    def test_zero_collection_is_explicit(self):
        expected = {PIM + "::test_install_then_exactly_one_forwarding_ready"}
        executed, skipped = parse(junit([]))
        problems = guard.verify(expected, executed, skipped)
        self.assertTrue(problems)
        self.assertIn("ZERO test results", problems[0])
        self.assertIn(PIM, problems[0])

    def test_skip_is_not_a_pass(self):
        expected = {PIM + "::test_v1_only_consumer_ignores_and_advances"}
        executed, skipped = parse(
            junit([(PIM, "test_v1_only_consumer_ignores_and_advances", "skipped")])
        )
        problems = guard.verify(expected, executed, skipped)
        self.assertTrue(problems)
        self.assertIn("SKIPPED", problems[0])

    def test_empty_expectation_set_refuses_to_certify(self):
        executed, skipped = parse(junit([(GRPC, "test_shutdown_checks", "pass")]))
        self.assertTrue(guard.verify(set(), executed, skipped))

    def test_file_level_expectation_met_by_any_test_from_that_file(self):
        """analyze.py emits a bare path when a whole module errors out."""
        expected = {GRPC}
        executed, skipped = parse(junit([(GRPC, "test_shutdown_checks", "pass")]))
        self.assertEqual(guard.verify(expected, executed, skipped), [])

    def test_file_level_expectation_unmet_by_a_different_file(self):
        expected = {PIM}
        executed, skipped = parse(junit([(GRPC, "test_shutdown_checks", "pass")]))
        self.assertTrue(guard.verify(expected, executed, skipped))

    def test_node_id_expectation_not_satisfied_by_sibling_in_same_file(self):
        """The precise ID matters: a sibling passing proves nothing about it."""
        expected = {PIM + "::test_install_then_exactly_one_forwarding_ready"}
        executed, skipped = parse(junit([(PIM, "test_some_other_thing", "pass")]))
        problems = guard.verify(expected, executed, skipped)
        self.assertTrue(problems)
        self.assertIn("NEVER EXECUTED", problems[0])


class TestIdConstruction(unittest.TestCase):
    """Spelling must agree with analyze.py get_filtered(), or nothing matches."""

    def test_file_and_name_join_with_double_colon(self):
        executed, _ = parse(junit([(GRPC, "test_shutdown_checks", "pass")]))
        self.assertEqual(executed, {GRPC + "::test_shutdown_checks"})

    def test_xdist_worker_pseudo_testcase_is_ignored(self):
        xml = (
            '<?xml version="1.0"?><testsuites><testsuite>'
            '<testcase name="gw5"><error message="collection">boom</error></testcase>'
            "</testsuite></testsuites>"
        )
        executed, skipped = parse(xml)
        self.assertEqual(executed, set())
        self.assertEqual(skipped, set())

    def test_classname_only_falls_back_to_dotted_path(self):
        xml = (
            '<?xml version="1.0"?><testsuites><testsuite>'
            '<testcase classname="grpc_basic.test_basic_grpc" name="test_x" />'
            "</testsuite></testsuites>"
        )
        executed, _ = parse(xml)
        self.assertEqual(executed, {GRPC + "::test_x"})

    def test_bare_testsuite_root_is_handled(self):
        """Some pytest versions emit <testsuite> as the document root."""
        xml = (
            '<?xml version="1.0"?><testsuite>'
            '<testcase file="{}" name="test_x" />'
            "</testsuite>"
        ).format(GRPC)
        executed, _ = parse(xml)
        self.assertEqual(executed, {GRPC + "::test_x"})


class TestWorkflowWiring(unittest.TestCase):
    """Pin the shell bug that caused BLO-29523 in the first place.

    The guard above catches an under-covered rerun after the fact, but the
    root cause was upstream of it: appending an unquoted word list to a
    `bash -c '...'` script string delivers only the FIRST word to the command.
    Everything after it becomes $0, $1, ... of the -c script and vanishes.
    These are plain text assertions -- no YAML parser -- so they run anywhere.
    """

    @classmethod
    def setUpClass(cls):
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            os.pardir,
            "workflows",
            "github-ci.yml",
        )
        with open(os.path.normpath(path)) as f:
            cls.workflow = f.read()

    def test_no_test_list_is_concatenated_onto_a_bash_c_string(self):
        # e.g.  bash -c '... pytest '$rerun_tests   <- drops all but the first
        offenders = re.findall(r"pytest[^\n']*'\$\w+", self.workflow)
        self.assertEqual(
            offenders,
            [],
            "test list concatenated onto a `bash -c` string; only its first "
            "word reaches pytest. Pass the list as arguments to \"$@\" instead. "
            "Offending fragment(s): {}".format(offenders),
        )

    def test_pytest_invocations_consume_positional_arguments(self):
        invocations = re.findall(r"sudo -E pytest[^\n]*", self.workflow)
        self.assertTrue(invocations, "expected to find the pytest invocations")
        for inv in invocations:
            self.assertIn(
                '"$@"',
                inv,
                'pytest invocation does not consume "$@", so any test list '
                "passed after the -c script is silently ignored: " + inv,
            )

    def test_rerun_harvest_keeps_full_node_ids(self):
        harvest = [
            line
            for line in self.workflow.splitlines()
            if "rerun_tests=$(" in line
        ]
        self.assertTrue(harvest, "expected to find the rerun harvest line")
        for line in harvest:
            self.assertNotIn(
                "cut -f1 -d:",
                line,
                "harvest truncates file.py::test_name to file.py, discarding "
                "the IDs the coverage check needs: " + line.strip(),
            )

    def test_rerun_result_is_gated_on_the_coverage_check(self):
        self.assertIn("verify_rerun_coverage.py", self.workflow)
        # "All rerun tests passed." must not be reachable on pytest's exit
        # code alone; the coverage check has to run before it.
        guard_at = self.workflow.index("verify_rerun_coverage.py")
        claim_at = self.workflow.index("All rerun tests passed.")
        self.assertLess(
            guard_at,
            claim_at,
            "the success message is printed before the coverage check runs",
        )


if __name__ == "__main__":
    unittest.main()
