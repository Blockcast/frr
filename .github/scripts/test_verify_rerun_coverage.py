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


class TestUnexpectedFailureReporting(unittest.TestCase):
    """BLO-36839: name the culprit when a whole-file rerun fails off-target.

    BLO-36708 made the rerun hand pytest whole FILES, so it can now fail on a
    test that was never in the harvested set.  The step exits 1 -- which is
    the right verdict -- but the log only carried RERUN_TESTS/RERUN_FILES,
    neither of which need mention the test that actually failed.  These pin
    the diagnostic, not the verdict: nothing here may change pass/fail.
    """

    def failures(self, xml):
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(xml)
            path = f.name
        try:
            return guard.parse_failures(path)
        finally:
            os.unlink(path)

    def test_offtarget_sibling_failure_is_named(self):
        """The motivating case: requested test passes, a sibling does not."""
        expected = {PIM + "::test_install_then_exactly_one_forwarding_ready"}
        failed = self.failures(
            junit(
                [
                    (PIM, "test_install_then_exactly_one_forwarding_ready", "pass"),
                    (PIM, "test_v1_only_consumer_ignores_and_advances", "failure"),
                ]
            )
        )
        outside = guard.unexpected_failures(expected, failed)
        self.assertEqual(
            outside, [PIM + "::test_v1_only_consumer_ignores_and_advances"]
        )

    def test_requested_failure_is_not_reported_as_unexpected(self):
        """A test we asked about failing again is expected, not a surprise."""
        expected = {GRPC + "::test_shutdown_checks"}
        failed = self.failures(junit([(GRPC, "test_shutdown_checks", "failure")]))
        self.assertEqual(guard.unexpected_failures(expected, failed), [])

    def test_file_level_expectation_accounts_for_any_failure_in_that_file(self):
        """Mirrors covers(): a bare path stands for the whole module."""
        expected = {GRPC}
        failed = self.failures(junit([(GRPC, "test_anything_at_all", "failure")]))
        self.assertEqual(guard.unexpected_failures(expected, failed), [])

    def test_a_different_files_failure_is_still_unexpected(self):
        expected = {GRPC}
        failed = self.failures(junit([(PIM, "test_x", "failure")]))
        outside = guard.unexpected_failures(expected, failed)
        self.assertEqual(outside, [PIM + "::test_x"])

    def test_errors_count_as_failures(self):
        """A module that errors out never reports <failure>, only <error>."""
        expected = {GRPC + "::test_shutdown_checks"}
        failed = self.failures(junit([(PIM, "test_x", "error")]))
        outside = guard.unexpected_failures(expected, failed)
        self.assertEqual(outside, [PIM + "::test_x"])

    def test_passes_and_skips_are_never_reported(self):
        expected = {GRPC + "::test_shutdown_checks"}
        failed = self.failures(
            junit([(PIM, "test_x", "pass"), (PIM, "test_y", "skipped")])
        )
        self.assertEqual(failed, set())
        self.assertEqual(guard.unexpected_failures(expected, failed), [])

    def test_clean_rerun_reports_nothing(self):
        """The negative case: no failures means no note in the log."""
        expected = {GRPC + "::test_shutdown_checks"}
        failed = self.failures(junit([(GRPC, "test_shutdown_checks", "pass")]))
        self.assertEqual(guard.unexpected_failures(expected, failed), [])

    def test_reporting_does_not_alter_the_verdict(self):
        """Diagnosability only: verify() must be unmoved by off-target failures."""
        expected = {GRPC + "::test_shutdown_checks"}
        executed, skipped = parse(
            junit(
                [
                    (GRPC, "test_shutdown_checks", "pass"),
                    (GRPC, "test_some_sibling", "failure"),
                ]
            )
        )
        self.assertEqual(guard.verify(expected, executed, skipped), [])


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
        # Matches the harvest whatever the variable is called, so renaming it
        # cannot silently retire this assertion.
        harvest = [
            line
            for line in self.workflow.splitlines()
            if re.search(r"\brerun_tests(_raw)?=\$\(", line)
        ]
        self.assertTrue(harvest, "expected to find the rerun harvest line")
        for line in harvest:
            self.assertNotIn(
                "cut -f1 -d:",
                line,
                "harvest truncates file.py::test_name to file.py, discarding "
                "the IDs the coverage check needs: " + line.strip(),
            )

    def test_rerun_list_is_passed_as_an_array_not_a_split_scalar(self):
        """Full node IDs make word-splitting reachable; an array prevents it.

        Dropping `cut -f1 -d:` means the list now carries `file.py::test_name`
        rather than bare paths, and a parametrized ID can contain spaces and
        glob metacharacters (`test_x[a b]`).  Expanding that unquoted would
        re-split one real ID into two bogus ones, so the list has to reach
        pytest as a quoted array expansion.
        """
        invocations = re.findall(r"sudo -E pytest[^\n]*", self.workflow)
        self.assertTrue(invocations, "expected to find the pytest invocations")
        for inv in invocations:
            self.assertNotRegex(
                inv,
                r"\$(run_tests|rerun_tests)\b",
                "test list expanded as an unquoted scalar, which re-splits "
                "node IDs on spaces and globs them: " + inv.strip(),
            )
        for name in ("run_tests", "rerun_tests"):
            self.assertIn(
                '"${%s[@]}"' % name,
                self.workflow,
                "%s must reach pytest as a quoted array expansion" % name,
            )

    def test_rerun_harvest_still_aborts_when_analyze_fails(self):
        """`set -e` coverage must survive the move to an array.

        The harvest is a command substitution precisely so that a failing
        analyze.py still aborts the step.  Feeding mapfile straight from a
        process substitution silently drops that, because a process
        substitution is not a pipeline component `set -e` inspects.
        """
        self.assertNotRegex(
            self.workflow,
            r"mapfile[^\n]*<\s*<\([^\n]*(analyze\.py|python3)",
            "mapfile reads analyze.py or a python3 helper through a process "
            "substitution, so a failure there no longer aborts the step under "
            "set -e",
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

    def test_rerun_runs_whole_files_but_verifies_node_ids(self):
        """BLO-36708: the serial rerun must hand pytest FILES, not node IDs.

        A topotest module is a stateful sequence sharing one module-scoped
        topology fixture, so re-running a single node ID runs it against a
        topology its predecessors never built -- it then fails on an
        assertion the parallel run never reached, and the flake filter can
        never clear it.  Coverage is still checked per node ID, which is the
        property `cut -f1 -d:` used to destroy; the two must not be collapsed
        back into one list in either direction.
        """
        rerun = re.search(
            r"sudo -E pytest[^\n]*pytest-rerun[^\n]*", self.workflow
        )
        self.assertTrue(rerun, "expected to find the serial rerun invocation")
        self.assertIn(
            '"${rerun_files[@]}"',
            rerun.group(0),
            "the rerun must pass whole files: " + rerun.group(0).strip(),
        )
        self.assertNotIn(
            '"${rerun_tests[@]}"',
            rerun.group(0),
            "the rerun passes node IDs, which breaks intra-module ordering: "
            + rerun.group(0).strip(),
        )
        # ...and the coverage check must still be fed the node IDs.
        expected = re.search(
            r"printf[^\n]*>\s*/tmp/rerun-expected\.txt", self.workflow
        )
        self.assertTrue(expected, "expected to find the --expected harvest")
        self.assertIn(
            '"${rerun_tests[@]}"',
            expected.group(0),
            "coverage must be verified per node ID, not per file: "
            + expected.group(0).strip(),
        )


if __name__ == "__main__":
    unittest.main()
