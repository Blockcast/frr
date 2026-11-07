#!/usr/bin/env python3
"""Unit tests for tools/review-gate-sync-guard.sh.

The guard decides whether the canonical Ally review gate may overwrite a fleet
repo's vendored copy. Every test below pins a REFUSAL as much as a pass,
because the failure this guard exists to prevent is a silent `cp` over work
nobody knew the target had: a guard that waves something through is
indistinguishable from no guard at all, and that is precisely the state
tools/sync-review-gate.sh shipped in for three months (PEN-5925).

Run: python3 -m unittest discover -s tools -p 'test_review_gate_sync_guard.py'
"""

import pathlib
import subprocess
import tempfile
import unittest

GUARD = pathlib.Path(__file__).resolve().parent / "review-gate-sync-guard.sh"

SAFE = 0
REFUSE = 2
USAGE = 64

# A minimal file shaped like the real gate: the guard reads def/class names and
# line counts, so the bodies are irrelevant and deliberately absent.
CANONICAL = "\n".join(
    ["#!/usr/bin/env python3", '"""gate."""']
    + [f"def helper_{i}():\n    return {i}\n" for i in range(20)]
)


def write(directory, name, text):
    path = pathlib.Path(directory) / name
    path.write_text(text)
    return path


class GuardTestCase(unittest.TestCase):
    def run_guard(self, *args):
        result = subprocess.run(
            ["bash", str(GUARD), *[str(a) for a in args]],
            capture_output=True,
            text=True,
        )
        # stdout carries the report, stderr the refusal lines; tests assert
        # against both because the caller splices stdout into the PR body and
        # an operator reads stderr.
        return result.returncode, result.stdout + result.stderr

    def guard(self, canonical, target, **kw):
        args = ["--canonical", canonical, "--target", target]
        args += ["--canonical-committed", kw.pop("canon_date", "2026-10-15T20:58:05Z")]
        target_date = kw.pop("target_date", "2026-10-01T00:00:00Z")
        if target_date is not None:
            args += ["--target-committed", target_date]
        for flag in kw.pop("flags", []):
            args.append(flag)
        for key, value in kw.items():
            args += [f"--{key.replace('_', '-')}", str(value)]
        return self.run_guard(*args)


class FirstRollout(GuardTestCase):
    def test_absent_target_is_safe(self):
        """A repo with no copy has nothing to lose; this is the one path that
        legitimately skips every check, so it is pinned explicitly."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            code, out = self.guard(canonical, pathlib.Path(d) / "nope.py")
            self.assertEqual(code, SAFE, out)
            self.assertIn("first rollout", out)

    def test_absent_target_does_not_need_dates(self):
        """Check C refuses on unknown dates, but a first rollout must not be
        blocked by a date that cannot exist yet."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            code, out = self.run_guard(
                "--canonical", canonical, "--target", pathlib.Path(d) / "nope.py"
            )
            self.assertEqual(code, SAFE, out)


class DefinitionLoss(GuardTestCase):
    def test_target_only_definition_refuses(self):
        """onprem-k8s in miniature: the target grew a function canonical has
        never had, so the overwrite would delete it."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL + "\ndef fold_finding_history():\n    pass\n")
            code, out = self.guard(canonical, target)
            self.assertEqual(code, REFUSE, out)
            self.assertIn("fold_finding_history", out)
            self.assertIn("deletes them", out)

    def test_methods_count_as_definitions(self):
        """A subsystem moved inside a class is still work an overwrite deletes,
        so indented def/class must be read, not just column-zero ones."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(
                d, "target.py", CANONICAL + "\nclass Ledger:\n    def mint(self):\n        pass\n"
            )
            code, out = self.guard(canonical, target)
            self.assertEqual(code, REFUSE, out)
            self.assertIn("mint", out)

    def test_override_allows_loss_and_records_it(self):
        """The escape hatch must work AND must say so in the report: an
        override invisible to the generated PR is the same hole with a flag."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL + "\ndef only_here():\n    pass\n")
            code, out = self.guard(canonical, target, flags=["--allow-definition-loss"])
            self.assertEqual(code, SAFE, out)
            self.assertIn("OVERRIDE", out)
            self.assertIn("--allow-definition-loss", out)

    def test_canonical_ahead_is_safe(self):
        """The normal, intended sync: canonical has definitions the target
        lacks. That direction is what the script is FOR and must not refuse."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL + "\ndef brand_new():\n    pass\n")
            target = write(d, "target.py", CANONICAL)
            code, out = self.guard(canonical, target)
            self.assertEqual(code, SAFE, out)
            self.assertIn("verdict: SAFE", out)


class NetSize(GuardTestCase):
    def test_large_target_refuses(self):
        """Defence in depth behind check A, for extra work that happens to
        reuse canonical's names and so defines nothing new."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL + "\n# pad\n" * 400)
            code, out = self.guard(canonical, target)
            self.assertEqual(code, REFUSE, out)
            self.assertIn("net lines", out)

    def test_threshold_is_raisable(self):
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL + "\n# pad\n" * 400)
            code, out = self.guard(canonical, target, max_net_added=5000)
            self.assertEqual(code, SAFE, out)

    def test_shrinking_target_is_safe(self):
        """A stale target is SMALLER than canonical. Net removal is negative
        there, and the threshold must not fire on the healthy direction."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL + "\n# pad\n" * 400)
            target = write(d, "target.py", CANONICAL)
            code, out = self.guard(canonical, target)
            self.assertEqual(code, SAFE, out)


class Recency(GuardTestCase):
    def test_newer_target_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL)
            code, out = self.guard(canonical, target, target_date="2026-11-07T11:20:38Z")
            self.assertEqual(code, REFUSE, out)
            self.assertIn("NEWER", out)

    def test_newer_target_override(self):
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL)
            code, out = self.guard(
                canonical, target, target_date="2026-11-07T11:20:38Z",
                flags=["--allow-older-canonical"],
            )
            self.assertEqual(code, SAFE, out)
            self.assertIn("OVERRIDE", out)

    def test_equal_dates_are_safe(self):
        """A target synced from this very canonical commit carries the same
        date; refusing it would make every re-run of a landed sync fail."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL)
            code, out = self.guard(canonical, target, target_date="2026-10-15T20:58:05Z")
            self.assertEqual(code, SAFE, out)

    def test_missing_dates_refuse(self):
        """Fail CLOSED on what could not be measured. An unknown date read as
        'probably fine' is the fail-open behaviour this guard replaces."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL)
            code, out = self.run_guard("--canonical", canonical, "--target", target)
            self.assertEqual(code, REFUSE, out)
            self.assertIn("cannot compare commit dates", out)

    def test_malformed_date_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL)
            code, out = self.guard(canonical, target, target_date="last tuesday")
            self.assertEqual(code, REFUSE, out)
            self.assertIn("ISO-8601", out)

    def test_offset_and_fractional_forms_are_accepted(self):
        """GitHub returns `...Z`, git returns `+00:00`, and some surfaces add
        fractional seconds. All three name the same instant; rejecting the
        spelling would be a refusal with no safety content."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL)
            code, out = self.guard(
                canonical, target,
                canon_date="2026-10-15T20:58:05+00:00",
                target_date="2026-10-01T00:00:00.123Z",
            )
            self.assertEqual(code, SAFE, out)


class Plumbing(GuardTestCase):
    def test_unreadable_canonical_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            target = write(d, "target.py", CANONICAL)
            code, out = self.guard(pathlib.Path(d) / "missing.py", target)
            self.assertEqual(code, REFUSE, out)

    def test_unknown_flag_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            code, out = self.run_guard("--canonical", canonical, "--heuristics")
            self.assertEqual(code, USAGE, out)

    def test_missing_required_argument(self):
        code, out = self.run_guard("--canonical", "/dev/null")
        self.assertEqual(code, USAGE, out)

    def test_report_file_is_written(self):
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL)
            report = pathlib.Path(d) / "report.txt"
            code, out = self.guard(canonical, target, report=report)
            self.assertEqual(code, SAFE, out)
            self.assertIn("verdict: SAFE", report.read_text())

    def test_report_is_written_on_refusal_too(self):
        """The PR body quotes this report, and the refusing case is the one
        worth reading."""
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL + "\ndef extra():\n    pass\n")
            report = pathlib.Path(d) / "report.txt"
            code, out = self.guard(canonical, target, report=report)
            self.assertEqual(code, REFUSE, out)
            self.assertIn("REFUSED", report.read_text())

    def test_non_integer_threshold_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as d:
            canonical = write(d, "canon.py", CANONICAL)
            target = write(d, "target.py", CANONICAL)
            code, out = self.guard(canonical, target, max_net_added="lots")
            self.assertEqual(code, USAGE, out)


if __name__ == "__main__":
    unittest.main()
