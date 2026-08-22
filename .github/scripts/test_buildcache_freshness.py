#!/usr/bin/env python3
"""Fixtures pinning the buildcache freshness gate's decision logic.

The failure this gate exists to catch is *silent*: a buildcache that stopped
being written looks identical to a warm one from inside CI. So a bug here that
reports "fresh" for a stale tag does not merely lose a test -- it reinstates the
exact blind spot the gate was added to close. Each test names the property it
protects.

Stdlib only, no network -- evaluate() and parse_push_time() are pure.

Run: python3 -m unittest discover -s .github/scripts -p 'test_*.py'
"""

import datetime as dt
import importlib.util
import os
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "buildcache_freshness",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "buildcache_freshness.py"),
)
bcf = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bcf)

NOW = dt.datetime(2026, 8, 22, 12, 0, 0, tzinfo=dt.timezone.utc)
UTC = dt.timezone.utc


def hours_ago(n):
    return NOW - dt.timedelta(hours=n)


class TestParsePushTime(unittest.TestCase):
    """Harbor's timestamp format must round-trip, including nanoseconds."""

    def test_plain_zulu(self):
        self.assertEqual(
            bcf.parse_push_time("2026-08-22T11:00:00Z"),
            dt.datetime(2026, 8, 22, 11, 0, 0, tzinfo=UTC),
        )

    def test_milliseconds(self):
        self.assertEqual(
            bcf.parse_push_time("2026-08-22T11:00:00.123Z"),
            dt.datetime(2026, 8, 22, 11, 0, 0, 123000, tzinfo=UTC),
        )

    def test_nanoseconds_truncate_to_microseconds(self):
        # Harbor emits 9 fractional digits; datetime accepts at most 6.
        # Without truncation this raises and the probe exits "cannot determine",
        # which is a different -- and misleading -- failure than "stale".
        self.assertEqual(
            bcf.parse_push_time("2026-08-22T11:00:00.123456789Z"),
            dt.datetime(2026, 8, 22, 11, 0, 0, 123456, tzinfo=UTC),
        )

    def test_explicit_offset_normalized_to_utc(self):
        self.assertEqual(
            bcf.parse_push_time("2026-08-22T13:00:00+02:00"),
            dt.datetime(2026, 8, 22, 11, 0, 0, tzinfo=UTC),
        )

    def test_nanoseconds_with_offset_keeps_the_offset(self):
        """Truncating the fraction must not swallow a trailing offset."""
        self.assertEqual(
            bcf.parse_push_time("2026-08-22T13:00:00.987654321+02:00"),
            dt.datetime(2026, 8, 22, 11, 0, 0, 987654, tzinfo=UTC),
        )

    def test_naive_timestamp_assumed_utc(self):
        self.assertEqual(
            bcf.parse_push_time("2026-08-22T11:00:00"),
            dt.datetime(2026, 8, 22, 11, 0, 0, tzinfo=UTC),
        )


class TestAbsoluteAgeMode(unittest.TestCase):
    """Scheduled-probe mode: is the cache within its freshness budget?"""

    def test_fresh_tag_is_ok(self):
        (row,) = bcf.evaluate({"u22": hours_ago(5)}, NOW, 72.0)
        self.assertEqual(row["status"], "ok")
        self.assertAlmostEqual(row["age_hours"], 5.0, places=6)

    def test_tag_older_than_budget_is_stale(self):
        (row,) = bcf.evaluate({"u22": hours_ago(100)}, NOW, 72.0)
        self.assertEqual(row["status"], "stale")
        self.assertIn("exceeds budget", row["detail"])

    def test_boundary_exactly_at_budget_is_ok(self):
        """Exactly 72h must not trip a >72h budget, or the gate flaps daily."""
        (row,) = bcf.evaluate({"u22": hours_ago(72)}, NOW, 72.0)
        self.assertEqual(row["status"], "ok")

    def test_one_second_past_budget_is_stale(self):
        observed = {"u22": NOW - dt.timedelta(hours=72, seconds=1)}
        (row,) = bcf.evaluate(observed, NOW, 72.0)
        self.assertEqual(row["status"], "stale")

    def test_missing_tag_is_never_silently_ok(self):
        """The original incident WAS a missing tag (cache importer 'not found')."""
        (row,) = bcf.evaluate({"u22": None}, NOW, 72.0)
        self.assertEqual(row["status"], "missing")

    def test_observed_ten_day_window_is_caught(self):
        """Regression guard for the real 2026-08-03 -> 08-11 staleness window.

        Measured gap between successful master cache writes was 214.9h; the
        gate must call that stale.
        """
        (row,) = bcf.evaluate({"amd64_u22-buildcache": hours_ago(214.9)}, NOW, 72.0)
        self.assertEqual(row["status"], "stale")

    def test_all_three_platform_tags_are_evaluated_independently(self):
        observed = {
            "amd64_u22-buildcache": hours_ago(1),
            "amd64_u24-buildcache": hours_ago(200),
            "amd64_u24_lttng-buildcache": None,
        }
        results = bcf.evaluate(observed, NOW, 72.0)
        self.assertEqual(
            [r["status"] for r in results], ["ok", "stale", "missing"]
        )


class TestBaselineMode(unittest.TestCase):
    """Post-seed mode: did the push timestamp actually advance?"""

    def test_advance_is_ok(self):
        (row,) = bcf.evaluate(
            {"u22": hours_ago(1)}, NOW, 72.0, baseline={"u22": hours_ago(30)}
        )
        self.assertEqual(row["status"], "ok")
        self.assertIn("advanced", row["detail"])

    def test_unchanged_push_time_fails(self):
        """A seeding run that published nothing is the failure mode that let
        the cache rot behind green checks. It must be loud."""
        same = hours_ago(30)
        (row,) = bcf.evaluate({"u22": same}, NOW, 72.0, baseline={"u22": same})
        self.assertEqual(row["status"], "not_advanced")

    def test_regressed_push_time_fails(self):
        (row,) = bcf.evaluate(
            {"u22": hours_ago(40)}, NOW, 72.0, baseline={"u22": hours_ago(10)}
        )
        self.assertEqual(row["status"], "not_advanced")

    def test_missing_prior_tag_counts_as_advance(self):
        """First-ever seed: no baseline entry, so any push is progress."""
        (row,) = bcf.evaluate({"u22": hours_ago(1)}, NOW, 72.0, baseline={})
        self.assertEqual(row["status"], "ok")
        self.assertIn("no prior tag", row["detail"])

    def test_absolute_age_is_ignored_when_baseline_given(self):
        """An old-but-advanced tag is still a successful write; only the
        scheduled probe judges absolute age."""
        (row,) = bcf.evaluate(
            {"u22": hours_ago(90)}, NOW, 72.0, baseline={"u22": hours_ago(200)}
        )
        self.assertEqual(row["status"], "ok")

    def test_missing_tag_still_flagged_in_baseline_mode(self):
        (row,) = bcf.evaluate(
            {"u22": None}, NOW, 72.0, baseline={"u22": hours_ago(200)}
        )
        self.assertEqual(row["status"], "missing")


class TestRenderSummary(unittest.TestCase):

    def test_marks_pass_and_fail_distinctly(self):
        results = bcf.evaluate({"good": hours_ago(1), "bad": hours_ago(300)}, NOW, 72.0)
        out = bcf.render_summary(results, 72.0)
        self.assertIn("`good`", out)
        self.assertIn("`bad`", out)
        self.assertIn("✅", out)
        self.assertIn("❌", out)
        self.assertIn("budget: 72h", out)

    def test_missing_tag_renders_without_crashing(self):
        results = bcf.evaluate({"gone": None}, NOW, 72.0)
        self.assertIn("—", bcf.render_summary(results, 72.0))


if __name__ == "__main__":
    unittest.main()
