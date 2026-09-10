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
import json
import os
import re
import tempfile
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


class TestCorruptHarborDataIsAProbeError(unittest.TestCase):
    """Bad Harbor data must exit 2, never 1.

    Exit 1 means "the cache is stale"; exit 2 means "the probe could not tell".
    An uncaught ValueError/AttributeError terminates Python with status 1, so a
    leaked exception here does not merely crash -- it actively *misdiagnoses*
    corrupt Harbor data as a stale cache and sends someone to reseed a cache
    that was never stale. Each case below leaked before this class existed.
    """

    def test_unparseable_timestamp_string(self):
        with self.assertRaises(bcf.ProbeError):
            bcf.parse_push_time("not-a-date")

    def test_out_of_range_timestamp(self):
        with self.assertRaises(bcf.ProbeError):
            bcf.parse_push_time("2026-13-45T99:99:99Z")

    def test_non_string_push_time(self):
        # Harbor returning a numeric epoch instead of RFC3339.
        for value in (1787412231, None, {"nested": 1}, ["list"]):
            with self.subTest(value=value):
                with self.assertRaises(bcf.ProbeError):
                    bcf.parse_push_time(value)

    def test_probe_error_message_names_the_offending_value(self):
        # The operator reading CI logs needs to see *what* was malformed.
        with self.assertRaises(bcf.ProbeError) as ctx:
            bcf.parse_push_time("not-a-date")
        self.assertIn("not-a-date", str(ctx.exception))

    def test_empty_string_push_time(self):
        with self.assertRaises(bcf.ProbeError):
            bcf.parse_push_time("")

    def test_valid_timestamps_still_parse(self):
        # Guard against the hardening swallowing the happy path.
        self.assertEqual(
            bcf.parse_push_time("2026-08-22T11:00:00Z"),
            dt.datetime(2026, 8, 22, 11, 0, 0, tzinfo=UTC),
        )
        self.assertEqual(
            bcf.parse_push_time("2026-08-22T11:00:00.123456789Z"),
            dt.datetime(2026, 8, 22, 11, 0, 0, 123456, tzinfo=UTC),
        )


class TestFetchPushTimesRejectsMalformedPayloads(unittest.TestCase):
    """The artifacts response is attacker-adjacent data: validate its shape."""

    def _fetch(self, payload):
        original = bcf._request_json
        bcf._request_json = lambda url, headers, timeout: payload
        try:
            return bcf.fetch_push_times(
                "reg", "cache", "frr-ci", ["amd64_u22-buildcache"], "u", "p"
            )
        finally:
            bcf._request_json = original

    def test_artifact_record_that_is_not_an_object(self):
        with self.assertRaises(bcf.ProbeError):
            self._fetch(["just-a-string"])

    def test_artifact_with_malformed_push_time(self):
        with self.assertRaises(bcf.ProbeError):
            self._fetch([{"push_time": "not-a-date"}])

    def test_artifact_with_numeric_push_time(self):
        with self.assertRaises(bcf.ProbeError):
            self._fetch([{"push_time": 1787412231}])

    def test_empty_payload_means_missing_not_error(self):
        # A tag that genuinely does not exist is a *stale* verdict (exit 1),
        # not a probe error -- this distinction is the whole point.
        self.assertEqual(self._fetch([]), {"amd64_u22-buildcache": None})

    def test_well_formed_payload_parses(self):
        observed = self._fetch([{"push_time": "2026-08-21T06:41:00Z"}])
        self.assertEqual(
            observed["amd64_u22-buildcache"],
            dt.datetime(2026, 8, 21, 6, 41, 0, tzinfo=UTC),
        )


class TestMainExitCodes(unittest.TestCase):
    """End-to-end: the exit code is the contract the workflow branches on."""

    def setUp(self):
        self._original = bcf._request_json
        os.environ["HARBOR_USERNAME"] = "u"
        os.environ["HARBOR_PASSWORD"] = "p"

    def tearDown(self):
        bcf._request_json = self._original

    def _main(self, payload, extra_argv=()):
        bcf._request_json = lambda url, headers, timeout: payload
        return bcf.main(["--tag", "amd64_u22-buildcache", *extra_argv])

    def test_corrupt_push_time_exits_probe_error_not_stale(self):
        self.assertEqual(
            self._main([{"push_time": "not-a-date"}]), bcf.EXIT_PROBE_ERROR
        )

    def test_non_string_push_time_exits_probe_error_not_stale(self):
        self.assertEqual(
            self._main([{"push_time": 1787412231}]), bcf.EXIT_PROBE_ERROR
        )

    def test_non_object_artifact_exits_probe_error_not_stale(self):
        self.assertEqual(self._main(["oops"]), bcf.EXIT_PROBE_ERROR)

    def test_missing_tag_exits_stale_not_probe_error(self):
        self.assertEqual(self._main([]), bcf.EXIT_STALE)

    def test_corrupt_baseline_exits_probe_error_not_stale(self):
        # Regression: the baseline path is the post-seed "did it advance"
        # assertion. Leaking here reports a *successful* seed as a failure.
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump({"amd64_u22-buildcache": 1787412231}, fh)
            path = fh.name
        self.addCleanup(os.unlink, path)
        self.assertEqual(
            self._main(
                [{"push_time": "2026-08-21T06:41:00Z"}], ("--baseline", path)
            ),
            bcf.EXIT_PROBE_ERROR,
        )

    def test_baseline_that_is_not_an_object_exits_probe_error(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(["not", "a", "dict"], fh)
            path = fh.name
        self.addCleanup(os.unlink, path)
        self.assertEqual(
            self._main(
                [{"push_time": "2026-08-21T06:41:00Z"}], ("--baseline", path)
            ),
            bcf.EXIT_PROBE_ERROR,
        )

    def test_missing_credentials_exits_probe_error(self):
        os.environ["HARBOR_USERNAME"] = ""
        self.assertEqual(
            self._main([{"push_time": "2026-08-21T06:41:00Z"}]),
            bcf.EXIT_PROBE_ERROR,
        )


class TestSeederMatrixMatchesCI(unittest.TestCase):
    """The seeder must build every platform github-ci.yml consumes.

    `buildcache-seed.yml` is the *sole* writer of the buildcache; `github-ci.yml`
    is read-only against it. So a platform added to the CI Build matrix but not
    to the seeder matrix builds cold on every PR, forever, with nothing to say
    so -- green checks, just slower. That is precisely the silent failure mode
    this whole gate exists to close, reintroduced one matrix entry at a time.

    Both files carry a comment saying the matrices must stay in lockstep. A
    comment is not a check, so this asserts it. Stdlib only (no PyYAML in CI):
    the matrix entries are single-line flow mappings, parsed by regex below.
    """

    WORKFLOWS = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "workflows"
    )

    # -  { rel: '22.04', name: 'Ubuntu 22.04 amd64', platform: 'amd64_u22' }
    _ENTRY = re.compile(r"^\s*-\s*\{.*\}\s*$")
    _FIELD = re.compile(r"(\w+)\s*:\s*'([^']*)'")

    def _job_block(self, filename, job_id):
        """Lines belonging to one top-level job (2-space indented key)."""
        path = os.path.join(self.WORKFLOWS, filename)
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        start = None
        for i, line in enumerate(lines):
            if line == f"  {job_id}:":
                start = i + 1
                break
        self.assertIsNotNone(start, f"job '{job_id}' not found in {filename}")
        block = []
        for line in lines[start:]:
            # Next top-level job key ends the block.
            if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
                break
            block.append(line)
        return block

    def _matrix_platforms(self, filename, job_id):
        """{platform: lttng_flag} for the job's matrix cfg entries."""
        entries = {}
        for line in self._job_block(filename, job_id):
            if not self._ENTRY.match(line):
                continue
            fields = dict(self._FIELD.findall(line))
            if "platform" not in fields:
                continue
            entries[fields["platform"]] = fields.get("lttng", "")
        self.assertTrue(
            entries, f"no matrix platforms parsed from {filename}:{job_id}"
        )
        return entries

    def test_platform_sets_are_identical(self):
        ci = self._matrix_platforms("github-ci.yml", "Build")
        seed = self._matrix_platforms("buildcache-seed.yml", "seed")
        unseeded = set(ci) - set(seed)
        self.assertFalse(
            unseeded,
            f"platform(s) built by github-ci.yml but never seeded: "
            f"{sorted(unseeded)} -- these will build cold on every PR with no "
            f"signal. Add them to buildcache-seed.yml's matrix.",
        )
        orphaned = set(seed) - set(ci)
        self.assertFalse(
            orphaned,
            f"platform(s) seeded but no longer built by github-ci.yml: "
            f"{sorted(orphaned)} -- wasted runner time. Remove from the seeder.",
        )

    def test_lttng_flag_matches_per_platform(self):
        # `platform` is the cache key, but LTTng changes the build content. A
        # mismatch would seed a cache the CI build cannot use.
        ci = self._matrix_platforms("github-ci.yml", "Build")
        seed = self._matrix_platforms("buildcache-seed.yml", "seed")
        for platform in sorted(set(ci) & set(seed)):
            with self.subTest(platform=platform):
                self.assertEqual(
                    ci[platform],
                    seed[platform],
                    f"lttng flag differs for {platform}",
                )

    def test_parser_actually_found_the_expected_platforms(self):
        # Guard against the regex silently matching nothing and the drift
        # assertions above passing vacuously on two empty sets.
        ci = self._matrix_platforms("github-ci.yml", "Build")
        self.assertIn("amd64_u22", ci)
        self.assertIn("amd64_u24", ci)
        self.assertGreaterEqual(len(ci), 3)


class TestFreshnessGateFailsClosedOnFailedVerify(unittest.TestCase):
    """The required gate must not go green on a still-fresh cache after a failed seed.

    `freshness-gate` runs with `always()` so a failed `verify` is visible rather
    than skipped, but the age probe only measures the cache that already exists.
    A seed that fails today leaves yesterday's cache inside the 72h budget, so
    the gate must consume `needs.verify.result` before it ever probes age.
    """

    def _freshness_gate_block(self):
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "workflows", "buildcache-seed.yml"
        )
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        match = re.search(r"^  freshness-gate:\n(.*?)(?=^  \S|\Z)", text, re.S | re.M)
        self.assertIsNotNone(match, "freshness-gate job not found in buildcache-seed.yml")
        return match.group(1)

    def test_gate_propagates_a_non_success_verify_result(self):
        block = self._freshness_gate_block()
        self.assertIn("needs.verify.result != 'success'", block)
        self.assertRegex(block, r"if: \$\{\{ needs\.verify\.result != 'success' \}\}[\s\S]*?exit 1")

    def test_verify_verdict_is_consumed_before_the_age_probe(self):
        block = self._freshness_gate_block()
        guard = block.index("needs.verify.result != 'success'")
        probe = block.index("buildcache_freshness.py")
        self.assertLess(guard, probe, "the age probe must not run before the verify verdict is consumed")

    def test_gate_still_runs_after_a_failed_verify(self):
        # Without always() a failed verify skips the gate entirely, which is the
        # other way to hide the failure; the guard above only helps if it runs.
        block = self._freshness_gate_block()
        self.assertIn("always()", block)


if __name__ == "__main__":
    unittest.main()
