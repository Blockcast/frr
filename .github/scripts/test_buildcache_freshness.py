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
import urllib.error
from unittest import mock

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

    def _ci_platforms(self):
        """Every platform github-ci.yml builds: Build's matrix plus
        Build-LTTng's (BLO-35428 moved the LTTng leg into its own job so it no
        longer gates Test). Both read the buildcache the seeder writes."""
        build = self._matrix_platforms("github-ci.yml", "Build")
        lttng = self._matrix_platforms("github-ci.yml", "Build-LTTng")
        both = set(build) & set(lttng)
        self.assertFalse(
            both, f"platform(s) built by both Build and Build-LTTng: {sorted(both)}"
        )
        return {**build, **lttng}

    def test_platform_sets_are_identical(self):
        ci = self._ci_platforms()
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
        #
        # Compared as the build arg both workflows actually pass,
        # ENABLE_LTTNG=${{ matrix.cfg.lttng || 'false' }}: an absent flag (the
        # seeder's u22/u24 rows) and an explicit 'false' (github-ci.yml's,
        # spelled out since BLO-35428 left no LTTng row in Build) build the
        # same image. The expression itself is pinned below, so this
        # equivalence cannot silently stop holding.
        ci = self._ci_platforms()
        seed = self._matrix_platforms("buildcache-seed.yml", "seed")
        for platform in sorted(set(ci) & set(seed)):
            with self.subTest(platform=platform):
                self.assertEqual(
                    ci[platform] or "false",
                    seed[platform] or "false",
                    f"lttng flag differs for {platform}",
                )
        for filename in ("github-ci.yml", "buildcache-seed.yml"):
            with open(os.path.join(self.WORKFLOWS, filename), encoding="utf-8") as fh:
                text = "\n".join(
                    line for line in fh if not line.lstrip().startswith("#")
                )
            with self.subTest(workflow=filename):
                self.assertIn("ENABLE_LTTNG=${{ matrix.cfg.lttng || 'false' }}", text)
                self.assertNotRegex(text, r"ENABLE_LTTNG=(?!\$\{\{ matrix\.cfg\.lttng)")

    def test_parser_actually_found_the_expected_platforms(self):
        # Guard against the regex silently matching nothing and the drift
        # assertions above passing vacuously on two empty sets.
        ci = self._ci_platforms()
        self.assertIn("amd64_u22", ci)
        self.assertIn("amd64_u24", ci)
        self.assertIn("amd64_u24_lttng", ci)
        self.assertGreaterEqual(len(ci), 3)
        self.assertEqual(ci["amd64_u24_lttng"], "true")
        self.assertEqual(
            set(self._matrix_platforms("github-ci.yml", "Build-LTTng")),
            {"amd64_u24_lttng"},
        )


class TestLttngBuildMirrorsBuild(unittest.TestCase):
    """Build-LTTng is a hand copy of Build's first five steps (BLO-35428).

    It left Build's matrix so the LTTng leg (which delayed the Build gate in
    16 of 39 runs, by up to 47.1 min) no longer holds Test back.  The copy
    may differ from Build only where the move requires: it exports
    `type=cacheonly` (nothing pulls an LTTng image) and has none of Build's
    seed/cleanup steps.  Any other drift -- a different cache-from, build
    arg, MIB key or timeout -- would test a build CI no longer runs for u24,
    so it fails here.  Comment lines are ignored.
    """

    WORKFLOW = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "workflows",
        "github-ci.yml",
    )

    @classmethod
    def setUpClass(cls):
        with open(cls.WORKFLOW, encoding="utf-8") as fh:
            text = fh.read()

        def job(name):
            m = re.search(
                r"\n  " + re.escape(name) + r":\n(.*?)(?=\n  [A-Za-z][\w-]*:\n|\Z)",
                text,
                re.S,
            )
            return m.group(1) if m else ""

        cls.build, cls.lttng = job("Build"), job("Build-LTTng")

    @staticmethod
    def _code(block):
        return [
            line.rstrip()
            for line in block.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    def _steps(self, block):
        self.assertIn("\n    steps:\n", block)
        body = block[block.index("\n    steps:\n") :]
        steps = {}
        for item in body.split("\n      - ")[1:]:
            code = self._code("      - " + item)
            name = code[0][len("      - name: ") :]
            self.assertTrue(code[0].startswith("      - name: "), code[0])
            self.assertNotIn(name, steps, f"duplicate step name {name!r}")
            steps[name] = code
        return steps

    def _header(self, block):
        """Job-level lines before `steps:`, minus matrix entries and comments."""
        head = block[: block.index("\n    steps:\n")]
        return [
            line
            for line in self._code(head)
            if not re.match(r"^\s*-\s*\{", line)
        ]

    def test_job_exists(self):
        self.assertTrue(self.lttng, "Build-LTTng job not found in github-ci.yml")

    def test_same_runner_gate_and_timeout(self):
        self.assertEqual(self._header(self.lttng), self._header(self.build))

    def test_steps_are_builds_first_steps(self):
        build, lttng = self._steps(self.build), self._steps(self.lttng)
        names = list(lttng)
        self.assertEqual(names, list(build)[: len(names)])
        self.assertEqual(names[-1], "Build docker image (cached)")

    def test_shared_steps_are_identical(self):
        build, lttng = self._steps(self.build), self._steps(self.lttng)
        for name in list(lttng)[:-1]:
            with self.subTest(step=name):
                self.assertEqual(lttng[name], build[name])

    def test_build_step_differs_only_in_its_exporter(self):
        name = "Build docker image (cached)"
        build, lttng = self._steps(self.build)[name], self._steps(self.lttng)[name]

        def without_outputs(code):
            out, skipping = [], False
            for line in code:
                if line == "          outputs: |":
                    skipping = True
                    continue
                if skipping and line.startswith(" " * 12):
                    continue
                skipping = False
                if line.startswith("          outputs:"):
                    continue
                out.append(line)
            return out

        self.assertEqual(without_outputs(lttng), without_outputs(build))
        self.assertIn("          outputs: type=cacheonly", lttng)
        self.assertNotIn("push=true", "\n".join(lttng))

    def test_lttng_uploads_nothing(self):
        self.assertNotIn("actions/upload-artifact", "\n".join(self._code(self.lttng)))


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


def _seeder_job_block(test, job_id):
    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "workflows", "buildcache-seed.yml"
    )
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    match = re.search(rf"^  {re.escape(job_id)}:\n(.*?)(?=^  \S|\Z)", text, re.S | re.M)
    test.assertIsNotNone(match, f"{job_id} job not found in buildcache-seed.yml")
    return match.group(1)


class TestFreshnessGateToleratesOnlyUnmeasurableAge(unittest.TestCase):
    """Ally Important on #114: tolerating every exit 2 turned a Harbor defect
    (the case AUTHZ_STATUSES exists to keep loud) into a green gate."""

    def test_gate_tolerates_exactly_the_age_unmeasurable_exit(self):
        block = _seeder_job_block(self, "freshness-gate")
        tolerated = re.findall(r'\[ "\$\{rc\}" -eq (\d+) \]', block)
        self.assertEqual([str(bcf.EXIT_AGE_UNMEASURABLE)], tolerated)


class TestVerifyRequiresTheSeedResult(unittest.TestCase):
    """An unchanged digest is a warning, so it cannot prove a push happened;
    `verify` must take that evidence from the seed legs' own result."""

    def test_verify_fails_closed_on_a_non_success_seed(self):
        block = _seeder_job_block(self, "verify")
        self.assertRegex(
            block, r"if: \$\{\{ needs\.seed\.result != 'success' \}\}[\s\S]*?exit 1"
        )

    def test_seed_does_not_swallow_a_failed_cache_export(self):
        """Ally suggestion on #114: the check above is only evidence of a push
        because a failed `cache-to` export fails its leg. buildx's
        `ignore-error=true` would break exactly that -- the seed would go green
        without rewriting the cache and `verify` would certify it, which is the
        failure the old unconditional exit 1 used to catch. Locked here because
        the coupling was stated only in a comment.
        """
        block = _seeder_job_block(self, "seed")
        self.assertIn("cache-to:", block)
        self.assertNotIn("ignore-error", block)


class TestEveryJobIsConfinedToTheCanonicalRepo(unittest.TestCase):
    """No job in the seeder may run outside Blockcast/frr.

    The registry coordinates at `cache-to` are hard-coded to
    registry.blockcast.net, so a job that runs in a fork points a build and a
    cache push at *our* registry -- an external side effect of someone else's
    push. `probe-before` carries `github.repository == 'Blockcast/frr'`, and
    while every other job merely inherited that boundary transitively through
    `needs` + the default success() condition, that was enough.

    It stops being enough the moment a job takes `always()`: always() runs the
    job even when its dependency was *skipped*, so a fork's push skips
    probe-before and the boundary silently evaporates for everything
    downstream. The condition that makes a probe outage non-blocking is the
    same condition that drops the fork guard -- one expression doing two
    unrelated jobs, which is why this needs a check and not a comment.

    So: assert the boundary directly on every job, rather than assuming the
    dependency graph carries it.
    """

    WORKFLOW = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "workflows",
        "buildcache-seed.yml",
    )
    BOUNDARY = "github.repository == 'Blockcast/frr'"

    def _jobs(self):
        """{job_id: block_text} for every top-level job in the seeder."""
        with open(self.WORKFLOW, encoding="utf-8") as handle:
            text = handle.read()
        jobs_at = text.index("\njobs:\n")
        blocks = {}
        for match in re.finditer(
            r"^  ([A-Za-z0-9_-]+):\n(.*?)(?=^  \S|\Z)", text[jobs_at:], re.S | re.M
        ):
            blocks[match.group(1)] = match.group(2)
        self.assertTrue(blocks, "no jobs parsed from buildcache-seed.yml")
        return blocks

    def _condition(self, block):
        """The job-level `if:` expression, or None when the job has none."""
        match = re.search(r"^    if:(.*)$", block, re.M)
        return match.group(1).strip() if match else None

    def test_parser_found_the_expected_jobs(self):
        # Guard against the regex matching nothing and every assertion below
        # passing vacuously over an empty dict.
        jobs = self._jobs()
        for expected in ("probe-before", "seed", "verify", "freshness-gate"):
            self.assertIn(expected, jobs)

    def test_every_job_carries_the_repository_boundary(self):
        for job_id, block in sorted(self._jobs().items()):
            with self.subTest(job=job_id):
                condition = self._condition(block)
                self.assertIsNotNone(
                    condition,
                    f"job '{job_id}' has no `if:` at all, so it runs in any "
                    f"fork that pushes. Add {self.BOUNDARY}.",
                )
                self.assertIn(
                    self.BOUNDARY,
                    condition,
                    f"job '{job_id}' can run outside Blockcast/frr. Every job "
                    f"here touches registry.blockcast.net directly or gates "
                    f"something that does.",
                )

    def test_always_jobs_still_restate_the_boundary(self):
        # The specific regression: always() ignores a skipped dependency, so
        # inheriting the boundary via `needs` does not hold for these jobs.
        always_jobs = {
            job_id: condition
            for job_id, block in self._jobs().items()
            if (condition := self._condition(block)) and "always()" in condition
        }
        self.assertTrue(
            always_jobs,
            "expected at least one always() job; if the seeder no longer uses "
            "always(), delete this test rather than letting it pass vacuously.",
        )
        for job_id, condition in sorted(always_jobs.items()):
            with self.subTest(job=job_id):
                self.assertIn(self.BOUNDARY, condition, f"always() job '{job_id}'")

    def test_the_registry_writer_is_boundary_guarded(self):
        # Narrowest, highest-consequence case stated on its own: the only job
        # that runs `cache-to` must never execute in a fork.
        jobs = self._jobs()
        writers = [job_id for job_id, block in jobs.items() if "cache-to:" in block]
        self.assertEqual(
            ["seed"],
            sorted(writers),
            "the set of cache-writing jobs changed; re-check the boundary on "
            "each new writer.",
        )
        self.assertIn(self.BOUNDARY, self._condition(jobs["seed"]))



class TestEvaluateDigests(unittest.TestCase):
    """The digest fallback must answer advancement and refuse to answer age.

    This path exists because Harbor authorizes /api/v2.0 and /v2 separately and
    the CI credential only holds the latter (BLO-33101). The risk it carries is
    the same silent one the whole gate guards: reporting a cache advanced when
    nothing was actually measured.
    """

    A = "sha256:" + "a" * 64
    B = "sha256:" + "b" * 64

    def test_unchanged_digest_is_a_warning_not_a_failure(self):
        # A no-op re-seed on an unchanged master re-pushes identical content
        # under the same digest. That is the successful steady state, so it
        # must not go red -- but it must not claim "advanced" either.
        rows = bcf.evaluate_digests({"t": self.A}, {"t": self.A})
        self.assertEqual("unchanged", rows[0]["status"])
        self.assertIn("unchanged", bcf.WARN_STATUSES)

    def test_changed_digest_advances(self):
        rows = bcf.evaluate_digests({"t": self.B}, {"t": self.A})
        self.assertEqual("ok", rows[0]["status"])

    def test_absent_tag_is_missing_not_ok(self):
        rows = bcf.evaluate_digests({"t": None}, {"t": self.A})
        self.assertEqual("missing", rows[0]["status"])

    def test_no_prior_tag_counts_as_seeded(self):
        rows = bcf.evaluate_digests({"t": self.A}, {})
        self.assertEqual("ok", rows[0]["status"])

    def test_digest_rows_never_claim_an_age(self):
        # render_summary prints whatever is in the row; a non-None age here
        # would put an unmeasured number into the job summary.
        for baseline in ({}, {"t": self.A}):
            rows = bcf.evaluate_digests({"t": self.B}, baseline)
            self.assertIsNone(rows[0]["age_hours"])
            self.assertIsNone(rows[0]["push_time"])


class TestDigestSummary(unittest.TestCase):
    def test_summary_does_not_advertise_a_budget_it_did_not_measure(self):
        rows = bcf.evaluate_digests({"t": "sha256:" + "c" * 64}, None)
        out = bcf.render_summary(rows, 72.0, mode="digest")
        self.assertNotIn("budget: 72h", out)
        self.assertIn("age NOT measured", out)

    def test_push_time_summary_is_unchanged(self):
        rows = bcf.evaluate({"t": hours_ago(1)}, NOW, 72.0, None)
        out = bcf.render_summary(rows, 72.0)
        self.assertIn("budget: 72h", out)


class TestAuthChallengeParsing(unittest.TestCase):
    """Parsed, not hard-coded, so a registry or token-service rename cannot
    silently break the only fallback surface."""

    # Captured verbatim from registry.blockcast.net on 2026-09-29.
    LIVE = (
        'Bearer realm="https://registry.blockcast.net/service/token",'
        'service="harbor-registry",scope="repository:cache/frr-ci:pull"'
    )

    def test_parses_the_live_harbor_challenge(self):
        got = bcf._parse_auth_challenge(self.LIVE)
        self.assertEqual(
            "https://registry.blockcast.net/service/token", got["realm"]
        )
        self.assertEqual("harbor-registry", got["service"])
        self.assertEqual("repository:cache/frr-ci:pull", got["scope"])

    def test_rejects_a_non_bearer_challenge(self):
        with self.assertRaises(bcf.ProbeError):
            bcf._parse_auth_challenge('Basic realm="harbor"')

    def test_rejects_an_empty_challenge(self):
        with self.assertRaises(bcf.ProbeError):
            bcf._parse_auth_challenge("")


def _refuse_harbor(*_a, **_k):
    raise bcf.ProbeError("HTTP 403 from artifacts API", status=403)


def _harbor_returns_garbage(*_a, **_k):
    # No status: a parse failure, not an authorization failure.
    raise bcf.ProbeError("artifact for t has no push_time field")


class TestFallbackWiring(unittest.TestCase):
    """End-to-end exit codes for the degraded path.

    A digest baseline and a push_time baseline are not comparable, and neither
    can answer absolute age; both confusions would certify an unmeasured cache.
    """

    CREDS = {"HARBOR_USERNAME": "u", "HARBOR_PASSWORD": "p"}

    def _main(self, argv, digests):
        with mock.patch.dict(os.environ, self.CREDS), \
                mock.patch.object(bcf, "fetch_push_times", _refuse_harbor), \
                mock.patch.object(bcf, "fetch_digests", digests):
            return bcf.main(argv)

    def _with_baseline(self, baseline_obj, digests):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "b.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(baseline_obj, fh)
            return self._main(["--tag", "t", "--baseline", path], digests)

    def test_digest_run_against_push_time_baseline_is_a_probe_error(self):
        rc = self._with_baseline(
            {"t": "2026-08-22T11:00:00Z"},
            lambda *a, **k: {"t": "sha256:" + "d" * 64},
        )
        self.assertEqual(bcf.EXIT_PROBE_ERROR, rc)

    def test_unchanged_digest_after_a_reseed_does_not_go_red(self):
        # Ally Critical on #114: a successful no-op re-seed keeps the digest,
        # and exit 1 here was tolerated nowhere in buildcache-seed.yml, so the
        # gate went red on success. The push evidence is the seed job result,
        # asserted in TestVerifyRequiresTheSeedResult.
        same = "sha256:" + "d" * 64
        rc = self._with_baseline({"t": same}, lambda *a, **k: {"t": same})
        self.assertEqual(bcf.EXIT_OK, rc)

    def test_absent_tag_against_a_digest_baseline_still_goes_red(self):
        # The warning is for "unchanged" only; a tag that vanished (Harbor
        # retention, the thing this gate guards) must stay exit 1.
        rc = self._with_baseline(
            {"t": "sha256:" + "d" * 64}, lambda *a, **k: {"t": None}
        )
        self.assertEqual(bcf.EXIT_STALE, rc)

    def test_digest_run_reports_advancement(self):
        rc = self._with_baseline(
            {"t": "sha256:" + "d" * 64},
            lambda *a, **k: {"t": "sha256:" + "e" * 64},
        )
        self.assertEqual(bcf.EXIT_OK, rc)

    def test_age_question_is_refused_when_only_digests_are_available(self):
        # No --baseline: the only remaining question is absolute age, which a
        # digest cannot answer. This must NOT come back green.
        # Its own exit code, so freshness-gate can tolerate exactly this and
        # still fail on exit 2 (a Harbor defect).
        rc = self._main(["--tag", "t"], lambda *a, **k: {"t": "sha256:" + "e" * 64})
        self.assertEqual(bcf.EXIT_AGE_UNMEASURABLE, rc)
        self.assertNotEqual(bcf.EXIT_PROBE_ERROR, bcf.EXIT_AGE_UNMEASURABLE)

    def test_both_surfaces_down_is_a_probe_error(self):
        rc = self._main(["--tag", "t"], _refuse_harbor)
        self.assertEqual(bcf.EXIT_PROBE_ERROR, rc)

    def test_a_harbor_defect_does_not_silently_switch_surfaces(self):
        # The fallback exists for 403 only. A malformed Harbor response is a
        # Harbor fault; degrading to digests there would hide it behind a run
        # that still goes green, which is the blind spot this gate exists to
        # close. The digest fetcher must never be reached.
        def _boom(*_a, **_k):  # pragma: no cover - must not be called
            raise AssertionError("fell back on a non-authorization error")

        with mock.patch.dict(os.environ, self.CREDS), \
                mock.patch.object(bcf, "fetch_push_times",
                                  _harbor_returns_garbage), \
                mock.patch.object(bcf, "fetch_digests", _boom):
            self.assertEqual(bcf.EXIT_PROBE_ERROR, bcf.main(["--tag", "t"]))

    def test_http_errors_carry_their_status(self):
        # The narrowing above is only as good as this field being populated.
        with self.assertRaises(bcf.ProbeError) as caught:
            with mock.patch.object(
                bcf.urllib.request, "urlopen",
                mock.Mock(side_effect=urllib.error.HTTPError(
                    "u", 403, "Forbidden", None, None)),
            ):
                bcf._request_json("https://example.invalid/x", {}, 1)
        self.assertEqual(403, caught.exception.status)

    def test_a_bare_string_token_payload_is_never_echoed(self):
        # Ally suggestion on #114: this message lands in the Actions log, and a
        # token service answering with a bare JSON string is most likely
        # handing back the credential itself. Diagnose by type, never by value.
        secret = "eyJhbGciOiJIUzI1NiJ9.SUPERSECRETTOKEN"
        with self.assertRaises(bcf.ProbeError) as caught:
            with mock.patch.object(bcf, "_request_json", return_value=secret):
                bcf._registry_bearer_token(
                    {"realm": "https://example.invalid/token"}, "u", "p", 1
                )
        self.assertNotIn(secret, str(caught.exception))
        self.assertIn("str", str(caught.exception))

    def test_report_only_baseline_snapshot_survives_the_fallback(self):
        # probe-before must still exit 0 and emit a usable baseline, otherwise
        # the seeding run it guards gets skipped -- the BLO-33101 failure.
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "before.json")
            rc = self._main(
                ["--tag", "t", "--report-only", "--json-out", out],
                lambda *a, **k: {"t": "sha256:" + "f" * 64},
            )
            self.assertEqual(bcf.EXIT_OK, rc)
            with open(out, encoding="utf-8") as fh:
                self.assertEqual({"t": "sha256:" + "f" * 64}, json.load(fh))


class TestFetchDigests(unittest.TestCase):
    """A 200 that carries no digest is 'could not tell', not 'tag absent'.

    The file's whole exit-code contract rests on that distinction: 'missing'
    exits 1 and sends someone to reseed a cache that may be perfectly fine,
    while a probe error exits 2 and says the measurement failed.
    """

    @staticmethod
    def _response(headers):
        resp = mock.MagicMock()
        resp.headers = headers
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda s, *a: False
        return resp

    def test_missing_digest_header_is_a_probe_error_not_a_missing_tag(self):
        with mock.patch.object(
            bcf.urllib.request, "urlopen",
            mock.Mock(return_value=self._response({})),
        ):
            with self.assertRaises(bcf.ProbeError):
                bcf.fetch_digests("r", "p", "repo", ["t"], "u", "pw")

    def test_digest_header_is_returned(self):
        digest = "sha256:" + "1" * 64
        with mock.patch.object(
            bcf.urllib.request, "urlopen",
            mock.Mock(return_value=self._response(
                {"Docker-Content-Digest": digest})),
        ):
            self.assertEqual(
                {"t": digest},
                bcf.fetch_digests("r", "p", "repo", ["t"], "u", "pw"),
            )

    def test_404_is_a_missing_tag(self):
        with mock.patch.object(
            bcf.urllib.request, "urlopen",
            mock.Mock(side_effect=urllib.error.HTTPError(
                "u", 404, "Not Found", None, None)),
        ):
            self.assertEqual(
                {"t": None},
                bcf.fetch_digests("r", "p", "repo", ["t"], "u", "pw"),
            )

    @staticmethod
    def _challenge_401():
        exc = urllib.error.HTTPError("u", 401, "Unauthorized", None, None)
        exc.headers = {
            "Www-Authenticate": TestAuthChallengeParsing.LIVE,
        }
        return exc

    def test_404_after_the_token_exchange_is_a_missing_tag(self):
        # The realistic flow: anonymous HEAD -> 401 -> token -> HEAD -> 404.
        # The pre-auth 404 branch never sees this, so it needs its own case.
        with mock.patch.object(
            bcf.urllib.request, "urlopen",
            mock.Mock(side_effect=[
                self._challenge_401(),
                urllib.error.HTTPError("u", 404, "Not Found", None, None),
            ]),
        ), mock.patch.object(
            bcf, "_request_json", mock.Mock(return_value={"token": "t0k"})
        ):
            self.assertEqual(
                {"t": None},
                bcf.fetch_digests("r", "p", "repo", ["t"], "u", "pw"),
            )

    def test_a_rejected_token_is_a_probe_error_not_a_second_challenge(self):
        with mock.patch.object(
            bcf.urllib.request, "urlopen",
            mock.Mock(side_effect=[self._challenge_401(), self._challenge_401()]),
        ), mock.patch.object(
            bcf, "_request_json", mock.Mock(return_value={"token": "t0k"})
        ):
            with self.assertRaises(bcf.ProbeError) as caught:
                bcf.fetch_digests("r", "p", "repo", ["t"], "u", "pw")
        self.assertEqual(401, caught.exception.status)

    def test_digest_is_read_after_a_successful_token_exchange(self):
        digest = "sha256:" + "2" * 64
        with mock.patch.object(
            bcf.urllib.request, "urlopen",
            mock.Mock(side_effect=[
                self._challenge_401(),
                self._response({"Docker-Content-Digest": digest}),
            ]),
        ), mock.patch.object(
            bcf, "_request_json", mock.Mock(return_value={"token": "t0k"})
        ):
            self.assertEqual(
                {"t": digest},
                bcf.fetch_digests("r", "p", "repo", ["t"], "u", "pw"),
            )

if __name__ == "__main__":
    unittest.main()
