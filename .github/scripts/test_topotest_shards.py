#!/usr/bin/env python3
"""Fixtures pinning topotest sharding and its workflow wiring (BLO-35428).

The properties: over the REAL tree the shards are disjoint and their union is
exactly what pytest would walk (norecursedirs read from pytest.ini, pruned at
any depth); the split is deterministic; unknown files get the median; and the
shard count agrees everywhere it is written in github-ci.yml -- a shard with
no Build seed would resume from stale results on "Re-run all jobs", and a
verdict told the wrong count would check the wrong artifacts.

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
    "topotest_shards", os.path.join(_HERE, "topotest_shards.py")
)
shards = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(shards)


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = shards.main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestRealTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = shards.enumerate_tests(shards.DEFAULT_ROOT)
        cls.table = shards.load_durations(shards.DEFAULT_DURATIONS)

    def test_enumeration_is_nonempty_and_well_formed(self):
        self.assertGreater(len(self.files), 600)
        for f in self.files:
            base = f.rsplit("/", 1)[-1]
            self.assertTrue(base.startswith("test_") or base.endswith("_test.py"), f)
            self.assertFalse(f.startswith("/"), f)

    def test_complete_and_disjoint_for_every_shard_count(self):
        for n in (1, 2, 3, 4):
            split = shards.shard(self.files, self.table, n)
            flat = [f for s in split for f in s]
            self.assertEqual(len(flat), len(set(flat)), n)
            self.assertEqual(sorted(flat), self.files, n)

    def test_deterministic(self):
        a = shards.shard(self.files, self.table, 2)
        b = shards.shard(list(reversed(self.files)), dict(self.table), 2)
        self.assertEqual(a, b)
        self.assertEqual(shards.enumerate_tests(shards.DEFAULT_ROOT), self.files)

    def test_lib_and_other_norecursedirs_are_pruned(self):
        self.assertNotIn("lib/test_kernel_state.py", self.files)
        prune = shards.norecursedirs(shards.DEFAULT_ROOT)
        self.assertIn("lib", prune)
        for f in self.files:
            for part in f.split("/")[:-1]:
                self.assertFalse(any(shards.fnmatch.fnmatch(part, p) for p in prune), f)

    def test_norecursedirs_is_read_from_pytest_ini_not_copied(self):
        with open(os.path.join(shards.DEFAULT_ROOT, "pytest.ini")) as f:
            line = [x for x in f if x.startswith("norecursedirs")][0]
        self.assertEqual(
            shards.norecursedirs(shards.DEFAULT_ROOT), line.split("=", 1)[1].split()
        )

    def test_table_covers_the_tree_it_was_built_from(self):
        """The committed table: 648 files from the three initial junits."""
        self.assertEqual(len(self.table), 648)
        self.assertFalse(
            set(self.table) - set(self.files),
            "table names files the tree no longer has",
        )

    def test_list_matches_plan_and_is_longest_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, _, _ = run_main(["plan", "--shards", "2", "--out", tmp])
            self.assertEqual(rc, 0)
            for k in (1, 2):
                uni = os.path.join(tmp, "u%d.txt" % k)
                rc, out, _ = run_main(
                    ["list", "--shards", "2", "--index", str(k), "--universe-out", uni]
                )
                self.assertEqual(rc, 0)
                with open(os.path.join(tmp, "plan-%d.txt" % k)) as f:
                    self.assertEqual(out, f.read())
                with open(uni) as f, open(os.path.join(tmp, "universe.txt")) as g:
                    self.assertEqual(f.read(), g.read())
                listed = out.split()
                median = shards.statistics.median(
                    self.table[f] for f in self.files if f in self.table
                )
                costs = [self.table.get(f, median) for f in listed]
                self.assertEqual(costs, sorted(costs, reverse=True))


class Synthetic(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def touch(self, rel, text=""):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    def ini(
        self,
        body="[pytest]\nlog_format = %(asctime)s x\nnorecursedirs = lib munet ex*\n",
    ):
        self.touch("pytest.ini", body)

    def table(self, d):
        path = os.path.join(self.root, "d.json")
        with open(path, "w") as f:
            json.dump(d, f)
        return path


class TestEnumeration(Synthetic):
    def test_nested_norecursedirs_basename_is_pruned(self):
        self.ini()
        for rel in (
            "a/test_a.py",
            "a/lib/test_hidden.py",
            "b/c/munet/test_m.py",
            "b/c/test_c.py",
            "exotic/test_e.py",
            "d/x_test.py",
            "d/helper.py",
            "lib/test_kernel_state.py",
        ):
            self.touch(rel)
        self.assertEqual(
            shards.enumerate_tests(self.root),
            ["a/test_a.py", "b/c/test_c.py", "d/x_test.py"],
        )

    def test_symlink_cycle_terminates(self):
        self.ini()
        self.touch("a/test_a.py")
        os.symlink(os.path.join(self.root, "a"), os.path.join(self.root, "a", "loop"))
        self.assertEqual(shards.enumerate_tests(self.root), ["a/test_a.py"])

    def test_missing_pytest_ini_is_an_error(self):
        self.touch("a/test_a.py")
        with self.assertRaises(shards.ShardError):
            shards.enumerate_tests(self.root)

    def test_missing_norecursedirs_is_an_error(self):
        self.ini("[pytest]\nlog_level = ERROR\n")
        with self.assertRaises(shards.ShardError):
            shards.enumerate_tests(self.root)


class TestBalance(Synthetic):
    def test_unknown_file_gets_the_median(self):
        files = ["a.py", "b.py", "c.py", "new.py"]
        split = shards.shard(files, {"a.py": 10.0, "b.py": 30.0, "c.py": 20.0}, 2)
        # new.py costs median(10,20,30)=20; LPT order b(30) c(20) new(20) a(10):
        # b->s1, c->s2, new->s2 (20<30), a->s1 (30<40).
        self.assertEqual(split, [["b.py", "a.py"], ["c.py", "new.py"]])

    def test_ties_break_on_path_then_shard_index(self):
        split = shards.shard(
            ["z.py", "y.py", "x.py"], {"x.py": 5, "y.py": 5, "z.py": 5}, 2
        )
        self.assertEqual(split, [["x.py", "z.py"], ["y.py"]])

    def test_more_shards_than_files_is_an_error(self):
        with self.assertRaises(shards.ShardError):
            shards.shard(["a.py"], {"a.py": 1}, 2)

    def test_check_rejects_overlap_and_gaps(self):
        with self.assertRaises(shards.ShardError):
            shards.check(["a", "b"], [["a"], ["a", "b"]])
        with self.assertRaises(shards.ShardError):
            shards.check(["a", "b", "c"], [["a"], ["b"]])

    def test_bad_tables_are_errors(self):
        for bad in ("{}", "[]", '{"a.py": "x"}', '{"a.py": -1}', "{nope"):
            path = os.path.join(self.root, "bad.json")
            with open(path, "w") as f:
                f.write(bad)
            with self.assertRaises(shards.ShardError, msg=bad):
                shards.load_durations(path)

    def test_cli_rejects_out_of_range_index(self):
        self.ini()
        self.touch("a/test_a.py")
        self.touch("b/test_b.py")
        t = self.table({"a/test_a.py": 1})
        for idx in ("0", "3"):
            rc, out, err = run_main(
                [
                    "--root",
                    self.root,
                    "--durations",
                    t,
                    "list",
                    "--shards",
                    "2",
                    "--index",
                    idx,
                ]
            )
            self.assertEqual((rc, out), (1, ""), err)


class TestWorkflowWiring(unittest.TestCase):
    """One shard count, written in five places, must agree."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(_HERE, os.pardir, "workflows", "github-ci.yml")
        with open(os.path.normpath(path)) as f:
            cls.workflow = f.read()

        def job(name):
            m = re.search(
                r"\n  " + re.escape(name) + r":\n(.*?)(?=\n  [A-Za-z][\w-]*:\n|\Z)",
                cls.workflow,
                re.S,
            )
            return m.group(1) if m else ""

        cls.build, cls.test, cls.verdict = job("Build"), job("Test"), job("CI-Verdict")
        cls.n = int(
            re.search(r'^      TOPOTEST_SHARDS: "(\d+)"$', cls.test, re.M).group(1)
        )

    def step(self, job, name):
        m = re.search(
            r"      - name: " + re.escape(name) + r"\n(.*?)(?=\n      - name:|\Z)",
            job,
            re.S,
        )
        self.assertIsNotNone(m, name)
        return m.group(1)

    def test_matrix_shard_list_is_1_to_n(self):
        m = re.search(r"^        shard: \[([^\]]*)\]$", self.test, re.M)
        self.assertEqual(
            [int(x) for x in m.group(1).split(",")], list(range(1, self.n + 1))
        )

    def test_build_seeds_one_artifact_per_shard(self):
        seeds = re.findall(
            r"- name: Save cleared previous results \(shard (\d+)\)\n"
            r"        uses: actions/upload-artifact@v\d+\n        with:\n"
            r"          name: test-results-\$\{\{ matrix\.cfg\.platform \}\}-s(\d+)\n"
            r"          path: test-results-\$\{\{ matrix\.cfg\.platform \}\}-s(\d+)\n"
            r"          overwrite: true\n",
            self.build,
        )
        self.assertEqual(len(seeds), self.n)
        self.assertEqual(
            [tuple(int(x) for x in s) for s in seeds],
            [(k, k, k) for k in range(1, self.n + 1)],
        )
        loop = re.search(
            r"for k in ([\d ]+); do",
            self.step(self.build, "Clear any previous results"),
        )
        self.assertEqual(
            [int(x) for x in loop.group(1).split()], list(range(1, self.n + 1))
        )
        self.assertNotRegex(
            self.build, r"name: test-results-\$\{\{ matrix\.cfg\.platform \}\}\n"
        )

    def test_job_name_and_verdict_use_the_same_count(self):
        self.assertIn(
            "name: ${{ matrix.cfg.name }} (shard ${{ matrix.shard }}/%d)" % self.n,
            self.test,
        )
        self.assertRegex(self.verdict, r"--shards %d\b" % self.n)

    def test_verdict_platforms_are_the_test_matrix_platforms(self):
        platforms = re.findall(
            r"^        -  \{[^}]*platform: '([^']+)' \}$", self.test, re.M
        )
        self.assertEqual(len(platforms), 2)
        m = re.search(r"--platforms ([\w,]+) --event-name", self.verdict)
        self.assertEqual(m.group(1).split(","), platforms)

    def test_result_id_names_every_per_shard_thing(self):
        self.assertIn(
            "RESULT_ID: ${{ matrix.cfg.platform }}-s${{ matrix.shard }}", self.test
        )
        self.assertIn("TOPOTEST_SHARD: ${{ matrix.shard }}", self.test)
        self.assertNotIn("frr-${{ matrix.cfg.platform }}-cont", self.test)
        self.assertNotRegex(
            self.test,
            r"test-results-\$\{\{ matrix\.cfg\.platform \}\}"
            r"(?!-s\$\{\{ matrix\.shard \}\})",
        )
        per_shard = "test-results-${{ matrix.cfg.platform }}-s${{ matrix.shard }}"
        fetch = self.step(self.test, "Fetch previous results")
        upload = self.step(self.test, "Upload test results")
        self.assertIn("name: " + per_shard + "\n", fetch)
        self.assertIn("name: " + per_shard + "\n", upload)
        self.assertIn('--id "${RESULT_ID}"', self.step(self.test, "Run topotests"))

    def test_shard_plan_is_captured_by_command_substitution(self):
        run = self.step(self.test, "Run topotests")
        self.assertRegex(
            run,
            r"shard_raw=\$\(python3 \.github/scripts/topotest_shards\.py list "
            r"--shards \"\$\{TOPOTEST_SHARDS\}\" --index \"\$\{TOPOTEST_SHARD\}\"",
        )
        self.assertIn("[ ${#shard_files[@]} -gt 0 ] ||", run)

    def test_resume_and_coverage_are_scoped_to_the_shard(self):
        run = self.step(self.test, "Run topotests")
        self.assertIn(
            '--collected "${RUNNER_TEMP}/collected-shard.txt" '
            '--universe "${RUNNER_TEMP}/shard-universe.txt"',
            run,
        )
        cov = run[run.index("topotest_coverage.py") :]
        self.assertIn(
            '--collected "${RUNNER_TEMP}/collected-shard.txt"', cov.split("\n")[0]
        )
        self.assertIn('--accounted-out "${plan_dir}/accounted.txt"', cov[:400])

    def test_parallel_run_keeps_the_plan_order(self):
        run = self.step(self.test, "Run topotests")
        self.assertIn('--dist=loadfile --no-loadscope-reorder "$@"', run)

    def test_plan_upload_is_gating_and_overwrites(self):
        up = self.step(self.test, "Upload topotest shard plan")
        self.assertIn("if: ${{ always() }}", up)
        self.assertNotRegex(up, r"(?m)^        continue-on-error:")
        self.assertIn(
            "name: topotest-plan-${{ matrix.cfg.platform }}-s${{ matrix.shard }}\n", up
        )
        self.assertIn("path: ${{ runner.temp }}/plan\n", up)
        self.assertIn("overwrite: true", up)
        self.assertIn(
            "name: topotest-stats-${{ matrix.cfg.platform }}-s${{ matrix.shard }}",
            self.step(self.test, "Upload topotest footprint samples"),
        )

    def test_max_parallel_starts_at_two(self):
        """Critic: 4 concurrent frr containers per run is unmeasured."""
        self.assertRegex(self.test, r"(?m)^      max-parallel: 2$")


if __name__ == "__main__":
    unittest.main()
