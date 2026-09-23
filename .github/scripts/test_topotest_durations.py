#!/usr/bin/env python3
"""Fixtures pinning the topotest duration table builder (BLO-35428).

junit has no `file` attribute, only a dotted classname, so the file is found
by the longest dotted prefix that exists under tests/topotests; per file the
table holds the median across XMLs of the summed testcase times.

Stdlib only, no network.

Run: python3 -m unittest discover -s .github/scripts -p 'test_topotest_*.py'
"""

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_SPEC = importlib.util.spec_from_file_location(
    "topotest_durations", os.path.join(_HERE, "topotest_durations.py")
)
dur = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(dur)


def junit(records):
    body = "".join(
        '<testcase classname="{}" name="{}" time="{}"/>'.format(c, n, t)
        for c, n, t in records
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite '
        'name="pytest">{}</testsuite></testsuites>'
    ).format(body)


class TestDurations(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self._tmp.name, "topotests")
        for rel in ("bgp_x/test_bgp_x.py", "a/test_b.py", "a.py"):
            path = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w").close()

    def tearDown(self):
        self._tmp.cleanup()

    def xml(self, name, records):
        path = os.path.join(self._tmp.name, name)
        with open(path, "w") as f:
            f.write(junit(records))
        return path

    def test_class_based_classname_maps_to_longest_existing_prefix(self):
        self.assertEqual(dur.map_classname("a.test_b.TestC", self.root), "a/test_b.py")
        self.assertEqual(
            dur.map_classname("bgp_x.test_bgp_x", self.root), "bgp_x/test_bgp_x.py"
        )
        self.assertIsNone(dur.map_classname("nope.test_nope", self.root))

    def test_sum_per_file_then_median_across_xmls(self):
        x1 = self.xml(
            "1.xml",
            [
                ("bgp_x.test_bgp_x", "t1", 10.0),
                ("bgp_x.test_bgp_x", "t2", 5.0),
                ("a.test_b.TestC", "t", 1.04),
            ],
        )
        x2 = self.xml("2.xml", [("bgp_x.test_bgp_x", "t1", 30.0)])
        x3 = self.xml(
            "3.xml", [("bgp_x.test_bgp_x", "t1", 20.0), ("a.test_b.TestC", "t", 3.0)]
        )
        table, unmapped = dur.build([x1, x2, x3], self.root)
        # bgp_x: sums 15, 30, 20 -> median 20; a/test_b: 1.04, 3.0 -> 2.02 -> 2.0
        self.assertEqual(table, {"bgp_x/test_bgp_x.py": 20.0, "a/test_b.py": 2.0})
        self.assertEqual(unmapped, {})

    def test_worker_records_skipped_and_unmapped_reported(self):
        x = self.xml(
            "1.xml",
            [
                ("", "gw0", 9.0),
                ("gone.test_gone", "t", 1.0),
                ("bgp_x.test_bgp_x", "t", 2.0),
            ],
        )
        table, unmapped = dur.build([x], self.root)
        self.assertEqual(table, {"bgp_x/test_bgp_x.py": 2.0})
        self.assertEqual(unmapped, {"gone.test_gone": 1})

    def test_cli_refuses_empty_table_and_unreadable_xml(self):
        out = os.path.join(self._tmp.name, "out.json")
        empty = self.xml("e.xml", [("gone.test_gone", "t", 1.0)])
        trunc = os.path.join(self._tmp.name, "t.xml")
        with open(trunc, "w") as f:
            f.write(junit([("bgp_x.test_bgp_x", "t", 1.0)])[:-20])
        for xml in (empty, trunc):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(dur.main(["--out", out, "--root", self.root, xml]), 1)
            self.assertFalse(os.path.exists(out))

    def test_committed_table_is_sorted_rounded_and_nonnegative(self):
        path = os.path.join(_HERE, os.pardir, "topotest-durations.json")
        with open(os.path.normpath(path)) as f:
            table = json.load(f)
        self.assertEqual(list(table), sorted(table))
        for k, v in table.items():
            self.assertGreaterEqual(v, 0, k)
            self.assertEqual(round(v, 1), v, k)


if __name__ == "__main__":
    unittest.main()
