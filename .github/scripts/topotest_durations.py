#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build the per-file topotest duration table that topotest_shards.py balances
# its shards on (BLO-35428).
#
#   topotest_durations.py --out .github/topotest-durations.json XML [XML ...]
#
# For every junit file given, a test file's duration is the sum of the `time`
# of its <testcase> elements.  Across the files it is the median of those
# sums, rounded to 0.1 s.  A test file absent from some XMLs takes the median
# of the XMLs it does appear in.
#
# xunit2 junit, which topotests writes, carries no `file` attribute, only a
# dotted classname (`bgp_x.test_bgp_x`, or `a.test_b.TestC` for a class-based
# test).  The file is recovered by trying successively shorter dotted
# prefixes until tests/topotests/<prefix with "/">.py exists.  A testcase
# whose classname maps to no file is counted and reported, never guessed.
#
# The table only steers balance: a stale or missing entry makes the shards
# less even, never incomplete, because topotest_shards.py plans the files it
# enumerates from the tree and gives unknown ones the median.  So an unmapped
# testcase is a warning here, not an error.

import argparse
import json
import os
import statistics
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_rerun_coverage import XDIST_WORKER_RE  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_ROOT = os.path.join(REPO_ROOT, "tests", "topotests")


def map_classname(dotted, root):
    """Return the tests/topotests-relative .py path for a dotted classname.

    Longest prefix first, so `a.test_b.TestC` resolves to `a/test_b.py` and
    never to a shorter, unrelated `a.py`.  None when nothing exists.
    """
    parts = [p for p in dotted.split(".") if p]
    for cut in range(len(parts), 0, -1):
        rel = "/".join(parts[:cut]) + ".py"
        if os.path.isfile(os.path.join(root, rel)):
            return rel
    return None


def file_times(path, root):
    """Return ({file: summed seconds}, [unmapped dotted names]) for one XML.

    Raises ET.ParseError / OSError on an unreadable file.
    """
    sums = {}
    unmapped = []
    for tc in ET.parse(path).iter("testcase"):
        cname = tc.get("classname", "")
        name = tc.get("name", "")
        if not cname:
            # Module-level records (collection errors) put the dotted module
            # in `name`; xdist worker pseudo-testcases are named gwN.
            if not name or XDIST_WORKER_RE.match(name):
                continue
            cname = name
        rel = map_classname(cname, root)
        if rel is None:
            unmapped.append(cname)
            continue
        sums[rel] = sums.get(rel, 0.0) + float(tc.get("time") or 0.0)
    return sums, unmapped


def build(paths, root):
    """Return ({file: median seconds rounded to 0.1}, {unmapped name: count})."""
    per_file = {}
    unmapped = {}
    for path in paths:
        sums, missing = file_times(path, root)
        for rel, secs in sums.items():
            per_file.setdefault(rel, []).append(secs)
        for name in missing:
            unmapped[name] = unmapped.get(name, 0) + 1
    table = {
        rel: round(statistics.median(vals), 1) for rel, vals in sorted(per_file.items())
    }
    return table, unmapped


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Median per-file topotest durations from junit XML (BLO-35428)."
    )
    parser.add_argument("--out", required=True, help="JSON file to write")
    parser.add_argument(
        "--root",
        default=DEFAULT_ROOT,
        help="topotests directory the classnames resolve against",
    )
    parser.add_argument("xml", nargs="+", help="junit XML file(s)")
    args = parser.parse_args(argv)

    try:
        table, unmapped = build(args.xml, args.root)
    except (ET.ParseError, OSError) as e:
        print("ERROR: cannot read junit input: {}".format(e), file=sys.stderr)
        return 1
    if not table:
        print(
            "ERROR: no testcase mapped to a file; refusing to write an empty table",
            file=sys.stderr,
        )
        return 1
    for name, count in sorted(unmapped.items()):
        print(
            "WARNING: {} testcase(s) of {} map to no file under {}".format(
                count, name, args.root
            ),
            file=sys.stderr,
        )
    with open(args.out, "w") as f:
        json.dump(table, f, indent=1, sort_keys=True)
        f.write("\n")
    print(
        "wrote {} file durations from {} XML(s) to {}".format(
            len(table), len(args.xml), args.out
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
