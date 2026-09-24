#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Split the topotest tree into N shards of roughly equal wall time
# (BLO-35428), deterministically, so every Test shard job of a run can compute
# its own share without talking to the others.
#
#   topotest_shards.py list --shards N --index K [--universe-out FILE]
#       print shard K (1-based), longest file first, one path per line;
#       optionally write the whole enumeration, sorted, to FILE
#   topotest_shards.py plan --shards N --out DIR
#       write DIR/plan-<k>.txt for k = 1..N and DIR/universe.txt
#
# Paths are relative to tests/topotests, i.e. exactly how pytest spells them
# in node IDs when run from that directory.
#
# Enumeration mirrors what `pytest --collect-only` walks from that directory:
# files named test_*.py or *_test.py (pytest's default python_files; the
# topotests pytest.ini does not override it), pruning any directory whose
# basename fnmatches a `norecursedirs` entry AT ANY DEPTH.  The list is read
# from tests/topotests/pytest.ini, never copied here, so a change there moves
# both collection and sharding.  Pruning matters more than it looks: the run
# hands pytest explicit file paths, and norecursedirs does not apply to
# explicit paths, so a file this enumeration wrongly included (lib/ holds
# test_kernel_state.py) would really be run.  Symlinked directories are
# followed, as pytest's own directory walk follows them; today the only test
# files reachable that way sit under symlinked `lib` dirs and are pruned.
#
# Balance is LPT (longest processing time first): files sorted by
# (-duration, path), each assigned to the shard with the smallest
# (load, index).  Durations come from .github/topotest-durations.json
# (topotest_durations.py); a file it does not know gets the median of the
# known durations of the enumerated files.  The table only affects balance:
# every enumerated file lands in exactly one shard whatever the table says,
# and the result is asserted disjoint and complete before anything is printed.

import argparse
import configparser
import fnmatch
import json
import os
import statistics
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_ROOT = os.path.join(REPO_ROOT, "tests", "topotests")
DEFAULT_DURATIONS = os.path.join(REPO_ROOT, ".github", "topotest-durations.json")
PYTHON_FILES = ("test_*.py", "*_test.py")


class ShardError(Exception):
    """An input or invariant problem; the caller must fail closed."""


def norecursedirs(root):
    """The norecursedirs patterns from <root>/pytest.ini, as a list.

    Interpolation is off because the file carries %-style log formats.  A
    missing file or key is an error: sharding without the pruning list would
    plan lib/ and the example dirs into the run.
    """
    ini = os.path.join(root, "pytest.ini")
    cfg = configparser.ConfigParser(interpolation=None, strict=False)
    if not cfg.read(ini):
        raise ShardError("cannot read {}".format(ini))
    try:
        value = cfg.get("pytest", "norecursedirs")
    except (configparser.NoSectionError, configparser.NoOptionError):
        raise ShardError("{} has no [pytest] norecursedirs".format(ini))
    patterns = value.split()
    if not patterns:
        raise ShardError("{}: norecursedirs is empty".format(ini))
    return patterns


def enumerate_tests(root):
    """Sorted test file paths under root, relative to it, '/'-separated."""
    prune = norecursedirs(root)
    found = []
    seen_real = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=True):
        real = os.path.realpath(dirpath)
        if real in seen_real:
            # A symlink cycle, or a second route to a directory already
            # walked; its files are already recorded under the first route.
            dirnames[:] = []
            continue
        seen_real.add(real)
        dirnames[:] = sorted(
            d for d in dirnames if not any(fnmatch.fnmatch(d, p) for p in prune)
        )
        for name in filenames:
            if any(fnmatch.fnmatch(name, p) for p in PYTHON_FILES):
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                found.append(rel.replace(os.sep, "/"))
    return sorted(found)


def load_durations(path):
    """{file: seconds} from the table; unreadable or malformed is an error."""
    try:
        with open(path) as f:
            table = json.load(f)
    except (OSError, ValueError) as e:
        raise ShardError("cannot read durations table {}: {}".format(path, e))
    if not isinstance(table, dict) or not table:
        raise ShardError("durations table {} is empty or not an object".format(path))
    out = {}
    for k, v in table.items():
        if not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0:
            raise ShardError("durations table {}: bad value for {}".format(path, k))
        out[k] = float(v)
    return out


def shard(files, durations, n):
    """Return n lists of files, each in assignment (longest-first) order."""
    if n < 1:
        raise ShardError("--shards must be >= 1, got {}".format(n))
    if not files:
        raise ShardError("the enumeration is empty; nothing to shard")
    if n > len(files):
        raise ShardError(
            "{} shards for {} files would leave a shard empty".format(n, len(files))
        )
    known = [durations[f] for f in files if f in durations]
    fallback = statistics.median(known) if known else 1.0
    cost = {f: durations.get(f, fallback) for f in files}
    loads = [0.0] * n
    shards = [[] for _ in range(n)]
    for f in sorted(files, key=lambda f: (-cost[f], f)):
        k = min(range(n), key=lambda i: (loads[i], i))
        shards[k].append(f)
        loads[k] += cost[f]
    check(files, shards)
    return shards


def check(files, shards):
    """Raise unless the shards are pairwise disjoint and cover files exactly."""
    owner = {}
    for k, s in enumerate(shards, 1):
        if not s:
            raise ShardError("shard {} is empty".format(k))
        for f in s:
            if f in owner:
                raise ShardError("{} is in shards {} and {}".format(f, owner[f], k))
            owner[f] = k
    missing = sorted(set(files) - set(owner))
    extra = sorted(set(owner) - set(files))
    if missing or extra:
        raise ShardError(
            "shards do not partition the enumeration: missing {} extra {}".format(
                missing[:5], extra[:5]
            )
        )


def _write(path, lines):
    with open(path, "w") as f:
        f.writelines(line + "\n" for line in lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Deterministic LPT sharding of the topotest tree (BLO-35428)."
    )
    parser.add_argument("--root", default=DEFAULT_ROOT, help="tests/topotests dir")
    parser.add_argument(
        "--durations", default=DEFAULT_DURATIONS, help="per-file duration table (JSON)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_list = sub.add_parser("list", help="print one shard, longest file first")
    p_list.add_argument("--shards", type=int, required=True)
    p_list.add_argument("--index", type=int, required=True, help="1-based shard")
    p_list.add_argument("--universe-out", help="also write the whole enumeration here")
    p_plan = sub.add_parser("plan", help="write every shard and the universe")
    p_plan.add_argument("--shards", type=int, required=True)
    p_plan.add_argument("--out", required=True, help="output directory")
    args = parser.parse_args(argv)

    try:
        files = enumerate_tests(args.root)
        shards = shard(files, load_durations(args.durations), args.shards)
        if args.cmd == "list" and not 1 <= args.index <= args.shards:
            raise ShardError(
                "--index must be in 1..{}, got {}".format(args.shards, args.index)
            )
    except ShardError as e:
        print("ERROR: " + str(e), file=sys.stderr)
        return 1

    if args.cmd == "plan":
        os.makedirs(args.out, exist_ok=True)
        for k, s in enumerate(shards, 1):
            _write(os.path.join(args.out, "plan-{}.txt".format(k)), s)
        _write(os.path.join(args.out, "universe.txt"), files)
        print(
            "wrote {} shard(s) over {} files to {}".format(
                len(shards), len(files), args.out
            ),
            file=sys.stderr,
        )
        return 0

    if args.universe_out:
        _write(args.universe_out, files)
    mine = shards[args.index - 1]
    print(
        "shard {}/{}: {} of {} files".format(
            args.index, args.shards, len(mine), len(files)
        ),
        file=sys.stderr,
    )
    sys.stdout.write("".join(f + "\n" for f in mine))
    return 0


if __name__ == "__main__":
    sys.exit(main())
