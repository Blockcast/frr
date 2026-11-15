#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim_ssm_rejoin_expiry.py: a Join that follows a Prune must start the
downstream (S,G) Expiry Timer afresh (RFC 7761 4.5.2).

    h1 ---- s1 ---- r1 ---- s2 ---- r2 ---- s3 ---- h2
  source           FHR                             IGMPv3 receiver

h1 sends, so r1's (S,G) keepalive timer runs.  Without the fix, Prune-Pending
expiry left r1's Expiry Timer running into NoInfo, the keepalive kept the
channel, and the re-Join kept the old deadline: r1 removed the oif at the
first Join's deadline with no Prune behind it.

r2 runs join-prune-interval 10, so its Joins carry a 35 s holdtime.
"""

import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.pim import McastTesterHelper
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.pimd, pytest.mark.staticd]

SOURCE = "10.0.1.2"
GROUP = "232.1.1.1"
DOWNSTREAM = "r1-eth1"  # r1's interface toward r2
HOLDTIME = 35  # r2's join-prune-interval 10 x 3.5

app_helper = McastTesterHelper()
pruned_at = None


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_host("h1", SOURCE + "/24", "via 10.0.1.1")
    tgen.add_host("h2", "10.0.2.2/24", "via 10.0.2.1")
    links = (("s1", "r1", "h1"), ("s2", "r1", "r2"), ("s3", "r2", "h2"))
    for sname, left, right in links:
        switch = tgen.add_switch(sname)
        switch.add_link(tgen.gears[left])
        switch.add_link(tgen.gears[right])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname in ("r1", "r2"):
        tgen.gears[rname].load_frr_config(os.path.join(CWD, rname, "frr.conf"))
    tgen.start_router()
    app_helper.init(tgen)


def teardown_module():
    app_helper.cleanup()
    get_topogen().stop_topology()


def r1_channel():
    "r1's (S,G) downstream channel on DOWNSTREAM, or None when there is none"
    out = get_topogen().gears["r1"].vtysh_cmd("show ip pim join json", isjson=True)
    return out.get(DOWNSTREAM, {}).get(GROUP, {}).get(SOURCE)


def r1_channel_state():
    channel = r1_channel()
    return channel["channelJoinName"] if channel else None


def expiry_seconds(channel):
    "the channel's Expiry Timer in seconds, or None when it is not running"
    mm, _, ss = channel["expire"].partition(":")
    return None if mm.startswith("-") else int(mm) * 60 + int(ss)


def test_neighbor_and_stream():
    "r2 has r1 as PIM neighbor, and h1's stream gives r1 an (S,G) keepalive"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run_traffic("h1", GROUP, bind_intf="h1-eth0")

    def ready():
        nbrs = tgen.gears["r2"].vtysh_cmd("show ip pim neighbor json", isjson=True)
        if "10.0.12.1" not in nbrs.get("r2-eth0", {}):
            return "r2 has no PIM neighbor r1: {}".format(nbrs)
        up = tgen.gears["r1"].vtysh_cmd("show ip pim upstream json", isjson=True)
        kat = up.get(GROUP, {}).get(SOURCE, {}).get("keepaliveTimer", "--")
        if kat.startswith("-"):
            return "r1 has no ({}, {}) keepalive: {}".format(SOURCE, GROUP, up)
        return None

    _, result = topotest.run_and_expect(ready, None, count=60, wait=1)
    assert result is None, result


def test_prune_leaves_no_expiry_timer():
    "A Prune takes r1's channel to NoInfo, where no Expiry Timer runs"
    global pruned_at
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run_join("h2", GROUP, join_intf="h2-eth0", source=SOURCE)
    _, state = topotest.run_and_expect(r1_channel_state, "JOIN", count=30, wait=1)
    assert state == "JOIN", "r1 got no Join for ({}, {})".format(SOURCE, GROUP)

    app_helper.stop_host("h2")  # h2's socket closes: it leaves, and r2 sends a Prune
    _, state = topotest.run_and_expect(
        lambda: r1_channel_state() not in ("JOIN", "PRUNEP"), True, count=30, wait=1
    )
    assert state, "r1 saw no Prune for ({}, {})".format(SOURCE, GROUP)
    pruned_at = time.monotonic()

    channel = r1_channel()
    assert channel is None or expiry_seconds(channel) is None, (
        "r1's ({}, {}) is {} with its Expiry Timer still running ({}); "
        "no timer runs in NoInfo".format(
            SOURCE, GROUP, channel["channelJoinName"], channel["expire"]
        )
    )


def test_rejoin_restarts_expiry_timer():
    "A Join in NoInfo starts the Expiry Timer at the received holdtime"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    assert pruned_at is not None, "needs the Prune of the test before"

    # Re-join half a holdtime after the Prune: a timer inherited from the
    # first Join has at most HOLDTIME / 2 left by now, a fresh one about HOLDTIME.
    time.sleep(max(0.0, pruned_at + HOLDTIME / 2 - time.monotonic()))
    app_helper.run_join("h2", GROUP, join_intf="h2-eth0", source=SOURCE)
    _, state = topotest.run_and_expect(r1_channel_state, "JOIN", count=30, wait=1)
    assert state == "JOIN", "r1 got no re-Join for ({}, {})".format(SOURCE, GROUP)

    expiry = expiry_seconds(r1_channel())
    assert expiry is not None and expiry > HOLDTIME * 3 / 4, (
        "r1's Expiry Timer after the re-Join is {} s; a fresh one is close to "
        "the {} s holdtime".format(expiry, HOLDTIME)
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
