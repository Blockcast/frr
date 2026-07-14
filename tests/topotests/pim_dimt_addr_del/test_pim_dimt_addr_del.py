#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim_dimt_addr_del.py: deleting the connected subnet that resolved a
DIMT light interface toward the UMH -- while the interface itself stays up
-- must unpin the (S,G) upstreams pinned there.

A DIMT pin carries STATIC_IIF, which makes pim_rpf_update() a no-op, so no
normal RPF-repair path re-resolves it.  The address-add path already
re-applies (pim_if_addr_add -> pim_dimt_iface_up), but the address-delete
path had no such hook: a bare `no ip address` on a still-operative light
interface left the pin stranded on an interface that no longer faced the
UMH, while a freshly created upstream for the same source unpinned -- two
divergent RPF outcomes for one source.

Topology (BGP + the mapping ride s1; the pin rides s4, so deleting s4's
address does not disturb BGP -- the live deployment shape):

    r1 ==== s1 (10.0.0.0/24, eBGP) ==== r2 ---- s3 (receiver stub)
       ---- s4 (10.0.1.0/24, pin) ----

r1 advertises 10.10.10.0/24 with `set extcommunity umh 10.0.1.1 pim`, so
the UMH (r1's s4 address) resolves onto r2-eth1.  An IGMP (S,G) join pins
the upstream to r2-eth1; deleting r2-eth1's 10.0.1.2/24 must unpin it.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"
SRC_PREFIX = "10.10.10.0/24"
UMH = "10.0.1.1"


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # s1: the eBGP + mapping segment (stays up throughout)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # s4: the light segment the pin rides -- its r2 address is the one the
    # test deletes out from under the pin
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # s3: r2's receiver stub (the IGMP join lives here)
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PIM, os.path.join(CWD, "{}/pimd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _json_cmd(rname, cmd):
    """vtysh JSON helper: returns None (NOT {}) on unparseable output, so a
    crashed/unresponsive daemon can never satisfy an absence-assertion
    (unpinned) vacuously -- every predicate must treat None as failure."""
    out = get_topogen().gears[rname].vtysh_cmd(cmd)
    try:
        return json.loads(out)
    except ValueError:
        return None


def test_mapping_resolves_on_s4():
    """r2 learns the source prefix's UMH and resolves it onto the s4 light
    interface r2-eth1 (which carries the UMH-covering subnet)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _mapping_on_eth1():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        entry = data.get(SRC_PREFIX, {})
        if entry.get("umh") != UMH:
            return "r2 UMH mapping missing/wrong: {}".format(data)
        if entry.get("interface") != "r2-eth1":
            return "r2 UMH not resolved on the s4 light iface: {}".format(entry)
        return None

    _, result = topotest.run_and_expect(_mapping_on_eth1, None, count=60, wait=1)
    assert result is None, result


def test_addr_del_unpins_then_readd_repins():
    """THE regression: an IGMP (S,G) join pins the upstream onto r2-eth1
    via the UMH; deleting r2-eth1's UMH-covering address (interface stays
    up) must UNPIN it -- before the fix no DIMT apply ran on address
    delete, so the pin stranded on r2-eth1.  Re-adding the address must
    re-pin (proving the same re-apply also heals forward)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth2
 ip igmp join-group {} {}
""".format(GROUP, SOURCE)
    )

    def _pinned_to_eth1():
        data = _json_cmd("r2", "show ip pim upstream json")
        if data is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if updata.get("staticIncomingInterface") is not True:
            return "r2 upstream not pinned: {}".format(updata)
        if updata.get("inboundInterface") != "r2-eth1":
            return "r2 upstream not pinned to r2-eth1: {}".format(updata)
        return None

    _, result = topotest.run_and_expect(_pinned_to_eth1, None, count=60, wait=1)
    assert result is None, result

    # delete the UMH-covering subnet while r2-eth1 stays operative
    tgen.gears["r2"].run("ip addr del 10.0.1.2/24 dev r2-eth1")

    def _unpinned_from_eth1():
        out = tgen.gears["r2"].vtysh_cmd("show ip pim upstream json")
        try:
            data = json.loads(out)
        except ValueError:
            # a dead pimd must NOT satisfy this absence-assertion
            return "r2 pimd unresponsive (crashed?): {}".format(out[:200])
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if (
            updata.get("staticIncomingInterface") is True
            and updata.get("inboundInterface") == "r2-eth1"
        ):
            return "r2 upstream still pinned to the de-addressed iface: {}".format(
                updata
            )
        # the mapping must also stop resolving r2-eth1
        mapping = _json_cmd("r2", "show ip pim dimt umh json")
        if mapping is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        if mapping.get(SRC_PREFIX, {}).get("interface") == "r2-eth1":
            return "r2 UMH still resolves the de-addressed iface: {}".format(
                mapping
            )
        return None

    _, result = topotest.run_and_expect(_unpinned_from_eth1, None, count=30, wait=1)
    assert result is None, result

    # re-adding the address must re-resolve and re-pin
    tgen.gears["r2"].run("ip addr add 10.0.1.2/24 dev r2-eth1")

    _, result = topotest.run_and_expect(_pinned_to_eth1, None, count=60, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
