#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim_dimt.py: PIM Light (RFC 9739) end-to-end forwarding test --
draft-zzhang-mboned-dynamic-internet-mcast-tunnel Phase A.

Topology (the r1--r2 segment stands in for the dynamic tunnel; the draft is
encapsulation-agnostic, and CI kernels lack FOU modules):

    h1 ---- s2 ---- r1 ---- s1 (light "tunnel") ---- r2 ---- s3 (receiver stub)
  (sender)      upstream PE                      receiver PoP

Both r1-eth0 and r2-eth0 run `ip pim` + `ip pim light`: NO hello adjacency
may form across s1, yet an IGMPv3 (S,G) join on r2's stub must:
  1. drive r2's (S,G) upstream to JOINED with RPF over the light interface
     (static route via 10.0.0.1 supplies the MRIB nexthop = the UMH),
  2. cross s1 as a neighborless PIM Join that r1 accepts (synthetic light
     neighbor),
  3. program r1's kernel MFC with OIF = the light interface,
  4. natively forward the sender's traffic r1->r2->stub through both kernel
     MFCs (packet counters increment on both routers).

There is deliberately NO bgpd and NO mvpn-gtm here -- this is the
native-forwarding path that replaces the MVPN Type-7 + userspace-replicator
scaffolding.
"""

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.pimd]

SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"

# left running so counters keep moving across the forwarding tests, reaped
# in teardown_module.
SENDER = None


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # s1: the light "tunnel" segment (no hellos may cross it)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # s2: r1's source segment with host h1
    tgen.add_host("h1", "10.10.10.10/24", "via 10.10.10.1")
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    # s3: r2's receiver stub (IGMP joins are placed here)
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
        staticd_conf = os.path.join(CWD, "{}/staticd.conf".format(rname))
        if os.path.exists(staticd_conf):
            router.load_config(TopoRouter.RD_STATIC, staticd_conf)

    tgen.start_router()


def teardown_module(mod):
    global SENDER
    if SENDER is not None:
        SENDER.terminate()
        SENDER = None
    tgen = get_topogen()
    tgen.stop_topology()


def _json_cmd(rname, cmd):
    """vtysh JSON helper: returns None (NOT {}) on unparseable output, so
    a crashed/unresponsive daemon can never satisfy an absence-assertion
    vacuously -- every predicate must treat None as failure."""
    out = get_topogen().gears[rname].vtysh_cmd(cmd)
    try:
        return json.loads(out)
    except ValueError:
        return None


def test_light_flag_and_no_adjacency():
    """`ip pim light` shows on the tunnel interfaces and -- the RFC 9739
    baseline -- no hello adjacency ever forms across s1."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _light_shown(rname, ifname):
        data = _json_cmd(rname, "show ip pim interface {} json".format(ifname))
        if data is None:
            return "{}: unparseable pim interface JSON (pimd dead?)".format(
                rname
            )
        ifdata = data.get(ifname, {})
        if ifdata.get("light") is not True:
            return "{}: light flag not shown on {}: {}".format(
                rname, ifname, ifdata
            )
        return None

    for rname, ifname in (("r1", "r1-eth0"), ("r2", "r2-eth0")):
        test_func = functools.partial(_light_shown, rname, ifname)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, result

    # Give hellos every chance to (wrongly) fire, then assert none did:
    # no neighbor exists anywhere yet, and zero hellos were sent on the
    # light interfaces.
    topotest.sleep(5, "letting any (wrong) hellos fire")
    for rname, ifname in (("r1", "r1-eth0"), ("r2", "r2-eth0")):
        neigh = _json_cmd(rname, "show ip pim neighbor json")
        assert neigh is not None, (
            "{}: unparseable pim neighbor JSON (pimd dead?)".format(rname)
        )
        assert not neigh.get(ifname), (
            "{}: unexpected PIM neighbor on light interface {}: {}".format(
                rname, ifname, neigh.get(ifname)
            )
        )
        traffic = _json_cmd(rname, "show ip pim interface traffic json")
        assert traffic is not None, (
            "{}: unparseable pim traffic JSON (pimd dead?)".format(rname)
        )
        hello_tx = traffic.get(ifname, {}).get("helloTx", 0)
        assert hello_tx == 0, "{}: {} sent {} hellos on a light interface".format(
            rname, ifname, hello_tx
        )


def test_igmp_join_forms_upstream_over_light():
    """An IGMPv3 (S,G) join on r2's stub drives the upstream to JOINED with
    RPF over the light interface, and r1 materializes a synthetic light
    neighbor from the neighborless Join."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ip igmp join-group {} {}
""".format(GROUP, SOURCE)
    )

    def _upstream_joined():
        data = _json_cmd("r2", "show ip pim upstream json")
        if data is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if updata.get("joinState") != "Joined":
            return "r2 upstream not Joined: {}".format(updata)
        if updata.get("inboundInterface") != "r2-eth0":
            return "r2 upstream RPF not on the light interface: {}".format(
                updata
            )
        return None

    _, result = topotest.run_and_expect(_upstream_joined, None, count=60, wait=1)
    assert result is None, result

    def _synthetic_neighbor():
        neigh = _json_cmd("r1", "show ip pim neighbor json")
        if neigh is None:
            return "r1: unparseable pim neighbor JSON (pimd dead?)"
        if "10.0.0.2" not in neigh.get("r1-eth0", {}):
            return "r1 has no light neighbor 10.0.0.2 on r1-eth0: {}".format(
                neigh
            )
        return None

    _, result = topotest.run_and_expect(_synthetic_neighbor, None, count=60, wait=1)
    assert result is None, (
        "the neighborless Join did not materialize a synthetic light neighbor: %s"
        % result
    )

    # DR must remain r1 itself: synthetic light neighbors carry no hello
    # state and never participate in DR election.  If that exclusion
    # regressed, the light neighbor 10.0.0.2 > 10.0.0.1 would win DR by
    # address the instant it materialized.
    ifdata = _json_cmd("r1", "show ip pim interface r1-eth0 json")
    assert ifdata is not None, (
        "r1: unparseable pim interface JSON (pimd dead?)"
    )
    dr_addr = ifdata.get("r1-eth0", {}).get("drAddress")
    assert dr_addr == "10.0.0.1", (
        "r1-eth0 DR stolen by the synthetic light neighbor: {}".format(
            dr_addr
        )
    )


def test_r1_oif_programmed():
    """r1's kernel MFC gains the light interface as OIF for the (S,G),
    IIF = the source LAN."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _mroute_oif():
        data = _json_cmd("r1", "show ip mroute json")
        if data is None:
            return "r1: unparseable mroute JSON (pimd dead?)"
        sgdata = data.get(GROUP, {}).get(SOURCE, {})
        if not sgdata:
            return "r1 has no (S,G) mroute yet: {}".format(data)
        if sgdata.get("iif") != "r1-eth1":
            return "r1 (S,G) IIF is not the source LAN: {}".format(sgdata)
        oil = sgdata.get("oil", {})
        if "r1-eth0" not in oil:
            return "r1 (S,G) OIL lacks the light interface: {}".format(sgdata)
        return None

    _, result = topotest.run_and_expect(_mroute_oif, None, count=60, wait=1)
    assert result is None, result


def test_native_forwarding_end_to_end():
    """A live sender behind r1 is natively forwarded through BOTH kernel
    MFCs to r2's stub -- the packet counters that stay at 0 forever under
    the userspace-replicator scaffolding must increment here."""
    global SENDER
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    mcast_tester = os.path.join(CWD, "../lib/mcast-tester.py")
    SENDER = tgen.gears["h1"].popen(
        [mcast_tester, GROUP, "h1-eth0", "--send", "0.7"]
    )
    logger.info("started sender on h1: %s -> %s", SOURCE, GROUP)

    def _counts(rname, iif, oif):
        data = _json_cmd(rname, "show ip mroute count json")
        if data is None:
            return "{}: unparseable mroute count JSON (pimd dead?)".format(
                rname
            )
        # shape: {"group": {"source": {..., "packets": N, ...}}} across
        # implementations the (S,G) row carries a packet counter; navigate
        # defensively.
        sgdata = data.get(GROUP, {}).get(SOURCE, {})
        pkts = sgdata.get("packets", 0)
        if pkts <= 0:
            return "{}: no packets counted for ({}, {}): {}".format(
                rname, SOURCE, GROUP, sgdata
            )
        return None

    for rname, iif, oif in (
        ("r1", "r1-eth1", "r1-eth0"),
        ("r2", "r2-eth0", "r2-eth1"),
    ):
        test_func = functools.partial(_counts, rname, iif, oif)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result


def test_leave_prunes_oif():
    """Removing the join prunes r1's light-interface OIF (neighborless
    Prune handling)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 no ip igmp join-group {} {}
""".format(GROUP, SOURCE)
    )

    def _oif_gone():
        data = _json_cmd("r1", "show ip mroute json")
        if data is None:
            # a dead pimd must NOT satisfy this absence-assertion
            return "r1: unparseable mroute JSON (pimd dead?)"
        sgdata = data.get(GROUP, {}).get(SOURCE, {})
        oil = sgdata.get("oil", {})
        if "r1-eth0" in oil:
            return "r1 (S,G) OIL still holds the light interface: {}".format(
                sgdata
            )
        return None

    _, result = topotest.run_and_expect(_oif_gone, None, count=90, wait=1)
    assert result is None, result

    # a full join/prune lifecycle later, the light interfaces must STILL
    # have sent zero hellos -- this catches a periodic hello-timer leak
    # that the 5s post-startup window in test_light_flag_and_no_adjacency
    # is too short to see.
    for rname, ifname in (("r1", "r1-eth0"), ("r2", "r2-eth0")):
        traffic = _json_cmd(rname, "show ip pim interface traffic json")
        assert traffic is not None, (
            "{}: unparseable pim traffic JSON (pimd dead?)".format(rname)
        )
        hello_tx = traffic.get(ifname, {}).get("helloTx", 0)
        assert hello_tx == 0, (
            "{}: {} sent {} hellos on a light interface over the test's "
            "lifetime (periodic hello-timer leak)".format(
                rname, ifname, hello_tx
            )
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
