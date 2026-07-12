#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim_dimt_umh.py: DIMT Phase B -- BGP UMH extended community drives the
(S,G) RPF pin, replacing Phase A's per-source static route.

Topology (same shape as pim_dimt, plus an eBGP session across the light
segment):

    h1 ---- s2 ---- r1 ---- s1 (light "tunnel") ---- r2 ---- s3 (receiver stub)
  (sender)      upstream PE                      receiver PoP

r1 advertises the source prefix 10.10.10.0/24 over BGP with
`set extcommunity umh 10.0.0.1 pim preference 5`. r2 has NO static route:
the bgpd -> zebra -> pimd UMH relay must populate `show ip pim dimt umh`
and pin the (S,G) upstream's RPF (STATIC_IIF) onto the light interface with
rpf_addr = the UMH.

Withdraw semantics get their own tests: a prefix re-announced WITHOUT the
EC must act as a DEL (attribute loss, not route loss), and a full withdraw
must drop the upstream entirely.

NOTE: the tests in this module are ORDER-DEPENDENT.  Each stage mutates
BGP / route-map / interface state that the next stage builds on (and
restores what it changed for the stages after it).  In particular,
test_light_iface_delete_unpins_safely permanently deletes r2-eth2, so
every test that needs the s4 light segment must run before it.

The suite is dual-stack: the test_v6_* stages at the END of the module
exercise the IPv6 sibling of the pipeline -- a 20-byte
IPv6-address-specific UMH EC on the IPv6 Extended Communities attribute,
relayed bgpd -> zebra -> pim6d (pimd and pim6d each drop the other
family's mappings; that isolation is asserted explicitly).  The v6 leg
rides its own eBGP session over the s1 global addresses (2001:db8:1::/64)
with the v4 AF deactivated on it, so the v4 stages' single-session,
single-path state is untouched.  Because the v6 stages run after
test_light_iface_delete_unpins_safely they must not depend on the s4
segment (r2-eth2 is gone by then) and they inherit that stage's v4
mapping leftovers -- see V4_LEFTOVER_UMH.
"""

import functools
import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd, pytest.mark.pim6d]

SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"
# GROUP2 is joined via `ip igmp static-group` in r2's startup config: the
# membership is processed at config-load time, BEFORE zebra has delivered
# interface state and BEFORE BGP has delivered the UMH mapping.
GROUP2 = "232.1.1.20"
# GROUP3 is joined at runtime by test_umh_on_nonprimary_local_address: a
# FRESH group whose very first Join carries the non-primary
# upstream-neighbor address (pre-existing ifchannels would mask a
# regressed gate for the full J/P holdtime).
GROUP3 = "232.1.1.30"
SRC_PREFIX = "10.10.10.0/24"
# a broader covering prefix used by the LPM test
SRC_PREFIX16 = "10.10.0.0/16"
UMH = "10.0.0.1"

# ---- the IPv6 leg (the test_v6_* stages at the end of the module) ----
# v6 mirrors of the v4 subnets: s1 = 2001:db8:1::/64, s2 (source LAN) =
# 2001:db8:10::/64, s3 (receiver stub) = 2001:db8:20::/64, s4 =
# 2001:db8:2::/64.  All addresses below are written in the canonical
# lowercase-compressed form the JSON keys use.
SOURCE6 = "2001:db8:10::10"
GROUP6 = "ff3e::10"
SRC_PREFIX6 = "2001:db8:10::/64"
UMH6 = "2001:db8:1::1"
# What the LAST v4 stage (test_light_iface_delete_unpins_safely) leaves in
# pimd's mapping table for the v6 stages to assert family isolation
# against: it restored `redistribute connected route-map UMH` with the
# UMH moved to r1's s4 address and then deleted r2-eth2, so pimd still
# holds SRC_PREFIX -> 10.0.1.1 (interface unresolved: r2-eth2 is gone).
V4_LEFTOVER_UMH = "10.0.1.1"


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # s1: the light "tunnel" segment (carries the eBGP session too)
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

    # s4: a second light segment (r1-eth2 <-> r2-eth2).  The BGP session
    # stays on s1, so a UMH pointing at the s4 address exercises pins
    # whose interface can die while the mapping survives -- the live
    # deployment shape (BGP over the overlay, pin on the tunnel).
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
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
            TopoRouter.RD_PIM6, os.path.join(CWD, "{}/pim6d.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _json_cmd(rname, cmd):
    """vtysh JSON helper: returns None (NOT {}) on unparseable output, so
    a crashed/unresponsive daemon can never satisfy an absence-assertion
    (mapping gone, unpinned, OIF gone) vacuously -- every predicate must
    treat None as failure."""
    out = get_topogen().gears[rname].vtysh_cmd(cmd)
    try:
        return json.loads(out)
    except ValueError:
        return None


def test_bgp_converges():
    """r2 learns the source prefix over BGP (across the light segment)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _route_learned():
        data = _json_cmd("r2", "show ip route {} json".format(SRC_PREFIX))
        if data is None:
            return "r2: unparseable route JSON (zebra dead?)"
        routes = data.get(SRC_PREFIX, [])
        for rt in routes:
            if rt.get("protocol") == "bgp" and rt.get("selected"):
                return None
        return "r2 has no selected BGP route for {}: {}".format(
            SRC_PREFIX, data
        )

    _, result = topotest.run_and_expect(_route_learned, None, count=60, wait=1)
    assert result is None, result


def test_umh_mapping_relayed():
    """The UMH EC on the source route lands in pimd's mapping table with
    the light interface resolved."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _mapping_present():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        entry = data.get(SRC_PREFIX, {})
        if entry.get("umh") != UMH:
            return "r2 UMH mapping missing/wrong: {}".format(data)
        if entry.get("type") != "pim":
            return "r2 UMH type wrong: {}".format(entry)
        if entry.get("preference") != 5:
            return "r2 UMH preference wrong: {}".format(entry)
        if entry.get("interface") != "r2-eth0":
            return "r2 UMH light interface not resolved: {}".format(entry)
        return None

    _, result = topotest.run_and_expect(_mapping_present, None, count=60, wait=1)
    assert result is None, result


def test_static_group_at_boot_pins_rpf_via_umh():
    """A static-group present in the STARTUP config (processed before zebra
    interface state and before the BGP UMH mapping exist) must still end up
    Joined and pinned once that state arrives -- no config kick allowed."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _boot_static_group_pinned():
        data = _json_cmd("r2", "show ip pim upstream json")
        if data is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = data.get(GROUP2, {}).get(SOURCE, {})
        if not updata:
            return "r2 has no upstream for boot-time static-group: {}".format(
                data
            )
        if updata.get("joinState") != "Joined":
            return "r2 boot static-group upstream not Joined: {}".format(
                updata
            )
        if updata.get("inboundInterface") != "r2-eth0":
            return "r2 boot static-group RPF not on light iface: {}".format(
                updata
            )
        mroute = _json_cmd("r2", "show ip mroute json")
        if mroute is None:
            return "r2: unparseable mroute JSON (pimd dead?)"
        sgdata = mroute.get(GROUP2, {}).get(SOURCE, {})
        if "r2-eth1" not in sgdata.get("oil", {}):
            return "r2 boot static-group mroute lacks LAN OIF: {}".format(
                sgdata
            )
        return None

    _, result = topotest.run_and_expect(
        _boot_static_group_pinned, None, count=60, wait=1
    )
    assert result is None, result


def test_static_group_survives_pim_toggle():
    """Saved configs write the igmp/static-group lines BEFORE `ip pim`, so
    on (re)apply the static-group membership is refused while pim is
    disabled and the interface's first DR election has not run yet.  It
    must re-form as soon as this router becomes DR -- no config kick."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 no ip pim
"""
    )

    def _membership_torn_down():
        data = _json_cmd("r2", "show ip pim upstream json")
        if data is None:
            # a dead pimd must NOT satisfy this absence-assertion
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        if data.get(GROUP2, {}).get(SOURCE, {}).get("joinState") == "Joined":
            return "r2 GROUP2 upstream survived pim disable: {}".format(data)
        return None

    _, result = topotest.run_and_expect(_membership_torn_down, None, count=30, wait=1)
    assert result is None, result

    # re-enable in saved-config order: the igmp + static-group lines are
    # already present, `ip pim` comes last.
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ip pim
 ip pim passive
"""
    )

    def _membership_reformed():
        data = _json_cmd("r2", "show ip pim upstream json")
        if data is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = data.get(GROUP2, {}).get(SOURCE, {})
        if updata.get("joinState") != "Joined":
            return "r2 GROUP2 upstream not re-Joined after pim toggle: {}".format(
                data
            )
        if updata.get("inboundInterface") != "r2-eth0":
            return "r2 GROUP2 RPF not back on the light iface: {}".format(
                updata
            )
        mroute = _json_cmd("r2", "show ip mroute json")
        if mroute is None:
            return "r2: unparseable mroute JSON (pimd dead?)"
        sgdata = mroute.get(GROUP2, {}).get(SOURCE, {})
        if "r2-eth1" not in sgdata.get("oil", {}):
            return "r2 GROUP2 mroute lacks LAN OIF after toggle: {}".format(
                sgdata
            )
        return None

    _, result = topotest.run_and_expect(_membership_reformed, None, count=60, wait=1)
    assert result is None, result


def test_igmp_join_pins_rpf_via_umh():
    """An IGMPv3 (S,G) join drives the upstream to JOINED with a
    STATIC_IIF pin: RPF interface = the light interface facing the UMH,
    rpf address = the UMH -- with NO static route anywhere."""
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

    def _upstream_pinned():
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
        if updata.get("staticIncomingInterface") is not True:
            return "r2 upstream not STATIC_IIF-pinned: {}".format(updata)
        # the upstream-show's rpfAddress is upstream_addr (= S for SSM);
        # the actual rpf_addr (the Join's Upstream-Neighbor-Addr) shows in
        # `show ip pim rpf`.
        rpf = _json_cmd("r2", "show ip pim rpf json")
        if rpf is None:
            return "r2: unparseable pim rpf JSON (pimd dead?)"
        rpfdata = rpf.get(GROUP, {}).get(SOURCE, {})
        if rpfdata.get("rpfAddress") != UMH:
            return "r2 rpf address is not the UMH: {}".format(rpfdata)
        return None

    _, result = topotest.run_and_expect(_upstream_pinned, None, count=60, wait=1)
    assert result is None, result

    # and the neighborless Join must have reached r1 (synthetic neighbor)
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
    assert result is None, result


def test_r1_not_self_pinned_and_forwarding():
    """r1 (the UMH itself) must IGNORE its own echoed-back mapping: its
    (S,G) IIF stays the source LAN, OIF the light interface, and traffic
    natively forwards through both kernel MFCs."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _r1_mroute():
        data = _json_cmd("r1", "show ip mroute json")
        if data is None:
            return "r1: unparseable mroute JSON (pimd dead?)"
        sgdata = data.get(GROUP, {}).get(SOURCE, {})
        if not sgdata:
            return "r1 has no (S,G) mroute yet: {}".format(data)
        if sgdata.get("iif") != "r1-eth1":
            return (
                "r1 (S,G) IIF is not the source LAN (self-pin bug?): "
                "{}".format(sgdata)
            )
        oil = sgdata.get("oil", {})
        if "r1-eth0" not in oil:
            return "r1 (S,G) OIL lacks the light interface: {}".format(sgdata)
        return None

    _, result = topotest.run_and_expect(_r1_mroute, None, count=60, wait=1)
    assert result is None, result

    mcast_tester = os.path.join(CWD, "../lib/mcast-tester.py")
    sender = tgen.gears["h1"].popen(
        [mcast_tester, GROUP, "h1-eth0", "--send", "0.7"]
    )
    logger.info("started sender on h1: %s -> %s", SOURCE, GROUP)
    try:

        def _counts(rname):
            data = _json_cmd(rname, "show ip mroute count json")
            if data is None:
                return "{}: unparseable mroute count JSON (pimd dead?)".format(
                    rname
                )
            sgdata = data.get(GROUP, {}).get(SOURCE, {})
            pkts = sgdata.get("packets", 0)
            if pkts <= 0:
                return "{}: no packets counted for ({}, {}): {}".format(
                    rname, SOURCE, GROUP, sgdata
                )
            return None

        for rname in ("r1", "r2"):
            test_func = functools.partial(_counts, rname)
            _, result = topotest.run_and_expect(
                test_func, None, count=60, wait=1
            )
            assert result is None, result
    finally:
        sender.terminate()


def test_ec_removal_acts_as_del():
    """The same prefix re-announced WITHOUT the UMH EC must clear the
    mapping and unpin the upstream (attribute loss == DEL). The upstream
    itself survives on normal light-interface RPF via the remaining BGP
    route."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 no set extcommunity umh
"""
    )

    def _mapping_gone():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            # a dead pimd must NOT satisfy this absence-assertion
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        if SRC_PREFIX in data:
            return "r2 UMH mapping survived EC removal: {}".format(data)
        return None

    _, result = topotest.run_and_expect(_mapping_gone, None, count=90, wait=1)
    assert result is None, result

    def _upstream_unpinned_but_alive():
        data = _json_cmd("r2", "show ip pim upstream json")
        if data is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if updata.get("staticIncomingInterface") is not False:
            return "r2 upstream still STATIC_IIF-pinned: {}".format(updata)
        if updata.get("joinState") != "Joined":
            return (
                "r2 upstream did not survive on normal light RPF: {}".format(
                    updata
                )
            )
        if updata.get("inboundInterface") != "r2-eth0":
            return "r2 upstream RPF left the light interface: {}".format(
                updata
            )
        return None

    _, result = topotest.run_and_expect(
        _upstream_unpinned_but_alive, None, count=60, wait=1
    )
    assert result is None, result


def test_ec_reappears_repins():
    """Putting the EC back re-populates the mapping and re-pins the
    existing upstream."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 set extcommunity umh {} pim preference 5
""".format(UMH)
    )

    def _repinned():
        data = _json_cmd("r2", "show ip pim upstream json")
        if data is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if updata.get("staticIncomingInterface") is not True:
            return "r2 upstream not re-pinned: {}".format(updata)
        rpf = _json_cmd("r2", "show ip pim rpf json")
        if rpf is None:
            return "r2: unparseable pim rpf JSON (pimd dead?)"
        rpfdata = rpf.get(GROUP, {}).get(SOURCE, {})
        if rpfdata.get("rpfAddress") != UMH:
            return "r2 rpf address is not the UMH: {}".format(rpfdata)
        return None

    _, result = topotest.run_and_expect(_repinned, None, count=90, wait=1)
    assert result is None, result


def test_amt_relay_mapping_does_not_pin():
    """An amt-relay-type UMH mapping is recorded and displayed but must
    NOT steer PIM RPF (only pim-type mappings drive joins).  Switching
    the type in place exercises the upsert path: pim -> amt-relay must
    UNPIN the existing upstream, amt-relay -> pim must re-pin."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 set extcommunity umh {} amt-relay preference 5
""".format(UMH)
    )

    def _amt_mapping_no_pin():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        entry = data.get(SRC_PREFIX, {})
        if entry.get("type") != "amt-relay":
            return "r2 mapping is not amt-relay yet: {}".format(data)
        ups = _json_cmd("r2", "show ip pim upstream json")
        if ups is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = ups.get(GROUP, {}).get(SOURCE, {})
        if updata.get("staticIncomingInterface") is not False:
            return "r2 upstream pinned by an amt-relay mapping: {}".format(
                updata
            )
        return None

    _, result = topotest.run_and_expect(
        _amt_mapping_no_pin, None, count=90, wait=1
    )
    assert result is None, result

    # back to pim type: the pin must return
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 set extcommunity umh {} pim preference 5
""".format(UMH)
    )

    def _repinned_after_amt():
        data = _json_cmd("r2", "show ip pim upstream json")
        if data is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if updata.get("staticIncomingInterface") is not True:
            return "r2 upstream not re-pinned after amt->pim: {}".format(
                updata
            )
        return None

    _, result = topotest.run_and_expect(
        _repinned_after_amt, None, count=90, wait=1
    )
    assert result is None, result


def test_light_iface_flap_repins():
    """A light interface disappearing and coming back (the reconciler's
    recreate lifecycle) must re-pin existing upstreams: iface down ->
    unpin; iface up -> the mapping resolves again and the pin re-forms
    without any mapping or config churn."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # move the UMH to r1's s4 address so the pin rides r2-eth2 while
    # BGP (and the mapping) stay on r2-eth0.
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 set extcommunity umh 10.0.1.1 pim preference 5
"""
    )

    def _pinned_to(iface):
        def check():
            data = _json_cmd("r2", "show ip pim upstream json")
            if data is None:
                return "r2: unparseable pim upstream JSON (pimd dead?)"
            updata = data.get(GROUP, {}).get(SOURCE, {})
            if updata.get("staticIncomingInterface") is not True:
                return "r2 upstream not pinned: {}".format(updata)
            if updata.get("inboundInterface") != iface:
                return "r2 upstream not pinned to {}: {}".format(
                    iface, updata
                )
            return None

        return check

    _, result = topotest.run_and_expect(
        _pinned_to("r2-eth2"), None, count=90, wait=1
    )
    assert result is None, result

    tgen.gears["r2"].run("ip link set r2-eth2 down")

    def _unpinned_from_eth2():
        data = _json_cmd("r2", "show ip pim upstream json")
        if data is None:
            # a dead pimd must NOT satisfy this absence-assertion
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if (
            updata.get("staticIncomingInterface") is True
            and updata.get("inboundInterface") == "r2-eth2"
        ):
            return "r2 upstream still pinned to downed iface: {}".format(
                updata
            )
        return None

    _, result = topotest.run_and_expect(
        _unpinned_from_eth2, None, count=30, wait=1
    )
    assert result is None, result

    tgen.gears["r2"].run("ip link set r2-eth2 up")

    _, result = topotest.run_and_expect(
        _pinned_to("r2-eth2"), None, count=60, wait=1
    )
    assert result is None, result

    # restore the UMH to the s1 address for the tests that follow
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 set extcommunity umh {} pim preference 5
""".format(UMH)
    )

    _, result = topotest.run_and_expect(
        _pinned_to("r2-eth0"), None, count=60, wait=1
    )
    assert result is None, result


def test_lpm_and_shorter_mapping_fallback():
    """Overlapping mappings: the /24's UMH (s1 segment) must win over a
    covering /16 (s4 UMH) by longest prefix match, and removing the /24's
    EC must fall the pin back to the covering /16's UMH and interface --
    the 'another, shorter mapping may still cover it' DEL path."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # announce a covering /16 whose UMH lives on the OTHER light segment
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH16 permit 10
 set extcommunity umh 10.0.1.1 pim preference 5
exit
router bgp 65001
 no bgp network import-check
 address-family ipv4 unicast
  network {} route-map UMH16
""".format(SRC_PREFIX16)
    )

    def _lpm_pin_holds():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        if data.get(SRC_PREFIX16, {}).get("umh") != "10.0.1.1":
            return "r2 /16 mapping not relayed: {}".format(data)
        if data.get(SRC_PREFIX, {}).get("umh") != UMH:
            return "r2 /24 mapping missing: {}".format(data)
        ups = _json_cmd("r2", "show ip pim upstream json")
        if ups is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = ups.get(GROUP, {}).get(SOURCE, {})
        if updata.get("inboundInterface") != "r2-eth0":
            return "LPM violated: pin left the /24's interface: {}".format(
                updata
            )
        rpf = _json_cmd("r2", "show ip pim rpf json")
        if rpf is None:
            return "r2: unparseable pim rpf JSON (pimd dead?)"
        if rpf.get(GROUP, {}).get(SOURCE, {}).get("rpfAddress") != UMH:
            return "LPM violated: rpf is not the /24's UMH: {}".format(rpf)
        return None

    _, result = topotest.run_and_expect(_lpm_pin_holds, None, count=90, wait=1)
    assert result is None, result

    # drop the /24's EC: the source must FALL BACK to the covering /16
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 no set extcommunity umh
"""
    )

    def _fell_back_to_16():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            # a dead pimd must NOT satisfy this absence-assertion
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        if SRC_PREFIX in data:
            return "r2 /24 mapping survived EC removal: {}".format(data)
        ups = _json_cmd("r2", "show ip pim upstream json")
        if ups is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = ups.get(GROUP, {}).get(SOURCE, {})
        if updata.get("inboundInterface") != "r2-eth2":
            return "no fallback to the covering /16's interface: {}".format(
                updata
            )
        rpf = _json_cmd("r2", "show ip pim rpf json")
        if rpf is None:
            return "r2: unparseable pim rpf JSON (pimd dead?)"
        if rpf.get(GROUP, {}).get(SOURCE, {}).get("rpfAddress") != "10.0.1.1":
            return "no fallback to the covering /16's UMH: {}".format(rpf)
        return None

    _, result = topotest.run_and_expect(_fell_back_to_16, None, count=90, wait=1)
    assert result is None, result

    # restore: /24 EC back, /16 announcement gone
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 set extcommunity umh {} pim preference 5
exit
router bgp 65001
 address-family ipv4 unicast
  no network {}
exit
exit
no route-map UMH16
""".format(UMH, SRC_PREFIX16)
    )

    def _restored_to_24():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        if SRC_PREFIX16 in data:
            return "r2 /16 mapping survived its withdraw: {}".format(data)
        ups = _json_cmd("r2", "show ip pim upstream json")
        if ups is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = ups.get(GROUP, {}).get(SOURCE, {})
        if updata.get("inboundInterface") != "r2-eth0":
            return "pin did not return to the /24's interface: {}".format(
                updata
            )
        return None

    _, result = topotest.run_and_expect(_restored_to_24, None, count=90, wait=1)
    assert result is None, result


def test_umh_on_nonprimary_local_address():
    """RFC 9739 allows a Join's Upstream-Neighbor-Address to be ANY local
    address of the target router, not just the receiving interface's
    primary.  Advertise a secondary r1-eth0 address as the UMH and drive
    a FRESH group's first join against it: if the any-local-address gate
    on r1 regressed, that join is silently dropped and no OIF ever forms
    (production tunnels use exactly this shape -- the UMH is never the
    interface primary)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].run("ip addr add 10.0.0.100/24 dev r1-eth0")
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 set extcommunity umh 10.0.0.100 pim preference 5
"""
    )

    # a fresh group so its very FIRST join carries the non-primary
    # upstream address (a pre-existing ifchannel would mask a regressed
    # gate until the next full J/P refresh)
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ip igmp join-group {} {}
""".format(GROUP3, SOURCE)
    )

    def _join_accepted_on_r1():
        rpf = _json_cmd("r2", "show ip pim rpf json")
        if rpf is None:
            return "r2: unparseable pim rpf JSON (pimd dead?)"
        rpfdata = rpf.get(GROUP3, {}).get(SOURCE, {})
        if rpfdata.get("rpfAddress") != "10.0.0.100":
            return "r2 rpf is not the non-primary UMH: {}".format(rpfdata)
        data = _json_cmd("r1", "show ip mroute json")
        if data is None:
            return "r1: unparseable mroute JSON (pimd dead?)"
        sgdata = data.get(GROUP3, {}).get(SOURCE, {})
        if "r1-eth0" not in sgdata.get("oil", {}):
            return (
                "r1 mroute lacks the light OIF -- join with a non-primary "
                "upstream address rejected? {}".format(sgdata)
            )
        return None

    _, result = topotest.run_and_expect(
        _join_accepted_on_r1, None, count=90, wait=1
    )
    assert result is None, result

    # cleanup: drop the fresh group, restore the UMH, remove the secondary
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 no ip igmp join-group {} {}
""".format(GROUP3, SOURCE)
    )
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 set extcommunity umh {} pim preference 5
""".format(UMH)
    )
    tgen.gears["r1"].run("ip addr del 10.0.0.100/24 dev r1-eth0")

    def _restored_primary_umh():
        rpf = _json_cmd("r2", "show ip pim rpf json")
        if rpf is None:
            return "r2: unparseable pim rpf JSON (pimd dead?)"
        if rpf.get(GROUP, {}).get(SOURCE, {}).get("rpfAddress") != UMH:
            return "r2 rpf did not return to the primary UMH: {}".format(rpf)
        return None

    _, result = topotest.run_and_expect(
        _restored_primary_umh, None, count=90, wait=1
    )
    assert result is None, result


def test_no_pim_light_unpins_safely():
    """`no ip pim light` on the pinned interface is the CONFIG analog of
    the link-delete crash: STATIC_IIF suppresses every rpf-update repair
    path, so the disable hook must unpin (and delete the synthetic light
    neighbors) or the join timer fires on a dangling pin.  Re-enabling
    must re-pin with zero mapping churn.

    Ordering matters: the synthetic-neighbor-deletion assert on r1 runs
    FIRST, while r2-eth2 is still light and the s4 wire carries only
    Join/Prune.  Once either end goes non-light it starts periodic
    hellos, and the peer then holds a REAL hello-based neighbor
    (holdTimeMax 105) that `no ip pim light` must NOT delete -- checking
    the r1 side after the r2 side would observe exactly that neighbor
    and fail on a correct implementation."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # move the pin onto the s4 segment; BGP and the mapping stay on s1
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 set extcommunity umh 10.0.1.1 pim preference 5
"""
    )

    def _pinned_to(iface):
        def check():
            data = _json_cmd("r2", "show ip pim upstream json")
            if data is None:
                return "r2: unparseable pim upstream JSON (pimd dead?)"
            updata = data.get(GROUP, {}).get(SOURCE, {})
            if updata.get("staticIncomingInterface") is not True:
                return "r2 upstream not pinned: {}".format(updata)
            if updata.get("inboundInterface") != iface:
                return "r2 upstream not pinned to {}: {}".format(
                    iface, updata
                )
            return None

        return check

    _, result = topotest.run_and_expect(
        _pinned_to("r2-eth2"), None, count=90, wait=1
    )
    assert result is None, result

    # r1-side: `no ip pim light` must DELETE the synthetic (L) neighbor
    # that r2's joins materialized on r1-eth2, not leave it to linger.
    def _r1_has_synthetic_neighbor():
        neigh = _json_cmd("r1", "show ip pim neighbor json")
        if neigh is None:
            return "r1: unparseable pim neighbor JSON (pimd dead?)"
        nbr = neigh.get("r1-eth2", {}).get("10.0.1.2")
        if not nbr:
            return "r1 has no neighbor 10.0.1.2 on r1-eth2: {}".format(neigh)
        if nbr.get("light") is not True:
            return "r1 neighbor 10.0.1.2 is not synthetic/light: {}".format(
                nbr
            )
        return None

    _, result = topotest.run_and_expect(
        _r1_has_synthetic_neighbor, None, count=90, wait=1
    )
    assert result is None, result

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
interface r1-eth2
 no ip pim light
"""
    )

    def _r1_light_neighbor_deleted():
        neigh = _json_cmd("r1", "show ip pim neighbor json")
        if neigh is None:
            # a dead pimd must NOT satisfy this absence-assertion
            return "r1: unparseable pim neighbor JSON (pimd dead?)"
        # r2 is still light (never hellos) and r2's J/P is now rejected
        # on the non-light r1-eth2, so NOTHING may re-create 10.0.1.2
        if "10.0.1.2" in neigh.get("r1-eth2", {}):
            return "r1 synthetic neighbor survived light disable: {}".format(
                neigh.get("r1-eth2")
            )
        return None

    _, result = topotest.run_and_expect(
        _r1_light_neighbor_deleted, None, count=10, wait=1
    )
    assert result is None, result

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
interface r1-eth2
 ip pim light
"""
    )

    # r2-side: disable light under the pinned, Joined upstream
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth2
 no ip pim light
"""
    )
    logger.info("disabled ip pim light under a pinned Joined upstream")

    def _unpinned_mapping_survives():
        out = tgen.gears["r2"].vtysh_cmd("show ip pim upstream json")
        try:
            data = json.loads(out)
        except ValueError:
            return "r2 pimd unresponsive (crashed?): {}".format(out[:200])
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if (
            updata.get("staticIncomingInterface") is True
            and updata.get("inboundInterface") == "r2-eth2"
        ):
            return "r2 upstream still pinned to the no-light iface: {}".format(
                updata
            )
        mapping = _json_cmd("r2", "show ip pim dimt umh json")
        if mapping is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        if SRC_PREFIX not in mapping:
            return "UMH mapping unexpectedly gone (test premise broken): {}".format(
                mapping
            )
        return None

    _, result = topotest.run_and_expect(
        _unpinned_mapping_survives, None, count=30, wait=1
    )
    assert result is None, result

    # the join timer period is 60s: outlast it to prove nothing fires on
    # a dangling pin.
    time.sleep(65)
    out = tgen.gears["r2"].vtysh_cmd("show ip pim upstream json")
    try:
        json.loads(out)
    except ValueError:
        assert False, "r2 pimd died after join-timer period: {}".format(
            out[:200]
        )

    # re-enable on r2: the pin must return with zero mapping churn
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth2
 ip pim light
"""
    )

    _, result = topotest.run_and_expect(
        _pinned_to("r2-eth2"), None, count=60, wait=1
    )
    assert result is None, result

    # restore the UMH to the s1 address
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 set extcommunity umh {} pim preference 5
""".format(UMH)
    )

    _, result = topotest.run_and_expect(
        _pinned_to("r2-eth0"), None, count=60, wait=1
    )
    assert result is None, result

    if tgen.routers_have_failure():
        assert False, "router failure after pim light toggle: {}".format(
            tgen.errors
        )


def test_pimd_restart_replays_umh():
    """pimd restart with ZERO BGP churn: the whole
    subscribe -> zebra relay -> bgpd shadow-table replay axis must
    repopulate the UMH table and re-pin the config-file static-group.
    Without replay-from-shadow a restarted pimd runs with an empty table
    until the next route flap.

    Only GROUP2 (the pimd.conf static-group) survives the restart: the
    restart deliberately uses save_config=False so pimd boots from the
    pristine pimd.conf.  (save_config's `write memory` would bake the
    runtime `ip igmp join-group` into the loaded config, and a
    boot-time join-group fails its kernel socket join before the
    interface is usable and never retries -- an upstream-inherited
    boot-order gap in the join-group path, distinct from the
    static-group replay this branch fixed; re-applying the identical
    config line afterwards is then a northbound no-op.)  The runtime
    join for GROUP is re-added fresh afterwards -- which doubles as
    proof that memberships arriving AFTER the replay pin against the
    replayed table."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    kill_router_daemons(tgen, "r2", ["pimd"], save_config=False)
    start_router_daemons(tgen, "r2", ["pimd"])

    def _replayed_and_static_group_repinned():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        if data.get(SRC_PREFIX, {}).get("umh") != UMH:
            return "r2 UMH mapping not replayed after restart: {}".format(
                data
            )
        ups = _json_cmd("r2", "show ip pim upstream json")
        if ups is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = ups.get(GROUP2, {}).get(SOURCE, {})
        if updata.get("joinState") != "Joined":
            return "r2 static-group upstream not re-Joined after restart: {}".format(
                updata
            )
        if updata.get("inboundInterface") != "r2-eth0":
            return "r2 static-group upstream not re-pinned after restart: {}".format(
                updata
            )
        rpf = _json_cmd("r2", "show ip pim rpf json")
        if rpf is None:
            return "r2: unparseable pim rpf JSON (pimd dead?)"
        if rpf.get(GROUP2, {}).get(SOURCE, {}).get("rpfAddress") != UMH:
            return "r2 rpf is not the UMH after restart: {}".format(rpf)
        return None

    _, result = topotest.run_and_expect(
        _replayed_and_static_group_repinned, None, count=120, wait=1
    )
    assert result is None, result

    # re-apply the runtime membership lost across the restart: a NEW
    # join must pin against the REPLAYED table (and the tests that
    # follow depend on GROUP being Joined again)
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ip igmp join-group {} {}
""".format(GROUP, SOURCE)
    )

    def _new_join_pins_from_replayed_table():
        ups = _json_cmd("r2", "show ip pim upstream json")
        if ups is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = ups.get(GROUP, {}).get(SOURCE, {})
        if updata.get("joinState") != "Joined":
            return "r2 re-joined upstream not Joined: {}".format(updata)
        if updata.get("inboundInterface") != "r2-eth0":
            return "r2 re-joined upstream not pinned via the replayed mapping: {}".format(
                updata
            )
        return None

    _, result = topotest.run_and_expect(
        _new_join_pins_from_replayed_table, None, count=60, wait=1
    )
    assert result is None, result


def test_withdraw_drops_upstream():
    """A full route withdraw clears the mapping AND the upstream's RPF
    (nothing left to resolve against)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
router bgp 65001
 address-family ipv4 unicast
  no redistribute connected route-map UMH
"""
    )

    def _mapping_and_rpf_gone():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            # a dead pimd must NOT satisfy this absence-assertion
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        if SRC_PREFIX in data:
            return "r2 UMH mapping survived withdraw: {}".format(data)
        data = _json_cmd("r2", "show ip pim upstream json")
        if data is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if updata and updata.get("joinState") == "Joined":
            return "r2 upstream still Joined after withdraw: {}".format(updata)
        return None

    _, result = topotest.run_and_expect(
        _mapping_and_rpf_gone, None, count=90, wait=1
    )
    assert result is None, result


def test_light_iface_delete_unpins_safely():
    """Deleting the light interface out from under a pinned, Joined
    upstream -- while the UMH mapping SURVIVES (BGP rides another
    interface, as live) -- must unpin it.  STATIC_IIF suppresses every
    rpf-update repair path, so without the ifdown hook the join timer
    fires on a freed interface and pimd segfaults (seen live)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # restore the announcement withdrawn by the previous test, but with
    # the UMH moved to r1's s4 address: the pin lands on r2-eth2 while
    # BGP (and the mapping) stay alive on r2-eth0.
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH permit 10
 set extcommunity umh 10.0.1.1 pim preference 5
exit
router bgp 65001
 address-family ipv4 unicast
  redistribute connected route-map UMH
"""
    )

    def _pinned_on_s4():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        entry = data.get(SRC_PREFIX, {})
        if entry.get("interface") != "r2-eth2":
            return "r2 UMH not resolved on the s4 light iface: {}".format(
                data
            )
        data = _json_cmd("r2", "show ip pim upstream json")
        if data is None:
            return "r2: unparseable pim upstream JSON (pimd dead?)"
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if updata.get("joinState") != "Joined":
            return "r2 upstream not re-Joined: {}".format(updata)
        if updata.get("staticIncomingInterface") is not True:
            return "r2 upstream not pinned: {}".format(updata)
        if updata.get("inboundInterface") != "r2-eth2":
            return "r2 upstream not pinned to r2-eth2: {}".format(updata)
        return None

    _, result = topotest.run_and_expect(_pinned_on_s4, None, count=90, wait=1)
    assert result is None, result

    tgen.gears["r2"].run("ip link del r2-eth2")
    logger.info("deleted r2-eth2 under a pinned Joined upstream")

    def _unpinned_and_alive():
        out = tgen.gears["r2"].vtysh_cmd("show ip pim upstream json")
        try:
            data = json.loads(out)
        except ValueError:
            return "r2 pimd unresponsive (crashed?): {}".format(out[:200])
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if (
            updata.get("staticIncomingInterface") is True
            and updata.get("inboundInterface") == "r2-eth2"
        ):
            return "r2 upstream still pinned to deleted iface: {}".format(
                updata
            )
        # the mapping survives (BGP is on r2-eth0): verify it did
        mapping = _json_cmd("r2", "show ip pim dimt umh json")
        if mapping is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        if SRC_PREFIX not in mapping:
            return "UMH mapping unexpectedly gone (test premise broken): {}".format(
                mapping
            )
        return None

    _, result = topotest.run_and_expect(
        _unpinned_and_alive, None, count=30, wait=1
    )
    assert result is None, result

    # the join timer period is 60s: outlast it to prove nothing fires on
    # a stale interface pointer.
    time.sleep(65)
    out = tgen.gears["r2"].vtysh_cmd("show ip pim upstream json")
    try:
        json.loads(out)
    except ValueError:
        assert False, "r2 pimd died after join-timer period: {}".format(
            out[:200]
        )

    if tgen.routers_have_failure():
        assert False, "router failure after light-iface delete: {}".format(
            tgen.errors
        )


def test_v6_umh_mapping_relayed():
    """The v6 sibling of test_umh_mapping_relayed: a v6 unicast route
    announced with `set extcommunity umh <v6-addr> pim preference 5` (a
    20-byte IPv6-address-specific EC on the IPv6 Extended Communities
    attribute) must land in pim6d's mapping table with the light interface
    resolved -- and in pim6d's table ONLY (pimd drops non-v4 mappings).
    The EC itself must render on r2's received path as
    "UMH:<v6>:pim:5" under extendedIpv6Community.

    Runs at the END of the module: r2-eth2 is already gone, so the whole
    v6 leg lives on the s1 segment."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _v6_route_learned():
        data = _json_cmd("r2", "show ipv6 route {} json".format(SRC_PREFIX6))
        if data is None:
            return "r2: unparseable v6 route JSON (zebra dead?)"
        routes = data.get(SRC_PREFIX6, [])
        for rt in routes:
            if rt.get("protocol") == "bgp" and rt.get("selected"):
                return None
        return "r2 has no selected BGP route for {}: {}".format(
            SRC_PREFIX6, data
        )

    _, result = topotest.run_and_expect(_v6_route_learned, None, count=60, wait=1)
    assert result is None, result

    def _v6_mapping_present():
        data = _json_cmd("r2", "show ipv6 pim dimt umh json")
        if data is None:
            return "r2: unparseable v6 dimt umh JSON (pim6d dead?)"
        entry = data.get(SRC_PREFIX6, {})
        if entry.get("umh") != UMH6:
            return "r2 v6 UMH mapping missing/wrong: {}".format(data)
        if entry.get("type") != "pim":
            return "r2 v6 UMH type wrong: {}".format(entry)
        if entry.get("preference") != 5:
            return "r2 v6 UMH preference wrong: {}".format(entry)
        if entry.get("interface") != "r2-eth0":
            return "r2 v6 UMH light interface not resolved: {}".format(entry)
        # family isolation, leak direction: pim6d holds the v6 mapping,
        # pimd must NOT (both daemons subscribe as ZEBRA_ROUTE_PIM and
        # each drops the other family's relays).
        v4data = _json_cmd("r2", "show ip pim dimt umh json")
        if v4data is None:
            return "r2: unparseable v4 dimt umh JSON (pimd dead?)"
        if SRC_PREFIX6 in v4data:
            return "v6 mapping leaked into pimd's v4 table: {}".format(
                v4data
            )
        return None

    _, result = topotest.run_and_expect(_v6_mapping_present, None, count=60, wait=1)
    assert result is None, result

    def _v6_ec_rendered():
        data = _json_cmd(
            "r2", "show bgp ipv6 unicast {} json".format(SRC_PREFIX6)
        )
        if data is None:
            return "r2: unparseable bgp ipv6 unicast JSON (bgpd dead?)"
        paths = data.get("paths", [])
        if not paths:
            return "r2 has no BGP paths for {}: {}".format(SRC_PREFIX6, data)
        want = "UMH:{}:pim:5".format(UMH6)
        for path in paths:
            ecstr = path.get("extendedIpv6Community", {}).get("string", "")
            if want in ecstr:
                return None
        return "no r2 path for {} carries '{}': {}".format(
            SRC_PREFIX6, want, paths
        )

    _, result = topotest.run_and_expect(_v6_ec_rendered, None, count=60, wait=1)
    assert result is None, result


def test_v6_mld_join_pins_rpf():
    """The v6 sibling of test_igmp_join_pins_rpf_via_umh: a real MLDv2
    (S,G) join on r2's LAN drives the v6 upstream to JOINED with a
    STATIC_IIF pin -- RPF interface = the light interface facing the v6
    UMH, rpf address = the UMH -- with NO static route and NO v6 PIM
    adjacency anywhere.  The neighborless Join must materialize a
    synthetic light neighbor on r1; PIMv6 J/P is sourced from r2-eth0's
    link-local (not predictable from config), so the r1 assertion scans
    r1-eth0's neighbors for the light flag instead of a literal address."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ipv6 mld join-group {} {}
""".format(GROUP6, SOURCE6)
    )

    def _v6_upstream_pinned():
        data = _json_cmd("r2", "show ipv6 pim upstream json")
        if data is None:
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        updata = data.get(GROUP6, {}).get(SOURCE6, {})
        if updata.get("joinState") != "Joined":
            return "r2 v6 upstream not Joined: {}".format(updata)
        if updata.get("inboundInterface") != "r2-eth0":
            return "r2 v6 upstream RPF not on the light interface: {}".format(
                updata
            )
        if updata.get("staticIncomingInterface") is not True:
            return "r2 v6 upstream not STATIC_IIF-pinned: {}".format(updata)
        rpf = _json_cmd("r2", "show ipv6 pim rpf json")
        if rpf is None:
            return "r2: unparseable v6 pim rpf JSON (pim6d dead?)"
        rpfdata = rpf.get(GROUP6, {}).get(SOURCE6, {})
        if rpfdata.get("rpfAddress") != UMH6:
            return "r2 v6 rpf address is not the UMH: {}".format(rpfdata)
        return None

    # MLD/PIMv6 convergence can lag IGMP: give it the longer leash
    _, result = topotest.run_and_expect(_v6_upstream_pinned, None, count=90, wait=1)
    assert result is None, result

    def _v6_synthetic_neighbor():
        neigh = _json_cmd("r1", "show ipv6 pim neighbor json")
        if neigh is None:
            return "r1: unparseable v6 pim neighbor JSON (pim6d dead?)"
        for nbr in neigh.get("r1-eth0", {}).values():
            if nbr.get("light") is True:
                return None
        return "r1 has no synthetic light neighbor on r1-eth0: {}".format(
            neigh
        )

    _, result = topotest.run_and_expect(
        _v6_synthetic_neighbor, None, count=90, wait=1
    )
    assert result is None, result


def test_v6_ec_removal_acts_as_del():
    """The v6 sibling of test_ec_removal_acts_as_del, doubling as the
    family-isolation proof: the v6 prefix re-announced WITHOUT the UMH EC
    (route survives) must clear the v6 mapping and unpin the v6 upstream
    while pimd's v4 mapping -- whatever the v4 stages left behind -- stays
    untouched.  Restoring the set must bring the v6 mapping back and
    re-pin the still-Joined upstream.

    The v4 leftover asserted against is documented at V4_LEFTOVER_UMH:
    SRC_PREFIX -> 10.0.1.1, alive in pimd's table since
    test_light_iface_delete_unpins_safely."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH6 permit 10
 no set extcommunity umh
"""
    )

    def _v6_mapping_gone_v4_untouched():
        data = _json_cmd("r2", "show ipv6 pim dimt umh json")
        if data is None:
            # a dead pim6d must NOT satisfy this absence-assertion
            return "r2: unparseable v6 dimt umh JSON (pim6d dead?)"
        if SRC_PREFIX6 in data:
            return "r2 v6 UMH mapping survived EC removal: {}".format(data)
        # family isolation, delete direction: the v6 DEL must not have
        # touched pimd's v4 table.
        v4data = _json_cmd("r2", "show ip pim dimt umh json")
        if v4data is None:
            return "r2: unparseable v4 dimt umh JSON (pimd dead?)"
        if v4data.get(SRC_PREFIX, {}).get("umh") != V4_LEFTOVER_UMH:
            return "v4 mapping disturbed by the v6 DEL: {}".format(v4data)
        # the v6 upstream must have unpinned (attribute loss == DEL) but
        # survive on its MLD membership.
        ups = _json_cmd("r2", "show ipv6 pim upstream json")
        if ups is None:
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        updata = ups.get(GROUP6, {}).get(SOURCE6, {})
        if updata.get("staticIncomingInterface") is not False:
            return "r2 v6 upstream still STATIC_IIF-pinned: {}".format(
                updata
            )
        return None

    _, result = topotest.run_and_expect(
        _v6_mapping_gone_v4_untouched, None, count=90, wait=1
    )
    assert result is None, result

    # restore the set: the v6 mapping must return and re-pin
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map UMH6 permit 10
 set extcommunity umh {} pim preference 5
""".format(UMH6)
    )

    def _v6_mapping_back_and_repinned():
        data = _json_cmd("r2", "show ipv6 pim dimt umh json")
        if data is None:
            return "r2: unparseable v6 dimt umh JSON (pim6d dead?)"
        entry = data.get(SRC_PREFIX6, {})
        if entry.get("umh") != UMH6:
            return "r2 v6 UMH mapping did not return: {}".format(data)
        if entry.get("type") != "pim" or entry.get("preference") != 5:
            return "r2 v6 UMH mapping returned wrong: {}".format(entry)
        if entry.get("interface") != "r2-eth0":
            return "r2 v6 UMH light interface not resolved: {}".format(entry)
        ups = _json_cmd("r2", "show ipv6 pim upstream json")
        if ups is None:
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        updata = ups.get(GROUP6, {}).get(SOURCE6, {})
        if updata.get("staticIncomingInterface") is not True:
            return "r2 v6 upstream not re-pinned: {}".format(updata)
        rpf = _json_cmd("r2", "show ipv6 pim rpf json")
        if rpf is None:
            return "r2: unparseable v6 pim rpf JSON (pim6d dead?)"
        if rpf.get(GROUP6, {}).get(SOURCE6, {}).get("rpfAddress") != UMH6:
            return "r2 v6 rpf address is not the UMH: {}".format(rpf)
        # and the v4 leftover is STILL intact after the v6 re-add
        v4data = _json_cmd("r2", "show ip pim dimt umh json")
        if v4data is None:
            return "r2: unparseable v4 dimt umh JSON (pimd dead?)"
        if v4data.get(SRC_PREFIX, {}).get("umh") != V4_LEFTOVER_UMH:
            return "v4 mapping disturbed by the v6 re-add: {}".format(
                v4data
            )
        return None

    _, result = topotest.run_and_expect(
        _v6_mapping_back_and_repinned, None, count=90, wait=1
    )
    assert result is None, result


def test_v6_join_group_pim_toggle_leaves_cleanly():
    """The v6 sibling of test_static_group_survives_pim_toggle, plus the
    leave-side regression it exposed: saved configs write the mld +
    join-group lines BEFORE `ipv6 pim`, so on (re)apply the sg's TIB join
    is refused while pim is disabled ("PIM is not configured on this
    interface").  pim_if_membership_refresh() used to feed such
    not-yet-joined sgs straight into pim_ifchannel_local_membership_add()
    when `ipv6 pim` came back -- bypassing tib_sg_gm_join(), so
    sg->tib_joined stayed false, every later gm_sg_update() join retry
    failed on the duplicate-oif check, and removing the join-group
    skipped the prune: the INCLUDE membership (and with it the oif and
    the upstream) was stranded until pim6d restarted, immune even to
    join-group add/remove cycles."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 no ipv6 pim
"""
    )

    def _v6_membership_torn_down():
        data = _json_cmd("r2", "show ipv6 pim upstream json")
        if data is None:
            # a dead pim6d must NOT satisfy this absence-assertion
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        if data.get(GROUP6, {}).get(SOURCE6, {}).get("joinState") == "Joined":
            return "r2 v6 upstream survived pim disable: {}".format(data)
        return None

    _, result = topotest.run_and_expect(
        _v6_membership_torn_down, None, count=30, wait=1
    )
    assert result is None, result

    # re-enable in saved-config order: the mld + join-group lines are
    # already present, `ipv6 pim` comes last, so membership_refresh runs
    # against a live-but-unjoined sg.  The clear nudges the querier so
    # the kernel's join-group socket re-reports promptly instead of
    # waiting out a general query interval.
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ipv6 pim
"""
    )
    tgen.gears["r2"].vtysh_cmd("clear ipv6 mld interfaces")

    def _v6_membership_reformed():
        data = _json_cmd("r2", "show ipv6 pim local-membership json")
        if data is None:
            return "r2: unparseable v6 local-membership JSON (pim6d dead?)"
        row = data.get("r2-eth1", {}).get(GROUP6, {})
        if row.get("localMembership") != "INCLUDE":
            return "r2 v6 local membership not re-formed: {}".format(data)
        ups = _json_cmd("r2", "show ipv6 pim upstream json")
        if ups is None:
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        if ups.get(GROUP6, {}).get(SOURCE6, {}).get("joinState") != "Joined":
            return "r2 v6 upstream not re-Joined after pim toggle: {}".format(
                ups
            )
        return None

    _, result = topotest.run_and_expect(
        _v6_membership_reformed, None, count=90, wait=1
    )
    assert result is None, result

    # THE regression: removing the join-group must tear everything down.
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 no ipv6 mld join-group {} {}
""".format(GROUP6, SOURCE6)
    )

    def _v6_leave_cleans_up():
        data = _json_cmd("r2", "show ipv6 pim local-membership json")
        if data is None:
            return "r2: unparseable v6 local-membership JSON (pim6d dead?)"
        row = data.get("r2-eth1", {}).get(GROUP6, {})
        if row.get("localMembership") == "INCLUDE":
            return "r2 v6 local membership stranded after leave: {}".format(
                data
            )
        ups = _json_cmd("r2", "show ipv6 pim upstream json")
        if ups is None:
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        if ups.get(GROUP6, {}).get(SOURCE6, {}).get("joinState") == "Joined":
            return "r2 v6 upstream stranded after leave: {}".format(ups)
        return None

    _, result = topotest.run_and_expect(_v6_leave_cleans_up, None, count=90, wait=1)
    assert result is None, result

    # re-add: a leaked oif would make this join unclaimable ("OIF twice"),
    # so a working re-join doubles as proof nothing was left behind.  It
    # also restores the module's steady state.
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ipv6 mld join-group {} {}
""".format(GROUP6, SOURCE6)
    )

    def _v6_rejoin_works():
        ups = _json_cmd("r2", "show ipv6 pim upstream json")
        if ups is None:
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        updata = ups.get(GROUP6, {}).get(SOURCE6, {})
        if updata.get("joinState") != "Joined":
            return "r2 v6 upstream did not re-Join after re-add: {}".format(
                ups
            )
        if updata.get("staticIncomingInterface") is not True:
            return "r2 v6 upstream not UMH-pinned after re-add: {}".format(
                updata
            )
        return None

    _, result = topotest.run_and_expect(_v6_rejoin_works, None, count=90, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
