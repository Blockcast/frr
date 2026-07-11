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

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"
# GROUP2 is joined via `ip igmp static-group` in r2's startup config: the
# membership is processed at config-load time, BEFORE zebra has delivered
# interface state and BEFORE BGP has delivered the UMH mapping.
GROUP2 = "232.1.1.20"
SRC_PREFIX = "10.10.10.0/24"
UMH = "10.0.0.1"


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
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _json_cmd(rname, cmd):
    out = get_topogen().gears[rname].vtysh_cmd(cmd)
    try:
        return json.loads(out)
    except ValueError:
        return {}


def test_bgp_converges():
    """r2 learns the source prefix over BGP (across the light segment)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _route_learned():
        data = _json_cmd("r2", "show ip route {} json".format(SRC_PREFIX))
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
        rpfdata = rpf.get(GROUP, {}).get(SOURCE, {})
        if rpfdata.get("rpfAddress") != UMH:
            return "r2 rpf address is not the UMH: {}".format(rpfdata)
        return None

    _, result = topotest.run_and_expect(_upstream_pinned, None, count=60, wait=1)
    assert result is None, result

    # and the neighborless Join must have reached r1 (synthetic neighbor)
    def _synthetic_neighbor():
        neigh = _json_cmd("r1", "show ip pim neighbor json")
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
        if SRC_PREFIX in data:
            return "r2 UMH mapping survived EC removal: {}".format(data)
        return None

    _, result = topotest.run_and_expect(_mapping_gone, None, count=90, wait=1)
    assert result is None, result

    def _upstream_unpinned_but_alive():
        data = _json_cmd("r2", "show ip pim upstream json")
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
        updata = data.get(GROUP, {}).get(SOURCE, {})
        if updata.get("staticIncomingInterface") is not True:
            return "r2 upstream not re-pinned: {}".format(updata)
        rpf = _json_cmd("r2", "show ip pim rpf json")
        rpfdata = rpf.get(GROUP, {}).get(SOURCE, {})
        if rpfdata.get("rpfAddress") != UMH:
            return "r2 rpf address is not the UMH: {}".format(rpfdata)
        return None

    _, result = topotest.run_and_expect(_repinned, None, count=90, wait=1)
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
        if SRC_PREFIX in data:
            return "r2 UMH mapping survived withdraw: {}".format(data)
        data = _json_cmd("r2", "show ip pim upstream json")
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
        entry = data.get(SRC_PREFIX, {})
        if entry.get("interface") != "r2-eth2":
            return "r2 UMH not resolved on the s4 light iface: {}".format(
                data
            )
        data = _json_cmd("r2", "show ip pim upstream json")
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
    import time

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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
