#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_mvpn_gtm.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Blockcast, Inc.
#

"""
test_bgp_mvpn_gtm.py:

Verify the BGP MCAST-VPN address family (AFI 1/2, SAFI 5 / IANA SAFI 5,
RFC 6514) in its Global-Table Multicast form (RFC 7716), including the
pimd<->bgpd glue: a real IGMPv3 (S,G) join originates a C-multicast Source
Tree Join (Type 7), and a real directly-connected multicast sender
originates a Source Active A-D (Type 5).

Topology:

    h1 --- s2 --- r1 --- s1 --- r2 --- s3 (receiver stub)
  (source)      (FHR PE)      (receiver PE)

Both routers run `router bgp 65001` (iBGP over s1) with the MVPN AF, and
pimd with `router pim` / `mvpn-gtm`.  There is deliberately NO PIM
adjacency between r1 and r2 -- the BGP MCAST-VPN AF is the inter-PE
multicast control plane (r2-eth0 runs pim for RPF machinery, r1-eth0 does
not, so no neighbor can form).

h1 is a multicast sender on r1's PIM-passive segment (drives FHR source
detection -> Type-5).  r2's stub interface takes runtime
`ip igmp join-group <G> <S>` static joins (drives local SSM membership ->
Type-7).
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd, pytest.mark.pim6d]

# The (S, G) driven end-to-end by real pimd state: h1 sends to GROUP,
# r2 IGMP-joins (SOURCE, GROUP).
SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"

# Module-scoped sender process (h1 -> GROUP), started by the Type-5 test,
# left running so the SA route stays up for the Type-7 tests, reaped in
# teardown_module.
SENDER = None


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # s1: inter-PE (BGP-only, no PIM adjacency)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # s2: r1's source segment with host h1
    tgen.add_host("h1", "10.10.10.10/24", "via 10.10.10.1")
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    # s3: r2's receiver stub (static IGMP joins are placed here)
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
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
    global SENDER
    if SENDER is not None:
        SENDER.terminate()
        SENDER = None
    tgen = get_topogen()
    tgen.stop_topology()


def _mvpn_routes(router, v6=False):
    tgen = get_topogen()
    cmd = "show bgp ipv6 mvpn json" if v6 else "show bgp ipv4 mvpn json"
    return json.loads(tgen.gears[router].vtysh_cmd(cmd)).get("routes", [])


def _selective_route(routes, route_type, source=SOURCE, group=GROUP):
    for route in routes:
        if (
            route.get("routeType") == route_type
            and route.get("source") == source
            and route.get("group") == group
        ):
            return route
    return None


def test_bgp_mvpn_converge():
    """The iBGP session must reach Established before capabilities are stable."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge(router, peer):
        output = json.loads(
            tgen.gears[router].vtysh_cmd(
                "show bgp neighbor {} json".format(peer)
            )
        )
        expected = {peer: {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, "r1", "10.0.0.2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 did not converge with r2"


def test_mvpn_af_negotiated():
    """The MVPN AF multiprotocol capability must be advertised and received."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _mvpn_capability(router, peer):
        output = json.loads(
            tgen.gears[router].vtysh_cmd(
                "show bgp neighbor {} json".format(peer)
            )
        )
        expected = {
            peer: {
                "neighborCapabilities": {
                    "multiprotocolExtensions": {
                        "ipv4Mvpn": {"advertisedAndReceived": True}
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)

    for router, peer in (("r1", "10.0.0.2"), ("r2", "10.0.0.1")):
        test_func = functools.partial(_mvpn_capability, router, peer)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{}: ipv4 mvpn capability not advertisedAndReceived".format(
            router
        )


def test_type5_source_active_propagates():
    """A static GTM Source Active (Type 5) route on r1 must reach r2 via BGP.

    r1 is configured with `bgp mvpn source-active 10.10.10.1 group 232.1.1.1`
    under `address-family ipv4 mvpn`. r2 must learn it and expose it via
    `show bgp ipv4 mvpn json` with routeType 5 and the matching (S,G).

    The SA route must also carry the GTM global-table Route Target (an
    IP-address-specific RT with Global Administrator = 0.0.0.0 and Local
    Administrator = 0), so r2 sees an extendedCommunity of "RT:0.0.0.0:0". This
    is the fixed import/export target a GTM receiver (e.g. Junos
    mpls-internet-multicast) matches on; without it -- or with a group-address
    RT -- the receiver rejects the route "due to the lack of a valid target
    community".
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _type5_present(router):
        routes = _mvpn_routes(router)
        for r in routes:
            if (
                r.get("routeType") == 5
                and r.get("source") == "10.10.10.1"
                and r.get("group") == "232.1.1.1"
                and r.get("extendedCommunity", {}).get("string") == "RT:0.0.0.0:0"
            ):
                return None
        return "Type-5 (10.10.10.1, 232.1.1.1) with RT:0.0.0.0:0 not found in {}".format(
            routes
        )

    test_func = functools.partial(_type5_present, "r2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 did not learn r1's MVPN Type-5 Source Active route"


def test_type5_from_pimd_source_detect():
    """A real multicast sender behind r1 must originate a Type-5 via pimd.

    h1 (10.10.10.10, directly connected to r1's PIM-passive interface) sends
    UDP to 232.1.1.10.  r1's pimd detects the directly-connected source (FHR,
    kernel NOCACHE upcall -> upstream with SRC_STREAM, keep-alive running) and,
    with `mvpn-gtm` enabled, signals bgpd over ZEBRA_MVPN_SG; bgpd originates
    the Source Active A-D.  r2 must learn Type-5 (10.10.10.10, 232.1.1.10)
    with the GTM global-table RT.

    This is the pimd->bgpd glue SOURCE leg -- no static `source-active`
    involved.
    """
    global SENDER
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    mcast_tester = os.path.join(CWD, "../lib/mcast-tester.py")
    SENDER = tgen.gears["h1"].popen(
        [mcast_tester, GROUP, "h1-eth0", "--send", "0.7"]
    )
    logger.info("started sender on h1: %s -> %s", SOURCE, GROUP)

    def _type5_pimd(router):
        routes = _mvpn_routes(router)
        saw_type5 = False
        for r in routes:
            if (
                r.get("routeType") == 5
                and r.get("source") == SOURCE
                and r.get("group") == GROUP
                and r.get("extendedCommunity", {}).get("string") == "RT:0.0.0.0:0"
            ):
                saw_type5 = True
                break
        type3 = _selective_route(routes, 3)
        if saw_type5 and type3:
            pmsi = type3.get("pmsiTunnel", {})
            if (
                type3.get("originator") == "10.0.0.1"
                and pmsi.get("type") == "ingressReplication"
                and pmsi.get("endpoint") == "10.0.0.1"
                and pmsi.get("leafInfoRequired") is True
                and type3.get("extendedCommunity", {}).get("string")
                == "RT:0.0.0.0:0"
            ):
                return None
        return "pimd-driven Type-5/Type-3 ({}, {}) not complete in {}".format(
            SOURCE, GROUP, routes
        )

    test_func = functools.partial(_type5_pimd, "r2")
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "r2 did not learn the pimd-originated Type-5/Type-3 for the live source"


def test_type7_from_igmp_join():
    """A real IGMPv3 (S,G) join on r2 must originate a Type-7 via pimd.

    r2 takes `ip igmp join-group 232.1.1.10 10.10.10.10` on its receiver stub
    interface.  pimd builds local SSM membership -> (S,G) upstream in JOINED,
    and with `mvpn-gtm` enabled signals bgpd over ZEBRA_MVPN_SG; bgpd
    originates the C-multicast Source Tree Join.  r1 must learn Type-7
    (10.10.10.10, 232.1.1.10) with:

    - sourceAs 65001: no Source-AS extended community exists on the source
      route (single-AS iBGP), so bgpd falls back to the local AS per
      RFC 6514 Section 4.6.
    - RT:10.0.0.1:0: the upstream PE resolved from the Source Active route's
      next hop (r1's router-id; the covering unicast route 10.10.10.0/24
      carries no route-import EC, driving the SA-next-hop fallback arm).

    There is NO PIM adjacency between r1 and r2 -- the join crosses the
    fabric purely as BGP.  This is the pimd->bgpd glue JOIN leg, replacing
    the removed `bgp mvpn test-join` scaffold.
    """
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

    def _type7_present(router):
        routes = _mvpn_routes(router)
        saw_type7 = False
        for r in routes:
            if (
                r.get("routeType") == 7
                and r.get("source") == SOURCE
                and r.get("group") == GROUP
                and r.get("sourceAs") == 65001
                and r.get("extendedCommunity", {}).get("string") == "RT:10.0.0.1:0"
            ):
                saw_type7 = True
                break
        type4 = _selective_route(routes, 4)
        if (
            saw_type7
            and type4
            and type4.get("originator") == "10.0.0.1"
            and type4.get("leafOriginator") == "10.0.0.2"
            and type4.get("extendedCommunity", {}).get("string") == "RT:10.0.0.1:0"
        ):
            return None
        return "Type-7/Type-4 ({}, {}) not complete in {}".format(
            SOURCE, GROUP, routes
        )

    test_func = functools.partial(_type7_present, "r1")
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "r1 did not learn the pimd-originated Type-7/Type-4 for the IGMP join"


def test_type7_umh_from_route_import():
    """The Type-7 upstream-node RT must come from the source route's route-import
    RT (RFC 6514 Section 5.1), not the Source Active next hop.

    A GTM source PE advertises the unicast route toward C-S carrying a route-
    import Route Target target:<PE>:0; a PE that joins (C-S, C-G) must set the
    C-multicast (Type-7) join's upstream-node RT to that value so the source PE's
    __vrf-mvpn-import-cmcast-*-internal__ policy imports it. Over eBGP the Source
    Active next hop is rewritten to the peering address, so resolving the
    upstream from the SA next hop yields a non-matching RT -- the bug this guards.
    Verified against Junos MX204 22.2R3, whose cmcast import keys on the lo0 PE
    address.

    r1 originates 10.99.99.1/32 with route-import RT 10.255.0.2:0 (route-map at
    config time) plus a static Source Active for (10.99.99.1, 232.9.9.9).  r2
    IGMP-joins that (S,G) on its stub; the pimd-driven Type-7 on r2 must carry
    RT:10.255.0.2:0 (the route-import Global Administrator), NOT RT:10.0.0.1:0
    (the SA next hop).
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ip igmp join-group 232.9.9.9 10.99.99.1
"""
    )

    def _type7_rtimport(router):
        routes = _mvpn_routes(router)
        for r in routes:
            if (
                r.get("routeType") == 7
                and r.get("source") == "10.99.99.1"
                and r.get("group") == "232.9.9.9"
            ):
                rt = r.get("extendedCommunity", {}).get("string")
                if rt == "RT:10.255.0.2:0":
                    return None
                return "Type-7 (10.99.99.1, 232.9.9.9) carries {} (want RT:10.255.0.2:0 from route-import)".format(
                    rt
                )
        return "Type-7 (10.99.99.1, 232.9.9.9) not found in {}".format(routes)

    test_func = functools.partial(_type7_rtimport, "r2")
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "Type-7 upstream RT was not resolved from the source route's route-import RT"


def test_type7_umh_from_vrf_route_import_ec():
    """The Type-7 upstream RT resolves from a VRF Route Import EC (sub-type 0x0b),
    exercising the RFC 6514 Section 4.1 route-import community and the FRR-source
    export path (`set extcommunity vrf-route-import`).

    This is the export half of rt-import: an FRR source PE tags the unicast route
    toward C-S with a VRF Route Import extended community (IP-address-specific,
    sub-type 0x0b) naming itself. A PE joining (C-S, C-G) reads that community and
    echoes its Global Administrator as the Type-7 upstream-node Route Target, so a
    conformant source (FRR or Junos "rt-import") imports the join. The resolver
    prefers 0x0b over a plain Route Target (0x02); this test drives the 0x0b
    branch, complementing test_type7_umh_from_route_import which drives 0x02.

    r1 originates 10.99.99.2/32 carrying vrf-route-import 10.255.0.3:0 plus a
    static Source Active for (10.99.99.2, 232.9.9.10).  r2 IGMP-joins that
    (S,G); the pimd-driven Type-7 on r2 must carry RT:10.255.0.3:0.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ip igmp join-group 232.9.9.10 10.99.99.2
"""
    )

    def _type7_vri(router):
        routes = _mvpn_routes(router)
        for r in routes:
            if (
                r.get("routeType") == 7
                and r.get("source") == "10.99.99.2"
                and r.get("group") == "232.9.9.10"
            ):
                rt = r.get("extendedCommunity", {}).get("string")
                if rt == "RT:10.255.0.3:0":
                    return None
                return "Type-7 (10.99.99.2, 232.9.9.10) carries {} (want RT:10.255.0.3:0 from vrf-route-import)".format(
                    rt
                )
        return "Type-7 (10.99.99.2, 232.9.9.10) not found in {}".format(routes)

    test_func = functools.partial(_type7_vri, "r2")
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "Type-7 upstream RT was not resolved from the VRF Route Import (0x0b) EC"


def test_type7_reresolves_when_route_import_arrives_after_join():
    """A local Type-7 must re-resolve its upstream RT when the unicast route
    toward C-S changes *after* the join is already up (reactive re-resolution).

    The RFC 6514 Section 5 upstream RT is read from the unicast route toward C-S
    at origination. A receiver can join before that route carries its route-
    import EC -- e.g. the source PE advertises the covering route, or adds the
    EC, only later. Without reactive re-resolution the Type-7 keeps whatever it
    resolved at origination (here the Source-Active next-hop fallback) and never
    targets the real upstream PE, so the source PE never imports the join.

    r1 advertises 10.99.99.3/32 with NO route-import and a static Source Active
    for (10.99.99.3, 232.9.9.11). r2 IGMP-joins that (S,G): with no route-import
    on the source route, the Type-7 falls back to the SA next hop RT:10.0.0.1:0.
    Then r1 re-advertises 10.99.99.3/32 carrying vrf-route-import 10.255.0.4:0.
    r2's Type-7 must switch to RT:10.255.0.4:0 WITHOUT the join being touched.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ip igmp join-group 232.9.9.11 10.99.99.3
"""
    )

    def _type7_rt(router, want):
        routes = _mvpn_routes(router)
        for r in routes:
            if (
                r.get("routeType") == 7
                and r.get("source") == "10.99.99.3"
                and r.get("group") == "232.9.9.11"
            ):
                rt = r.get("extendedCommunity", {}).get("string")
                if rt == want:
                    return None
                return "Type-7 (10.99.99.3, 232.9.9.11) carries {} (want {})".format(
                    rt, want
                )
        return "Type-7 (10.99.99.3, 232.9.9.11) not found in {}".format(routes)

    # Precondition: no route-import on the source route -> SA next-hop fallback.
    test_func = functools.partial(_type7_rt, "r2", "RT:10.0.0.1:0")
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "Type-7 did not originate with the SA next-hop fallback RT before route-import"

    # The source PE now attaches a route-import EC to the C-S unicast route.
    # The join is deliberately NOT touched -- only the unicast route changes.
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
route-map addvri3 permit 10
 set extcommunity vrf-route-import 10.255.0.4:0
router bgp 65001
 address-family ipv4 unicast
  network 10.99.99.3/32 route-map addvri3
"""
    )

    # The fix: r2's unicast best path for 10.99.99.3 changed, so the dependent
    # Type-7 must re-resolve to the route-import RT with no join churn.
    test_func = functools.partial(_type7_rt, "r2", "RT:10.255.0.4:0")
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "Type-7 did not re-resolve its upstream RT after route-import arrived post-join"


def test_type5_v6_source_active_propagates():
    """A local IPv6 GTM Source Active (Type 5) route on r1 must reach r2 (RFC 6515).

    r1 is configured under `address-family ipv6 mvpn` with
    `bgp mvpn source-active 2001:db8::1 group ff3e::1`. r2 must learn it and
    expose it via `show bgp ipv6 mvpn json` with routeType 5, the v6 (S,G), and
    the GTM global-table Route Target RT:0.0.0.0:0 -- exercising the AFI_IP6
    MCAST-VPN AF (capability negotiated over the shared session, the v6 NLRI
    codec, and the v6 RIB).
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _type5_v6_present(router):
        routes = _mvpn_routes(router, v6=True)
        for r in routes:
            if (
                r.get("routeType") == 5
                and r.get("source") == "2001:db8::1"
                and r.get("group") == "ff3e::1"
                and r.get("extendedCommunity", {}).get("string") == "RT:0.0.0.0:0"
            ):
                return None
        return "IPv6 Type-5 (2001:db8::1, ff3e::1) with RT:0.0.0.0:0 not found in {}".format(
            routes
        )

    test_func = functools.partial(_type5_v6_present, "r2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 did not learn r1's IPv6 MVPN Type-5 Source Active route"


def test_type1_v6_plane_with_v4_originator():
    """r1's Intra-AS I-PMSI A-D must also appear in r2's IPv6 MVPN table.

    A Type-1's plane is the AF the NLRI is advertised in, not the originator
    address family: RFC 6515 permits a v4 Originating Router address inside
    the IPv6 MCAST-VPN AF (Junos mpls-internet-multicast advertises exactly
    that shape). r1 originates one Type-1 per active GTM plane, both carrying
    the v4 router-id originator; r2 must hold the v6-plane copy in the
    AFI_IP6 MCAST-VPN RIB. Regressions guarded (all found live against Junos
    22.2R3):
    - rib selection previously keyed off the originator family, silently
      collapsing the v6-plane Type-1 into the v4 table (MX advertised 1
      prefix on bgp.mvpn-inet6.0, FRR's ipv6 mvpn table stayed empty).
    - the AF-activation hook only fired for AFI_IP, so the v6-plane copy was
      never originated at boot (this test would see the route ABSENT).
    - bgp_attr_intern's hash-miss path steals a caller-owned attr->extra, so
      the second per-plane install interned a PMSI-flagged attr with no
      tunnel info, announced as a malformed len-5 NO_INFO PMSI (Junos
      NOTIFICATION loop; this test would see pmsiTunnel absent/noInfo).
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _type1_v6_present(router):
        routes = _mvpn_routes(router, v6=True)
        for r in routes:
            if r.get("routeType") != 1:
                continue
            pmsi = r.get("pmsiTunnel", {})
            if (
                pmsi.get("type") == "ingressReplication"
                and pmsi.get("endpoint") == "10.0.0.1"
                and pmsi.get("label") == 0
                and r.get("extendedCommunity", {}).get("string") == "RT:0.0.0.0:0"
            ):
                return None
        return "v6-plane Type-1 with v4 originator 10.0.0.1 not found in {}".format(routes)

    test_func = functools.partial(_type1_v6_present, "r2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 did not hold r1's Type-1 in the IPv6 MCAST-VPN RIB"


def test_type7_v6_from_mld_join():
    """A real MLDv2 (S,G) join on r2 must originate an IPv6 Type-7 via pim6d.

    r2 takes `ipv6 mld join-group ff3e::1 2001:db8::1` on its receiver stub.
    pim6d builds local v6 SSM membership -> (S,G) upstream in JOINED: the
    source RPFs via r2-eth0 to r1 (2001:db8:1::1), an interface with no v6 PIM
    neighbor -- the GTM neigh_needed=false path, shared from pimd via
    pim_common and reached here with the pim6d `mvpn-gtm` CLI.  With mvpn-gtm
    enabled pim6d signals bgpd over ZEBRA_MVPN_SG (v6 (S,G) carried as
    IPADDR_V6); bgpd originates the C-multicast Source Tree Join in the IPv6
    MCAST-VPN AF (bgp_mvpn_prefix_afi routes it to AFI_IP6).  r1 must learn
    Type-7 (2001:db8::1, ff3e::1) with:

    - sourceAs 65001: no Source-AS EC on the source (single-AS iBGP), so bgpd
      falls back to the local AS (RFC 6514 Section 4.6).
    - RT:10.0.0.1:0: the upstream PE resolved from r1's static Source Active
      route next hop (r1's v4 router-id; the MVPN originator stays v4 even in
      the v6 plane).

    This is the pim6d->bgpd glue JOIN leg driven by MLD, mirroring
    test_type7_from_igmp_join.  There is NO PIM adjacency between r1 and r2 --
    the join crosses the fabric purely as BGP.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ipv6 mld join-group ff3e::1 2001:db8::1
"""
    )

    def _type7_v6_present(router):
        routes = _mvpn_routes(router, v6=True)
        for r in routes:
            if (
                r.get("routeType") == 7
                and r.get("source") == "2001:db8::1"
                and r.get("group") == "ff3e::1"
                and r.get("sourceAs") == 65001
                and r.get("extendedCommunity", {}).get("string") == "RT:10.0.0.1:0"
            ):
                return None
        return "IPv6 Type-7 (2001:db8::1, ff3e::1, AS 65001) with RT:10.0.0.1:0 not found in {}".format(
            routes
        )

    test_func = functools.partial(_type7_v6_present, "r1")
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "r1 did not learn the pim6d-originated IPv6 Type-7 for the MLD join"


def test_type1_ipmsi_with_ir_pmsi():
    """On MVPN AF enable, r1 auto-originates its Intra-AS I-PMSI A-D route.

    RFC 6514 Section 4.1 Route Type 1 (Intra-AS I-PMSI A-D) is originated by
    each PE when the MCAST-VPN AF is enabled. r1's Type-1 carries a PMSI Tunnel
    attribute (RFC 6514 Section 5) with Tunnel Type = Ingress Replication (6)
    and r1's own unicast address (10.0.0.1, the pinned router-id) as the
    tunnel endpoint. It also carries the GTM global-table Route Target
    "RT:0.0.0.0:0" (the fixed import/export target for non-C-multicast GTM
    routes). r2 must learn it via `show bgp ipv4 mvpn json` with routeType 1, the
    matching pmsiTunnel object, and that extendedCommunity.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _type1_present(router):
        routes = _mvpn_routes(router)
        for r in routes:
            if r.get("routeType") != 1:
                continue
            pmsi = r.get("pmsiTunnel", {})
            if (
                pmsi.get("type") == "ingressReplication"
                and pmsi.get("endpoint") == "10.0.0.1"
                # RFC 6514 Section 5: zero label = unlabeled tunnel (GTM
                # label-free IR). A stray MPLS_INVALID_LABEL leaks 0xFFFFF
                # onto the wire and Junos hides the A-D route.
                and pmsi.get("label") == 0
                and r.get("extendedCommunity", {}).get("string") == "RT:0.0.0.0:0"
            ):
                return None
        return "Type-1 I-PMSI with IR PMSI endpoint 10.0.0.1 (label 0) + RT:0.0.0.0:0 not found in {}".format(
            routes
        )

    test_func = functools.partial(_type1_present, "r2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 did not learn r1's MVPN Type-1 Intra-AS I-PMSI route"


def test_selective_routes_replay_after_daemon_restarts():
    """pimd-owned (S,G) state reconstructs Type-3/4 after daemon restarts."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    kill_router_daemons(tgen, "r1", ["bgpd"])
    start_router_daemons(tgen, "r1", ["bgpd"])

    def _type3_replayed():
        route = _selective_route(_mvpn_routes("r2"), 3)
        if route and route.get("pmsiTunnel", {}).get("leafInfoRequired") is True:
            return None
        return "r1 bgpd restart did not replay pimd's Type-3: {}".format(
            _mvpn_routes("r2")
        )

    _, result = topotest.run_and_expect(_type3_replayed, None, count=90, wait=1)
    assert result is None, result

    # Save the runtime IGMP join, then restart both consumers/producers. The
    # order is deliberately not controlled: either the PIM replay or the remote
    # Type-3 can arrive first, and the reconcile hooks must converge to Type-4.
    kill_router_daemons(tgen, "r2", ["bgpd", "pimd"], save_config=True)
    start_router_daemons(tgen, "r2", ["pimd", "bgpd"])

    def _type4_replayed():
        route = _selective_route(_mvpn_routes("r1"), 4)
        if (
            route
            and route.get("originator") == "10.0.0.1"
            and route.get("leafOriginator") == "10.0.0.2"
        ):
            return None
        return "r2 bgpd/pimd restart did not replay Type-4: {}".format(
            _mvpn_routes("r1")
        )

    _, result = topotest.run_and_expect(_type4_replayed, None, count=120, wait=1)
    assert result is None, result


def test_full_mvpn_exchange():
    """End-to-end: SAFI-5 session + Type-1/5/7 exchange in one scenario.

    Combined assertion over the whole deliverable: with the iBGP session
    Established and the MVPN AF negotiated, BOTH peers' MVPN tables
    (`show bgp ipv4 mvpn json`) must simultaneously contain the full expected
    route mix:

    - r2 sees r1's Type-1 Intra-AS I-PMSI A-D with an Ingress Replication
      PMSI tunnel and endpoint 10.0.0.1, AND the pimd-originated Type-5
      Source Active for the live sender (10.10.10.10, 232.1.1.10).
    - r1 sees r2's Type-1 with endpoint 10.0.0.2, AND the pimd-originated
      Type-7 Source Tree Join for (10.10.10.10, 232.1.1.10) carrying
      Source AS 65001 -- driven by the standing IGMP join, no test
      scaffolding.

    All of this is RIB-level control plane; forwarding is a later milestone.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _established(router, peer):
        output = json.loads(
            tgen.gears[router].vtysh_cmd(
                "show bgp neighbor {} json".format(peer)
            )
        )
        expected = {peer: {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    for router, peer in (("r1", "10.0.0.2"), ("r2", "10.0.0.1")):
        test_func = functools.partial(_established, router, peer)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{}: session with {} not Established".format(
            router, peer
        )

    def _has_type1(routes, endpoint):
        for r in routes:
            if r.get("routeType") != 1:
                continue
            pmsi = r.get("pmsiTunnel", {})
            if (
                pmsi.get("type") == "ingressReplication"
                and pmsi.get("endpoint") == endpoint
                and pmsi.get("label") == 0
                and r.get("extendedCommunity", {}).get("string") == "RT:0.0.0.0:0"
            ):
                return True
        return False

    def _has_type5(routes, source, group):
        for r in routes:
            if (
                r.get("routeType") == 5
                and r.get("source") == source
                and r.get("group") == group
                and r.get("extendedCommunity", {}).get("string") == "RT:0.0.0.0:0"
            ):
                return True
        return False

    def _has_type7(routes, source, group, source_as):
        for r in routes:
            if (
                r.get("routeType") == 7
                and r.get("source") == source
                and r.get("group") == group
                and r.get("sourceAs") == source_as
                and r.get("extendedCommunity", {}).get("string") == "RT:10.0.0.1:0"
            ):
                return True
        return False

    def _has_type3(routes, source, group):
        route = _selective_route(routes, 3, source, group)
        return bool(
            route
            and route.get("originator") == "10.0.0.1"
            and route.get("pmsiTunnel", {}).get("leafInfoRequired") is True
        )

    def _has_type4(routes, source, group):
        route = _selective_route(routes, 4, source, group)
        return bool(
            route
            and route.get("originator") == "10.0.0.1"
            and route.get("leafOriginator") == "10.0.0.2"
        )

    def _full_exchange():
        r1_routes = _mvpn_routes("r1")
        r2_routes = _mvpn_routes("r2")

        missing = []
        if not _has_type1(r2_routes, "10.0.0.1"):
            missing.append("r2 lacks r1's Type-1 (IR endpoint 10.0.0.1)")
        if not _has_type5(r2_routes, SOURCE, GROUP):
            missing.append(
                "r2 lacks r1's pimd Type-5 ({}, {})".format(SOURCE, GROUP)
            )
        if not _has_type3(r2_routes, SOURCE, GROUP):
            missing.append("r2 lacks r1's pimd Type-3 ({}, {})".format(SOURCE, GROUP))
        if not _has_type1(r1_routes, "10.0.0.2"):
            missing.append("r1 lacks r2's Type-1 (IR endpoint 10.0.0.2)")
        if not _has_type7(r1_routes, SOURCE, GROUP, 65001):
            missing.append(
                "r1 lacks r2's pimd Type-7 ({}, {}, AS 65001)".format(
                    SOURCE, GROUP
                )
            )
        if not _has_type4(r1_routes, SOURCE, GROUP):
            missing.append("r1 lacks r2's pimd Type-4 ({}, {})".format(SOURCE, GROUP))

        if missing:
            return "{} [r1={} r2={}]".format(
                "; ".join(missing), r1_routes, r2_routes
            )
        return None

    _, result = topotest.run_and_expect(_full_exchange, None, count=60, wait=1)
    assert result is None, "full MVPN exchange incomplete: {}".format(result)


def test_selective_reconcile_both_arrival_orders():
    """Type-3 (S-PMSI) and the receiver join reconcile to a Type-4 in EITHER order.

    test_selective_routes_replay_after_daemon_restarts proves convergence but the
    arrival order a given run produces is nondeterministic (its own docstring says
    so). This drives BOTH orderings explicitly, on fresh groups (same source h1,
    distinct G) that do not touch the standing (SOURCE, GROUP) state:

    - order A (join before Type-3): r2 IGMP-joins (SOURCE, GA) while no sender for
      GA exists -> a Type-7 is originated but there is no remote Type-3, so no
      Type-4. h1 then starts sending to GA -> r1 pimd originates the Type-3 ->
      r2's local-join reconcile (bgp_mvpn_selective_join_set) installs the Type-4.
    - order B (Type-3 before join): h1 sends to GB first -> r1's Type-3 exists (and
      reaches r2) -> r2 then IGMP-joins (SOURCE, GB) -> r2's remote-Type-3
      reconcile (route_install, has_local_join) installs the Type-4.

    Both orderings must end with r1 holding the Type-4 (leafOriginator 10.0.0.2).
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    ga = "232.1.1.20"
    gb = "232.1.1.21"
    mcast_tester = os.path.join(CWD, "../lib/mcast-tester.py")
    senders = []

    def _type4_present(group):
        route = _selective_route(_mvpn_routes("r1"), 4, SOURCE, group)
        if (
            route
            and route.get("originator") == "10.0.0.1"
            and route.get("leafOriginator") == "10.0.0.2"
        ):
            return None
        return "Type-4 ({}, {}) not present on r1: {}".format(
            SOURCE, group, _mvpn_routes("r1")
        )

    def _type4_absent(group):
        if _selective_route(_mvpn_routes("r1"), 4, SOURCE, group) is None:
            return None
        return "Type-4 ({}, {}) present on r1 with no remote Type-3".format(
            SOURCE, group
        )

    def _type3_present(router, group):
        if _selective_route(_mvpn_routes(router), 3, SOURCE, group):
            return None
        return "Type-3 ({}, {}) not yet on {}".format(SOURCE, group, router)

    def _join(group):
        tgen.gears["r2"].vtysh_cmd(
            "configure terminal\ninterface r2-eth1\n ip igmp join-group {} {}\n".format(
                group, SOURCE
            )
        )

    try:
        # ---- order A: join first, source second ----
        _join(ga)
        # No sender for GA yet: local join without a remote Type-3 -> no Type-4.
        _, result = topotest.run_and_expect(
            functools.partial(_type4_absent, ga), None, count=10, wait=1
        )
        assert result is None, result
        senders.append(
            tgen.gears["h1"].popen([mcast_tester, ga, "h1-eth0", "--send", "0.7"])
        )
        _, result = topotest.run_and_expect(
            functools.partial(_type4_present, ga), None, count=90, wait=1
        )
        assert result is None, "order A (join before Type-3) did not reconcile to Type-4"

        # ---- order B: source first, join second ----
        senders.append(
            tgen.gears["h1"].popen([mcast_tester, gb, "h1-eth0", "--send", "0.7"])
        )
        _, result = topotest.run_and_expect(
            functools.partial(_type3_present, "r2", gb), None, count=90, wait=1
        )
        assert result is None, "order B setup: r1 did not originate/propagate the Type-3 for GB"
        _join(gb)
        _, result = topotest.run_and_expect(
            functools.partial(_type4_present, gb), None, count=90, wait=1
        )
        assert result is None, "order B (Type-3 before join) did not reconcile to Type-4"
    finally:
        # Restore the standing state: drop the extra joins, reap the extra
        # senders. (Their FHR Type-3/5 age out on the PIM keep-alive; distinct
        # groups, so they do not perturb the SOURCE/GROUP tests that follow.)
        tgen.gears["r2"].vtysh_cmd(
            "configure terminal\ninterface r2-eth1\n"
            " no ip igmp join-group {} {}\n no ip igmp join-group {} {}\n".format(
                ga, SOURCE, gb, SOURCE
            )
        )
        for sender in senders:
            sender.terminate()


def test_type7_withdraw_on_igmp_leave():
    """Removing the IGMP join must withdraw the Type-7 from r1.

    `no ip igmp join-group 232.1.1.10 10.10.10.10` on r2's stub tears down the
    local membership -> pimd upstream leaves JOINED -> the glue sends
    ZEBRA_MVPN_SG DEL -> bgpd withdraws the Type-7 -> it disappears from r1's
    MVPN table.  Runs LAST: every earlier test relies on the standing join.

    (The Type-5 side has no fast withdraw assert: FHR source expiry is the
    PIM keep-alive timeout, 210s by default -- out of topotest budget.)
    """
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

    def _type7_absent(router):
        routes = _mvpn_routes(router)
        for r in routes:
            if (
                r.get("routeType") in (4, 7)
                and r.get("source") == SOURCE
                and r.get("group") == GROUP
            ):
                return "Type-{} ({}, {}) still present after IGMP leave".format(
                    r.get("routeType"), SOURCE, GROUP
                )
        return None

    test_func = functools.partial(_type7_absent, "r1")
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "r1 still holds the Type-7/Type-4 after the IGMP leave"


def test_type7_v6_withdraw_on_mld_leave():
    """Removing the MLD join must withdraw the IPv6 Type-7 from r1.

    The v6 mirror of test_type7_withdraw_on_igmp_leave: the MLD leave drives
    tib_sg_gm_prune() -> pim_ifchannel_local_membership_del -> pim6d upstream
    leaves JOINED -> ZEBRA_MVPN_SG DEL -> bgpd withdraws the Type-7.  Guards
    the teardown ordering in tib_sg_gm_prune(): the local-membership delete
    must run even when the kernel MFC update fails (a pim6d on a kernel
    without CONFIG_IPV6_PIMSM_V2 has no mroute socket at all; an early return
    on that failure was observed to strand the membership -- and the announced
    Type-7 -- forever).  Runs LAST among the v6 tests: earlier ones rely on
    the standing MLD join.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 no ipv6 mld join-group ff3e::1 2001:db8::1
"""
    )

    def _type7_v6_absent(router):
        routes = _mvpn_routes(router, v6=True)
        for r in routes:
            if (
                r.get("routeType") == 7
                and r.get("source") == "2001:db8::1"
                and r.get("group") == "ff3e::1"
            ):
                return "IPv6 Type-7 (2001:db8::1, ff3e::1) still present after MLD leave"
        return None

    test_func = functools.partial(_type7_v6_absent, "r1")
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "r1 still holds the IPv6 Type-7 after the MLD leave"


def test_type1_router_id_lifecycle():
    """A router-id change withdraws the old Type-1 in both MVPN planes."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1.vtysh_cmd(
        """
configure terminal
router bgp 65001
 bgp router-id 10.0.0.3
"""
    )

    def _type1_rekeyed(router, v6):
        endpoints = {
            route.get("pmsiTunnel", {}).get("endpoint")
            for route in _mvpn_routes(router, v6=v6)
            if route.get("routeType") == 1
        }
        if "10.0.0.3" in endpoints and "10.0.0.1" not in endpoints:
            return None
        return "Type-1 endpoints did not rekey from 10.0.0.1 to 10.0.0.3: {}".format(
            endpoints
        )

    for router in ("r1", "r2"):
        for v6 in (False, True):
            test_func = functools.partial(_type1_rekeyed, router, v6)
            _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
            assert result is None, "{} retained a stale {} Type-1 after router-id change".format(
                router, "IPv6" if v6 else "IPv4"
            )

    r1.vtysh_cmd(
        """
configure terminal
router bgp 65001
 no bgp router-id
"""
    )

    def _removed_id_absent(v6):
        endpoints = {
            route.get("pmsiTunnel", {}).get("endpoint")
            for route in _mvpn_routes("r1", v6=v6)
            if route.get("routeType") == 1
        }
        if "10.0.0.3" not in endpoints:
            return None
        return "removed router-id still has a Type-1 route: {}".format(endpoints)

    for v6 in (False, True):
        test_func = functools.partial(_removed_id_absent, v6)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "r1 retained the removed router-id's Type-1"

    # Persist the removal, restart bgpd, and verify reconstruction does not
    # resurrect the removed Type-1 key.
    kill_router_daemons(tgen, "r1", ["bgpd"], save_config=True)
    start_router_daemons(tgen, "r1", ["bgpd"])
    for v6 in (False, True):
        test_func = functools.partial(_removed_id_absent, v6)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "r1 resurrected a removed Type-1 after bgpd restart"


def test_type1_address_family_and_instance_lifecycle():
    """AF deactivation and instance deletion withdraw self-originated Type-1s."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _local_type1_endpoints(v6):
        return {
            route.get("pmsiTunnel", {}).get("endpoint")
            for route in _mvpn_routes("r1", v6=v6)
            if route.get("routeType") == 1
        }

    def _own_type1_endpoints(v6):
        return {
            route.get("pmsiTunnel", {}).get("endpoint")
            for route in _mvpn_routes("r1", v6=v6)
            if route.get("routeType") == 1 and route.get("selfOriginated")
        }

    initial_v4 = _local_type1_endpoints(False)
    initial_v6 = _local_type1_endpoints(True)
    assert initial_v4, "r1 had no IPv4 Type-1 before lifecycle test"
    assert initial_v6, "r1 had no IPv6 Type-1 before lifecycle test"
    # A neighbor/instance teardown withdraws THIS router's own
    # self-originated Type-1. A peer's self route legitimately remains
    # while that peer is still configured on the far side, so the absence
    # checks below key on r1's own endpoints, not the full initial set.
    own_v4 = _own_type1_endpoints(False)
    own_v6 = _own_type1_endpoints(True)
    assert own_v4, "r1 self-originated no IPv4 Type-1 before lifecycle test"
    assert own_v6, "r1 self-originated no IPv6 Type-1 before lifecycle test"

    r1.vtysh_cmd(
        """
configure terminal
router bgp 65001
 address-family ipv6 mvpn
  no neighbor 10.0.0.2 activate
"""
    )

    def _v6_withdrawn_v4_retained():
        v4 = _local_type1_endpoints(False)
        v6 = _local_type1_endpoints(True)
        if initial_v4.issubset(v4) and not initial_v6.intersection(v6):
            return None
        return "AF deactivation left v4={} v6={}".format(v4, v6)

    _, result = topotest.run_and_expect(
        _v6_withdrawn_v4_retained, None, count=60, wait=1
    )
    assert result is None, result

    # Repeating cleanup after the AF and route are already absent is a no-op.
    r1.vtysh_cmd(
        """
configure terminal
router bgp 65001
 address-family ipv6 mvpn
  no neighbor 10.0.0.2 activate
"""
    )
    assert _v6_withdrawn_v4_retained() is None

    r1.vtysh_cmd(
        """
configure terminal
router bgp 65001
 address-family ipv6 mvpn
  neighbor 10.0.0.2 activate
"""
    )

    def _both_restored():
        if initial_v4.issubset(_local_type1_endpoints(False)) and initial_v6.issubset(
            _local_type1_endpoints(True)
        ):
            return None
        return "Type-1 routes were not restored after AF reactivation"

    _, result = topotest.run_and_expect(_both_restored, None, count=60, wait=1)
    assert result is None, result

    r1.vtysh_cmd(
        """
configure terminal
router bgp 65001
 no neighbor 10.0.0.2
"""
    )

    def _type1_absent_after_neighbor_delete(v6, endpoints):
        local = _local_type1_endpoints(v6)
        remaining = {
            route.get("pmsiTunnel", {}).get("endpoint")
            for route in _mvpn_routes("r2", v6=v6)
            if route.get("routeType") == 1
        }
        if not endpoints.intersection(local) and not endpoints.intersection(remaining):
            return None
        return "deleted neighbor's Type-1 remains: local={} remote={}".format(
            local, remaining
        )

    for v6, endpoints in ((False, own_v4), (True, own_v6)):
        test_func = functools.partial(
            _type1_absent_after_neighbor_delete, v6, endpoints
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result

    r1.vtysh_cmd(
        """
configure terminal
router bgp 65001
 neighbor 10.0.0.2 remote-as 65001
 address-family ipv4 unicast
  neighbor 10.0.0.2 activate
 address-family ipv4 mvpn
  neighbor 10.0.0.2 activate
 address-family ipv6 mvpn
  neighbor 10.0.0.2 activate
"""
    )

    _, result = topotest.run_and_expect(_both_restored, None, count=60, wait=1)
    assert result is None, result

    r1.vtysh_cmd(
        """
configure terminal
no router bgp 65001
"""
    )

    def _type1_absent_after_instance_delete(v6, endpoints):
        local = {
            route.get("pmsiTunnel", {}).get("endpoint")
            for route in _mvpn_routes("r1", v6=v6)
            if route.get("routeType") == 1
        }
        remaining = {
            route.get("pmsiTunnel", {}).get("endpoint")
            for route in _mvpn_routes("r2", v6=v6)
            if route.get("routeType") == 1
        }
        if not endpoints.intersection(local) and not endpoints.intersection(remaining):
            return None
        return "deleted instance's Type-1 remains: local={} remote={}".format(
            local, remaining
        )

    for v6, endpoints in ((False, own_v4), (True, own_v6)):
        test_func = functools.partial(
            _type1_absent_after_instance_delete, v6, endpoints
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
