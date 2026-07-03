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

Verify that the BGP MCAST-VPN address family (AFI 1, SAFI 5 / IANA SAFI 5,
RFC 6514) registers and negotiates the multiprotocol capability between two
iBGP speakers.

Topology:

    +----+   10.0.0.0/24   +----+
    | r1 |-----------------| r2 |
    +----+                 +----+

Both routers run `router bgp 65001`, peer over the shared subnet, and enable
`address-family ipv4 mvpn` with `neighbor <peer> activate`. The test asserts
the MVPN AF is advertised and received in the multiprotocol capability, and
that a locally-originated Route Type 5 (Source Active A-D, RFC 6514 / GTM
RFC 7716) route on r1 propagates to r2.
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
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
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


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
    """A local GTM Source Active (Type 5) route on r1 must reach r2 via BGP.

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
        out = json.loads(tgen.gears[router].vtysh_cmd("show bgp ipv4 mvpn json"))
        routes = out.get("routes", [])
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


def test_type7_source_tree_join_propagates():
    """A local GTM Source Tree Join (Type 7) route on r2 must reach r1 via BGP.

    r2 injects a C-multicast Source Tree Join (Type 7, RFC 6514 Section 4.6) via
    the TEST-ONLY `bgp mvpn test-join <S> group <G> source-as <asn>` scaffold
    (Plan 3 replaces this with pimd-driven origination). r1 must learn it and
    expose it via `show bgp ipv4 mvpn json` with routeType 7, the matching
    (S,G), and the carried Source AS.

    The Type-7 must also carry the RFC 7716 Section 2.2 / 2.9 upstream-node RT
    (Global Administrator = the upstream PE, Local Administrator = 0). r2
    auto-resolves the upstream from r1's Source Active route (next hop 10.0.0.1),
    so r1 sees extendedCommunity "RT:10.0.0.1:0" -- the RT that identifies r1 as
    the upstream PBR that must import the join.

    AUTHORED-NOT-RUN: this repo has no network namespaces, so the topotest is
    authored and py_compile-checked but not executed here.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
router bgp 65001
 address-family ipv4 mvpn
  bgp mvpn test-join 10.10.10.1 group 232.1.1.1 source-as 65001
"""
    )

    def _type7_present(router):
        out = json.loads(tgen.gears[router].vtysh_cmd("show bgp ipv4 mvpn json"))
        routes = out.get("routes", [])
        for r in routes:
            if (
                r.get("routeType") == 7
                and r.get("source") == "10.10.10.1"
                and r.get("group") == "232.1.1.1"
                and r.get("sourceAs") == 65001
                and r.get("extendedCommunity", {}).get("string") == "RT:10.0.0.1:0"
            ):
                return None
        return "Type-7 (10.10.10.1, 232.1.1.1, AS 65001) with RT:10.0.0.1:0 not found in {}".format(
            routes
        )

    test_func = functools.partial(_type7_present, "r1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 did not learn r2's MVPN Type-7 Source Tree Join route"


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

    r2 originates 10.99.99.1/32 with route-import RT 10.255.0.2:0 and a Source
    Active for (10.99.99.1, 232.9.9.9) whose next hop is r2's router-id 10.0.0.2,
    then test-joins it. The Type-7 must carry RT:10.255.0.2:0 (the route-import
    Global Administrator), NOT RT:10.0.0.2:0 (the SA next hop).

    AUTHORED-NOT-RUN: this repo has no network namespaces, so the topotest is
    authored and py_compile-checked but not executed here. The resolver path was
    exercised live on a single dev-build bgpd: with the source route carrying
    RT:10.255.0.2:0, the locally-originated Type-7 carried RT:10.255.0.2:0.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
route-map set-rtimport permit 10
 set extcommunity rt 10.255.0.2:0
exit
router bgp 65001
 no bgp network import-check
 address-family ipv4 unicast
  network 10.99.99.1/32 route-map set-rtimport
 exit-address-family
 address-family ipv4 mvpn
  bgp mvpn source-active 10.99.99.1 group 232.9.9.9
  bgp mvpn test-join 10.99.99.1 group 232.9.9.9 source-as 65001
"""
    )

    def _type7_rtimport(router):
        out = json.loads(tgen.gears[router].vtysh_cmd("show bgp ipv4 mvpn json"))
        routes = out.get("routes", [])
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
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
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

    r2 originates 10.99.99.2/32 carrying vrf-route-import 10.255.0.3:0 and a Source
    Active for (10.99.99.2, 232.9.9.10), then test-joins it. The Type-7 must carry
    RT:10.255.0.3:0 (the route-import Global Administrator), NOT RT:10.0.0.2:0 (the
    SA next hop).

    AUTHORED-NOT-RUN: this repo has no network namespaces, so the topotest is
    authored and py_compile-checked but not executed here. The clause and resolver
    branch were exercised live on a single dev-build bgpd: the source route tagged
    with vrf-route-import 10.255.0.3:0 round-tripped through running-config, and
    the locally-originated Type-7 carried RT:10.255.0.3:0.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
route-map set-vri permit 10
 set extcommunity vrf-route-import 10.255.0.3:0
exit
router bgp 65001
 no bgp network import-check
 address-family ipv4 unicast
  network 10.99.99.2/32 route-map set-vri
 exit-address-family
 address-family ipv4 mvpn
  bgp mvpn source-active 10.99.99.2 group 232.9.9.10
  bgp mvpn test-join 10.99.99.2 group 232.9.9.10 source-as 65001
"""
    )

    def _type7_vri(router):
        out = json.loads(tgen.gears[router].vtysh_cmd("show bgp ipv4 mvpn json"))
        routes = out.get("routes", [])
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
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Type-7 upstream RT was not resolved from the VRF Route Import (0x0b) EC"


def test_type5_v6_source_active_propagates():
    """A local IPv6 GTM Source Active (Type 5) route on r1 must reach r2 (RFC 6515).

    r1 is configured under `address-family ipv6 mvpn` with
    `bgp mvpn source-active 2001:db8::1 group ff3e::1`. r2 must learn it and
    expose it via `show bgp ipv6 mvpn json` with routeType 5, the v6 (S,G), and
    the GTM global-table Route Target RT:0.0.0.0:0 -- exercising the AFI_IP6
    MCAST-VPN AF (capability negotiated over the shared session, the v6 NLRI
    codec, and the v6 RIB).

    AUTHORED-NOT-RUN: this repo has no network namespaces; authored and
    py_compile-checked. Verified live on a dev-build bgpd: the v6 source-active
    installs into the AFI_IP6 MCAST-VPN RIB and renders source 2001:db8::1 group
    ff3e::1 under `show bgp ipv6 mvpn`.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _type5_v6_present(router):
        out = json.loads(tgen.gears[router].vtysh_cmd("show bgp ipv6 mvpn json"))
        routes = out.get("routes", [])
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

    AUTHORED-NOT-RUN: this repo has no network namespaces; authored and
    py_compile-checked.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _type1_v6_present(router):
        out = json.loads(tgen.gears[router].vtysh_cmd("show bgp ipv6 mvpn json"))
        routes = out.get("routes", [])
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


def test_type7_v6_umh_from_vrf_route_import():
    """IPv6 Type-7 upstream RT resolves from the v6 source route's VRF Route
    Import EC (RFC 6514 Section 5.1 / RFC 6515), exercising the AFI_IP6 unicast
    RIB lookup in the resolver.

    r2 originates 2001:db8:99::1/128 tagged with vrf-route-import 10.255.0.3:0
    (the upstream PE is a v4-core identity even for a v6 C-S) and a v6 Source
    Active for (2001:db8:99::1, ff3e::9), then test-joins it. The Type-7 must
    carry RT:10.255.0.3:0 (the route-import Global Administrator).

    AUTHORED-NOT-RUN: authored and py_compile-checked. The v6 resolver arm and
    origination were exercised on a dev-build bgpd (v6 routes install into the
    AFI_IP6 RIB and the join resolves the v4-core upstream from the v6 source
    route's route-import EC).
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
route-map set-vri6 permit 10
 set extcommunity vrf-route-import 10.255.0.3:0
exit
router bgp 65001
 no bgp network import-check
 address-family ipv6 unicast
  network 2001:db8:99::1/128 route-map set-vri6
 exit-address-family
 address-family ipv6 mvpn
  bgp mvpn source-active 2001:db8:99::1 group ff3e::9
  bgp mvpn test-join 2001:db8:99::1 group ff3e::9 source-as 65001
"""
    )

    def _type7_v6_vri(router):
        out = json.loads(tgen.gears[router].vtysh_cmd("show bgp ipv6 mvpn json"))
        routes = out.get("routes", [])
        for r in routes:
            if (
                r.get("routeType") == 7
                and r.get("source") == "2001:db8:99::1"
                and r.get("group") == "ff3e::9"
            ):
                rt = r.get("extendedCommunity", {}).get("string")
                if rt == "RT:10.255.0.3:0":
                    return None
                return "IPv6 Type-7 (2001:db8:99::1, ff3e::9) carries {} (want RT:10.255.0.3:0)".format(
                    rt
                )
        return "IPv6 Type-7 (2001:db8:99::1, ff3e::9) not found in {}".format(routes)

    test_func = functools.partial(_type7_v6_vri, "r2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), "IPv6 Type-7 upstream RT was not resolved from the v6 route's VRF Route Import EC"


def test_type1_ipmsi_with_ir_pmsi():
    """On MVPN AF enable, r1 auto-originates its Intra-AS I-PMSI A-D route.

    RFC 6514 Section 4.1 Route Type 1 (Intra-AS I-PMSI A-D) is originated by
    each PE when the MCAST-VPN AF is enabled. r1's Type-1 carries a PMSI Tunnel
    attribute (RFC 6514 Section 5) with Tunnel Type = Ingress Replication (6)
    and r1's own unicast address (10.0.0.1, the auto-derived router-id) as the
    tunnel endpoint. It also carries the GTM global-table Route Target
    "RT:0.0.0.0:0" (the fixed import/export target for non-C-multicast GTM
    routes). r2 must learn it via `show bgp ipv4 mvpn json` with routeType 1, the
    matching pmsiTunnel object, and that extendedCommunity.

    AUTHORED-NOT-RUN: this repo has no network namespaces, so the topotest is
    authored and py_compile-checked but not executed here.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _type1_present(router):
        out = json.loads(tgen.gears[router].vtysh_cmd("show bgp ipv4 mvpn json"))
        routes = out.get("routes", [])
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


def test_plan1_full_mvpn_exchange():
    """Plan-1 end-to-end: SAFI-5 session + Type-1/5/7 exchange in one scenario.

    Combined assertion over the whole Plan-1 deliverable: with the iBGP
    session Established and the MVPN AF negotiated, BOTH peers' MVPN tables
    (`show bgp ipv4 mvpn json`) must simultaneously contain the full expected
    route mix:

    - r2 sees r1's Type-1 Intra-AS I-PMSI A-D with an Ingress Replication
      PMSI tunnel and endpoint 10.0.0.1, AND r1's Type-5 Source Active for
      (10.10.10.1, 232.1.1.1).
    - r1 sees r2's Type-1 with endpoint 10.0.0.2, AND (after the test-only
      Type-7 inject on r2) r2's Type-7 Source Tree Join for
      (10.10.10.1, 232.1.1.1) carrying Source AS 65001.

    All of this is RIB-level control plane; forwarding is a later milestone.

    AUTHORED-NOT-RUN: this repo has no network namespaces, so the topotest is
    authored and py_compile-checked but not executed here.
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

    # Re-assert the test-only Type-7 inject on r2. Idempotent, so this keeps
    # the combined test self-contained regardless of per-type test ordering.
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
router bgp 65001
 address-family ipv4 mvpn
  bgp mvpn test-join 10.10.10.1 group 232.1.1.1 source-as 65001
"""
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

    def _full_exchange():
        r1_routes = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp ipv4 mvpn json")
        ).get("routes", [])
        r2_routes = json.loads(
            tgen.gears["r2"].vtysh_cmd("show bgp ipv4 mvpn json")
        ).get("routes", [])

        missing = []
        if not _has_type1(r2_routes, "10.0.0.1"):
            missing.append("r2 lacks r1's Type-1 (IR endpoint 10.0.0.1)")
        if not _has_type5(r2_routes, "10.10.10.1", "232.1.1.1"):
            missing.append("r2 lacks r1's Type-5 (10.10.10.1, 232.1.1.1)")
        if not _has_type1(r1_routes, "10.0.0.2"):
            missing.append("r1 lacks r2's Type-1 (IR endpoint 10.0.0.2)")
        if not _has_type7(r1_routes, "10.10.10.1", "232.1.1.1", 65001):
            missing.append(
                "r1 lacks r2's Type-7 (10.10.10.1, 232.1.1.1, AS 65001)"
            )

        if missing:
            return "{} [r1={} r2={}]".format(
                "; ".join(missing), r1_routes, r2_routes
            )
        return None

    _, result = topotest.run_and_expect(_full_exchange, None, count=60, wait=1)
    assert result is None, "Plan-1 full MVPN exchange incomplete: {}".format(
        result
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
