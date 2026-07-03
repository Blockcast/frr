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
                and r.get("extendedCommunity", {}).get("string") == "RT:0.0.0.0:0"
            ):
                return None
        return "Type-1 I-PMSI with IR PMSI endpoint 10.0.0.1 + RT:0.0.0.0:0 not found in {}".format(
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
