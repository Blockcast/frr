#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_mvpn_gtm_malformed.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Blockcast, Inc.
#

"""
test_bgp_mvpn_gtm_malformed.py:

Adversarial receive-path tests for the BGP MCAST-VPN (AFI 1, SAFI 5, RFC 6514)
Global Table Multicast decoder. A raw BGP speaker (peer1/crafter.py) negotiates
the MCAST-VPN AF with an FRR router and sends Type-3/4/5 NLRIs plus an empty
MP_UNREACH. The FRR side must:

  * install a VALID Type-5 (positive control),
  * DROP a Type-5 whose group is outside the SSM range 232.0.0.0/8,
  * DROP a Type-5 carrying a non-zero Route Distinguisher (GTM requires RD 0),
  * install valid S-PMSI A-D and Leaf A-D routes,
  * install BOTH NLRI of a pair that share one PMSI Tunnel attribute in one
    MP_REACH -- for a hash HIT and a hash MISS on the shared attr, and for a
    Type-1 + Type-3 mix (the parser used to let the first install strip
    attr->extra from the shared packet attr, so everything behind it lost its
    PMSI and was dropped),
  * DROP a Leaf A-D route with a malformed embedded S-PMSI route key,
  * WITHDRAW an earlier copy when a reject carries the SAME NLRI (a Type-3 or
    Type-1 re-sent without its PMSI Tunnel attribute) and KEEP it when the
    reject carries a different NLRI (a non-zero-RD Type-5 for an installed
    (S,G)) -- RFC 4271 Section 9 replacement-route semantics,
  * install the trailing sentinel Type-5, which is what proves the receiver
    consumed the whole crafted stream rather than stopping at the first
    rejection,
  * NOT crash on an MP_UNREACH that carries only AFI+SAFI (empty NLRI) -- the
    stream_new(0) assertion-abort that the receive-path hardening fixes,
  * DROP a Type-5 whose AS_PATH already contains r1's own AS (the MVPN parser
    bypasses bgp_update(), so it needs its own aspath_loop_check()), while
    still installing a Type-5 with a non-empty foreign-only AS_PATH.

The positive control is load-bearing: it proves the crafted NLRI encoding and
AF negotiation are correct, so a dropped route means the reject logic fired,
not that the whole path is broken.

Topology:

    +----+   10.0.0.0/24   +-------+
    | r1 |-----------------| peer1 |   (raw BGP speaker, crafter.py)
    +----+                 +-------+
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

VALID_SG = ("10.9.9.9", "232.9.9.9")
NONSSM_SG = ("10.20.20.1", "239.1.1.1")
NONRD_SG = ("10.20.20.2", "232.2.2.2")
SELECTIVE_SG = ("10.30.30.1", "232.30.30.1")
MALFORMED_SG = ("10.30.30.2", "232.30.30.2")
RECOVER_SG = ("10.40.40.1", "232.40.40.1")
TYPE3_ORIGINATOR = "10.0.0.2"
TYPE4_LEAF = "10.0.0.3"
PAIR_A_SG = ("10.60.60.1", "232.60.60.1")
PAIR_B_SG = ("10.60.60.2", "232.60.60.2")
MISS_A_SG = ("10.61.61.1", "232.61.61.1")
MISS_B_SG = ("10.61.61.2", "232.61.61.2")
MIX_T3_SG = ("10.62.62.1", "232.62.62.1")
MIX_T1_ORIGINATOR = "10.0.0.4"
MISS_LABEL = 0x23456
NO_PMSI_SG = ("10.30.30.9", "232.30.30.9")
V6_SELECTIVE_SG = ("2001:db8:30::1", "ff3e::30")
V6_TYPE3_ORIGINATOR = "10.0.0.2"
V6_TYPE4_LEAF = "10.0.0.3"
V6_RECOVER_SG = ("2001:db8:40::1", "ff3e::40")
V6_TYPE4_RECOVER_SG = ("2001:db8:40::2", "ff3e::41")
V6_TRUNC_RECOVER_SG = ("2001:db8:40::3", "ff3e::42")
V6_NESTED_RECOVER_SG = ("2001:db8:40::4", "ff3e::43")
SELECTIVE_LABEL = 0x12345
LOOP_SG = ("10.50.50.1", "232.50.50.1")
FOREIGN_SG = ("10.50.50.2", "232.50.50.2")
# Crafter case Z: the LAST UPDATE on the wire. Reject assertions gate on this
# so that "route absent" cannot mean "not processed yet".
SENTINEL_SG = ("10.70.70.1", "232.70.70.1")
# r1's own router-id, i.e. the originator the crafter reflects back in case G2.
R1_ORIGINATOR = "10.0.0.1"
# Crafter phase 2: each of these installs cleanly in phase 1, then is re-sent
# ~30 s later in a form that must be rejected.
STRAND_T3_SG = ("10.90.90.1", "232.90.90.1")
STRAND_T1_ORIGINATOR = "10.0.0.7"
RDKEEP_SG = ("10.91.91.1", "232.91.91.1")
SENTINEL2_SG = ("10.92.92.1", "232.92.92.1")
SENTINEL3_SG = ("10.93.93.1", "232.93.93.1")
SENTINEL4_SG = ("10.94.94.1", "232.94.94.1")
TRIGGER_DIR = None  # set in setup_module; the crafter polls it for phase files


def _fire_phase(name):
    """Tell the crafter to send a later phase, and wait for nothing.

    The crafter polls for this file rather than sleeping, so the test decides
    when each phase lands. A timed crafter would race this test: whichever ran
    first would decide whether the earlier state was still observable, and a
    lost race reports as "route not installed" -- the same message a real parse
    regression produces.
    """
    get_topogen().gears["peer1"].cmd("touch {}/{}".format(TRIGGER_DIR, name))


def _pick_route(routes, route_type, sg):
    """The route with this exact type and (S,G), or None.

    Never `next(r for r in routes if r["routeType"] == N)`: several cases now
    install Type-3s, so the first one in JSON order is not necessarily the one
    under test, and the assertion would pass or fail on iteration order.
    """
    src, grp = sg
    for route in routes:
        if (
            route.get("routeType") == route_type
            and route.get("source") == src
            and route.get("group") == grp
        ):
            return route
    return None


def _sentinel_present():
    """The crafter's last UPDATE (case Z) has been installed.

    Any assertion of the form "case X was rejected" must wait for this, not for
    an earlier positive control: the earlier control proves only that the
    receiver got that far, while the sentinel proves it consumed the whole
    crafted stream.
    """
    if _has_type5(_mvpn_routes("r1"), SENTINEL_SG):
        return None
    return "sentinel Type-5 {} not installed yet".format(SENTINEL_SG)


def build_topo(tgen):
    tgen.add_router("r1")
    peer1 = tgen.add_exabgp_peer(
        "peer1", ip="10.0.0.2/24", defaultRoute="via 10.0.0.1"
    )
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(peer1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))
    router.start()

    # Start the raw crafter on peer1. It completes the OPEN handshake,
    # advertises the MCAST-VPN capability, sends the crafted UPDATEs, then
    # holds the session open with keepalives.
    peer = tgen.gears["peer1"]
    crafter = os.path.join(CWD, "peer1/crafter.py")
    log_dir = os.path.join(peer.logdir, peer.name)
    peer.cmd("chmod 777 {}".format(log_dir))
    log_file = os.path.join(log_dir, "crafter.log")
    global TRIGGER_DIR
    TRIGGER_DIR = log_dir
    peer.cmd(
        "python3 {} 10.0.0.1 65001 10.0.0.2 {} > {} 2>&1 &".format(
            crafter, TRIGGER_DIR, log_file
        )
    )
    logger.info("crafter started on peer1")


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _mvpn_routes(router, v6=False):
    afi = "ipv6" if v6 else "ipv4"
    out = json.loads(
        get_topogen().gears[router].vtysh_cmd("show bgp {} mvpn json".format(afi))
    )
    return out.get("routes", [])


def _has_type5(routes, sg):
    src, grp = sg
    for r in routes:
        if r.get("routeType") == 5 and r.get("source") == src and r.get("group") == grp:
            return True
    return False


def _has_selective_route(
    routes, route_type, sg, leaf=None, originator=TYPE3_ORIGINATOR
):
    src, grp = sg
    for route in routes:
        if (
            route.get("routeType") == route_type
            and route.get("source") == src
            and route.get("group") == grp
            and route.get("originator") == originator
            and (leaf is None or route.get("leafOriginator") == leaf)
        ):
            return True
    return False


def test_session_established():
    """The crafter's session with r1 must reach Established.

    This proves the OPEN handshake (with the MCAST-VPN capability) completed
    and that r1 did not abort while processing the crafted UPDATE stream.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _established():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp neighbor 10.0.0.2 json")
        )
        return topotest.json_cmp(output, {"10.0.0.2": {"bgpState": "Established"}})

    _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
    assert result is None, "r1 did not reach Established with the crafter"


def test_reject_withdraws_or_keeps_per_nlri_identity():
    """A reject must withdraw an earlier copy only when it is the SAME NLRI.

    RFC 4271 Section 9: a replacement route carrying the same NLRI implicitly
    withdraws the previous advertisement. So the question at every reject is
    not "is this route bad" but "is this the same NLRI I already hold".

    Phase 1 installs three routes. ~30 s later phase 2 re-advertises all three
    in rejectable forms:

      Type-3, PMSI removed  -> same NLRI, so our copy MUST GO.
      Type-1, PMSI removed  -> same NLRI, so our copy MUST GO.
      Type-5, RD 0 -> RD 1  -> DIFFERENT NLRI, so our copy MUST SURVIVE.

    The last one is the load-bearing case. Our RIB key (struct prefix_mvpn)
    drops the Route Distinguisher because GTM mandates RD 0, so RD-0 and RD-1
    for one (S,G) collide on a single key. A reject that withdrew there would
    delete a route the peer never retracted. This test is what stops someone
    "fixing" the RD reject for symmetry with the other two.

    This test runs early and asserts the phase-1 state first, so it must see
    the installed routes before phase 2 fires.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _phase1_installed():
        routes = _mvpn_routes("r1")
        if _pick_route(routes, 3, STRAND_T3_SG) is None:
            return "phase-1 Type-3 {} not installed: {}".format(STRAND_T3_SG, routes)
        if not any(
            r.get("routeType") == 1 and r.get("originator") == STRAND_T1_ORIGINATOR
            for r in routes
        ):
            return "phase-1 Type-1 {} not installed".format(STRAND_T1_ORIGINATOR)
        if not _has_type5(routes, RDKEEP_SG):
            return "phase-1 RD-0 Type-5 {} not installed".format(RDKEEP_SG)
        return None

    _, result = topotest.run_and_expect(_phase1_installed, None, count=60, wait=1)
    assert result is None, (
        "phase-1 routes were not all installed, so the phase-2 assertions below "
        "could not distinguish a withdrawal from a route that never existed: "
        "{}".format(result)
    )

    _fire_phase("phase2")

    # POLL for the two withdrawals rather than snapshotting when the sentinel
    # lands. Removal is two-stage -- BGP_PATH_REMOVED is set and the reap runs
    # later on the work queue -- so a snapshot taken the instant the sentinel
    # appears can still see a route that is on its way out. That matters most
    # for the RD assertion below: polling until the two EXPECTED removals are
    # visible means a wrongly-removed RDKEEP would be gone by then too, which
    # is what keeps that assertion from passing vacuously.
    def _phase2_done():
        routes = _mvpn_routes("r1")
        if not _has_type5(routes, SENTINEL2_SG):
            return "phase-2 sentinel {} not seen yet".format(SENTINEL2_SG)
        if _pick_route(routes, 3, STRAND_T3_SG) is not None:
            return "Type-3 {} still present".format(STRAND_T3_SG)
        if any(
            r.get("routeType") == 1 and r.get("originator") == STRAND_T1_ORIGINATOR
            for r in routes
        ):
            return "Type-1 {} still present".format(STRAND_T1_ORIGINATOR)
        return None

    _, result = topotest.run_and_expect(_phase2_done, None, count=60, wait=1)
    assert result is None, (
        "phase 2 did not take effect: {}. A reject carrying the SAME NLRI must "
        "withdraw the earlier copy (RFC 4271 Section 9)".format(result)
    )

    routes = _mvpn_routes("r1")

    assert _pick_route(routes, 3, STRAND_T3_SG) is None, (
        "Type-3 {} survived a re-advertisement that removed its PMSI Tunnel "
        "attribute. Same NLRI, so that UPDATE replaced the earlier one and the "
        "stale selective-tunnel binding is still feeding leaf reconciliation; "
        "routes={}".format(STRAND_T3_SG, routes)
    )

    assert not any(
        r.get("routeType") == 1 and r.get("originator") == STRAND_T1_ORIGINATOR
        for r in routes
    ), (
        "Type-1 {} survived a re-advertisement that removed its PMSI Tunnel "
        "attribute; we would keep replicating to a PE that withdrew itself as "
        "an ingress-replication leaf; routes={}".format(STRAND_T1_ORIGINATOR, routes)
    )

    assert _has_type5(routes, RDKEEP_SG), (
        "RD-0 Type-5 {} was DELETED by a rejected RD-1 UPDATE for the same "
        "(S,G). Those are different NLRI: the peer never retracted the RD-0 "
        "route. The RD reject must skip, not withdraw -- our RIB key drops the "
        "RD, so withdrawing there destroys a valid route; routes={}".format(
            RDKEEP_SG, routes
        )
    )


def test_reject_withdraw_then_readvertise_restores_route():
    """A route withdrawn by a reject must come back when re-advertised well.

    Removal is two-stage: bgp_mvpn_route_remove() sets BGP_PATH_REMOVED and the
    reap runs later on the work queue. A re-advertisement that arrives before
    that drains hits the same bgp_path_info, so the install path has to call
    bgp_path_info_restore() instead of handing back a doomed one. Without that,
    the attrhash_cmp fast path returns early with the path still REMOVED and the
    route is black-holed: the peer's adj-rib-out still reads "advertised", so it
    never re-sends, and nothing recovers until a route refresh or session reset.

    This is exactly the toggle the reject-withdraw change makes easy to hit -- a
    peer whose Type-3 PMSI attribute comes and goes -- which is why it is tested
    here rather than left to the pre-existing MP_UNREACH path.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _fire_phase("phase3")

    def _restored():
        routes = _mvpn_routes("r1")
        if not _has_type5(routes, SENTINEL3_SG):
            return "phase-3 sentinel not seen yet"
        t3 = _pick_route(routes, 3, STRAND_T3_SG)
        if t3 is None:
            return "Type-3 {} did not come back".format(STRAND_T3_SG)
        if t3.get("pmsiTunnel", {}).get("label") != SELECTIVE_LABEL:
            return "Type-3 came back without its PMSI binding: {}".format(t3)
        if not any(
            r.get("routeType") == 1 and r.get("originator") == STRAND_T1_ORIGINATOR
            for r in routes
        ):
            return "Type-1 {} did not come back".format(STRAND_T1_ORIGINATOR)
        return None

    _, result = topotest.run_and_expect(_restored, None, count=60, wait=1)
    assert result is None, (
        "a route withdrawn by a reject did not return when re-advertised "
        "correctly: {}. The install path must restore a path still flagged "
        "BGP_PATH_REMOVED".format(result)
    )


def test_real_mp_unreach_withdraws_by_nlri():
    """An ordinary MP_UNREACH carrying an NLRI must remove that route.

    This is the withdraw path the reject-withdraw work is modelled on, and
    until now nothing in the tree exercised it: every other MP_UNREACH in these
    suites carries zero NLRI, and the other suites' withdrawals come from
    session teardown. Without this, someone consolidating the four
    bgp_mvpn_route_remove() call sites could break the real one and stay green.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _fire_phase("phase4")

    def _withdrawn():
        routes = _mvpn_routes("r1")
        if not _has_type5(routes, SENTINEL4_SG):
            return "phase-4 sentinel not seen yet"
        if _pick_route(routes, 3, STRAND_T3_SG) is not None:
            return "Type-3 {} survived a real MP_UNREACH".format(STRAND_T3_SG)
        return None

    _, result = topotest.run_and_expect(_withdrawn, None, count=60, wait=1)
    assert result is None, result


def test_valid_type5_accepted():
    """POSITIVE CONTROL: the valid Type-5 (RD 0, SSM group) must be installed."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _present():
        if _has_type5(_mvpn_routes("r1"), VALID_SG):
            return None
        return "valid Type-5 {} not installed on r1".format(VALID_SG)

    _, result = topotest.run_and_expect(_present, None, count=60, wait=1)
    assert result is None, (
        "r1 did not install the valid Type-5 positive control -- the crafted "
        "NLRI or AF negotiation is wrong, so the reject tests below would be "
        "meaningless"
    )


def test_non_ssm_group_rejected():
    """A Type-5 whose group is outside 232.0.0.0/8 must be dropped."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Gate on the SENTINEL (the crafter's last UPDATE), not on case A: case A
    # arrives first, so its presence would not prove this case was processed.
    _, result = topotest.run_and_expect(_sentinel_present, None, count=60, wait=1)
    assert result is None, "sentinel missing; cannot assert rejection"

    routes = _mvpn_routes("r1")
    assert not _has_type5(routes, NONSSM_SG), (
        "r1 installed a non-SSM Type-5 {} (group outside 232.0.0.0/8); "
        "routes={}".format(NONSSM_SG, routes)
    )


def test_non_zero_rd_rejected():
    """A Type-5 carrying a non-zero RD must be dropped under GTM (RD == 0)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _, result = topotest.run_and_expect(_sentinel_present, None, count=60, wait=1)
    assert result is None, "sentinel missing; cannot assert rejection"

    routes = _mvpn_routes("r1")
    assert not _has_type5(routes, NONRD_SG), (
        "r1 installed a non-zero-RD Type-5 {}; routes={}".format(NONRD_SG, routes)
    )


def test_valid_type3_and_type4_accepted():
    """Valid S-PMSI and Leaf A-D routes must install with their exact keys."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _present():
        routes = _mvpn_routes("r1")
        if not _has_selective_route(routes, 3, SELECTIVE_SG):
            return "valid Type-3 not installed: {}".format(routes)
        type3 = _pick_route(routes, 3, SELECTIVE_SG)
        if not type3.get("pmsiTunnel", {}).get("leafInfoRequired"):
            return "Type-3 PMSI L-bit was not preserved: {}".format(type3)
        if type3.get("pmsiTunnel", {}).get("label") != SELECTIVE_LABEL:
            return "Type-3 PMSI label was not decoded from its high 20 bits: {}".format(
                type3
            )
        if not _has_selective_route(routes, 4, SELECTIVE_SG, TYPE4_LEAF):
            return "valid Type-4 not installed: {}".format(routes)
        return None

    _, result = topotest.run_and_expect(_present, None, count=60, wait=1)
    assert result is None, result


def test_two_type3_one_pmsi_attr_both_install():
    """Two Type-3s sharing one PMSI Tunnel attribute in one UPDATE both install.

    bgp_nlri_parse_mvpn() passes the packet's single attr to every NLRI in
    the MP_REACH. bgp_attr_intern() treats an attr not marked as the
    NLRI-scoped parsed attr as caller-owned and either steals attr->extra
    (hash miss) or frees it (hash hit), so before the fix the first install
    stripped the PMSI Tunnel info from the shared attr and every following
    Type-3 in the same UPDATE was dropped as "without Ingress-Replication
    PMSI Tunnel". Live: a 17-Type-3 UPDATE from the sfo12 PE lost 16.

    PAIR_A (first NLRI) is the positive control that always installed;
    PAIR_B (second NLRI) is the one that used to vanish. Both must carry the
    IR tunnel type, the L-bit and the label -- proving the extra was copied
    into the RIB attr, not merely present at parse time.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _present():
        routes = _mvpn_routes("r1")
        if not _has_selective_route(routes, 3, PAIR_A_SG):
            return "first Type-3 of the pair {} not installed: {}".format(
                PAIR_A_SG, routes
            )
        if not _has_selective_route(routes, 3, PAIR_B_SG):
            return (
                "second Type-3 {} of a two-NLRI UPDATE not installed -- the "
                "first install stripped the shared attr's PMSI extra".format(
                    PAIR_B_SG
                )
            )
        for sg in (PAIR_A_SG, PAIR_B_SG):
            r = next(
                x
                for x in routes
                if x.get("routeType") == 3
                and x.get("source") == sg[0]
                and x.get("group") == sg[1]
            )
            pm = r.get("pmsiTunnel", {})
            if not pm.get("leafInfoRequired") or pm.get("label") != SELECTIVE_LABEL:
                return "Type-3 {} installed without its PMSI binding: {}".format(sg, r)
        return None

    _, result = topotest.run_and_expect(_present, None, count=60, wait=1)
    assert result is None, result


def test_two_type3_one_pmsi_attr_hash_miss_both_install():
    """Same as above, but where the shared attr's intern is a hash MISS.

    The two halves of the bug live in different branches of bgp_attr_intern().
    D3's attributes are byte-identical to case D's, so its intern is a hash HIT
    and it exercises bgp_attr_extra_discard(). D4 carries a PMSI label no other
    UPDATE uses, so its intern misses the attribute hash and runs
    bgp_attr_hash_alloc(), which is the branch that used to TAKE attr->extra and
    NULL it on the caller. Without this case a regression confined to that
    branch would pass the suite.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _present():
        routes = _mvpn_routes("r1")
        for sg in (MISS_A_SG, MISS_B_SG):
            route = _pick_route(routes, 3, sg)
            if route is None:
                return "hash-miss pair member {} not installed: {}".format(sg, routes)
            pm = route.get("pmsiTunnel", {})
            if not pm.get("leafInfoRequired") or pm.get("label") != MISS_LABEL:
                return "Type-3 {} lost its PMSI binding: {}".format(sg, route)
        return None

    _, result = topotest.run_and_expect(_present, None, count=60, wait=1)
    assert result is None, result


def test_type1_and_type3_one_pmsi_attr_both_install():
    """A Type-1 followed by a Type-3 behind one PMSI attribute -- the live shape.

    The live UPDATEs that exposed this carried mixed route types, and Type-1 has
    its own Ingress-Replication PMSI gate and its own RIB-AFI selection, so the
    Type-3-only pairs above do not cover it. The Type-1 here carries a FOREIGN
    originator; a reflection of our own is case G2 and must still be rejected.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _present():
        routes = _mvpn_routes("r1")
        type1 = [
            r
            for r in routes
            if r.get("routeType") == 1 and r.get("originator") == MIX_T1_ORIGINATOR
        ]
        if len(type1) != 1:
            return "want exactly 1 foreign Type-1 for {}, got {}: {}".format(
                MIX_T1_ORIGINATOR, len(type1), routes
            )
        # Type-1's JSON carries type/label/endpoint but no leafInfoRequired --
        # the parser gates Type-1 on the tunnel TYPE being ingress replication
        # (bgp_attr_get_pmsi_tnl_type), so assert that and the label.
        pm1 = type1[0].get("pmsiTunnel", {})
        if pm1.get("type") != "ingressReplication" or pm1.get("label") != SELECTIVE_LABEL:
            return "Type-1 lost its PMSI binding: {}".format(type1[0])
        type3 = _pick_route(routes, 3, MIX_T3_SG)
        if type3 is None:
            return "Type-3 behind the Type-1 not installed: {}".format(routes)
        if not type3.get("pmsiTunnel", {}).get("leafInfoRequired"):
            return "Type-3 after a Type-1 lost its PMSI binding: {}".format(type3)
        return None

    _, result = topotest.run_and_expect(_present, None, count=60, wait=1)
    assert result is None, result


def test_valid_ipv6_type3_and_type4_accepted():
    """IPv6 (S,G) with IPv4 router-id originators remains correctly framed."""

    def _present():
        routes = _mvpn_routes("r1", v6=True)
        if not _has_selective_route(
            routes, 3, V6_SELECTIVE_SG, originator=V6_TYPE3_ORIGINATOR
        ):
            return "valid IPv6 Type-3 not installed: {}".format(routes)
        if not _has_selective_route(
            routes,
            4,
            V6_SELECTIVE_SG,
            leaf=V6_TYPE4_LEAF,
            originator=V6_TYPE3_ORIGINATOR,
        ):
            return "valid IPv6 Type-4 not installed: {}".format(routes)
        type3 = _pick_route(routes, 3, V6_SELECTIVE_SG)
        if not type3.get("pmsiTunnel", {}).get("leafInfoRequired"):
            return "IPv6 Type-3 PMSI L-bit was not preserved: {}".format(type3)
        if not _has_type5(routes, V6_RECOVER_SG):
            return "Type-5 following IPv6 Type-3 was desynchronized: {}".format(routes)
        if not _has_type5(routes, V6_TYPE4_RECOVER_SG):
            return "Type-5 following IPv6 Type-4 was desynchronized: {}".format(routes)
        if not _has_type5(routes, V6_TRUNC_RECOVER_SG):
            return "Type-3 consumed the following Type-5 route-type byte: {}".format(
                routes
            )
        if not _has_type5(routes, V6_NESTED_RECOVER_SG):
            return "malformed Type-4 nested body consumed trailing Type-5: {}".format(
                routes
            )
        return None

    _, result = topotest.run_and_expect(_present, None, count=60, wait=1)
    assert result is None, result


def test_reflected_local_type1_rejected():
    """A peer cannot install a second Type-1 for this router's originator.

    Filter by originator rather than counting every Type-1: a peer may
    legitimately advertise Type-1s for ITS OWN originators, and this assertion
    is about the reflected copy of OURS.
    """
    _, result = topotest.run_and_expect(_sentinel_present, None, count=60, wait=1)
    assert result is None, "sentinel missing; cannot assert rejection"

    routes = [
        r
        for r in _mvpn_routes("r1")
        if r.get("routeType") == 1 and r.get("originator") == R1_ORIGINATOR
    ]
    assert len(routes) == 1 and routes[0].get("selfOriginated"), routes


def test_type3_without_pmsi_rejected():
    """A Type-3 without an ingress-replication PMSI binding is unusable."""
    _, result = topotest.run_and_expect(_sentinel_present, None, count=60, wait=1)
    assert result is None, "sentinel missing; cannot assert rejection"

    routes = _mvpn_routes("r1")
    assert not _has_selective_route(routes, 3, NO_PMSI_SG), routes


def test_malformed_nested_type3_rejected():
    """A Leaf A-D route with a lying embedded Type-3 length must not install."""
    _, result = topotest.run_and_expect(_sentinel_present, None, count=60, wait=1)
    assert result is None, "sentinel missing; cannot assert rejection"

    routes = _mvpn_routes("r1")
    assert not _has_selective_route(routes, 4, MALFORMED_SG, TYPE4_LEAF), routes


def test_intrapacket_framing_recovery():
    """A valid Type-5 following a malformed NLRI in the SAME UPDATE must install.

    test_malformed_nested_type3_rejected proves a lone malformed Leaf A-D is
    dropped without resetting the session, but not that framing recovers *within*
    the packet. Here (crafter case E2) a malformed Type-4 -- lying embedded Type-3
    length -- is immediately followed by a well-formed Type-5 in one MP_REACH. The
    receiver must skip the malformed NLRI by its outer length (the length-2 skip
    arithmetic) and still parse+install the trailing Type-5. If the skip is off by
    any amount, the trailing route never appears. (BLO-15578 review follow-up.)
    """

    def _present():
        if not _has_type5(_mvpn_routes("r1"), RECOVER_SG):
            return "trailing valid Type-5 {} after a malformed NLRI not installed".format(
                RECOVER_SG
            )
        return None

    _, result = topotest.run_and_expect(_present, None, count=60, wait=1)
    assert result is None, (
        "r1 did not install the Type-5 that followed a malformed NLRI in the same "
        "UPDATE -- intra-packet framing recovery (the length-2 skip) is broken"
    )


def test_no_crash_after_empty_mp_unreach():
    """The empty MP_UNREACH (AFI+SAFI only) must not abort bgpd.

    Before the fix, a zero-length MVPN withdraw NLRI reached stream_new(0),
    which asserts, aborting bgpd. If that happens the session drops and the
    positive-control route disappears. Assert both are still healthy after the
    crafter has sent the empty MP_UNREACH.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _healthy():
        nb = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp neighbor 10.0.0.2 json")
        )
        if topotest.json_cmp(nb, {"10.0.0.2": {"bgpState": "Established"}}) is not None:
            return "session not Established (bgpd may have aborted)"
        if not _has_type5(_mvpn_routes("r1"), VALID_SG):
            return "positive control gone (bgpd may have restarted)"
        # The sentinel is sent AFTER the empty MP_UNREACH, so its presence is
        # what proves bgpd survived that UPDATE and kept parsing.
        return _sentinel_present()

    _, result = topotest.run_and_expect(_healthy, None, count=60, wait=1)
    assert result is None, "r1 unhealthy after empty MP_UNREACH: bgpd did not survive"


def test_own_as_in_path_rejected():
    """A Type-5 whose AS_PATH contains r1's own AS must be dropped.

    bgp_nlri_parse_mvpn() installs into the MCAST-VPN RIB directly and never
    passes through bgp_update(), so it needs its own AS-path loop check.
    Without one a neighbour's copy of OUR route is accepted and re-advertised
    with our AS prepended again, and the two speakers ping-pong every MVPN
    route indefinitely.

    The live trigger was an eBGP session; this suite's session is iBGP. The
    check keys on the LOCAL AS (bgp->as), not on the peer's, so it fires the
    same either way -- but that also means this case alone cannot tell the two
    apart. bgp_mvpn_gtm_umh_ebgp::test_ebgp_own_as_in_path_rejected covers the
    same rejection over a genuine eBGP session, where a check written against
    peer->as would wrongly drop every route the peer sends.

    Gate on crafter case H2 (a Type-5 carrying a non-empty, foreign-only
    AS_PATH) being installed: that proves the AS_PATH encoding is accepted, so
    LOOP_SG's absence is the loop check firing and nothing else. The
    neighbour's aspathLoop denial counter must have moved as well.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _control_present():
        if _has_type5(_mvpn_routes("r1"), FOREIGN_SG):
            return None
        return "foreign-AS_PATH positive control {} not yet installed".format(
            FOREIGN_SG
        )

    _, result = topotest.run_and_expect(_control_present, None, count=60, wait=1)
    assert result is None, (
        "r1 did not install the Type-5 with a non-empty foreign-only AS_PATH; "
        "the AS_PATH encoding is wrong, so the loop-rejection assertion below "
        "would be meaningless"
    )

    routes = _mvpn_routes("r1")
    assert not _has_type5(routes, LOOP_SG), (
        "r1 installed a Type-5 {} whose AS_PATH contains its own AS 65001; "
        "routes={}".format(LOOP_SG, routes)
    )

    nb = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp neighbor 10.0.0.2 json"))
    loops = nb["10.0.0.2"].get("prefixStats", {}).get("aspathLoop")
    assert loops == 1, (
        "expected exactly one AS-path loop denial on the crafter session, "
        "got {}: {}".format(loops, nb["10.0.0.2"].get("prefixStats"))
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
