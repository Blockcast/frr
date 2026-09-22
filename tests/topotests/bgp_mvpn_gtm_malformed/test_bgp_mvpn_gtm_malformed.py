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
  * DROP a Leaf A-D route with a malformed embedded S-PMSI route key,
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
    peer.cmd("python3 {} 10.0.0.1 65001 10.0.0.2 > {} 2>&1 &".format(crafter, log_file))
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

    # Gate on the positive control so "absent" means "rejected", not "not yet
    # processed".
    def _control_present():
        if _has_type5(_mvpn_routes("r1"), VALID_SG):
            return None
        return "positive control not yet present"

    _, result = topotest.run_and_expect(_control_present, None, count=60, wait=1)
    assert result is None, "positive control missing; cannot assert rejection"

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

    def _control_present():
        if _has_type5(_mvpn_routes("r1"), VALID_SG):
            return None
        return "positive control not yet present"

    _, result = topotest.run_and_expect(_control_present, None, count=60, wait=1)
    assert result is None, "positive control missing; cannot assert rejection"

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
        type3 = next(route for route in routes if route.get("routeType") == 3)
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
        type3 = next(route for route in routes if route.get("routeType") == 3)
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
    """A peer cannot install a second Type-1 for this router's originator."""
    routes = [r for r in _mvpn_routes("r1") if r.get("routeType") == 1]
    assert len(routes) == 1 and routes[0].get("selfOriginated"), routes


def test_type3_without_pmsi_rejected():
    """A Type-3 without an ingress-replication PMSI binding is unusable."""
    routes = _mvpn_routes("r1")
    assert not _has_selective_route(routes, 3, NO_PMSI_SG), routes


def test_malformed_nested_type3_rejected():
    """A Leaf A-D route with a lying embedded Type-3 length must not install."""
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
        return None

    _, result = topotest.run_and_expect(_healthy, None, count=60, wait=1)
    assert result is None, "r1 unhealthy after empty MP_UNREACH: bgpd did not survive"


def test_own_as_in_path_rejected():
    """A Type-5 whose AS_PATH contains r1's own AS must be dropped.

    bgp_nlri_parse_mvpn() installs into the MCAST-VPN RIB directly and never
    passes through bgp_update(), so it needs its own AS-path loop check.
    Without one, an eBGP neighbour's copy of OUR route is accepted and
    re-advertised with our AS prepended again; measured live between the
    sfo12 PE (AS 65001) and the nbg6817 PoP (AS 65010) the AS_PATH had grown
    to ~1.9 kB and the session carried ~115 UPDATEs/s at idle.

    Gate on crafter case H2 (a Type-5 carrying a non-empty, foreign-only
    AS_PATH) being installed: that proves the AS4 AS_SEQUENCE encoding is
    accepted, so LOOP_SG's absence is the loop check firing and nothing else.
    The neighbour's aspathLoop denial counter must have moved as well.
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
