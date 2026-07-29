#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_mvpn_gtm_umh_lc.py: UMH resolution from the draft-ietf-mboned-dimt
transitive large community (RFC 8092), canonical RFC 8195 layout
<sourceAS>:<function>:<UMH-IPv4-as-uint32>, gated by the per-instance
"bgp mvpn umh-large-community <function>" knob (unset = decode disabled).

r2 (eBGP AS 65010) originates the source-covering routes with route-maps
attaching the communities -- exactly the by-policy origination a carrier
router (Junos/Arista) uses, so this doubles as the origination-path check.
eBGP matters: the origin AS is 65010, NOT r1's local 65001, so a Type-7 keyed
by Source AS 65010 proves the value flowed from the large community tuple
(the RFC 6514 fallback would have produced 65001).

Per-prefix scenarios (see r2/bgpd.conf):
  p1 10.10.10.0/24  LC + RT ec        precedence: EC when knob unset, LC when set
  p2 10.10.20.0/24  GA!=origin + ec   origin-AS trust reject -> EC fallback
  p3 10.10.30.0/24  two LC tuples     lowest tuple wins (10.0.0.1)
  p4 10.10.40.0/24  multicast param   invalid UMH -> EC fallback
  p5 10.10.50.0/24  LC only           no fallback exists: RT proves LC decode
  p6 2001:db8:53::/64 LC only         v6 C-S, v4 UMH (RFC 6515 pattern)
  p7 10.10.70.0/24  param 0           invalid UMH (0.0.0.0) -> EC fallback
  p8 10.10.80.0/24  param 127.0.0.1   invalid UMH (loopback) -> EC fallback
  p9 10.10.90.0/24  wrong function    fn 2 != knob 1, skipped -> EC fallback
  p10 10.10.100.0/24 param 255.255.255.255 Class E/broadcast -> EC fallback
  p11 10.10.110.0/24 param 240.0.0.1  Class E (240/4) -> EC fallback
  p12 10.10.120.0/24 param 169.254.0.1 link-local (169.254/16) -> EC fallback
  p13 10.10.130.0/24 param 0.0.0.1    nonzero 0/8 -> EC fallback

The knob is set mid-test (existing joins must re-resolve WITHOUT re-joining),
changed communities re-originate via the unicast-route reresolve, and the
unset must fall everything back to the extended-community path.

    +----+   10.0.0.0/24 + 2001:db8:1::/64   +----+
    | r1 |------------------------------------| r2 |
    +----+                                    +----+
      | 192.168.2.0/24 + 2001:db8:2::/64 (receiver stub)
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

LOCAL_AS = 65001
PEER_AS = 65010
FN = 1
# 184549374 == 10.255.255.254 -- the endian known-answer vector.
UMH_KAT = "10.255.255.254"
# 167772161 == 10.0.0.1 -- the lower of p3's two tuples.
UMH_LOW = "10.0.0.1"
EC_RT = "10.9.9.9"

JOINS_V4 = {
    "p1": ("10.10.10.10", "232.1.1.1"),
    "p2": ("10.10.20.10", "232.1.1.2"),
    "p3": ("10.10.30.10", "232.1.1.3"),
    "p4": ("10.10.40.10", "232.1.1.4"),
    "p5": ("10.10.50.10", "232.1.1.5"),
    "p7": ("10.10.70.10", "232.1.1.7"),
    "p8": ("10.10.80.10", "232.1.1.8"),
    "p9": ("10.10.90.10", "232.1.1.9"),
    "p10": ("10.10.100.10", "232.1.1.10"),
    "p11": ("10.10.110.10", "232.1.1.11"),
    "p12": ("10.10.120.10", "232.1.1.12"),
    "p13": ("10.10.130.10", "232.1.1.13"),
}
JOIN_V6 = ("2001:db8:53::10", "ff3e::232:1")


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1's receiver stub (the IGMP/MLD joins live here)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    r1.load_config(TopoRouter.RD_PIM, os.path.join(CWD, "r1/pimd.conf"))
    r1.load_config(TopoRouter.RD_PIM6, os.path.join(CWD, "r1/pim6d.conf"))
    r1.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))

    r2 = tgen.gears["r2"]
    r2.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r2/zebra.conf"))
    r2.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r2/bgpd.conf"))

    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def _mvpn_routes(v6=False):
    cmd = "show bgp ipv6 mvpn json" if v6 else "show bgp ipv4 mvpn json"
    out = json.loads(get_topogen().gears["r1"].vtysh_cmd(cmd))
    return out.get("routes", [])


def _type7(source, group, v6=False):
    for r in _mvpn_routes(v6):
        if (
            r.get("routeType") == 7
            and r.get("source") == source
            and r.get("group") == group
        ):
            return r
    return None


def _expect_type7(source, group, source_as, rt, v6=False):
    """Wait for the (S,G) Type-7 to exist with exactly this Source AS and
    upstream RT (rt=None: no extendedCommunity at all)."""

    def _check():
        r = _type7(source, group, v6)
        if r is None:
            return "no Type-7 for ({}, {})".format(source, group)
        if r.get("sourceAs") != source_as:
            return "Type-7 ({}, {}) has Source AS {}, want {}: {}".format(
                source, group, r.get("sourceAs"), source_as, r
            )
        got_rt = r.get("extendedCommunity", {}).get("string")
        want_rt = "RT:{}:0".format(rt) if rt else None
        if got_rt != want_rt:
            return "Type-7 ({}, {}) has RT {}, want {}: {}".format(
                source, group, got_rt, want_rt, r
            )
        return None

    _, result = topotest.run_and_expect(_check, None, count=90, wait=1)
    assert result is None, result


def _expect_single_type7(source, group, source_as, rt, v6=False):
    """Like _expect_type7, but also assert EXACTLY ONE Type-7 exists for
    (S,G). A re-resolution that changes the Source AS must WITHDRAW the old
    NLRI key, not strand it (the live-observed regression). _expect_type7
    matches on (source, group) only, so on a strand it passes or fails on RIB
    sort order; this counts the keys explicitly."""

    def _check():
        matches = [
            r
            for r in _mvpn_routes(v6)
            if r.get("routeType") == 7
            and r.get("source") == source
            and r.get("group") == group
        ]
        if len(matches) != 1:
            return "want exactly 1 Type-7 for ({}, {}), found {}: {}".format(
                source, group, len(matches), matches
            )
        r = matches[0]
        if r.get("sourceAs") != source_as:
            return "Type-7 ({}, {}) has Source AS {}, want {}: {}".format(
                source, group, r.get("sourceAs"), source_as, r
            )
        got_rt = r.get("extendedCommunity", {}).get("string")
        want_rt = "RT:{}:0".format(rt) if rt else None
        if got_rt != want_rt:
            return "Type-7 ({}, {}) has RT {}, want {}: {}".format(
                source, group, got_rt, want_rt, r
            )
        return None

    _, result = topotest.run_and_expect(_check, None, count=90, wait=1)
    assert result is None, result


def _join(source, group, v6=False):
    proto = "ipv6 mld" if v6 else "ip igmp"
    get_topogen().gears["r1"].vtysh_cmd(
        """
configure terminal
interface r1-eth1
 {} join-group {} {}
""".format(proto, group, source)
    )


def test_sessions_established():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for neigh in ("10.0.0.2", "2001:db8:1::2"):

        def _established(neigh=neigh):
            out = json.loads(
                tgen.gears["r1"].vtysh_cmd("show bgp neighbor {} json".format(neigh))
            )
            return topotest.json_cmp(out, {neigh: {"bgpState": "Established"}})

        _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
        assert result is None, "r1 did not reach Established with {}".format(neigh)


def test_knob_unset_ignores_large_community():
    """REGRESSION GUARD: with "bgp mvpn umh-large-community" unset, the
    resolver must not decode large communities at all -- p1's Type-7 resolves
    from the plain RT extended community, Source AS falls back to local."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p1"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_knob_set_reresolves_existing_join():
    """Setting the knob must re-resolve the ALREADY-JOINED p1 without a
    re-join: Source AS and RT both flip to the large community's tuple
    (Source AS 65010 proves the value came from the tuple, and
    RT:10.255.255.254:0 is the 184549374 endian known-answer)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
router bgp {}
 bgp mvpn umh-large-community {}
""".format(LOCAL_AS, FN)
    )

    src, grp = JOINS_V4["p1"]
    _expect_single_type7(src, grp, PEER_AS, UMH_KAT)


def test_vty_roundtrip():
    """The knob must survive a running-config write."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    running = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert (
        " bgp mvpn umh-large-community {}".format(FN) in running
    ), "knob missing from running-config"


def test_origin_as_mismatch_falls_back():
    """p2's tuple has GA 65999 != origin AS 65010: the trust check must
    reject it and resolve from the extended community."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p2"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_duplicate_tuples_lowest_wins():
    """p3 carries two valid tuples; the lowest (param 167772161 = 10.0.0.1)
    must win deterministically."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p3"]
    _join(src, grp)
    _expect_type7(src, grp, PEER_AS, UMH_LOW)


def test_invalid_param_falls_back():
    """p4's parameter decodes to 224.0.0.1 (multicast) -- not a usable
    upstream PE address; must fall back to the extended community."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p4"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_invalid_param_zero_falls_back():
    """p7's parameter is 0 -> 0.0.0.0, not a usable upstream PE address; the
    invalid-parameter check must reject it and fall back to the extended
    community (the param==0 branch of the UMH validity gate)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p7"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_invalid_param_loopback_falls_back():
    """p8's parameter is 2130706433 = 127.0.0.1 (loopback) -- not a usable
    upstream PE address; must fall back to the extended community (the 127/8
    branch of the UMH validity gate)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p8"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_wrong_function_falls_back():
    """p9 carries a tuple with function 2 while the knob is 1: the function
    filter must skip it (no valid tuple) and resolution fall back to the
    extended community. Guards the fn-mismatch continue that no positive test
    exercises."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p9"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_invalid_param_broadcast_falls_back():
    """p10's parameter is 4294967295 = 255.255.255.255 (limited broadcast, in
    Class E 240/4). ipv4_unicast_valid() treats 240/4 as usable unicast and
    would let this through; the explicit Class E gate must reject it and fall
    back to the extended community."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p10"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_invalid_param_class_e_falls_back():
    """p11's parameter is 4026531841 = 240.0.0.1 (Class E, non-broadcast) --
    the generic 240/4 case the old ipv4_unicast_valid() gate accepted; the
    explicit Class E reject must fall back to the extended community."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p11"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_invalid_param_link_local_falls_back():
    """p12's parameter is 2851995649 = 169.254.0.1 (link-local, 169.254/16).
    A link-local address has interface-local scope and is not globally unique,
    so as a UMH it either names nothing reachable or collides with a different
    box on some other link. Neither ipv4_unicast_valid() nor the 0/8, 127/8,
    Class D and Class E rejects cover it, so it needs its own gate; resolution
    must fall back to the extended community."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p12"]
    _join(src, grp)
    _expect_single_type7(src, grp, LOCAL_AS, EC_RT)


def test_invalid_param_net0_nonzero_falls_back():
    """p13's parameter is 1 = 0.0.0.1: inside 0/8 but NOT zero.

    Mutation-sensitive by construction. p7 only covers 0.0.0.0, so replacing
    the IPV4_NET0() prefix test with a bare `param == 0` comparison would keep
    p7 green while quietly re-admitting the rest of 0/8. This vector is what
    pins the gate to the prefix rather than to the single zero value."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p13"]
    _join(src, grp)
    _expect_single_type7(src, grp, LOCAL_AS, EC_RT)


def test_lc_only_no_fallback():
    """p5 has ONLY the large community -- no extended community and no Source
    Active route for its (S,G). The RT can only come from the LC decode."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS_V4["p5"]
    _join(src, grp)
    _expect_type7(src, grp, PEER_AS, UMH_KAT)


def test_v6_source_v4_umh():
    """A v6 C-S resolves the same v4 UMH from the large community on the v6
    covering route (the UMH is a v4 PE address in a v4 core either way)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOIN_V6
    _join(src, grp, v6=True)
    _expect_type7(src, grp, PEER_AS, UMH_KAT, v6=True)


def test_lc_change_reresolves():
    """Changing p1's tuple on the originator must ripple: r2 re-announces,
    r1's unicast-route reresolve re-originates the Type-7 with the new UMH."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
route-map rm-p1 permit 10
 set large-community 65010:1:167772161
"""
    )

    src, grp = JOINS_V4["p1"]
    _expect_type7(src, grp, PEER_AS, UMH_LOW)


def test_knob_unset_falls_back():
    """Unsetting the knob must re-resolve existing joins back to the
    extended-community path (p1 returns to the plain RT; Source AS returns
    to the local fallback)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
router bgp {}
 no bgp mvpn umh-large-community {}
""".format(LOCAL_AS, FN)
    )

    running = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert (
        "bgp mvpn umh-large-community" not in running
    ), "knob still in running-config after no"

    src, grp = JOINS_V4["p1"]
    _expect_single_type7(src, grp, LOCAL_AS, EC_RT)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
