#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_mvpn_gtm_umh_ebgp.py: general eBGP origin-AS trust validation for the
LC-UMH resolver.

The UMH large community <sourceAS>:<function>:<UMH> is trusted only when its
Global Administrator equals the AS that ORIGINATED the covering unicast route
(bgp_mvpn_resolve_from_lcommunity). This suite exercises that check over an
eBGP session -- the case the iBGP-only umh_lc / umh_bestpath suites structurally
cannot reach -- proving a neighbor cannot stamp GA == our own AS (or GA == 0)
and be believed, while a legitimate GA == origin is accepted.

SCOPE, read this before "strengthening" it: this suite is NOT a mutation-
sensitive regression for the `origin_as == 0` arm, and cannot be over eBGP.
aspath_get_last_as() == 0 is produced only by an empty or bare-AS_SET AS_PATH,
both of which FRR rejects as malformed for eBGP (RFC 7606 treat-as-withdraw)
before the route enters the RIB or the resolver runs -- verified: the route
never appears in `show bgp ipv4 unicast`. So the only eBGP-reachable trust
boundary is GA != origin, which is what these cases cover.

That arm IS reachable over iBGP, where an aggregate keeps its bare AS_SET
because iBGP does not prepend, and it is covered mutation-sensitively there --
see bgp_mvpn_gtm_umh_ibgp, which pins empty-AS_PATH (accept) against
bare-AS_SET (reject) with an otherwise identical route. Do not try to
reproduce that here.

A raw eBGP speaker (peer1, AS 65010) advertises three source-covering routes,
all with a well-formed AS_SEQUENCE path (origin AS 65010):

  local 10.30.10.0/24  UMH GA == r1's OWN local AS (65001). The route's real
                       origin over eBGP is 65010, so GA != origin: a neighbor
                       one hop away cannot stamp "GA == your AS" and be
                       believed -> rejected, EC fallback.
  ga0   10.30.20.0/24  UMH GA == 0 -> rejected outright, EC fallback.
  ok    10.30.30.0/24  UMH GA == 65010 == origin -> accepted (positive
                       control: proves the rejects are origin-AS-specific, not
                       a blanket eBGP refusal).

aspath_get_last_as() == 0 (the "unresolvable origin" case) is only produced by
an empty or bare-AS_SET AS_PATH, both malformed for eBGP and dropped by FRR
(RFC 7606) before the resolver runs -- so the origin-0 fail-open is guarded for
iBGP/local paths, not reachable over eBGP; the eBGP trust boundary is
GA != origin, exercised here.

    +----+   10.30.0.0/24 (eBGP)   +--------------------+
    | r1 |------------------------ | peer1 (raw AS65010) |
    +----+                         +--------------------+
      | 192.168.3.0/24 (receiver stub)
"""

import functools
import json
import os
import signal
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
# 184549374 == 10.255.255.254: the UMH the crafted tuples all carry.
UMH_KAT = "10.255.255.254"
# Fallback Route Import EC on the two routes whose UMH tuple must be rejected.
EC_RT = "10.9.9.9"
# MCAST-VPN Type-5 loop-check probes sent by the speaker (see umh_ebgp_peer.py).
LOOP_SG = ("10.80.80.1", "232.80.80.1")   # AS_PATH contains the PE's own AS
OK_SG = ("10.80.80.2", "232.80.80.2")     # AS_PATH is the peer's AS only
# Implicit-withdraw probes: installed with AS_PATH "65010", then re-sent with
# "65010 65001" once the test creates the probe's trigger file (see
# umh_ebgp_peer.py). WD3_SG's source is covered by the "ok" unicast route, so
# joining it originates a Type-7 and r1 answers the Type-3 with a Type-4.
WD5_SG = ("10.80.80.3", "232.80.80.3")
WD3_SG = ("10.30.30.20", "232.80.80.4")
PEER_ID = "10.30.0.2"   # the speaker's router-id: the Type-3 originator
R1_ID = "10.30.0.1"     # r1's router-id: the leaf originator of its Type-4

# (source, group) per crafted route; sources are covered by the speaker's /24s.
JOINS = {
    "local": ("10.30.10.10", "232.3.3.1"),
    "ga0": ("10.30.20.10", "232.3.3.2"),
    "ok": ("10.30.30.10", "232.3.3.3"),
}

PID_FILE = None
TRIGGER_DIR = None


def build_topo(tgen):
    tgen.add_router("r1")
    peer1 = tgen.add_exabgp_peer("peer1", ip="10.30.0.2/24", defaultRoute="via 10.30.0.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(peer1)

    # r1's receiver stub (the IGMP joins live here)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])


def _start_speaker(tgen):
    global PID_FILE, TRIGGER_DIR
    peer = tgen.gears["peer1"]
    speaker = os.path.join(CWD, "peer1/umh_ebgp_peer.py")
    log_dir = os.path.join(peer.logdir, peer.name)
    peer.cmd("chmod 777 {}".format(log_dir))
    log_file = os.path.join(log_dir, "umh_ebgp_peer.log")
    PID_FILE = os.path.join(log_dir, "umh_ebgp_peer.pid")
    TRIGGER_DIR = log_dir
    peer.cmd("rm -f {0}/send_wd5 {0}/send_wd3".format(TRIGGER_DIR))
    # umh_ebgp_peer.py <peer_ip> <local_as> <local_id> <pe_as> --trigger-dir D
    peer.cmd(
        "python3 {} 10.30.0.1 {} 10.30.0.2 {} --trigger-dir {} > {} 2>&1 "
        "& echo $! > {}".format(
            speaker, PEER_AS, LOCAL_AS, TRIGGER_DIR, log_file, PID_FILE
        )
    )
    logger.info("umh_ebgp_peer started")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    r1.load_config(TopoRouter.RD_PIM, os.path.join(CWD, "r1/pimd.conf"))
    r1.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))
    r1.start()

    _start_speaker(tgen)


def teardown_module(mod):
    tgen = get_topogen()
    if PID_FILE:
        try:
            pid = int(tgen.gears["peer1"].run("cat {}".format(PID_FILE)).strip())
            tgen.gears["peer1"].run("kill -{} {}".format(int(signal.SIGTERM), pid))
        except (ValueError, OSError):
            pass
    tgen.stop_topology()


def _mvpn_routes():
    out = json.loads(get_topogen().gears["r1"].vtysh_cmd("show bgp ipv4 mvpn json"))
    return out.get("routes", [])


def _expect_type7(source, group, source_as, rt):
    """Wait for EXACTLY ONE (S,G) Type-7, with this Source AS and upstream RT.

    Counting matters as much as matching. Returning the first hit would let a
    trust test pass while a second Type-7 carrying the forged Source AS/RT is
    still installed -- whether it passed or failed would depend on RIB
    iteration order. A re-resolution that changes the Source AS must WITHDRAW
    the old NLRI key, not strand it, so assert the key count explicitly.
    Mirrors _expect_single_type7() in the umh_lc suite.
    """

    def _check():
        matches = [
            r
            for r in _mvpn_routes()
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
            return "Type-7 ({}, {}) Source AS {}, want {}: {}".format(
                source, group, r.get("sourceAs"), source_as, r
            )
        got_rt = r.get("extendedCommunity", {}).get("string")
        want_rt = "RT:{}:0".format(rt)
        if got_rt != want_rt:
            return "Type-7 ({}, {}) RT {}, want {}: {}".format(
                source, group, got_rt, want_rt, r
            )
        return None

    _, result = topotest.run_and_expect(_check, None, count=90, wait=1)
    assert result is None, result


def _join(source, group):
    get_topogen().gears["r1"].vtysh_cmd(
        """
configure terminal
interface r1-eth1
 ip igmp join-group {} {}
""".format(group, source)
    )


def test_sessions_established():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _established():
        out = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp neighbor 10.30.0.2 json")
        )
        return topotest.json_cmp(out, {"10.30.0.2": {"bgpState": "Established"}})

    _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
    assert result is None, "r1 did not reach Established with the eBGP speaker"


def test_ebgp_local_as_ga_rejected():
    """local route: the UMH tuple's GA is r1's OWN local AS (65001), but the
    route is learned over eBGP with origin AS 65010, so GA != origin. The
    resolver must not trust it (a neighbor cannot claim to be us) and must fall
    back to the Route Import extended community."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS["local"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_ga_zero_rejects():
    """ga0 route: UMH Global Administrator 0 must be rejected outright, with
    fallback to the Route Import EC."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS["ga0"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_matching_origin_accepts():
    """ok route (positive control): a well-formed eBGP path whose origin AS
    equals the UMH GA must be ACCEPTED -- Source AS 65010 and the UMH as the
    upstream RT -- proving the rejects above are origin-AS-specific, not a
    blanket eBGP refusal."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS["ok"]
    _join(src, grp)
    _expect_type7(src, grp, PEER_AS, UMH_KAT)


def _has_type5(routes, sg):
    src, grp = sg
    return any(
        r.get("routeType") == 5 and r.get("source") == src and r.get("group") == grp
        for r in routes
    )


def test_ebgp_own_as_in_path_rejected():
    """Over eBGP, an MVPN route whose AS_PATH carries OUR AS must be dropped.

    bgp_nlri_parse_mvpn() installs straight into the MCAST-VPN RIB and never
    passes through bgp_update(), so it runs its own AS-path loop check. This is
    the eBGP half of that coverage; bgp_mvpn_gtm_malformed exercises the same
    rejection over iBGP.

    Why it has to be tested here too: on that iBGP session bgp->as == peer->as,
    so a check written against the PEER's AS instead of the LOCAL AS passes
    there while blackholing every route in production. Here the two differ
    (r1 65001, speaker 65010), and the OK_SG control -- whose AS_PATH is the
    peer's own AS and nothing else -- is exactly the route such a check would
    wrongly drop.

    OK_SG is sent after LOOP_SG on one TCP stream, so waiting for it proves
    LOOP_SG was already decided on.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _control_present():
        if _has_type5(_mvpn_routes(), OK_SG):
            return None
        return "eBGP control Type-5 {} not installed yet".format(OK_SG)

    _, result = topotest.run_and_expect(_control_present, None, count=90, wait=1)
    assert result is None, (
        "r1 did not install the Type-5 whose AS_PATH is just the peer's AS "
        "({}); either the MVPN AF is not usable over this eBGP session or the "
        "loop check is comparing against the peer's AS instead of ours".format(OK_SG)
    )

    routes = _mvpn_routes()
    assert not _has_type5(routes, LOOP_SG), (
        "r1 installed an eBGP Type-5 {} whose AS_PATH contains its own AS "
        "{}; routes={}".format(LOOP_SG, LOCAL_AS, routes)
    )

    nb = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp neighbor 10.30.0.2 json"))
    loops = nb["10.30.0.2"].get("prefixStats", {}).get("aspathLoop")
    assert loops == 1, (
        "expected exactly one AS-path loop denial on the eBGP session, got "
        "{}: {}".format(loops, nb["10.30.0.2"].get("prefixStats"))
    )


def _aspath_loops():
    nb = json.loads(
        get_topogen().gears["r1"].vtysh_cmd("show bgp neighbor 10.30.0.2 json")
    )
    return nb["10.30.0.2"].get("prefixStats", {}).get("aspathLoop")


def _peer_type3(routes, sg):
    src, grp = sg
    return [
        r
        for r in routes
        if r.get("routeType") == 3
        and r.get("source") == src
        and r.get("group") == grp
        and r.get("originator") == PEER_ID
        and not r.get("selfOriginated")
    ]


def _own_type4(routes, sg):
    src, grp = sg
    return [
        r
        for r in routes
        if r.get("routeType") == 4
        and r.get("source") == src
        and r.get("group") == grp
        and r.get("originator") == PEER_ID
        and r.get("leafOriginator") == R1_ID
        and r.get("selfOriginated")
    ]


def _release_loop_copy(probe):
    """Let the speaker re-send `probe` with r1's AS appended to its AS_PATH."""
    get_topogen().gears["peer1"].cmd(
        "touch {}".format(os.path.join(TRIGGER_DIR, probe))
    )


def test_ebgp_loop_withdraws_prior_type5():
    """A looping re-advertisement must REMOVE the Type-5 the peer sent before.

    Denying an install is an implicit withdraw (RFC 4271 Section 9): the peer
    has replaced its earlier route for that NLRI, so r1 must drop the copy it
    holds -- the bgp_mvpn_route_remove() call in bgp_nlri_parse_mvpn()'s loop
    branch. test_ebgp_own_as_in_path_rejected cannot reach it: LOOP_SG is the
    first UPDATE at its (S,G), so the remove finds no dest and returns.

    WD5_SG first arrives with AS_PATH "65010" and must install; only then is
    the "65010 65001" copy released, and the first copy must go. Removal is
    two-stage (mark, then reaped on the work queue), so poll.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _installed():
        if _has_type5(_mvpn_routes(), WD5_SG):
            return None
        return "first copy of {} (AS_PATH 65010) not installed".format(WD5_SG)

    _, result = topotest.run_and_expect(_installed, None, count=90, wait=1)
    assert result is None, "precondition: {}".format(result)
    loops_before = _aspath_loops()

    _release_loop_copy("send_wd5")

    def _withdrawn():
        if _has_type5(_mvpn_routes(), WD5_SG):
            return (
                "first copy of {} still present after the looping "
                "re-advertisement".format(WD5_SG)
            )
        return None

    _, result = topotest.run_and_expect(_withdrawn, None, count=30, wait=1)
    assert result is None, (
        "{} -- a denied MVPN install did not implicitly withdraw the peer's "
        "earlier route (bgp_mvpn_route_remove() in the AS-path loop branch)".format(
            result
        )
    )

    # It went because the loop check denied its replacement, not because the
    # session reset: exactly one more denial, and the control is untouched.
    assert _aspath_loops() == loops_before + 1, (
        "expected exactly one more AS-path loop denial, got {} (was {})".format(
            _aspath_loops(), loops_before
        )
    )
    assert _has_type5(_mvpn_routes(), OK_SG), (
        "the implicit withdraw of {} also removed {}".format(WD5_SG, OK_SG)
    )


def test_ebgp_loop_withdraws_prior_type3_and_its_leaf():
    """A looping Type-3 must remove the earlier Type-3 AND r1's Type-4 answer.

    A Type-3 (S-PMSI A-D) with Leaf Information Required, at an (S,G) r1 has
    joined, makes r1 originate a Type-4 Leaf A-D. bgp_mvpn_route_remove()
    re-runs that reconcile when it removes a peer's Type-3, so the implicit
    withdraw has a side effect beyond the one dest: with the only L-bit Type-3
    gone, r1's own Type-4 must be withdrawn too, or r1 keeps telling the
    ingress it is a leaf of a tunnel that no longer exists. The local join
    (Type-7) is not the Type-3's to remove and must stay.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _type3_installed():
        if _peer_type3(_mvpn_routes(), WD3_SG):
            return None
        return "first copy of Type-3 {} (AS_PATH 65010) not installed".format(WD3_SG)

    _, result = topotest.run_and_expect(_type3_installed, None, count=90, wait=1)
    assert result is None, "precondition: {}".format(result)

    src, grp = WD3_SG
    _join(src, grp)
    _expect_type7(src, grp, PEER_AS, UMH_KAT)

    def _leaf_originated():
        if len(_own_type4(_mvpn_routes(), WD3_SG)) == 1:
            return None
        return "r1 has not answered Type-3 {} with its own Type-4: {}".format(
            WD3_SG, _mvpn_routes()
        )

    _, result = topotest.run_and_expect(_leaf_originated, None, count=30, wait=1)
    assert result is None, (
        "precondition: {} -- without the Type-4 the leaf reconcile has nothing "
        "to remove".format(result)
    )
    loops_before = _aspath_loops()

    _release_loop_copy("send_wd3")

    def _withdrawn():
        routes = _mvpn_routes()
        if _peer_type3(routes, WD3_SG):
            return (
                "first copy of Type-3 {} still present after the looping "
                "re-advertisement".format(WD3_SG)
            )
        if _own_type4(routes, WD3_SG):
            return (
                "Type-3 {} withdrawn but r1's Type-4 answering it is still "
                "present".format(WD3_SG)
            )
        return None

    _, result = topotest.run_and_expect(_withdrawn, None, count=30, wait=1)
    assert result is None, (
        "{} -- a denied MVPN Type-3 install did not implicitly withdraw the "
        "peer's earlier Type-3 and reconcile r1's leaf".format(result)
    )

    assert _aspath_loops() == loops_before + 1, (
        "expected exactly one more AS-path loop denial, got {} (was {})".format(
            _aspath_loops(), loops_before
        )
    )
    # The receiver's join is independent of the tunnel: the Type-7 stays.
    _expect_type7(src, grp, PEER_AS, UMH_KAT)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
