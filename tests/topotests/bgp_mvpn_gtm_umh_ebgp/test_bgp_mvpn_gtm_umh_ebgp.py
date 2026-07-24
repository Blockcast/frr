#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_mvpn_gtm_umh_ebgp.py: origin-AS trust boundary for the LC-UMH
resolver over eBGP.

The UMH large community <sourceAS>:<function>:<UMH> is trusted only when its
Global Administrator equals the AS that ORIGINATED the covering unicast route
(bgp_mvpn_resolve_from_lcommunity). An unresolvable origin AS
(aspath_get_last_as() == 0) is collapsed to the local AS ONLY for an
iBGP-learned or locally-originated route -- never for an eBGP path, or an
attacker one hop away could stamp GA == our own AS and have it trusted. This
suite drives that fail-open guard, which the iBGP-only umh_lc / umh_bestpath
suites structurally cannot reach.

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

# (source, group) per crafted route; sources are covered by the speaker's /24s.
JOINS = {
    "local": ("10.30.10.10", "232.3.3.1"),
    "ga0": ("10.30.20.10", "232.3.3.2"),
    "ok": ("10.30.30.10", "232.3.3.3"),
}

PID_FILE = None


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
    global PID_FILE
    peer = tgen.gears["peer1"]
    speaker = os.path.join(CWD, "peer1/umh_ebgp_peer.py")
    log_dir = os.path.join(peer.logdir, peer.name)
    peer.cmd("chmod 777 {}".format(log_dir))
    log_file = os.path.join(log_dir, "umh_ebgp_peer.log")
    PID_FILE = os.path.join(log_dir, "umh_ebgp_peer.pid")
    # umh_ebgp_peer.py <peer_ip> <local_as> <local_id> <pe_as>
    peer.cmd(
        "python3 {} 10.30.0.1 {} 10.30.0.2 {} > {} 2>&1 & echo $! > {}".format(
            speaker, PEER_AS, LOCAL_AS, log_file, PID_FILE
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


def _type7(source, group):
    for r in _mvpn_routes():
        if (
            r.get("routeType") == 7
            and r.get("source") == source
            and r.get("group") == group
        ):
            return r
    return None


def _expect_type7(source, group, source_as, rt):
    """Wait for the (S,G) Type-7 with exactly this Source AS and upstream RT."""

    def _check():
        r = _type7(source, group)
        if r is None:
            return "no Type-7 for ({}, {})".format(source, group)
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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
