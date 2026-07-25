#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_mvpn_gtm_umh_ibgp.py: the LC-UMH origin-AS trust check must not treat
"unresolvable origin" as "origin is us" just because the route arrived over
iBGP.

bgp_mvpn_resolve_from_lcommunity() resolves the route's origin with
aspath_get_last_as(), which reads only AS_SEQUENCE members and so returns 0 for
two structurally different paths:

  empty  10.40.10.0/24  no AS_PATH segments at all. The route never crossed an
                        AS boundary, so the local AS really is its origin and a
                        tuple stamped GA == our AS is legitimate -> ACCEPTED,
                        upstream RT 10.255.255.254 from the tuple.
  as_set 10.40.20.0/24  one bare AS_SET {65002,65003} -- what
                        `aggregate-address ... as-set` originates. The origin is
                        genuinely unknown and is definitely not us, so the same
                        tuple is a forged claim -> REJECTED, falling back to the
                        Route Import EC 10.9.9.9.

Both routes carry an IDENTICAL large community (GA == 65001, r1's own AS) and an
identical Route Import EC. The AS_PATH shape is the only difference, so the two
expectations cannot both hold unless the resolver separates the empty path from
the bare AS_SET. Collapsing them -- gating only on `peer->sort == BGP_PEER_IBGP`,
which describes who *advertised* the route rather than where it came from --
makes the as_set case resolve from the tuple and fails this suite.

Reachability matters here, and it is narrower than it first looks. iBGP does
not prepend, so an aggregate originated inside the AS reaches a PE with its
bare AS_SET intact -- unlike over eBGP, where RFC 7606 discards a bare-AS_SET
AS_PATH as malformed before the resolver ever runs (see
bgp_mvpn_gtm_umh_ebgp, which covers the GA != origin boundary instead).

But FRR also sets reject_as_sets=true in bgp_create(), so by default ANY
AS_SET-bearing path is treated-as-withdraw at attribute parse and never reaches
the resolver at all. r1 therefore runs `no bgp reject-as-sets` here. That means
the hole this suite guards is only reachable on a deployment that has turned
that knob off -- a legitimate configuration for networks still aggregating with
as-set, but not the default. The default is genuine defense in depth; it is not
a substitute for the resolver getting its own trust decision right, since it is
an unrelated knob an operator can flip without any thought for MVPN.

    +----+   10.40.0.0/24 (iBGP, both AS 65001)   +---------------------+
    | r1 |----------------------------------------| peer1 (raw speaker) |
    +----+                                        +---------------------+
      | 192.168.4.0/24 (receiver stub)
"""

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
# 184549374 == 10.255.255.254: the UMH both crafted tuples carry.
UMH_KAT = "10.255.255.254"
# Fallback Route Import EC, present on both routes.
EC_RT = "10.9.9.9"

# (source, group) per route; sources are covered by the speaker's /24s.
JOINS = {
    "empty": ("10.40.10.10", "232.4.4.1"),
    "as_set": ("10.40.20.10", "232.4.4.2"),
}

PID_FILE = None


def build_topo(tgen):
    tgen.add_router("r1")
    peer1 = tgen.add_exabgp_peer("peer1", ip="10.40.0.2/24", defaultRoute="via 10.40.0.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(peer1)

    # r1's receiver stub (the IGMP joins live here)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])


def _start_speaker(tgen):
    global PID_FILE
    peer = tgen.gears["peer1"]
    speaker = os.path.join(CWD, "peer1/umh_ibgp_peer.py")
    log_dir = os.path.join(peer.logdir, peer.name)
    peer.cmd("chmod 777 {}".format(log_dir))
    log_file = os.path.join(log_dir, "umh_ibgp_peer.log")
    PID_FILE = os.path.join(log_dir, "umh_ibgp_peer.pid")
    # umh_ibgp_peer.py <peer_ip> <local_as> <local_id>
    peer.cmd(
        "python3 {} 10.40.0.1 {} 10.40.0.2 > {} 2>&1 & echo $! > {}".format(
            speaker, LOCAL_AS, log_file, PID_FILE
        )
    )
    logger.info("umh_ibgp_peer started")


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
            tgen.gears["r1"].vtysh_cmd("show bgp neighbor 10.40.0.2 json")
        )
        return topotest.json_cmp(out, {"10.40.0.2": {"bgpState": "Established"}})

    _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
    assert result is None, "r1 did not reach Established with the iBGP speaker"


def test_both_routes_installed():
    """Guard the premise: if either crafted route never enters the unicast RIB
    the trust assertions below would pass vacuously. The bare AS_SET must be
    accepted over iBGP (it is a legal aggregate) -- unlike over eBGP, where it
    is malformed and discarded."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for name, prefix in (("empty", "10.40.10.0/24"), ("as_set", "10.40.20.0/24")):

        def _installed(prefix=prefix):
            out = json.loads(
                tgen.gears["r1"].vtysh_cmd(
                    "show bgp ipv4 unicast {} json".format(prefix)
                )
            )
            return None if out.get("paths") else "no path for {}: {}".format(prefix, out)

        _, result = topotest.run_and_expect(_installed, None, count=60, wait=1)
        assert result is None, "{} route not installed: {}".format(name, result)


def test_empty_aspath_accepts_local_ga():
    """POSITIVE CONTROL: an empty AS_PATH means the route never left our AS, so
    a tuple stamped GA == our own AS is legitimate and must resolve the UMH.
    Without this the suite could pass by refusing everything."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS["empty"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, UMH_KAT)


def test_bare_as_set_rejects_local_ga():
    """A bare AS_SET has no resolvable origin and its members are not us, so the
    identical GA == our-AS tuple must be rejected and resolution must fall back
    to the Route Import EC.

    This is the mutation-sensitive case: gate the local-AS substitution on
    `peer->sort == BGP_PEER_IBGP` alone and this route resolves to
    RT:10.255.255.254:0 from the forged tuple instead of RT:10.9.9.9:0."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS["as_set"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
