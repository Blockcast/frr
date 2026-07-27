#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_mvpn_gtm_umh_ibgp.py: the LC-UMH origin-AS trust check must treat any
AS_SET-bearing path as having no determinable origin, rather than trusting
whatever a single "last AS" lookup happens to return.

bgp_mvpn_resolve_from_lcommunity() trusts a UMH tuple only when its Global
Administrator equals the AS that ORIGINATED the covering route. It resolves
that origin with aspath_get_last_as(), which returns the last member of the
last AS_SEQUENCE segment and skips set segments outright -- so it misreports
three different shapes in three different ways:

  empty      10.40.10.0/24  no segments. The route never crossed an AS
                            boundary, so the local AS really is its origin and
                            a tuple stamped GA == our AS is legitimate ->
                            ACCEPTED, upstream RT 10.255.255.254 from the
                            tuple.
  as_set     10.40.20.0/24  bare AS_SET {65002,65003}, what
                            `aggregate-address ... as-set` originates. Lookup
                            -> 0, same as empty, but the origin is unknown and
                            is not us -> REJECTED, EC fallback 10.9.9.9.
  mixed      10.40.30.0/24  AS_SEQUENCE [65010] + AS_SET {65002,65003}. Lookup
                            skips the set and returns 65010 -- non-zero, so no
                            empty-path guard fires -- but 65010 is the
                            AGGREGATOR, not the origin. GA == 65010 ->
                            REJECTED.
  confed_set 10.40.40.0/24  bare AS_CONFED_SET. Lookup -> 0 and
                            aspath_count_hops() -> 0 as well, since hop
                            counting scores an AS_SET as one hop but ignores
                            confederation segments; a hop-count discriminator
                            reads this as an empty path. GA == our AS ->
                            REJECTED.
  zero_seq   10.40.50.0/24  AS_SEQUENCE [0]. NOT empty, but AS 0 is an
                            encodable value rather than an absence sentinel,
                            so the lookup returns 0 while
                            aspath_check_as_sets() is false. Concluding
                            "empty path" from "lookup == 0" substitutes the
                            local AS. GA == our AS -> REJECTED.
  zero_confed_seq
             10.40.60.0/24  AS_CONFED_SEQUENCE [0]. Same collision via the
                            other sequence type the lookup reads.
                            GA == our AS -> REJECTED.

Every route carries the same UMH parameter and an identical Route Import EC;
only the AS_PATH shape and the stamped GA vary. Accepting `empty` while
rejecting the other five cannot hold unless the resolver (a) treats any
set-bearing or AS-0-bearing path as origin-ambiguous, and (b) keys the
local-AS substitution on structural emptiness rather than on a zero lookup.
Gating on `peer->sort == BGP_PEER_IBGP` (who *advertised* the route, not where
it came from) fails as_set; a hop-count test fails confed_set; trusting the
bare lookup fails mixed; and treating a zero lookup as emptiness fails both
zero_* vectors.

Reachability matters here, and it is narrower than it first looks. iBGP does
not prepend, so an aggregate originated or relayed inside the AS reaches a PE
with its set segments intact -- unlike over eBGP, where RFC 7606 discards a
bare-AS_SET AS_PATH as malformed before the resolver ever runs (see
bgp_mvpn_gtm_umh_ebgp, which covers the GA != origin boundary instead). The
confederation sanity check in bgp_attr_aspath_check() likewise only fires for
CONFED and EBGP peers, so an AS_CONFED_SET survives parse on a plain iBGP
session.

But FRR also sets reject_as_sets=true in bgp_create(), gating on the same
aspath_check_as_sets(), so by default ANY set-bearing path is
treated-as-withdraw at attribute parse and never reaches the resolver at all.
r1 therefore runs `no bgp reject-as-sets` here. That means
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
# The AS that aggregated the `mixed` route. A transit AS, not an origin -- but
# it is what aspath_get_last_as() reports for "65010 {65002,65003}".
AGGREGATOR_AS = 65010
# 184549374 == 10.255.255.254: the UMH every crafted tuple carries.
UMH_KAT = "10.255.255.254"
# Fallback Route Import EC, present on every route.
EC_RT = "10.9.9.9"

# (source, group) per route; sources are covered by the speaker's /24s.
JOINS = {
    "empty": ("10.40.10.10", "232.4.4.1"),
    "as_set": ("10.40.20.10", "232.4.4.2"),
    "mixed": ("10.40.30.10", "232.4.4.3"),
    "confed_set": ("10.40.40.10", "232.4.4.4"),
    "zero_seq": ("10.40.50.10", "232.4.4.5"),
    "zero_confed_seq": ("10.40.60.10", "232.4.4.6"),
}

# Every crafted route must reach the unicast RIB or the trust assertions pass
# vacuously; the premise guard walks this list.
PREFIXES = {
    "empty": "10.40.10.0/24",
    "as_set": "10.40.20.0/24",
    "mixed": "10.40.30.0/24",
    "confed_set": "10.40.40.0/24",
    "zero_seq": "10.40.50.0/24",
    "zero_confed_seq": "10.40.60.0/24",
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


def test_all_routes_installed():
    """Guard the premise: if any crafted route never enters the unicast RIB the
    trust assertions below would pass vacuously. The set-bearing paths must be
    accepted over iBGP -- an AS_SET aggregate is legal there (unlike over eBGP,
    where a bare set is malformed and discarded), and the confederation sanity
    check in bgp_attr_aspath_check() only fires for CONFED and EBGP peers, so
    an AS_CONFED_SET survives parse on an iBGP session."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for name, prefix in PREFIXES.items():

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


def test_mixed_sequence_set_rejects_aggregator_ga():
    """AS_SEQUENCE [65010] + AS_SET {65002,65003}: aspath_get_last_as() skips
    the set and returns 65010, so the origin lookup is NOT 0 and no
    empty-path/hop-count guard fires. But 65010 aggregated the route, it did
    not originate it, and RFC 4271 leaves the real origin indeterminate inside
    the set.

    Mutation-sensitive: trust `last AS` on its own and the GA == 65010 tuple
    matches, resolving to RT:10.255.255.254:0 with Source AS 65010 -- letting
    any AS that aggregates a route claim a UMH for an origin it merely
    transits. The resolver must instead treat the path as origin-ambiguous and
    fall back to the Route Import EC."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS["mixed"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_bare_confed_set_rejects_local_ga():
    """A bare AS_CONFED_SET reads as (origin 0, 0 hops): aspath_get_last_as()
    skips set segments and aspath_count_hops() counts an AS_SET as one hop but
    ignores confederation segments altogether.

    Mutation-sensitive: discriminate empty-vs-set on hop count and this path
    is indistinguishable from an empty AS_PATH, so the local AS is substituted
    and the GA == our-AS tuple is honoured. Only a check that looks for set
    segments directly (aspath_check_as_sets) separates them."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS["confed_set"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_zero_as_sequence_rejects_local_ga():
    """AS_SEQUENCE [0] is NOT an empty path, but its stored value is 0, so
    aspath_get_last_as() returns 0 while aspath_check_as_sets() returns false.

    Mutation-sensitive: infer "the path is empty" from "the origin lookup
    returned 0" and the local AS is substituted, making the GA == our-AS tuple
    match and resolve to RT:10.255.255.254:0. AS 0 is an encodable value, not
    just an absence sentinel, so the substitution must key on structural
    emptiness (aspath->segments == NULL) and a non-empty AS-0 path must be
    rejected as origin-ambiguous."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS["zero_seq"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


def test_zero_as_confed_sequence_rejects_local_ga():
    """AS_CONFED_SEQUENCE [0] reaches the same sentinel collision through the
    other sequence type aspath_get_last_as() reads.

    Reachable because bgp_attr_aspath_check() rejects AS 0 only for eBGP peers
    (bgpd/bgp_attr.c), so the shape survives parse on a plain iBGP session."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    src, grp = JOINS["zero_confed_seq"]
    _join(src, grp)
    _expect_type7(src, grp, LOCAL_AS, EC_RT)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
