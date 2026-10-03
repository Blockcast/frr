#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_dimt_umh_lc.py: the DIMT pin path reads the UMH LARGE community
(`<origin AS>:<function>:<UMH IPv4>`) as well as the UMH extended community.
BLO-36558; the contract is doc/dimt-lc-umh-mapping.md.

The large community is transitive where the RFC 6514 route-import EC is not,
which is the point: it survives the hops the EC does not.  So the same three
guards the EC lane has must hold on this one -- neighbour trust, origin-AS
authority over the claim, and a usable address -- plus the two the LC adds:
one family (a u32 parameter cannot name an IPv6 UMH) and one precedence rule
against the EC on the same route.

Topology -- two routers, an IPv4 and an IPv6 eBGP session, no forwarding plane
needed.  The assertion surfaces are pimd's mapping table (did the UMH steer
anything, and to what?) and bgpd's per-lane reject counter
(`show bgp umh-large-community json`).

    r1 (AS 65001) ---- s1 ---- r2 (AS 65002)
    source PE                  receiver PoP / box under test
    `network X route-map LC-*` `show ip pim dimt umh json`
                               `show bgp umh-large-community json`

r1 starts by originating one route; every later stage adds the prefix it
measures, so a counter delta is attributable to exactly one arrival.

THE TESTS IN THIS MODULE ARE ORDER-DEPENDENT, in file order:

  T1  an LC-only route pins: umh 10.255.255.254, type pim, preference 0.
      Checked FIRST and through pimd only -- no new command is used before
      it -- so on a build without the DIMT LC lane this stage fails on the
      behaviour ("mapping absent"), not on an unknown command.
  T2  a Global Administrator that is not the origin AS: no mapping, exactly
      +1, and no recount while the route sits in the RIB.
  T3  an unusable parameter (224.0.0.1): no mapping, exactly +1.
  T5  precedence: an amt-relay EC beats the LC on the same route (and the
      disagreement is logged); a pim EC loses to it.
  T6  an IPv6 route carrying the LC: refused, exactly +1, and the warning
      names a large community, not the 0x80 EC.
  T7  only the MVPN knob set: the DIMT lane is EC-only again; no session
      reset.
  T8  re-enabling the DIMT knob restores the LC mappings, again without a
      session reset, and re-adjudicates every LC on the lane.
  T9  DIMT on function 7, MVPN on 1: a function-1 LC is not on the DIMT lane
      and is never counted there; a function-7 one pins.
  T4  `no neighbor ... dimt-trusted`: the LC mapping goes, and the refusal is
      counted -- trust parity with the EC lane.  Last, because it bounces the
      session.
"""

import json
import os
import re
import sys
from time import sleep

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

# 184549374 == 0x0AFFFFFE, the known-answer vector of the spec.
LC_UMH = "10.255.255.254"
EC_UMH = "10.99.0.1"

P_OK = "10.10.1.0/24"  # LC only, function 1                 (startup)
P_GA = "10.10.2.0/24"  # GA 65009 != origin 65001            (T2)
P_BAD = "10.10.3.0/24"  # parameter 224.0.0.1                 (T3)
P_AMT = "10.10.5.0/24"  # LC + amt-relay EC, same address      (T5)
P_PIMEC = "10.10.6.0/24"  # LC + pim EC, another address        (T5)
P_V6 = "2001:db8:6::/48"  # IPv6 route carrying the LC          (T6)
P_FN7 = "10.10.9.0/24"  # LC with function 7                  (T9)


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # s1: both eBGP sessions.
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # s3: r2's receiver stub (pimd needs an interface to run on).
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # pimd only on r2 -- it is the mapping consumer.
    tgen.gears["r2"].load_config(
        TopoRouter.RD_PIM, os.path.join(CWD, "r2/pimd.conf")
    )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _json_cmd(rname, cmd):
    """vtysh JSON helper: returns None (NOT {}) on unparseable output, so a
    crashed or unresponsive daemon can never satisfy an absence-assertion
    vacuously.  Every predicate below MUST treat None as failure."""
    out = get_topogen().gears[rname].vtysh_cmd(cmd)
    try:
        return json.loads(out)
    except ValueError:
        return None


def _vtysh(rname, cmds):
    get_topogen().gears[rname].vtysh_cmd(cmds)


def _skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


def _lanes():
    """`show bgp umh-large-community json`, or None if bgpd is gone or the
    command does not exist."""
    data = _json_cmd("r2", "show bgp umh-large-community json")
    if not data or "dimtUmhLcRejected" not in data:
        return None
    return data


def _dimt_rejected():
    data = _lanes()
    return None if data is None else data["dimtUmhLcRejected"]


def _established(neighbor="10.0.0.1"):
    """How many times the session has come up: a knob that is meant to act
    without a session reset must leave this alone."""
    data = _json_cmd("r2", "show bgp neighbor {} json".format(neighbor))
    if data is None:
        return None
    return data.get(neighbor, {}).get("connectionsEstablished")


def _route_learned(prefix):
    """The route itself must arrive regardless of what happens to its UMH --
    refusing a UMH must never refuse the route."""
    afi = "ipv6" if ":" in prefix else "ip"

    def _check():
        data = _json_cmd("r2", "show {} route {} json".format(afi, prefix))
        if data is None:
            return "r2: unparseable route JSON (zebra dead?)"
        for rt in data.get(prefix, []):
            if rt.get("protocol") == "bgp" and rt.get("selected"):
                return None
        return "r2 has no selected BGP route for {}: {}".format(prefix, data)

    return _check


def _mapping(prefix, umh, utype, pref):
    def _check():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        entry = data.get(prefix)
        if entry is None:
            return "r2 has no UMH mapping for {} (mapping absent): {}".format(
                prefix, data
            )
        want = {"umh": umh, "type": utype, "preference": pref}
        got = {k: entry.get(k) for k in want}
        if got != want:
            return "r2 UMH mapping for {} is {}, expected {}".format(
                prefix, got, want
            )
        return None

    return _check


def _absent(prefix):
    def _check():
        data = _json_cmd("r2", "show ip pim dimt umh json")
        if data is None:
            return "r2: unparseable dimt umh JSON (pimd dead?)"
        if prefix in data:
            return "r2 mapped {} when it should not have: {}".format(
                prefix, data[prefix]
            )
        return None

    return _check


def _expect(pred, count=60, wait=1):
    _, result = topotest.run_and_expect(pred, None, count=count, wait=wait)
    assert result is None, result


def _counter_becomes(want):
    def _check():
        n = _dimt_rejected()
        if n is None:
            return (
                "r2: dimtUmhLcRejected unreadable (bgpd dead, or no "
                "`show bgp umh-large-community`)"
            )
        if n != want:
            return "r2 dimtUmhLcRejected is {}, expected {}".format(n, want)
        return None

    return _check


def _counter_holds(want, seconds=4):
    """The counter is the operator's probe detector, so it has to track what
    arrived, not how often something re-read it: a route that sits in the
    RIB must not keep counting."""
    for _ in range(seconds):
        sleep(1)
        n = _dimt_rejected()
        assert n == want, (
            "r2 dimtUmhLcRejected moved to {} while nothing new arrived "
            "(expected {})".format(n, want)
        )


def _snapshot():
    n = _dimt_rejected()
    assert n is not None, "r2: dimtUmhLcRejected unreadable"
    return n


def _originate(prefix, route_map):
    afi = "ipv6" if ":" in prefix else "ipv4"
    _vtysh(
        "r1",
        """
        configure terminal
         router bgp 65001
          address-family {} unicast
           network {} route-map {}
        """.format(afi, prefix, route_map),
    )


def _bgpd_log(rname="r2"):
    logfile = os.path.join(get_topogen().logdir, rname, "bgpd.log")
    with open(logfile) as f:
        return f.read()


def test_t1_lc_only_route_pins():
    """The failing-first stage: an LC-only route maps through the DIMT pin
    path as type pim, preference 0 -- the LC encodes neither, so those are
    the defaults (doc/dimt-lc-umh-mapping.md).  Only pre-existing commands are
    used here."""
    _skip_on_failure()

    _expect(_route_learned(P_OK))
    _expect(_mapping(P_OK, LC_UMH, "pim", 0), count=30)


def test_t2_ga_mismatch_refused_and_counted_once():
    """A tuple whose Global Administrator is not the route's origin AS is a
    claim made across an AS that does not originate the route."""
    _skip_on_failure()
    before = _snapshot()

    _originate(P_GA, "LC-GA")
    _expect(_route_learned(P_GA))
    _expect(_counter_becomes(before + 1))
    absent = _absent(P_GA)()
    assert absent is None, absent
    _counter_holds(before + 1)


def test_t3_unusable_parameter_refused_and_counted():
    """224.0.0.1 can never be a UMH; the originating AS naming it is a
    misconfiguration, and it is counted like any other reject."""
    _skip_on_failure()
    before = _snapshot()

    _originate(P_BAD, "LC-BAD")
    _expect(_route_learned(P_BAD))
    _expect(_counter_becomes(before + 1))
    absent = _absent(P_BAD)()
    assert absent is None, absent
    _counter_holds(before + 1)


def test_t5_precedence_against_the_extended_community():
    """The LC wins over the UMH EC on the same route EXCEPT when the EC's
    tuple is typed amt-relay: that EC is an explicit instruction pimd honours
    by NOT pinning, and letting the LC's default PIM type override it would
    turn a no-pin into a PIM Light join toward an AMT relay."""
    _skip_on_failure()
    before = _snapshot()

    _originate(P_AMT, "LC-AMT")
    _expect(_route_learned(P_AMT))
    _expect(_mapping(P_AMT, LC_UMH, "amt-relay", 5))

    # Same address, different type: the case only a type comparison catches.
    def _logged():
        pat = re.compile(
            r"DIMT UMH large community disagrees with the UMH extended "
            r"community on {} .*: the amt-relay extended community wins".format(
                re.escape(P_AMT)
            )
        )
        if pat.search(_bgpd_log()):
            return None
        return "no disagreement line for {}".format(P_AMT)

    _expect(_logged, count=10)

    _originate(P_PIMEC, "LC-PIMEC")
    _expect(_route_learned(P_PIMEC))
    _expect(_mapping(P_PIMEC, LC_UMH, "pim", 0))

    # Two valid LCs: nothing to reject.
    _counter_holds(before)


def test_t6_ipv6_route_refused_with_a_large_community_warning():
    """A u32 parameter cannot carry an IPv6 UMH, and the pin path is
    same-family by design.  The refusal is counted once, and the warning
    names the attribute actually rejected -- an operator sent looking for a
    0x80 EC that is not there is the failure this guards."""
    _skip_on_failure()
    before = _snapshot()

    _originate(P_V6, "LC-OK")
    _expect(_route_learned(P_V6))
    _expect(_counter_becomes(before + 1))

    def _warned():
        pat = re.compile(
            r"DIMT: {} from \S+ carries a UMH large community of the wrong "
            r"address family".format(re.escape(P_V6))
        )
        if pat.search(_bgpd_log()):
            return None
        return "no wrong-family LC warning for {}".format(P_V6)

    _expect(_warned, count=10)
    _counter_holds(before + 1)


def test_t7_mvpn_knob_only_leaves_the_dimt_lane_ec_only():
    """The DIMT lane has its own knob: setting only the MVPN one must not
    open the pin path to large communities."""
    _skip_on_failure()
    est = _established()
    assert est is not None, "r2: neighbor JSON unreadable"
    before = _snapshot()

    _vtysh(
        "r2",
        """
        configure terminal
         router bgp 65002
          no bgp dimt umh-large-community
          bgp mvpn umh-large-community 1
        """,
    )

    lanes = _lanes()
    assert lanes is not None, "r2: lane JSON unreadable"
    assert lanes["dimtFunction"] == 0 and lanes["mvpnFunction"] == 1, lanes

    _expect(_absent(P_OK))
    # The EC routes keep mapping -- now from the EC alone.
    _expect(_mapping(P_PIMEC, EC_UMH, "pim", 5))
    _expect(_mapping(P_AMT, LC_UMH, "amt-relay", 5))

    # Turning the lane off is not a reject, and it does not touch the
    # session: the attributes did not change, only how they are read.
    _counter_holds(before)
    assert _established() == est, "the DIMT knob reset the session"


def test_t8_reenabling_restores_without_a_session_reset():
    """Setting the knob again re-evaluates every route under it (DEL then
    ADD across the two stages) with no session reset -- and re-adjudicates,
    and so re-counts, every LC on the lane: the verdict depends on the code
    point as much as on the attributes (bgp_dimt_umh_lc_set_function())."""
    _skip_on_failure()
    est = _established()
    before = _snapshot()

    _vtysh(
        "r2",
        """
        configure terminal
         router bgp 65002
          bgp dimt umh-large-community 1
        """,
    )

    _expect(_mapping(P_OK, LC_UMH, "pim", 0))
    _expect(_mapping(P_PIMEC, LC_UMH, "pim", 0))
    _expect(_mapping(P_AMT, LC_UMH, "amt-relay", 5))

    # P_GA, P_BAD and P_V6 are each refused again, once.
    _expect(_counter_becomes(before + 3))
    _counter_holds(before + 3)
    assert _established() == est, "the DIMT knob reset the session"


def test_t9_function_7_lane_ignores_function_1():
    """Two lanes, two code points: with DIMT on 7 and MVPN on 1, a function-1
    LC is not on the DIMT lane at all -- not mapped, not counted -- while a
    function-7 one pins."""
    _skip_on_failure()

    # Off the lane while DIMT decodes function 1: no mapping, no count.
    before = _snapshot()
    _originate(P_FN7, "LC-FN7")
    _expect(_route_learned(P_FN7))
    sleep(2)
    absent = _absent(P_FN7)()
    assert absent is None, absent
    _counter_holds(before)

    _vtysh(
        "r2",
        """
        configure terminal
         router bgp 65002
          bgp dimt umh-large-community 7
        """,
    )

    _expect(_mapping(P_FN7, LC_UMH, "pim", 0))
    _expect(_absent(P_OK))
    _expect(_mapping(P_PIMEC, EC_UMH, "pim", 5))
    # P_GA, P_BAD and P_V6 carry function 1: re-adjudicated under 7, they are
    # off the lane, so nothing is counted.
    _counter_holds(before)


def test_t4_untrusting_the_peer_withdraws_the_lc_mapping():
    """Trust parity with the EC lane: revoking `dimt-trusted` takes an LC
    mapping away, and the refusal is counted once per route."""
    _skip_on_failure()
    before = _snapshot()

    _vtysh(
        "r2",
        """
        configure terminal
         router bgp 65002
          no neighbor 10.0.0.1 dimt-trusted
        """,
    )

    # The flag carries peer_change_reset, so the session bounces and the
    # withdraw alone would satisfy an absence poll.  Anchor on the counter:
    # it moves only when the RE-LEARNED route is refused.  Only P_FN7 is on
    # the function-7 lane, so exactly one.
    _expect(_counter_becomes(before + 1))
    _expect(_route_learned(P_FN7))
    for _ in range(5):
        sleep(1)
        absent = _absent(P_FN7)()
        assert absent is None, absent
    _counter_holds(before + 1)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
