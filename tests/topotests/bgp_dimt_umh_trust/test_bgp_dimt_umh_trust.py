#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_dimt_umh_trust.py: the DIMT UMH extended community is honoured only
from a neighbor that is BOTH marked `dimt-trusted` AND authorised by the
route's origin AS to claim a UMH for it.  BLO-36553.

The UMH EC says "send your PIM join toward <address>", so whoever can attach
one to a route we accept decides where a stream is pulled from.  Before the
gate under test, `bgp_dimt_umh_from_path()` honoured a 0x80 from any peer with
no origin check at all -- so any transit AS, or any IX route server, could
attach one to a prefix it merely carried and redirect our join.

Topology -- two routers, one eBGP session, no forwarding plane needed.  The
assertion surface is pimd's mapping table (did the UMH steer anything?) and
bgpd's per-peer refusal counter (was the refusal observable?).

    r1 (AS 65001) ---- s1 ---- r2 (AS 65002)
    source PE                  receiver PoP / box under test
    10.10.10.0/24              `show ip pim dimt umh`
    + UMH EC 10.99.0.1         `show bgp neighbor ... prefixStats`

THE TESTS IN THIS MODULE ARE ORDER-DEPENDENT.  Each stage mutates config the
next one builds on:

  1. test_untrusted_peer_umh_is_ignored_and_counted
        r2 has NOT marked r1 trusted (the startup default).  The route is
        learned, the mapping is absent, the counter moves -- once, and then
        stays put while the refused route just sits in the RIB.
  2. test_trusted_peer_umh_pins
        r2 marks r1 `dimt-trusted`.  The same route now maps, and the counter
        does NOT move further.
  3. test_origin_as_mismatch_is_rejected
        r1 stays trusted, but prepends AS 65000 outbound so the route's origin
        AS is no longer r1's own.  A trusted neighbor may claim a UMH for
        prefixes it originates, not for a third party's it merely transits --
        the mapping is withdrawn and the counter moves again.
  4. test_untrusting_the_peer_withdraws_the_mapping
        `no neighbor ... dimt-trusted` on an otherwise-valid route takes the
        mapping away again, proving the knob is live in both directions and
        not just an at-boot filter.
"""

import json
import os
import sys
from time import sleep

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

SRC_PREFIX = "10.10.10.0/24"
UMH = "10.99.0.1"
# The AS r1 prepends in stage 3 so that the route's origin stops being r1's
# own AS.  FRR applies the outbound route-map first and prepends the local AS
# after, so r2 sees "65001 65000" -- origin 65000, peer 65001.
FOREIGN_AS = 65000


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # s1: the eBGP session.
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # s2: r1's source LAN (gives `redistribute connected` something to
    # originate).
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])

    # s3: r2's receiver stub.
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

    # pimd only on r2 -- it is the mapping consumer, and r1 needs none.
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
    vacuously.  Every predicate below MUST treat None as failure -- this suite
    is mostly made of absence-assertions, and a dead pimd would otherwise pass
    all of them."""
    out = get_topogen().gears[rname].vtysh_cmd(cmd)
    try:
        return json.loads(out)
    except ValueError:
        return None


def _umh_rejected(rname="r2", neighbor="10.0.0.1"):
    """The per-peer DIMT UMH refusal counter.  Returns None on unparseable
    output so the caller can tell "bgpd is gone" from "zero refusals"."""
    data = _json_cmd(rname, "show bgp neighbor {} json".format(neighbor))
    if data is None:
        return None
    peer = data.get(neighbor, {})
    stats = peer.get("prefixStats")
    if stats is None:
        return None
    return stats.get("dimtUmhRejected")


def _route_learned():
    """The route itself must arrive regardless of UMH trust -- refusing a UMH
    must never refuse the route.  Asserted at every stage for that reason."""
    data = _json_cmd("r2", "show ip route {} json".format(SRC_PREFIX))
    if data is None:
        return "r2: unparseable route JSON (zebra dead?)"
    for rt in data.get(SRC_PREFIX, []):
        if rt.get("protocol") == "bgp" and rt.get("selected"):
            return None
    return "r2 has no selected BGP route for {}: {}".format(SRC_PREFIX, data)


def _mapping_present():
    data = _json_cmd("r2", "show ip pim dimt umh json")
    if data is None:
        return "r2: unparseable dimt umh JSON (pimd dead?)"
    entry = data.get(SRC_PREFIX, {})
    if entry.get("umh") != UMH:
        return "r2 UMH mapping missing/wrong: {}".format(data)
    return None


def _mapping_absent():
    data = _json_cmd("r2", "show ip pim dimt umh json")
    if data is None:
        return "r2: unparseable dimt umh JSON (pimd dead?)"
    if SRC_PREFIX in data:
        return "r2 honoured a UMH it should have refused: {}".format(data)
    return None


def _skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


def _precondition(pred, expected):
    """The stages below run in file order and each leaves trust state the next
    one depends on.  Nothing in pytest enforces that -- a `-k` selection, a
    shuffling plugin, or a stage inserted in the middle would run against state
    its predecessor never applied, and the stage would then assert against the
    WRONG trust state rather than erroring.  Fail loudly and say so."""
    err = pred()
    if err is not None:
        pytest.fail(
            "precondition not met -- expected {}, got: {}.  Stages in this "
            "file are order-dependent; run them in file order.".format(expected, err)
        )


def test_untrusted_peer_umh_is_ignored_and_counted():
    """DEFAULT DENY.  r1 is not marked dimt-trusted, so its UMH EC is refused
    -- but the route it rides on is still accepted, and the refusal is
    countable rather than only loggable."""
    _skip_on_failure()

    _, result = topotest.run_and_expect(_route_learned, None, count=60, wait=1)
    assert result is None, result

    def _refused():
        n = _umh_rejected()
        if n is None:
            return "r2: no dimtUmhRejected in neighbor JSON (bgpd dead, or the counter was not wired into prefixStats)"
        if n < 1:
            return "r2 did not count the refusal: dimtUmhRejected={}".format(n)
        return None

    _, result = topotest.run_and_expect(_refused, None, count=60, wait=1)
    assert result is None, result

    # Absence is checked only AFTER the counter has moved, so this is not a
    # race against a mapping that simply has not arrived yet: the counter
    # moving proves bgpd reached the decision point and refused.
    # Bound once: re-calling it in the message would report a different table
    # state than the one that failed.
    absent = _mapping_absent()
    assert absent is None, absent

    # ONE ARRIVING EC IS ONE REFUSAL.  The counter is the operator's probe
    # detector, so it has to track what the neighbor sent, not how often
    # something on our side happened to re-read the path it sent.  Nothing
    # new arrives while the refused route simply sits in the RIB, so the
    # count must not move.
    #
    # Honest scope: this fixture has no MVPN Type-7 lane, so it cannot
    # reproduce the specific re-read that drove the count up (join
    # origination and the re-emit sweep both re-resolve the unicast source
    # route).  It pins the invariant those lanes violated -- counting on
    # read rather than on arrival -- which is what a future consumer of
    # bgp_dimt_umh_from_path() would get wrong the same way.
    settled = _umh_rejected()
    assert settled is not None, "r2: counter unreadable after the refusal"
    sleep(4)
    after = _umh_rejected()
    assert after == settled, (
        "r2 kept counting refusals for an EC that arrived once and has not "
        "been re-sent: {} -> {}".format(settled, after)
    )


def test_trusted_peer_umh_pins():
    """Marking the neighbor dimt-trusted honours the same EC on the same
    route.

    The flag carries peer_change_reset, so the session bounces and the route
    is re-learned under the new trust state.  A route refresh would NOT do:
    the peer re-sends identical attributes, bgp_update() classes that as
    "Same attribute comes in" and returns without calling bgp_process(), so
    the bgp_route_update hook never fires.  This stage and stage 4 are what
    catch a regression back to a refresh."""
    _skip_on_failure()
    _precondition(_mapping_absent, "no mapping, as stage 1 left it")

    assert _umh_rejected() is not None, "r2: counter unreadable before the knob"

    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 65002
          neighbor 10.0.0.1 dimt-trusted
        """
    )

    _, result = topotest.run_and_expect(_mapping_present, None, count=60, wait=1)
    assert result is None, result

    # An accepted UMH must not count a refusal.  Sampled AFTER the mapping has
    # landed (so bgpd has demonstrably re-evaluated the path) and compared
    # against itself a few seconds later, rather than against `before`: the
    # session bounced in between, and this way the assertion does not depend
    # on whether peer counters survive that bounce.
    settled = _umh_rejected()
    assert settled is not None, "r2: counter unreadable after the knob"
    sleep(4)
    # Bound once: re-reading it in the message would report a different sample
    # than the one that actually failed the comparison.
    after = _umh_rejected()
    assert after == settled, (
        "r2 kept counting refusals while the UMH was being ACCEPTED: "
        "{} -> {}".format(settled, after)
    )


def test_origin_as_mismatch_is_rejected():
    """ORIGIN-AS PARITY with the UMH large community's trust rule.  r1 is
    still dimt-trusted, but now transits a prefix whose origin AS is 65000.  A
    trusted neighbor may claim a UMH for what it originates, not for a third
    party's prefix it merely carries -- so the mapping goes away again."""
    _skip_on_failure()
    _precondition(_mapping_present, "the mapping pinned, as stage 2 left it")

    before = _umh_rejected()
    assert before is not None, "r2: counter unreadable before the prepend"

    # Outbound prepend on r1.  FRR runs the outbound route-map and THEN
    # prepends the local AS, so r2 receives "65001 65000": origin 65000,
    # sending peer 65001.
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         route-map FOREIGN permit 10
          set as-path prepend {foreign}
         exit
         router bgp 65001
          address-family ipv4 unicast
           neighbor 10.0.0.2 route-map FOREIGN out
        """.format(foreign=FOREIGN_AS)
    )

    def _refused_again():
        n = _umh_rejected()
        if n is None:
            return "r2: counter unreadable (bgpd dead?)"
        if n <= before:
            return "r2 did not count the origin-AS refusal: {} -> {}".format(
                before, n
            )
        return None

    _, result = topotest.run_and_expect(_refused_again, None, count=60, wait=1)
    assert result is None, result

    _, result = topotest.run_and_expect(_mapping_absent, None, count=60, wait=1)
    assert result is None, result

    # The route must survive the UMH refusal -- only the UMH is refused.
    learned = _route_learned()
    assert learned is None, learned

    # Restore r1 for the next stage.
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 65001
          address-family ipv4 unicast
           no neighbor 10.0.0.2 route-map FOREIGN out
        """
    )
    _, result = topotest.run_and_expect(_mapping_present, None, count=60, wait=1)
    assert result is None, result


def test_untrusting_the_peer_withdraws_the_mapping():
    """`no neighbor ... dimt-trusted` must take an already-honoured mapping
    away.  A gate that only filters at session bring-up would leave a
    previously-trusted peer's UMH steering joins forever after the operator
    revoked it."""
    _skip_on_failure()
    _precondition(_mapping_present, "the mapping restored, as stage 3 left it")

    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 65002
          no neighbor 10.0.0.1 dimt-trusted
        """
    )

    # Anchor the absence to the RE-LEARNED route, not to the knob.  The flag
    # carries peer_change_reset, so the session bounces and the route is
    # transiently withdrawn -- and a withdraw DELs the mapping through the
    # `else` arm of bgp_dimt_route_update() regardless of trust.
    # run_and_expect() samples its predicate immediately and returns on the
    # first success, so polling for absence here would be satisfied by that
    # withdraw, BEFORE the re-learned route is ever evaluated under the
    # revoked flag: a regression making revocation a no-op on re-learn would
    # still go green.  Stages 1 and 3 order a counter check ahead of the
    # absence check for the same reason; the counter is the wrong anchor here
    # because the bounce is exactly what stage 2 declines to assume peer
    # counters survive.  Wait for the route back, then assert absence STAYS
    # true across the settle window rather than sampling it once: a single
    # sample can land before a wrongly-sent ADD reaches pimd, while repeated
    # absence checks cannot be satisfied early by a transient the way polling
    # for first-success can.
    _, result = topotest.run_and_expect(_route_learned, None, count=60, wait=1)
    assert result is None, result

    for _ in range(5):
        sleep(1)
        absent = _mapping_absent()
        assert absent is None, absent


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
