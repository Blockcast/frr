#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_mvpn_gtm_srcas.py: the exact reproduction of the Type-7 Source-AS
withdraw strand.

bgp_mvpn_source_tree_join_set() re-derives the Source AS from the source
route on withdraw and (before the fix) removed the Type-7 (C-multicast
Source Tree Join) by that exact NLRI key.  The Source AS is part of the
key, so when its origination-time value differs from the leave-time value
the exact-key remove misses the originally originated route and it strands
in the MCAST-VPN RIB, advertised indefinitely.

A plain FRR router cannot originate a Source AS extended community (it is
not route-map settable), so a raw BGP speaker (peer1/srcas_peer.py) feeds
r1 the source's covering unicast route carrying a Source AS EC = 65005
(!= r1's local AS 65001).  r1 then originates a Type-7 keyed by 65005.  The
test stops the speaker -- withdrawing the source route -- and removes the
join: the leave re-derives the Source AS as the *local* AS (source route
gone), so a Source-AS-keyed remove would strand the 65005 route.  With the
(C-S, C-G)-match withdraw the Type-7 disappears.

    +----+   10.0.0.0/24   +-------+
    | r1 |-----------------| peer1 |   (raw BGP speaker, srcas_peer.py)
    +----+                 +-------+
      | 192.168.2.0/24 (receiver stub, the IGMP join lives here)
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

SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"
SRC_PREFIX = "10.10.10.0/24"
LOCAL_AS = 65001
# The Source AS carried by the crafted peer's EC -- deliberately NOT the
# local AS, so a leave-time re-derivation (source route gone -> local AS)
# yields a different Type-7 key.
SRC_AS = 65005

PID_FILE = None


def build_topo(tgen):
    tgen.add_router("r1")
    peer1 = tgen.add_exabgp_peer(
        "peer1", ip="10.0.0.2/24", defaultRoute="via 10.0.0.1"
    )

    # s1: the iBGP segment to the crafted speaker
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(peer1)

    # s2: r1's receiver stub (the IGMP join lives here)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    global PID_FILE

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    r1.load_config(TopoRouter.RD_PIM, os.path.join(CWD, "r1/pimd.conf"))
    r1.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))
    r1.start()

    # Start the raw speaker on peer1: it establishes the iBGP session and
    # advertises the source route with a Source AS EC of SRC_AS.
    peer = tgen.gears["peer1"]
    speaker = os.path.join(CWD, "peer1/srcas_peer.py")
    log_dir = os.path.join(peer.logdir, peer.name)
    peer.cmd("chmod 777 {}".format(log_dir))
    log_file = os.path.join(log_dir, "srcas_peer.log")
    PID_FILE = os.path.join(log_dir, "srcas_peer.pid")
    peer.cmd(
        "python3 {} 10.0.0.1 {} 10.0.0.2 {} > {} 2>&1 & echo $! > {}".format(
            speaker, LOCAL_AS, SRC_AS, log_file, PID_FILE
        )
    )
    logger.info("srcas_peer started on peer1 (source AS %d)", SRC_AS)


def teardown_module(mod):
    tgen = get_topogen()
    if PID_FILE:
        tgen.gears["peer1"].cmd("kill $(cat {}) 2>/dev/null".format(PID_FILE))
    tgen.stop_topology()


def _mvpn_routes(router):
    out = json.loads(get_topogen().gears[router].vtysh_cmd("show bgp ipv4 mvpn json"))
    return out.get("routes", [])


def test_session_established():
    """The crafted speaker's iBGP session with r1 must reach Established."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _established():
        out = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp neighbor 10.0.0.2 json")
        )
        return topotest.json_cmp(out, {"10.0.0.2": {"bgpState": "Established"}})

    _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
    assert result is None, "r1 did not reach Established with the crafted speaker"


def test_source_route_learned():
    """r1 learns the source's covering unicast route from the speaker (it
    carries the Source AS EC that will key the Type-7)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _learned():
        data = json.loads(
            tgen.gears["r1"].vtysh_cmd(
                "show ip route {} json".format(SRC_PREFIX)
            )
        )
        for rt in data.get(SRC_PREFIX, []):
            if rt.get("protocol") == "bgp" and rt.get("selected"):
                return None
        return "r1 has no selected BGP route for {}: {}".format(SRC_PREFIX, data)

    _, result = topotest.run_and_expect(_learned, None, count=60, wait=1)
    assert result is None, result


def test_type7_originated_with_nonlocal_source_as():
    """An IGMP (S,G) join must originate a Type-7 keyed by the peer-supplied
    Source AS (65005), NOT the local AS -- proving the Source AS EC was
    parsed off the source route."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
interface r1-eth1
 ip igmp join-group {} {}
""".format(GROUP, SOURCE)
    )

    def _type7_srcas():
        for r in _mvpn_routes("r1"):
            if (
                r.get("routeType") == 7
                and r.get("source") == SOURCE
                and r.get("group") == GROUP
                and r.get("sourceAs") == SRC_AS
            ):
                return None
        return "Type-7 ({}, {}, AS {}) not originated: {}".format(
            SOURCE, GROUP, SRC_AS, _mvpn_routes("r1")
        )

    _, result = topotest.run_and_expect(_type7_srcas, None, count=90, wait=1)
    assert result is None, result


def test_leave_after_source_gone_fully_withdraws():
    """THE regression: stop the speaker so the source route is withdrawn,
    then remove the join.  The leave re-derives the Source AS as the local
    AS (source route gone), which differs from the originated 65005 -- a
    Source-AS-keyed remove would strand the 65005 Type-7.  The (C-S, C-G)
    match withdraw must leave NO Type-7 for the (S,G)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # stop the speaker -> its iBGP session drops -> source route withdrawn
    tgen.gears["peer1"].cmd("kill $(cat {}) 2>/dev/null".format(PID_FILE))

    def _source_gone():
        data = json.loads(
            tgen.gears["r1"].vtysh_cmd(
                "show ip route {} json".format(SRC_PREFIX)
            )
        )
        if data.get(SRC_PREFIX):
            return "r1 still has the source route: {}".format(data)
        return None

    _, result = topotest.run_and_expect(_source_gone, None, count=60, wait=1)
    assert result is None, result

    # now leave: the Type-7 must be fully withdrawn, not stranded
    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
interface r1-eth1
 no ip igmp join-group {} {}
""".format(GROUP, SOURCE)
    )

    def _no_type7():
        for r in _mvpn_routes("r1"):
            if (
                r.get("routeType") == 7
                and r.get("source") == SOURCE
                and r.get("group") == GROUP
            ):
                return "Type-7 ({}, {}, AS {}) stranded after leave: {}".format(
                    SOURCE, GROUP, r.get("sourceAs"), r
                )
        return None

    _, result = topotest.run_and_expect(_no_type7, None, count=90, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
