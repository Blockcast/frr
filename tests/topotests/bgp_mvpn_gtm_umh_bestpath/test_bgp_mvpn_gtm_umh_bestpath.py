#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_mvpn_gtm_umh_bestpath.py: the Type-7 resolver must read the RFC 6514
Section 5 communities (Source AS, upstream-PE route-import) off the SELECTED
path of the unicast route toward C-S -- both values from that one path, as a
unit.

Two crafted iBGP speakers advertise the same covering source route with
deliberately split communities:

  peer1 (LOCAL_PREF 100, non-best): Source AS EC = 65005, no route-import
  peer2 (LOCAL_PREF 200, best):     route-import 10.255.0.9, no Source AS

A resolver that walks every path filling each field from whichever path
happens to carry it produces the mixed pair (AS 65005, UMH 10.255.0.9) --
a combination no single advertisement carried. Reading the selected path
as a unit yields (local AS 65001 [Section 4.6 fallback, best path has no
Source AS EC], UMH 10.255.0.9).

Two later stages exercise the re-key: killing peer2 flips the best path to
peer1's (a withdrawal-driven flip), and restarting peer2 at a higher
LOCAL_PREF flips it back (an arrival-driven flip). The unicast-route
re-resolution -- which runs only after the BGP_PATH_SELECTED flag is
committed -- must re-key the Type-7 each time WITHOUT stranding the
previously originated route.

    +-------+   10.0.0.0/24   +----+   10.0.1.0/24   +-------+
    | peer1 |-----------------| r1 |-----------------| peer2 |
    +-------+                 +----+                 +-------+
                                | 192.168.2.0/24 (receiver stub)
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
# Carried only by the NON-best path: a mixed-field resolution leaks it into
# the Type-7 key; a selected-path resolution must not.
NONBEST_SRC_AS = 65005
# Carried only by the best path: the upstream PE the Type-7 must target.
BEST_RT_IMPORT = "10.255.0.9"
# Carried by the RE-ADDED best path (arrival-driven flip): a different
# upstream so the re-key to the arriving selection is observable.
ADD_RT_IMPORT = "10.255.0.11"

PID_FILES = {}


def build_topo(tgen):
    tgen.add_router("r1")
    peer1 = tgen.add_exabgp_peer(
        "peer1", ip="10.0.0.2/24", defaultRoute="via 10.0.0.1"
    )
    peer2 = tgen.add_exabgp_peer(
        "peer2", ip="10.0.1.2/24", defaultRoute="via 10.0.1.1"
    )

    # s1/s2: the iBGP segments to the two crafted speakers
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(peer1)

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(peer2)

    # s3: r1's receiver stub (the IGMP join lives here)
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])


def _start_speaker(tgen, name, extra_args):
    peer = tgen.gears[name]
    speaker = os.path.join(CWD, "peer1/umh_peer.py")
    log_dir = os.path.join(peer.logdir, peer.name)
    peer.cmd("chmod 777 {}".format(log_dir))
    log_file = os.path.join(log_dir, "umh_peer.log")
    pid_file = os.path.join(log_dir, "umh_peer.pid")
    PID_FILES[name] = pid_file
    peer.cmd(
        "python3 {} {} > {} 2>&1 & echo $! > {}".format(
            speaker, extra_args, log_file, pid_file
        )
    )
    logger.info("umh_peer started on %s (%s)", name, extra_args)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    r1.load_config(TopoRouter.RD_PIM, os.path.join(CWD, "r1/pimd.conf"))
    r1.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))
    r1.start()

    # peer1: LOCAL_PREF 100 (loses bestpath), Source AS EC only.
    _start_speaker(
        tgen,
        "peer1",
        "10.0.0.1 {} 10.0.0.2 100 --source-as {}".format(LOCAL_AS, NONBEST_SRC_AS),
    )
    # peer2: LOCAL_PREF 200 (wins bestpath), route-import EC only.
    _start_speaker(
        tgen,
        "peer2",
        "10.0.1.1 {} 10.0.1.2 200 --rt-import {}".format(LOCAL_AS, BEST_RT_IMPORT),
    )


def teardown_module(mod):
    tgen = get_topogen()
    for name, pid_file in PID_FILES.items():
        tgen.gears[name].cmd("kill $(cat {}) 2>/dev/null".format(pid_file))
    tgen.stop_topology()


def _mvpn_routes(router):
    out = json.loads(get_topogen().gears[router].vtysh_cmd("show bgp ipv4 mvpn json"))
    return out.get("routes", [])


def _type7s(router):
    return [
        r
        for r in _mvpn_routes(router)
        if r.get("routeType") == 7
        and r.get("source") == SOURCE
        and r.get("group") == GROUP
    ]


def test_sessions_established():
    """Both crafted speakers' iBGP sessions with r1 must reach Established."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for neigh in ("10.0.0.2", "10.0.1.2"):

        def _established(neigh=neigh):
            out = json.loads(
                tgen.gears["r1"].vtysh_cmd("show bgp neighbor {} json".format(neigh))
            )
            return topotest.json_cmp(out, {neigh: {"bgpState": "Established"}})

        _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
        assert result is None, "r1 did not reach Established with {}".format(neigh)


def test_source_route_bestpath_is_peer2():
    """r1 must hold BOTH paths for the source route, with peer2's
    (LOCAL_PREF 200) selected as best."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _two_paths_best_peer2():
        data = json.loads(
            tgen.gears["r1"].vtysh_cmd(
                "show bgp ipv4 unicast {} json".format(SRC_PREFIX)
            )
        )
        paths = data.get("paths", [])
        if len(paths) != 2:
            return "expected 2 paths for {}, have {}".format(SRC_PREFIX, len(paths))
        for path in paths:
            best = path.get("bestpath", {}).get("overall", False)
            peer = path.get("peer", {}).get("peerId")
            if best and peer != "10.0.1.2":
                return "best path is from {} not peer2".format(peer)
            if best and peer == "10.0.1.2":
                return None
        return "no overall best path selected: {}".format(paths)

    _, result = topotest.run_and_expect(_two_paths_best_peer2, None, count=60, wait=1)
    assert result is None, result


def test_type7_resolves_from_selected_path_only():
    """An IGMP (S,G) join must originate a Type-7 whose Source AS AND
    upstream RT both come off peer2's best path: Source AS = the local AS
    (best path carries no Source AS EC; the non-best path's 65005 must NOT
    leak in) and RT = the best path's route-import GA."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
interface r1-eth2
 ip igmp join-group {} {}
""".format(GROUP, SOURCE)
    )

    def _type7_atomic():
        routes = _type7s("r1")
        for r in routes:
            if (
                r.get("sourceAs") == LOCAL_AS
                and r.get("extendedCommunity", {}).get("string")
                == "RT:{}:0".format(BEST_RT_IMPORT)
            ):
                return None
        return "Type-7 (AS {}, RT:{}:0) not originated; have: {}".format(
            LOCAL_AS, BEST_RT_IMPORT, routes
        )

    _, result = topotest.run_and_expect(_type7_atomic, None, count=90, wait=1)
    assert result is None, result


def test_bestpath_flip_rekeys_without_strand():
    """Kill peer2: the best path flips to peer1's (Source AS EC 65005, no
    route-import). The re-resolution must re-key the Type-7 to Source AS
    65005 and remove the previously originated local-AS-keyed route -- one
    local Type-7 per (C-S, C-G), never two."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["peer2"].cmd("kill $(cat {}) 2>/dev/null".format(PID_FILES["peer2"]))

    def _rekeyed():
        routes = _type7s("r1")
        stale = [r for r in routes if r.get("sourceAs") == LOCAL_AS]
        rekeyed = [r for r in routes if r.get("sourceAs") == NONBEST_SRC_AS]
        if stale:
            return "stale local-AS Type-7 stranded after bestpath flip: {}".format(
                stale
            )
        if not rekeyed:
            return "Type-7 not re-keyed to AS {}; have: {}".format(
                NONBEST_SRC_AS, routes
            )
        if len(routes) != 1:
            return "want exactly 1 Type-7 after flip, have {}: {}".format(
                len(routes), routes
            )
        # peer1 carries no route-import: the re-keyed Type-7 must be RT-less,
        # not still carrying peer2's stale 10.255.0.9 upstream.
        got_rt = rekeyed[0].get("extendedCommunity", {}).get("string")
        if got_rt:
            return "re-keyed Type-7 still carries upstream RT {} (peer1 has none): {}".format(
                got_rt, rekeyed[0]
            )
        return None

    _, result = topotest.run_and_expect(_rekeyed, None, count=90, wait=1)
    assert result is None, result


def test_add_driven_flip_rekeys():
    """A BETTER path ARRIVING (not a withdrawal) must also re-key. Restart
    peer2 at LOCAL_PREF 300 with a fresh route-import: the arrival becomes
    best, and the resolver -- running only after the BGP_PATH_SELECTED flag
    is committed -- must re-key the Type-7 to (local AS, the new upstream),
    still exactly one Type-7 (peer1's 65005 key must not strand)."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _start_speaker(
        tgen,
        "peer2",
        "10.0.1.1 {} 10.0.1.2 300 --rt-import {}".format(LOCAL_AS, ADD_RT_IMPORT),
    )

    def _reflip():
        routes = _type7s("r1")
        if len(routes) != 1:
            return "want exactly 1 Type-7 after arrival flip, have {}: {}".format(
                len(routes), routes
            )
        r = routes[0]
        if r.get("sourceAs") != LOCAL_AS:
            return "Type-7 not re-keyed to local AS {} on arrival flip: {}".format(
                LOCAL_AS, r
            )
        got_rt = r.get("extendedCommunity", {}).get("string")
        want_rt = "RT:{}:0".format(ADD_RT_IMPORT)
        if got_rt != want_rt:
            return "Type-7 upstream RT {} != new {}: {}".format(got_rt, want_rt, r)
        return None

    _, result = topotest.run_and_expect(_reflip, None, count=90, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
