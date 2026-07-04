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
the MCAST-VPN AF with an FRR router and sends deliberately crafted Route Type 5
(Source Active) NLRIs plus an empty MP_UNREACH. The FRR side must:

  * install a VALID Type-5 (positive control),
  * DROP a Type-5 whose group is outside the SSM range 232.0.0.0/8,
  * DROP a Type-5 carrying a non-zero Route Distinguisher (GTM requires RD 0),
  * NOT crash on an MP_UNREACH that carries only AFI+SAFI (empty NLRI) -- the
    stream_new(0) assertion-abort that the receive-path hardening fixes.

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


def _mvpn_routes(router):
    out = json.loads(get_topogen().gears[router].vtysh_cmd("show bgp ipv4 mvpn json"))
    return out.get("routes", [])


def _has_type5(routes, sg):
    src, grp = sg
    for r in routes:
        if r.get("routeType") == 5 and r.get("source") == src and r.get("group") == grp:
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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
