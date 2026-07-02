#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_mvpn_gtm.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Blockcast, Inc.
#

"""
test_bgp_mvpn_gtm.py:

Verify that the BGP MCAST-VPN address family (AFI 1, SAFI 5 / IANA SAFI 5,
RFC 6514) registers and negotiates the multiprotocol capability between two
iBGP speakers.

Topology:

    +----+   10.0.0.0/24   +----+
    | r1 |-----------------| r2 |
    +----+                 +----+

Both routers run `router bgp 65001`, peer over the shared subnet, and enable
`address-family ipv4 mvpn` with `neighbor <peer> activate`. The test asserts
the MVPN AF is advertised and received in the multiprotocol capability, and
that a locally-originated Route Type 5 (Source Active A-D, RFC 6514 / GTM
RFC 7716) route on r1 propagates to r2.
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


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_mvpn_converge():
    """The iBGP session must reach Established before capabilities are stable."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge(router, peer):
        output = json.loads(
            tgen.gears[router].vtysh_cmd(
                "show bgp neighbor {} json".format(peer)
            )
        )
        expected = {peer: {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, "r1", "10.0.0.2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 did not converge with r2"


def test_mvpn_af_negotiated():
    """The MVPN AF multiprotocol capability must be advertised and received."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _mvpn_capability(router, peer):
        output = json.loads(
            tgen.gears[router].vtysh_cmd(
                "show bgp neighbor {} json".format(peer)
            )
        )
        expected = {
            peer: {
                "neighborCapabilities": {
                    "multiprotocolExtensions": {
                        "ipv4Mvpn": "advertisedAndReceived"
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)

    for router, peer in (("r1", "10.0.0.2"), ("r2", "10.0.0.1")):
        test_func = functools.partial(_mvpn_capability, router, peer)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{}: ipv4 mvpn capability not advertisedAndReceived".format(
            router
        )


def test_type5_source_active_propagates():
    """A local GTM Source Active (Type 5) route on r1 must reach r2 via BGP.

    r1 is configured with `bgp mvpn source-active 10.10.10.1 group 232.1.1.1`
    under `address-family ipv4 mvpn`. r2 must learn it and expose it via
    `show bgp ipv4 mvpn json` with routeType 5 and the matching (S,G).
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _type5_present(router):
        out = json.loads(tgen.gears[router].vtysh_cmd("show bgp ipv4 mvpn json"))
        routes = out.get("routes", [])
        for r in routes:
            if (
                r.get("routeType") == 5
                and r.get("source") == "10.10.10.1"
                and r.get("group") == "232.1.1.1"
            ):
                return None
        return "Type-5 (10.10.10.1, 232.1.1.1) not found in {}".format(routes)

    test_func = functools.partial(_type5_present, "r2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 did not learn r1's MVPN Type-5 Source Active route"

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
