#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_mvpn_v6_join_leave.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Blockcast, Inc.
#

"""Exercise the IPv6 MVPN receiver lifecycle across two FRR instances.

The peers use eBGP deliberately: the PoP role may advertise the PE role's
Type-1 route back to its originator, reproducing the stale non-local duplicate
seen in production.  An MLDv2 (S,G) join and leave drive the mixed-family IPv6
MVPN NLRI path while session counters prove neither transition reset BGP.
"""

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.pim6d]

PEER = {"r1": "10.0.0.2", "r2": "10.0.0.1"}
SOURCE = "2001:db8::1"
GROUP = "ff3e::1"
PE_ORIGINATOR = "10.0.0.1"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    fabric = tgen.add_switch("s1")
    fabric.add_link(tgen.gears["r1"])
    fabric.add_link(tgen.gears["r2"])

    receiver = tgen.add_switch("s2")
    receiver.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, rname, "zebra.conf")
        )
        router.load_config(
            TopoRouter.RD_PIM6, os.path.join(CWD, rname, "pim6d.conf")
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, rname, "bgpd.conf")
        )

    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def _neighbor(router):
    output = json.loads(
        get_topogen().gears[router].vtysh_cmd(
            "show bgp neighbor {} json".format(PEER[router])
        )
    )
    return output.get(PEER[router], {})


def _mvpn_routes(router):
    output = json.loads(
        get_topogen().gears[router].vtysh_cmd("show bgp ipv6 mvpn json")
    )
    return output.get("routes", [])


def _established(router):
    state = _neighbor(router).get("bgpState")
    if state == "Established":
        return None
    return "{} session is {}".format(router, state)


def _type1_unique():
    routes = [
        route
        for route in _mvpn_routes("r1")
        if route.get("routeType") == 1
        and route.get("pmsiTunnel", {}).get("endpoint") == PE_ORIGINATOR
    ]
    if len(routes) == 1 and routes[0].get("selfOriginated"):
        return None
    return "PE originator {} has {} Type-1 entries: {}".format(
        PE_ORIGINATOR, len(routes), routes
    )


def _type7_present(want_present):
    routes = _mvpn_routes("r1")
    present = any(
        route.get("routeType") == 7
        and route.get("source") == SOURCE
        and route.get("group") == GROUP
        for route in routes
    )
    if present == want_present:
        return None
    return "IPv6 Type-7 present={} (wanted {}): {}".format(
        present, want_present, routes
    )


def _assert_converged():
    for router in ("r1", "r2"):
        test_func = functools.partial(_established, router)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result


def _assert_unique_type1(stage):
    _, result = topotest.run_and_expect(_type1_unique, None, count=60, wait=1)
    assert result is None, "{}: {}".format(stage, result)


def _assert_no_parse_errors(stage):
    pattern = "MVPN NLRI length .* exceeds remaining|Error parsing NLRI"
    for router in ("r1", "r2"):
        output = get_topogen().gears[router].cmd(
            "grep -E '{}' bgpd.log || true".format(pattern)
        )
        assert not output.strip(), "{}: {} logged parser errors:\n{}".format(
            stage, router, output
        )


def test_ipv6_mvpn_join_leave_and_reestablish():
    """Join/leave must not reset BGP or duplicate the PE's local Type-1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _assert_converged()
    baseline = {
        router: _neighbor(router).get("connectionsEstablished")
        for router in ("r1", "r2")
    }
    assert all(value is not None for value in baseline.values()), baseline
    _assert_unique_type1("before join")
    _assert_no_parse_errors("before join")

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ipv6 mld join-group {} {}
""".format(GROUP, SOURCE)
    )

    _, result = topotest.run_and_expect(
        functools.partial(_type7_present, True), None, count=90, wait=1
    )
    assert result is None, result
    _assert_converged()
    assert {
        router: _neighbor(router).get("connectionsEstablished")
        for router in ("r1", "r2")
    } == baseline, "MLD join reset the BGP session"
    _assert_unique_type1("after join")
    _assert_no_parse_errors("after join")

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 no ipv6 mld join-group {} {}
""".format(GROUP, SOURCE)
    )

    _, result = topotest.run_and_expect(
        functools.partial(_type7_present, False), None, count=90, wait=1
    )
    assert result is None, result
    _assert_converged()
    assert {
        router: _neighbor(router).get("connectionsEstablished")
        for router in ("r1", "r2")
    } == baseline, "MLD leave reset the BGP session"
    _assert_unique_type1("after leave")
    _assert_no_parse_errors("after leave")

    tgen.gears["r1"].vtysh_cmd("clear bgp {}".format(PEER["r1"]))
    _assert_converged()
    assert _neighbor("r1").get("connectionsEstablished") > baseline["r1"], (
        "controlled clear did not re-establish the BGP session"
    )
    _assert_unique_type1("after controlled re-establishment")
    _assert_no_parse_errors("after controlled re-establishment")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
