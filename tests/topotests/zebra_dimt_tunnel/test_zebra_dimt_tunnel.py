#!/usr/bin/env python
# SPDX-License-Identifier: ISC

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.zebra]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_host("h1", "192.0.2.2/24")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    tgen.gears["r1"].load_config(
        TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf")
    )
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def request(action, tunnel_id, encap="gre"):
    client = os.path.join(CWD, "dimt_zapi_client.py")
    output = get_topogen().gears["r1"].run(
        "python3 {} {} {} --encap {}".format(client, action, tunnel_id, encap)
    )
    return json.loads(output)


def test_acknowledged_gre_lifecycle_and_owner_reconnect():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]

    installed = request("add", 1)
    assert installed["result"] == 0, installed
    assert installed["ifindex"] > 0, installed
    link = router.run("ip -d link show dimt-00000001")
    assert "gre remote 192.0.2.2 local 192.0.2.1" in link, link
    address = router.run("ip -o address show dev dimt-00000001")
    assert "10.200.0.1 peer 10.200.0.2/32" in address, address

    # A fresh socket has a new owner session. The idempotent retry must be
    # answered on that session rather than the disconnected original.
    reconnected = request("add", 1)
    assert reconnected == installed, (installed, reconnected)

    removed = request("del", 1)
    assert removed["result"] == 2, removed
    _, result = topotest.run_and_expect(
        lambda: router.run("ip link show dimt-00000001 2>/dev/null"), "", count=10, wait=0.2
    )
    assert result == "", result


def test_acknowledged_gre_in_fou_lifecycle():
    router = get_topogen().gears["r1"]
    installed = request("add", 2, "fou")
    if installed["result"] == 1:
        pytest.skip("test kernel does not support GRE-in-FOU")
    assert installed["result"] == 0, installed
    link = router.run("ip -d link show dimt-00000002")
    assert "encap fou" in link and "encap-dport 5555" in link, link
    removed = request("del", 2)
    assert removed["result"] == 2, removed


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
