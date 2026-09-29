#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test OSPF RFC4222 DSCP behavior:
# - "ip ospf dscp all 46"
# - "ip ospf dscp low-control 40"
#
# Verify on the wire:
#   - Hello (type 1) uses DSCP 46
#   - Ack (type 5) uses DSCP 46
#   - DB-Desc (2) or LSU (4) uses DSCP 40
#

import sys
import os
import pytest
import json

from lib.topogen import Topogen, get_topogen, TopoRouter, topotest
from lib.topolog import logger

# Must match the addresses in r1/frr.conf and r2/frr.conf.  r1's is not
# cosmetic: every DSCP assertion here is scoped to it (see
# _tshark_dscp_and_type).
R1_ADDR = "192.0.2.1"
R2_ADDR = "192.0.2.2"


def _build_topo(tgen):
    "Simple R1-R2 topology"
    # Create 2 routers
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    # Create a p2p connection between r1 and r2
    tgen.add_link(r1, r2, ifname1="r1-eth0", ifname2="r2-eth0")


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    tgen = Topogen(_build_topo, request.module.__name__)
    tgen.start_topology()
    router_list = tgen.routers()

    # Load FRR configs
    for router in router_list.values():
        router.load_frr_config()

    # Start all routers
    tgen.start_router()

    yield tgen

    # Teardown
    tgen.stop_topology()


# Fixture that executes before each test
@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def _vty(router, cmd):
    return get_topogen().gears[router].vtysh_cmd(cmd)


def _collect_neighbors(obj):
    """
    Recursively walk any JSON shape and collect neighbor dicts.
    Neighbor dicts typically have fields like 'nbrState' or 'state',
    and often 'ifaceName', 'ifaceAddress', etc.
    """
    found = []
    if isinstance(obj, dict):
        # Direct 'neighbors' container (can be dict or list)
        if "neighbors" in obj:
            nb = obj["neighbors"]
            if isinstance(nb, dict):
                for v in nb.values():
                    if isinstance(v, list):
                        found.extend(v)
                    elif isinstance(v, dict) and ("nbrState" in v or "state" in v):
                        found.append(v)
            elif isinstance(nb, list):
                for v in nb:
                    if isinstance(v, dict):
                        found.append(v)
        # In some versions, neighbor lists are nested under VRF/areas/interfaces
        for v in obj.values():
            found.extend(_collect_neighbors(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(_collect_neighbors(v))
    return found


def neighbors_full(router):
    """
    Return True if at least one neighbor on this router is Full.
    Robust to FRR JSON shape differences.
    """
    raw = _vty(router, "show ip ospf neighbor json")
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        # Fall back to non-JSON if something odd happened
        return False

    neigh = _collect_neighbors(data)
    if not neigh:
        return False

    # FRR sometimes uses 'nbrState' ("Full/-") or 'state' ("Full")
    for n in neigh:
        st = n.get("nbrState") or n.get("state") or ""
        if isinstance(st, str) and st.startswith("Full"):
            return True
    return False


def vty_json(router: str, cmd: str):
    """Run a vtysh *json command and return {} if empty/unparseable."""
    raw = get_topogen().gears[router].vtysh_cmd(cmd)
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def ospf_if_json(router: str, ifname: str):
    data = vty_json(router, "show ip ospf interface {} json".format(ifname))
    if not data:
        return {}

    if "interfaces" in data and ifname in data["interfaces"]:
        return data["interfaces"][ifname]

    if ifname in data:
        return data[ifname]

    return data


def _wait_for_neighbors_full(router, retries=20, delay=1):
    while retries > 0:
        if neighbors_full(router):
            return True
        topotest.sleep(delay, "Wait for neighbor")
        retries -= 1
    return False


def test_ospf_dscp_basic(tgen):
    assert _wait_for_neighbors_full("r1", delay=2)
    assert _wait_for_neighbors_full("r2")


def _capture_ospf_pcap(router, iface, pcap_path):
    """Run tshark for a short duration to capture OSPF packets"""
    router.cmd(f"rm -f {pcap_path}")
    router.cmd(f"tshark -i {iface} -w {pcap_path} -f 'proto ospf' >/dev/null 2>&1 &")


def _stop_ospf_capture(router, iface, pcap_path):
    """Stop tshark capture"""
    # tshark uses its own process name, so kill by output file
    router.cmd(f"pkill -f 'tshark -i {iface} -w {pcap_path}' || true")
    topotest.sleep(1, "Saving Capture")


def _tshark_dscp_and_type(router, pcap_path, src):
    """
    Return a list of (dscp, ospf.msg) tuples from the pcap, restricted to the
    packets *sourced by* `src`.

    The ip.src term is load-bearing, not tidiness.  r1-eth0 sees BOTH
    directions of the p2p link, so a capture taken there contains r2's OSPF
    packets as well as r1's.  Without the filter, "r1 sent a Hello with DSCP
    46" is satisfiable by a Hello r2 sent -- i.e. the test can pass while the
    very marking it exists to assert is broken.  Today the assertions isolate
    r1 only by accident, because r2-eth0 is unmarked and so emits CS6/48;
    test_ospf_dscp_source_isolation removes that accident and fails if this
    term is ever dropped.

    Requires tshark installed in the test environment.
    """
    cmd = (
        'tshark -r {} -Y "ospf && ip.src=={}" -T fields '
        "-e ip.dsfield.dscp -e ospf.msg 2>/dev/null"
    ).format(pcap_path, src)
    out = router.cmd(cmd).strip()
    res = []
    if not out:
        return res
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        dscp_str, msg_str = parts
        try:
            dscp = int(dscp_str)
            msg = int(msg_str)
            res.append((dscp, msg))
        except ValueError:
            continue
    return res


def _dscp_flags(router, iface, pcap_path, stimulate, src, settle=6):
    """Capture OSPF on `iface` across one window while `stimulate()` runs.

    Only packets sourced by `src` are counted.  It has no default on purpose:
    any capture on this p2p link also carries the peer's packets, so the
    source has to be named at every call site (see _tshark_dscp_and_type).

    Returns (hello_ok, ack_ok, low_ctrl_ok, npackets) as observed in THIS
    window only; the caller ORs successive windows together.
    """
    _capture_ospf_pcap(router, iface, pcap_path)
    topotest.sleep(2, "Setup packet capture")
    stimulate()
    topotest.sleep(settle, "Gathering Packets")
    _stop_ospf_capture(router, iface, pcap_path)

    hello_ok = ack_ok = low_ctrl_ok = False
    tuples = _tshark_dscp_and_type(router, pcap_path, src)
    for dscp, msg in tuples:
        # msg: 1=Hello, 2=DB-Desc, 3=LS-Req, 4=LS-Upd, 5=LS-Ack
        hello_ok = hello_ok or (msg == 1 and dscp == 46)
        ack_ok = ack_ok or (msg == 5 and dscp == 46)
        low_ctrl_ok = low_ctrl_ok or (msg in (2, 3, 4) and dscp == 40)
    return hello_ok, ack_ok, low_ctrl_ok, len(tuples)


def test_ospf_dscp_all_and_low_control(tgen):
    "Verify per-interface DSCP all/low-control markings on the wire"
    if not tgen.routers():
        pytest.skip("Topology not created")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Ensure adjacency is up before playing with DSCP.  WAIT rather than
    # assert once (BLO-36708): CI reruns a failing file on its own, and this
    # test then starts seconds after topology start rather than after
    # test_ospf_dscp_basic has already waited for Full.
    assert _wait_for_neighbors_full("r1", retries=30, delay=2), (
        "R1 did not reach Full with R2"
    )

    # Configure DSCP on R1:
    # - all = 46
    # - low-control = 40 (CS5, for example)
    r1.vtysh_cmd(
        """
configure terminal
interface r1-eth0
  ip ospf dscp all 46
  ip ospf dscp low-control 40
  exit
  exit
"""
    )

    # Every assertion below is "a packet of this kind flew inside the capture
    # window", which is a race the CI hosts lose under load -- observed
    # failing on all three of hello/ack/low-control across runs 36101674598,
    # 36185422488 and 36196482335.  So: stimulate BOTH directions and retry.
    #
    #   * r1's own redistributed loopbacks make r1 flood LS-Upd  -> low-control
    #   * r2's make r2 flood to r1, which r1 must LS-Ack         -> ack
    #
    # Without the r2 half there is nothing on a two-router p2p link that
    # obliges r1 to send an Ack at all, so ack_ok was pure luck.
    r1.vtysh_cmd("conf t\nrouter ospf\n redistribute connected\n exit")
    r2.vtysh_cmd("conf t\nrouter ospf\n redistribute connected\n exit")

    pcap = os.path.join(tgen.logdir, "r1-ospf-dscp.pcap")
    logger.info("PCAP DIR: {}".format(pcap))

    hello_ok = ack_ok = low_ctrl_ok = False
    npackets = 0
    for rnd in range(5):

        def stimulate(rnd=rnd):
            for i in range(1, 10):
                octet = rnd * 10 + i
                r1.cmd(f"ip addr add 198.51.100.{octet}/32 dev lo")
                r2.cmd(f"ip addr add 203.0.113.{octet}/32 dev lo")

        # Hellos are cheap here (hello-interval 1); a full LSU/Ack exchange is
        # not, and a single 8s window can simply miss one on a loaded CI host.
        #
        # The cause is host scheduling jitter, NOT MinLSInterval: each round
        # adds a fresh batch of /32s, so every LSU it provokes carries a NEW
        # Link State ID, and MinLSInterval only rate-limits re-originating the
        # SAME LSA.  Do not tune this window against a throttle that never
        # applies to it.
        hello, ack, low_ctrl, seen = _dscp_flags(
            r1, "r1-eth0", pcap, stimulate, src=R1_ADDR
        )
        hello_ok = hello_ok or hello
        ack_ok = ack_ok or ack
        low_ctrl_ok = low_ctrl_ok or low_ctrl
        npackets += seen
        if hello_ok and ack_ok and low_ctrl_ok:
            break

    # Keep this distinguishable from the three below: zero packets across all
    # windows means tshark or the capture is broken, not that DSCP is wrong.
    assert npackets, "No OSPF packets from R1 captured on r1-eth0"
    assert hello_ok, "No Hello packet from R1 with DSCP 46 observed"
    assert ack_ok, "No Ack packet from R1 with DSCP 46 observed"
    assert low_ctrl_ok, "No DB-Desc/LS-Req/LS-Upd from R1 with DSCP 40 observed"


def test_ospf_dscp_source_isolation(tgen):
    """The r1 DSCP assertions must not be satisfiable by r2's packets.

    r1-eth0 carries both directions, so every assertion in
    test_ospf_dscp_all_and_low_control rests on _tshark_dscp_and_type's
    ip.src term to mean "from r1" rather than "on this link".  That is
    invisible while r2 is unmarked: r2 emits CS6/48, which matches none of
    the values asserted for r1, so the test isolates r1 by accident.

    Remove the accident.  Mark r2 with the exact value r1's Hello assertion
    looks for (46) and move r1 to a different one (34), then require r1's
    filtered view to contain r1's value and NONE of r2's.  Drop the ip.src
    term and r2's Hellos land in r1's view, so this fails.
    """
    if not tgen.routers():
        pytest.skip("Topology not created")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    assert _wait_for_neighbors_full("r1", retries=30, delay=2), (
        "R1 did not reach Full with R2"
    )

    # r1 -> 34 only (clear the inherited low-control 40 so r1 emits one
    # value); r2 -> 46, the value the Hello/Ack assertions look for on r1.
    r1.vtysh_cmd(
        """
configure terminal
interface r1-eth0
  no ip ospf dscp low-control
  ip ospf dscp all 34
  exit
  exit
"""
    )
    r2.vtysh_cmd(
        """
configure terminal
interface r2-eth0
  ip ospf dscp all 46
  exit
  exit
"""
    )

    pcap = os.path.join(tgen.logdir, "r1-ospf-dscp-isolation.pcap")

    # Let the reconfig take effect before capturing, so no pre-change r1
    # packet still marked 46 can land in the window and look like leakage.
    topotest.sleep(3, "Applying DSCP reconfiguration")

    r1_dscps = r2_dscps = set()
    for _ in range(3):
        _capture_ospf_pcap(r1, "r1-eth0", pcap)
        topotest.sleep(2, "Setup packet capture")
        topotest.sleep(6, "Gathering Packets")
        _stop_ospf_capture(r1, "r1-eth0", pcap)

        r1_dscps = {d for d, _ in _tshark_dscp_and_type(r1, pcap, src=R1_ADDR)}
        r2_dscps = {d for d, _ in _tshark_dscp_and_type(r1, pcap, src=R2_ADDR)}
        # Both preconditions must hold in the SAME window for the negative
        # assertion below to mean anything.
        if 34 in r1_dscps and 46 in r2_dscps:
            break

    logger.info("isolation window: r1 dscps={} r2 dscps={}".format(r1_dscps, r2_dscps))

    # Captures are done; put r2-eth0 back to unmarked so the invariant
    # _tshark_dscp_and_type documents (r2 emits CS6/48) holds for any test
    # after this one.  r1 is reset by test_ospf_dscp_display's Case 1.
    r2.vtysh_cmd(
        """
configure terminal
interface r2-eth0
  no ip ospf dscp all
  exit
  exit
"""
    )

    # Preconditions.  Without these the real assertion is vacuous: "no 46
    # from r1" is trivially true if r2 never transmitted, or if the capture
    # caught nothing at all.
    assert 34 in r1_dscps, (
        "No OSPF packet from R1 with DSCP 34 observed, so this window cannot "
        "say anything about source isolation (saw {})".format(sorted(r1_dscps))
    )
    assert 46 in r2_dscps, (
        "R2 emitted no DSCP-46 OSPF packet on this link, so the isolation "
        "check below would pass vacuously (saw {})".format(sorted(r2_dscps))
    )

    # The property.
    assert 46 not in r1_dscps, (
        "R2's DSCP-46 packets appeared in R1's filtered view: the ip.src term "
        "in _tshark_dscp_and_type is not constraining, so an assertion about "
        "R1's marking can be satisfied by R2's packets. Saw {} for {}.".format(
            sorted(r1_dscps), R1_ADDR
        )
    )


def test_ospf_dscp_display(tgen):
    "Verify OSPF interface DSCP operational display"

    if tgen.routers() is None:
        pytest.skip("Topology not created")

    r1 = tgen.gears["r1"]

    assert _wait_for_neighbors_full("r1"), "R1 did not reach Full with R2"

    #
    # Case 1: no DSCP config => display should not be present
    #
    r1.vtysh_cmd(
        """
configure terminal
interface r1-eth0
  no ip ospf dscp low-control
  no ip ospf dscp all
  exit
  exit
"""
    )

    data = ospf_if_json("r1", "r1-eth0")
    assert (
        "dscpControlPackets" not in data
    ), "dscpControlPackets unexpectedly present with no DSCP config: {}".format(data)

    text = _vty("r1", "show ip ospf interface r1-eth0")
    assert "DSCP control-packet classes:" not in text

    #
    # Case 2: only 'all' configured => low-control should inherit
    #
    r1.vtysh_cmd(
        """
configure terminal
interface r1-eth0
  ip ospf dscp all 46
  no ip ospf dscp low-control
  exit
  exit
"""
    )

    data = ospf_if_json("r1", "r1-eth0")
    dscp = data.get("dscpControlPackets", {})
    assert dscp, "missing dscpControlPackets for 'ip ospf dscp all 46'"

    assert dscp.get("allConfigured") is True
    assert dscp.get("lowControlConfigured") is False
    assert dscp.get("highControlDscp") == 46
    assert dscp.get("lowControlDscp") == 46
    assert dscp.get("lowControlInheritedFromAll") is True

    text = _vty("r1", "show ip ospf interface r1-eth0")
    assert "DSCP control-packet classes:" in text
    assert "high-control : 46" in text
    assert "low-control  : 46" in text
    assert "inherited from all" in text

    #
    # Case 3: both configured => low-control should override
    #
    r1.vtysh_cmd(
        """
configure terminal
interface r1-eth0
  ip ospf dscp all 46
  ip ospf dscp low-control 40
  exit
  exit
"""
    )

    data = ospf_if_json("r1", "r1-eth0")
    dscp = data.get("dscpControlPackets", {})
    assert dscp, "missing dscpControlPackets for all+low-control config"

    assert dscp.get("allConfigured") is True
    assert dscp.get("lowControlConfigured") is True
    assert dscp.get("highControlDscp") == 46
    assert dscp.get("lowControlDscp") == 40
    assert "lowControlInheritedFromAll" not in dscp

    text = _vty("r1", "show ip ospf interface r1-eth0")
    assert "DSCP control-packet classes:" in text
    assert "high-control : 46" in text
    assert "low-control  : 40" in text
    assert "inherited from all" not in text


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
