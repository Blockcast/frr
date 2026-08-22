#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_mvpn_gtm_umh_dimt.py: the MVPN settlement event stream must attest the
Upstream Multicast Hop for a DIMT-steered join -- i.e. one whose UMH is carried
by ECOMMUNITY_UMH (0x80, draft-zzhang-mboned-dynamic-internet-mcast-tunnel)
rather than by the RFC 6514 route-import / route-target extended communities.

Before this suite's fix, bgpd had two UMH decoders that disagreed:

  * bgp_dimt.c resolved 0x80 and mirrored it to pimd (so `show ip pim dimt umh
    json` was right, and traffic forwarded);
  * bgp_mvpn.c's bgp_mvpn_resolve_from_ecommunity() looked up only 0x0b then
    0x02, so a DIMT-steered join resolved to INADDR_ANY and the event dropped
    BOTH `upstream_peer` and `lc_umh_origin`.

Because the schema documents both fields as conditional, the settlement
consumer could not tell "no upstream exists" from "bgpd could not decode the
one that does" -- every DIMT-steered join billed with no origin attestation at
all. test_install_attests_dimt_umh is the direct regression test: it is RED on
master and green with the fix.

The lane split (Paperclip BLO-29578) is what the rest of this suite pins down.
The resolved value is not event-only: bgp_mvpn_attach_ip_rt() turns it into the
RFC 7716 upstream-node-identifying Route Target, which decides which PE imports
the C-multicast join. So the attestation lane was added ALONGSIDE the RT lane,
never merged into it, and test_type7_rt_is_unaffected_by_umh_ec asserts the
Type-7's RT is byte-identical with and without a 0x80 EC present. That
invariant is precisely why no import-behaviour topotest is required.

r2 (the source-side PE) originates the C-S-covering routes by policy, which is
how a carrier router attaches these communities. p1 carries RT 10.0.0.2 AND
UMH 10.99.0.1 -- deliberately different addresses, since 0x0b/0x02 name an
MVPN PE identity while 0x80 names a PIM-Light/AMT-relay tunnel endpoint. p2
carries the RT only and is the "already correct, must not regress" control.

IPv4 only, per BLO-29578 Q4: lc_umh_origin is "<sourceAS>:1:<UMH-u32>", so a
16-byte UMH has no representation in the settlement contract (tracked as
BLO-29651).

    +----+   10.0.0.0/24   +----+
    | r1 |-----------------| r2 |
    +----+                 +----+
      | 192.168.2.0/24 (receiver stub, IGMP joins live here)
"""

import json
import os
import socket
import struct
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

LOCAL_AS = 65001
IPMSI_LABEL = 100

# The RT lane's value on both prefixes: r2's MVPN PE identity.
RT_UMH = "10.0.0.2"
# The DIMT 0x80 value on p1: a PIM-Light tunnel endpoint, NOT a PE identity.
# It differs from RT_UMH on purpose -- that divergence is the whole point.
DIMT_UMH = "10.99.0.1"

P1_PREFIX = "10.10.10.0/24"
P1_SRC, P1_GRP = "10.10.10.10", "232.1.1.1"  # steered by 0x80
P2_SRC, P2_GRP = "10.10.20.10", "232.1.1.2"  # RT only (control)

EVENT_SOCK = "/tmp/bgp_mvpn_gtm_umh_dimt-r1-{}.sock".format(os.getpid())

reader = None
attested_install_umh = None


def _ip4_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def _origin(umh, source_as=LOCAL_AS):
    """The settlement contract's SessionLease.lc_umh_origin encoding."""
    return "{}:1:{}".format(source_as, _ip4_to_int(umh))


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1's receiver stub (the IGMP joins live here)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    r1.load_config(TopoRouter.RD_PIM, os.path.join(CWD, "r1/pimd.conf"))
    r1.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))

    r2 = tgen.gears["r2"]
    r2.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r2/zebra.conf"))
    r2.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r2/bgpd.conf"))

    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()
    try:
        os.unlink(EVENT_SOCK)
    except OSError:
        pass


class EventReader:
    """Buffers newline-delimited JSON objects off the event socket, handing
    them out one at a time in arrival order. Mirrors the reader in
    bgp_mvpn_gtm_events."""

    def __init__(self, path, cursor=None, connect_timeout=30):
        # The listener socket can lag a beat behind bgpd's config apply, so
        # retry the connect rather than single-shot it.
        deadline = time.time() + connect_timeout
        while True:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(1)
            try:
                self.sock.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError, OSError):
                self.sock.close()
                if time.time() >= deadline:
                    raise
                time.sleep(0.5)
        self.buf = b""
        subscribe = {"type": "subscribe", "schema_version": 1}
        if cursor is not None:
            subscribe["last_boot_epoch"], subscribe["last_seq"] = cursor
        self.sock.sendall((json.dumps(subscribe) + "\n").encode("utf-8"))

    def close(self):
        self.sock.close()

    def read_event(self, timeout=15):
        deadline = time.time() + timeout
        while True:
            nl = self.buf.find(b"\n")
            if nl >= 0:
                line, self.buf = self.buf[:nl], self.buf[nl + 1 :]
                return json.loads(line.decode("utf-8"))
            if time.time() >= deadline:
                raise AssertionError(
                    "no event received within {}s (buffered: {!r})".format(
                        timeout, self.buf
                    )
                )
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise AssertionError("event socket closed by bgpd")
            self.buf += chunk

    def read_event_for(self, source, group, timeout=30):
        """Skip events for the other (S,G). Two joins are live in this suite
        and a route-map mutation re-resolves both, so ordering between them is
        not something a test should depend on."""
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise AssertionError(
                    "no event for ({}, {}) within {}s".format(source, group, timeout)
                )
            ev = self.read_event(timeout=remaining)
            if ev.get("source") == source and ev.get("group") == group:
                return ev
            logger.info(
                "skipping event for (%s, %s)", ev.get("source"), ev.get("group")
            )

    def acknowledge_snapshot(self, event):
        self.sock.sendall(
            (
                json.dumps(
                    {
                        "type": "snapshot_ack",
                        "boot_epoch": event["boot_epoch"],
                        "seq": event["seq"],
                    }
                )
                + "\n"
            ).encode("utf-8")
        )

    def read_snapshot(self):
        events = []
        while True:
            event = self.read_event()
            if event.get("type") == "snapshot_end":
                assert event["snapshot_count"] == len(events), event
                return events, event
            assert event.get("snapshot") is True, event
            assert event["snapshot_index"] == len(events) + 1, event
            events.append(event)


def _join(source, group):
    get_topogen().gears["r1"].vtysh_cmd(
        """
configure terminal
interface r1-eth1
 ip igmp join-group {} {}
""".format(
            group, source
        )
    )


def _type7_rt(source, group):
    """The extended-community string on the locally-originated Type-7 for
    (S,G) -- i.e. what bgp_mvpn_attach_ip_rt() actually put on the wire."""
    routes = json.loads(
        get_topogen().gears["r1"].vtysh_cmd("show bgp ipv4 mvpn json")
    ).get("routes", [])
    for route in routes:
        if (
            route.get("routeType") == 7
            and route.get("source") == source
            and route.get("group") == group
        ):
            return route.get("extendedCommunity", {}).get("string")
    return None


def test_sessions_established():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _established():
        out = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp neighbor 10.0.0.2 json"))
        return topotest.json_cmp(out, {"10.0.0.2": {"bgpState": "Established"}})

    _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
    assert result is None, "r1 did not reach Established with r2"


def test_dimt_umh_reaches_pimd():
    """Precondition, and half of the joint invariant this suite exists to
    pin: bgp_dimt.c decodes the 0x80 EC and mirrors it to pimd. This half
    already worked before the fix -- it is the half that made the settlement
    gap invisible."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _resolved():
        out = json.loads(tgen.gears["r1"].vtysh_cmd("show ip pim dimt umh json"))
        return topotest.json_cmp(out, {P1_PREFIX: {"umh": DIMT_UMH}})

    _, result = topotest.run_and_expect(_resolved, None, count=60, wait=1)
    assert result is None, "pimd never resolved the DIMT UMH for {}".format(P1_PREFIX)


def test_event_socket_connects():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
router bgp {}
 bgp mvpn event-socket {}
""".format(
            LOCAL_AS, EVENT_SOCK
        )
    )

    def _connect():
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(EVENT_SOCK)
            s.close()
            return None
        except OSError as exc:
            return str(exc)

    _, result = topotest.run_and_expect(_connect, None, count=30, wait=1)
    assert result is None, "event socket never accepted a connection"


def test_install_attests_dimt_umh():
    """THE regression test for this issue.

    A join steered by ECOMMUNITY_UMH (0x80) must emit an `install` carrying
    both `upstream_peer` and a well-formed `lc_umh_origin`, resolved from the
    0x80 EC -- not from the RT.

    On master this fails with KeyError: both fields are absent, because
    bgp_mvpn_resolve_from_ecommunity() never looked for 0x80 and the UMH
    stayed INADDR_ANY."""
    global reader
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reader = EventReader(EVENT_SOCK)
    snapshot, snapshot_end = reader.read_snapshot()
    assert snapshot == []
    reader.acknowledge_snapshot(snapshot_end)

    _join(P1_SRC, P1_GRP)

    ev = reader.read_event_for(P1_SRC, P1_GRP)
    assert ev["event_type"] == "install", ev
    assert ev["route_type"] == 7
    assert ev["source_as"] == LOCAL_AS
    assert ev["ipmsi_label"] == IPMSI_LABEL

    # The attestation lane reports the DIMT endpoint, NOT the RT lane's PE.
    missing = "0x80 not decoded, field absent: {}".format(ev)
    assert "upstream_peer" in ev, missing
    assert "lc_umh_origin" in ev, missing
    assert ev["upstream_peer"] == DIMT_UMH, ev
    assert ev["lc_umh_origin"] == _origin(DIMT_UMH), ev

    # Hand the attested value to the joint-invariant test below, so that test
    # compares two independently-observed sources rather than re-asserting a
    # constant.
    global attested_install_umh
    attested_install_umh = ev["upstream_peer"]


def test_pimd_and_events_agree_on_the_umh():
    """The joint invariant the issue was filed on: for one (S,G) steered by
    `set extcommunity umh`, pimd's view and the settlement record must name
    the SAME upstream. Before the fix pimd said 10.99.0.1 and the record said
    nothing at all."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pim = json.loads(tgen.gears["r1"].vtysh_cmd("show ip pim dimt umh json"))
    pim_umh = pim.get(P1_PREFIX, {}).get("umh")

    assert attested_install_umh is not None, "install test did not run"
    assert pim_umh == DIMT_UMH, pim
    assert pim_umh == attested_install_umh, (
        "pimd and the settlement record disagree on the UMH: "
        "pimd={} event={}".format(pim_umh, attested_install_umh)
    )


def test_type7_rt_is_unaffected_by_umh_ec():
    """AC 7 -- the invariant that makes an import-behaviour topotest
    unnecessary.

    The attestation lane must not touch the RFC 7716 upstream-node-identifying
    Route Target. p1 carries a 0x80 EC and p2 does not; both must produce a
    Type-7 whose RT is byte-identical and derived from the RT lane alone
    (10.0.0.2), never from the DIMT endpoint (10.99.0.1). If this ever fails,
    the change has silently retargeted which PE imports the join."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _join(P2_SRC, P2_GRP)
    # Drain p2's install so later tests read from a known point.
    ev = reader.read_event_for(P2_SRC, P2_GRP)
    assert ev["event_type"] == "install", ev

    expected_rt = "RT:{}:0".format(RT_UMH)

    def _rts():
        return _type7_rt(P1_SRC, P1_GRP), _type7_rt(P2_SRC, P2_GRP)

    def _both_present():
        p1_rt, p2_rt = _rts()
        return None if p1_rt and p2_rt else "p1={} p2={}".format(p1_rt, p2_rt)

    _, result = topotest.run_and_expect(_both_present, None, count=30, wait=1)
    assert result is None, "Type-7 routes never appeared: {}".format(result)

    p1_rt, p2_rt = _rts()
    leaked = "the 0x80 EC leaked into the RFC 7716 RT lane: got {} want {}".format(
        p1_rt, expected_rt
    )
    assert p1_rt == expected_rt, leaked
    assert p2_rt == expected_rt, p2_rt
    assert p1_rt == p2_rt, "RT differs with vs without a 0x80 EC: {} != {}".format(
        p1_rt, p2_rt
    )


def test_rt_only_join_is_unchanged():
    """The control: a join with no 0x80 EC must attest exactly what it
    attested before this change -- the RT lane's value. The attestation lane
    falls back rather than overriding, so events that are correct today do
    not move."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    routes = json.loads(
        tgen.gears["r1"].vtysh_cmd("show bgp ipv4 mvpn json")
    ).get("routes", [])
    assert any(
        r.get("routeType") == 7 and r.get("source") == P2_SRC for r in routes
    ), routes

    # Re-emit the live joins and read p2's record back off the socket: its
    # attested origin must still be the RT lane's PE.
    tgen.gears["r1"].vtysh_cmd("clear bgp 10.0.0.2 soft out")
    ev = reader.read_event_for(P2_SRC, P2_GRP)
    assert ev["upstream_peer"] == RT_UMH, ev
    assert ev["lc_umh_origin"] == _origin(RT_UMH), ev


def test_gaining_an_origin_emits_origin_change():
    """AC 6 -- the settlement-critical one.

    A join that is live when its source route GAINS a 0x80 EC (exactly what
    happens to a live join across this upgrade, or when an operator turns DIMT
    steering on) must emit an `origin_change` carrying `prior_route_version`,
    so the consumer closes the old billing window and opens a new one. It must
    NOT mutate the live join's attested origin in place -- contract P4: an
    lc_umh_origin change splits evidence."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
route-map rtonly permit 10
 set extcommunity umh {} pim preference 5
""".format(
            DIMT_UMH
        )
    )
    tgen.gears["r2"].vtysh_cmd("clear bgp 10.0.0.1 soft out")

    ev = reader.read_event_for(P2_SRC, P2_GRP)
    assert ev["event_type"] == "origin_change", ev
    assert ev["upstream_peer"] == DIMT_UMH, ev
    assert ev["lc_umh_origin"] == _origin(DIMT_UMH), ev
    # The billing-window split: both versions present and distinct.
    assert "prior_route_version" in ev, ev
    assert ev["route_version"] != ev["prior_route_version"], ev

    # And the RT lane still must not have moved.
    assert _type7_rt(P2_SRC, P2_GRP) == "RT:{}:0".format(RT_UMH)


def test_losing_the_ec_falls_back_not_stale():
    """AC 4 -- attribute loss, not route loss. Withdrawing the 0x80 EC must
    fall the attestation back to the RT lane and say so, rather than leaving
    the consumer pinned to a stale DIMT endpoint."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
route-map rtonly permit 10
 no set extcommunity umh
"""
    )
    tgen.gears["r2"].vtysh_cmd("clear bgp 10.0.0.1 soft out")

    ev = reader.read_event_for(P2_SRC, P2_GRP)
    assert ev["event_type"] == "origin_change", ev
    assert ev["upstream_peer"] == RT_UMH, "stale DIMT endpoint retained: {}".format(ev)
    assert ev["lc_umh_origin"] == _origin(RT_UMH), ev


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
