#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_mvpn_gtm_events.py: event-grade Type-7 (C-multicast Source Tree
Join) install/withdraw/origin-change emission over the settlement-plane
AF_UNIX event socket (Paperclip BLO-17645, settlement-readiness gate for
BLO-17642). `bgp mvpn event-socket PATH` under `router bgp` opens a
SOCK_STREAM listener; one JSON object per line, per Type-7 lifecycle
transition for a locally-originated (pimd-driven) join, broadcast to every
connected reader. See ../../../doc/mvpn-events-schema.md for the wire
contract this test pins down.

r1 is the receiver-side PE (pimd/igmp joins live here, r1-eth1 is the
receiver stub) and therefore the PE that locally originates Type-7s and runs
the event socket; r2 is the source-side PE, originating the C-S-covering
unicast prefix 10.10.10.0/24 with a route-map-attached upstream-PE RT so r1
can resolve an UMH.

    +----+   10.0.0.0/24                       +----+
    | r1 |-------------------------------------| r2 |
    +----+                                     +----+
      | 192.168.2.0/24 (receiver stub)
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
UPSTREAM_1 = "10.0.0.2"  # rtimport's initial RT (r2 itself)
UPSTREAM_2 = "10.0.0.3"  # rtimport's RT after test_origin_change_event
SRC, GRP = "10.10.10.10", "232.1.1.1"
IPMSI_LABEL = 100

EVENT_SOCK = "/tmp/bgp_mvpn_gtm_events-r1-{}.sock".format(os.getpid())
EVENT_SOCK_2 = "/tmp/bgp_mvpn_gtm_events-r1-restart-{}.sock".format(os.getpid())
EPOCH_FILE = "/var/lib/frr/bgpd-mvpn-events-default.epoch"


def _ip4_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


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
    try:
        os.unlink(EVENT_SOCK_2)
    except OSError:
        pass


class EventReader:
    """Buffers newline-delimited JSON objects off the event socket, handing
    them out one at a time in arrival order. A fresh instance re-connects
    (and therefore does not see anything emitted before the connection was
    accepted -- exactly the documented "dev-mode `show bgp mvpn json` covers
    bootstrap" behavior in doc/mvpn-events-schema.md)."""

    def __init__(self, path, cursor=None, connect_timeout=30):
        # The listener socket can lag a beat behind bgpd's config apply, so
        # retry the connect rather than single-shot it (a bare connect races
        # the bind and flakes with ENOENT/ECONNREFUSED).
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


def _join():
    get_topogen().gears["r1"].vtysh_cmd(
        """
configure terminal
interface r1-eth1
 ip igmp join-group {} {}
""".format(
            GRP, SRC
        )
    )


def _leave():
    get_topogen().gears["r1"].vtysh_cmd(
        """
configure terminal
interface r1-eth1
 no ip igmp join-group {} {}
""".format(
            GRP, SRC
        )
    )


def test_sessions_established():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _established():
        out = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp neighbor 10.0.0.2 json")
        )
        return topotest.json_cmp(out, {"10.0.0.2": {"bgpState": "Established"}})

    _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
    assert result is None, "r1 did not reach Established with r2"


def test_event_socket_connects():
    """The listener must be up (and its path in running-config) once the
    knob is configured -- connecting must not race daemon startup by more
    than a handful of seconds."""
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
            s.connect(EVENT_SOCK)
            s.close()
            return None
        except OSError as error:
            return str(error)

    _, result = topotest.run_and_expect(_connect, None, count=30, wait=1)
    assert result is None, "could not connect to {}: {}".format(EVENT_SOCK, result)

    running = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert " bgp mvpn event-socket {}".format(EVENT_SOCK) in running
    assert running.index(" bgp mvpn event-socket {}".format(EVENT_SOCK)) < running.index(
        " address-family ipv4 mvpn"
    ), running

    # Liveness surface: "configured" (running-config) is not the same as
    # "listening" -- a bind/listen failure would leave the config advertising
    # a dead stream. show bgp mvpn events must report the listener up.
    status = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp mvpn events json"))
    assert status.get("listening") is True, status
    assert status.get("path") == EVENT_SOCK, status

    # A syntactically valid control record with a non-string type must not
    # dereference NULL in bgpd. Keep the connection local and verify the
    # daemon still answers immediately afterward.
    malformed = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    malformed.connect(EVENT_SOCK)
    malformed.sendall(b'{"type":null}\n')
    malformed.close()
    status = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp mvpn events json"))
    assert status.get("listening") is True, status


def test_install_event():
    """A fresh (S,G) join emits exactly one "install" event: seq 1,
    route_version "<epoch>.1", the resolved Source AS and upstream PE, and
    the configured IR label."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global reader
    reader = EventReader(EVENT_SOCK)

    snapshot, snapshot_end = reader.read_snapshot()
    assert snapshot == []
    assert snapshot_end["seq"] == 0
    reader.acknowledge_snapshot(snapshot_end)

    _join()

    ev = reader.read_event()
    assert ev["schema_version"] == 1
    assert ev["event_type"] == "install"
    assert ev["route_type"] == 7
    assert ev["source"] == SRC
    assert ev["group"] == GRP
    assert ev["source_as"] == LOCAL_AS
    assert ev["upstream_peer"] == UPSTREAM_1
    assert ev["lc_umh_origin"] == "{}:1:{}".format(
        LOCAL_AS, _ip4_to_int(UPSTREAM_1)
    )
    assert ev["ipmsi_label"] == IPMSI_LABEL
    assert "prior_route_version" not in ev

    global boot_epoch
    boot_epoch = ev["boot_epoch"]
    assert boot_epoch == snapshot_end["boot_epoch"]
    assert ev["seq"] == snapshot_end["seq"] + 1
    assert ev["route_version"] == "{}.1".format(boot_epoch)

    # Event delivery is sequenced after the route mutation: once the event is
    # observable, the matching Type-7 must already be visible in the RIB.
    routes = json.loads(
        tgen.gears["r1"].vtysh_cmd("show bgp ipv4 mvpn json")
    ).get("routes", [])
    assert any(
        route.get("routeType") == 7
        and route.get("source") == SRC
        and route.get("group") == GRP
        and route.get("sourceAs") == LOCAL_AS
        for route in routes
    ), routes

    global last_seq
    last_seq = ev["seq"]


def test_withdraw_event():
    """Leaving must emit "withdraw" with a bumped, never-reused
    route_version, and seq must be exactly the next integer."""
    global last_seq
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _leave()

    ev = reader.read_event()
    assert ev["event_type"] == "withdraw"
    assert ev["source"] == SRC
    assert ev["group"] == GRP
    assert ev["route_version"] == "{}.2".format(boot_epoch)
    assert ev["boot_epoch"] == boot_epoch
    assert ev["seq"] == last_seq + 1
    # A withdraw closes the window: it must not carry a live upstream, or a
    # consumer would keep billing against a torn-down origin.
    assert "upstream_peer" not in ev
    assert "lc_umh_origin" not in ev

    last_seq = ev["seq"]


def test_rejoin_route_version_never_reused():
    """Rejoining the same (S,G) must emit a fresh "install" whose
    route_version continues the same join's generation counter (.3) rather
    than restarting at .1 -- a restarted consumer must never see the same
    route_version mean two different lease windows."""
    global last_seq
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _join()

    ev = reader.read_event()
    assert ev["event_type"] == "install"
    assert ev["route_version"] == "{}.3".format(boot_epoch)
    assert ev["seq"] == last_seq + 1

    last_seq = ev["seq"]


def test_origin_change_event():
    """Changing the upstream PE that the C-S-covering route points at (r2's
    rtimport route-map) must re-resolve the already-installed join in place
    -- no withdraw/re-join -- and emit "origin_change" carrying both the
    prior and new route_version so a consumer can split its billing
    window."""
    global last_seq
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
route-map rtimport permit 10
 set extcommunity rt {}:0
""".format(
            UPSTREAM_2
        )
    )
    # Route-map mutation alone re-evaluates statically-originated routes in
    # FRR (route_map_walk_update_list); force it explicitly too so the test
    # does not depend on that timing.
    tgen.gears["r2"].vtysh_cmd("clear bgp 10.0.0.1 soft out")

    ev = reader.read_event()
    assert ev["event_type"] == "origin_change"
    assert ev["source"] == SRC
    assert ev["group"] == GRP
    assert ev["upstream_peer"] == UPSTREAM_2
    assert ev["lc_umh_origin"] == "{}:1:{}".format(
        LOCAL_AS, _ip4_to_int(UPSTREAM_2)
    )
    assert ev["route_version"] == "{}.4".format(boot_epoch)
    assert ev["prior_route_version"] == "{}.3".format(boot_epoch)
    assert ev["seq"] == last_seq + 1

    last_seq = ev["seq"]
    reader.close()


def test_reconnect_snapshot_exposes_same_epoch_gap():
    """A reconnect snapshot baseline must classify events missed after the
    durable cursor as a gap before the consumer applies the snapshot."""
    global last_seq

    _leave()
    reconnect = EventReader(EVENT_SOCK, cursor=(boot_epoch, last_seq))
    snapshot, snapshot_end = reconnect.read_snapshot()
    assert snapshot == []
    assert snapshot_end["boot_epoch"] == boot_epoch
    assert snapshot_end["seq"] == last_seq + 1
    assert snapshot_end["cursor_status"] == "gap"
    reconnect.acknowledge_snapshot(snapshot_end)
    reconnect.close()

    last_seq = snapshot_end["seq"]
    _join()


def test_failed_reconfiguration_preserves_listener():
    """Neither an unusable replacement path nor invalid durable epoch state
    may tear down the healthy listener or replace its running configuration."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1.vtysh_cmd(
        """
configure terminal
router bgp {}
 bgp mvpn event-socket /missing/bgp-mvpn-events.sock
""".format(
            LOCAL_AS
        )
    )
    status = json.loads(r1.vtysh_cmd("show bgp mvpn events json"))
    assert status.get("listening") is True, status
    assert status.get("path") == EVENT_SOCK, status

    saved_epoch = r1.run("cat {}".format(EPOCH_FILE)).strip()
    assert saved_epoch.isdigit(), saved_epoch
    r1.net.unet.rootcmd.cmd_raises(
        "nsenter --mount=/proc/{}/ns/mnt -- runuser -u frr -- "
        "sh -c 'printf invalid > {}'".format(r1.net.pid, EPOCH_FILE)
    )
    assert r1.run("cat {}".format(EPOCH_FILE)).strip() == "invalid"
    try:
        r1.vtysh_cmd(
            """
configure terminal
router bgp {}
 bgp mvpn event-socket {}
""".format(
                LOCAL_AS, EVENT_SOCK_2
            )
        )
        status = json.loads(r1.vtysh_cmd("show bgp mvpn events json"))
        assert status.get("listening") is True, status
        assert status.get("path") == EVENT_SOCK, status
    finally:
        r1.net.unet.rootcmd.cmd_raises(
            "nsenter --mount=/proc/{}/ns/mnt -- runuser -u frr -- "
            "sh -c 'printf {} > {}'".format(r1.net.pid, saved_epoch, EPOCH_FILE)
        )


def test_listener_restart_snapshots_active_join():
    """Changing the listener creates a new epoch. Each consumer must receive
    a replacement install for the still-active join before live delivery so it
    can open a billing window without waiting for unrelated route churn."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure terminal
router bgp {}
 bgp mvpn event-socket {}
""".format(
            LOCAL_AS, EVENT_SOCK_2
        )
    )

    # A connect-only health probe cannot consume the epoch snapshot.
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.connect(EVENT_SOCK_2)
    probe.close()

    # A subscriber may remain connected without acknowledging its baseline.
    # That must not hold the listener-global handoff lock indefinitely.
    interrupted_reader = EventReader(EVENT_SOCK_2)
    interrupted_events, interrupted_end = interrupted_reader.read_snapshot()

    # Later subscribers still receive independent snapshots while the first
    # client's ACK is pending.
    observer = EventReader(EVENT_SOCK_2)
    replacement = EventReader(EVENT_SOCK_2)
    _, synced = topotest.run_and_expect(
        lambda: json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp mvpn events json")
        ).get("subscribedClients"),
        3,
        count=30,
        wait=0.1,
    )
    assert synced == 3

    replacement_events, replacement_end = replacement.read_snapshot()
    assert len(interrupted_events) == 1
    assert len(replacement_events) == 1
    interrupted = interrupted_events[0]
    ev = replacement_events[0]
    assert ev["event_type"] == "install"
    assert ev["source"] == SRC
    assert ev["group"] == GRP
    assert ev["source_as"] == LOCAL_AS
    assert ev["upstream_peer"] == UPSTREAM_2
    assert ev["boot_epoch"] > boot_epoch
    assert interrupted["seq"] == 0
    assert interrupted_end["seq"] == interrupted["seq"]
    assert replacement_end["seq"] == ev["seq"]
    replacement.acknowledge_snapshot(replacement_end)

    observer_events, observer_end = observer.read_snapshot()
    assert len(observer_events) == 1
    observer_snapshot = observer_events[0]
    for field in ("event_type", "source", "group", "source_as", "upstream_peer"):
        assert observer_snapshot[field] == ev[field]
    assert observer_snapshot["route_version"] == ev["route_version"]
    assert observer_snapshot["seq"] == ev["seq"]
    assert observer_end["seq"] == replacement_end["seq"]
    observer.acknowledge_snapshot(observer_end)

    # A real transition follows snapshot_end in socket order for all clients,
    # including the first client whose ACK is intentionally still pending.
    _leave()
    interrupted_live = interrupted_reader.read_event()
    replacement_live = replacement.read_event()
    observer_live = observer.read_event()
    assert replacement_live["event_type"] == "withdraw"
    assert interrupted_live == replacement_live
    assert observer_live == replacement_live
    assert replacement_live["seq"] == replacement_end["seq"] + 1
    interrupted_reader.close()
    observer.close()
    replacement.close()


def test_failed_initial_configuration_preserves_intent():
    """A failed startup without a healthy listener remains visible in
    running-config and the liveness surface for operator remediation."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1.vtysh_cmd(
        """
configure terminal
router bgp {}
 no bgp mvpn event-socket
 bgp mvpn event-socket /missing/bgp-mvpn-events.sock
""".format(
            LOCAL_AS
        )
    )
    status = json.loads(r1.vtysh_cmd("show bgp mvpn events json"))
    assert status.get("path") == "/missing/bgp-mvpn-events.sock", status
    assert status.get("listening") is False, status
    running = r1.vtysh_cmd("show running-config")
    assert " bgp mvpn event-socket /missing/bgp-mvpn-events.sock" in running


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
