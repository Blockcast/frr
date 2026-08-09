#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_bgp_mvpn_gtm_leaf_events.py: per-leaf (Type-4 Leaf A-D) settlement event
emission over the AF_UNIX event socket.

The Type-7 join events covered by ../bgp_mvpn_gtm_events are scoped to
(C-S, C-G) and describe the emitting PE's own upstream interest -- they name
no leaf. Under ingress replication a root replicates one (C-S, C-G) to many
leaves and settlement bills each of them separately, so the stream also
carries leaf_install / leaf_withdraw keyed (C-S, C-G, leaf), sourced from the
Type-4 leaf_originator. See ../../../doc/mvpn-events-schema.md.

Why the topology looks like this. A Type-4 only exists where a received Type-3
S-PMSI asked for one (ingress replication with LEAF_INFO_REQUIRED), and a PE
only answers with its own Type-4 when it has a local join for that (C-S, C-G).
So the causal chain being exercised is:

  1. h1 sends to (SRC, GRP); r1's pimd sees a directly-connected source and
     r1 originates the Type-5 and the Type-3 (IR + leaf-info-required).
  2. r2 and r3 receive that Type-3. Each has a local IGMP join for the same
     (C-S, C-G), so each originates its OWN Type-4 carrying its router-id as
     leaf_originator.
  3. r1 RECEIVES those two Type-4s and emits one leaf_install per leaf.

r1 is therefore the settlement observer: the root that would be billing, and
the only router here running the event socket.

    +----+  10.10.10.0/24        +----+  10.0.0.0/24   +----+
    | h1 |-----------------------| r1 |----------------| r2 | 192.168.2.0/24
    +----+   (source segment)    +----+       |        +----+  (receiver stub)
     sender                      root/        |        +----+
                                 observer     +--------| r3 | 192.168.3.0/24
                                                       +----+  (receiver stub)
"""

import json
import os
import socket
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

SRC, GRP = "10.10.10.10", "232.1.1.1"
LEAF_R2, LEAF_R3 = "10.0.0.2", "10.0.0.3"
ROUTE_TYPE_LEAF_AD = 4
ROUTE_TYPE_JOIN = 7

EVENT_SOCK = "/tmp/bgp_mvpn_leaf_events-r1-{}.sock".format(os.getpid())

SENDER = None


def build_topo(tgen):
    for n in range(1, 4):
        tgen.add_router("r{}".format(n))

    # s1: the BGP/MVPN core segment shared by the root and both leaves.
    switch = tgen.add_switch("s1")
    for n in range(1, 4):
        switch.add_link(tgen.gears["r{}".format(n)])

    # s2: r1's source segment. The sender here is what makes r1's pimd report
    # a local source, which is what makes r1 originate the Type-3 that asks
    # the leaves for their Type-4s.
    tgen.add_host("h1", "10.10.10.10/24", "via 10.10.10.1")
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    # s3/s4: receiver stubs where the leaves' IGMP joins live.
    for n in (2, 3):
        switch = tgen.add_switch("s{}".format(n + 1))
        switch.add_link(tgen.gears["r{}".format(n)])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PIM, os.path.join(CWD, "{}/pimd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    global SENDER
    if SENDER is not None:
        SENDER.terminate()
        SENDER.wait()
        SENDER = None
    get_topogen().stop_topology()
    try:
        os.unlink(EVENT_SOCK)
    except OSError:
        pass


class EventReader:
    """Buffers newline-delimited JSON off the event socket.

    Lifted from ../bgp_mvpn_gtm_events rather than re-derived: the socket has a
    small control protocol, and the subscribe frame below is not optional. The
    server only sets client->subscribed after parsing it, and an unsubscribed
    client is offered no snapshot and sent no live events -- so a reader that
    merely connects sees nothing at all.
    """

    def __init__(self, path, cursor=None, connect_timeout=30):
        # The listener can lag a beat behind bgpd's config apply, so retry
        # rather than single-shot (a bare connect races the bind).
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

    def collect_leaf_events(self, want, timeout=90):
        """Drain until `want` leaf records have arrived, ignoring the Type-7
        join traffic and snapshot framing that share this socket.

        Deliberately not "read N events and assert they are leaves": the join
        and leaf streams interleave by design, so a test that assumed adjacency
        would be asserting an ordering the contract does not offer.
        """
        out = []
        deadline = time.time() + timeout
        while len(out) < want and time.time() < deadline:
            try:
                ev = self.read_event(timeout=5)
            except AssertionError:
                continue  # quiet window; keep waiting until the outer deadline
            if ev.get("type") == "snapshot_end":
                self.acknowledge_snapshot(ev)
                continue
            if ev.get("route_type") == ROUTE_TYPE_LEAF_AD:
                out.append(ev)
        return out


def _configure_event_socket():
    get_topogen().gears["r1"].vtysh_cmd(
        """
configure terminal
router bgp 65001
 bgp mvpn event-socket {}
""".format(
            EVENT_SOCK
        )
    )


def _join(rname):
    get_topogen().gears[rname].vtysh_cmd(
        """
configure terminal
interface {}-eth1
 ip igmp join-group {} {}
""".format(
            rname, GRP, SRC
        )
    )


def _leave(rname):
    get_topogen().gears[rname].vtysh_cmd(
        """
configure terminal
interface {}-eth1
 no ip igmp join-group {} {}
""".format(
            rname, GRP, SRC
        )
    )


def _await_type3(rname, timeout=90):
    """Block until `rname` has r1's Type-3 S-PMSI in its MVPN RIB.

    This is an ordering fence, not decoration. A PE only originates its Type-4
    from bgp_mvpn_selective_join_set(), which runs off the JOIN path and walks
    the Type-3s present at that moment. Joining before r1's Type-3 has
    propagated means the walk finds nothing and no Type-4 is ever originated --
    the join does not get re-evaluated when the Type-3 later arrives. Without
    this wait the test would race and fail intermittently for a reason that has
    nothing to do with the code under test.
    """

    def _present():
        out = get_topogen().gears[rname].vtysh_cmd("show bgp ipv4 mvpn json")
        try:
            data = json.loads(out)
        except ValueError:
            return "{}: unparseable mvpn JSON (bgpd dead?)".format(rname)
        routes = data.get("routes", data)
        blob = json.dumps(routes)
        if '"routeType": 3' not in blob and '"routeType":3' not in blob:
            return "{}: no Type-3 S-PMSI received yet: {}".format(rname, blob[:400])
        return None

    _, result = topotest.run_and_expect(_present, None, count=timeout, wait=1)
    assert result is None, result


def test_sessions_established():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _established():
        out = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp summary json"))
        peers = out.get("ipv4Unicast", {}).get("peers", {})
        for peer in (LEAF_R2, LEAF_R3):
            if peers.get(peer, {}).get("state") != "Established":
                return "peer {} not established: {}".format(peer, peers.get(peer))
        return None

    _, result = topotest.run_and_expect(_established, None, count=60, wait=1)
    assert result is None, result


def test_leaf_install_per_receiving_pe():
    """Two leaves on ONE (C-S, C-G) must produce two distinct leaf_install
    records naming their own PEs.

    This is the property the whole per-leaf change exists for. Before it the
    stream carried only the (C-S, C-G) join, so a consumer had no way to tell
    these two receivers apart and billed the fan-out as one subscriber.
    """
    global SENDER
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _configure_event_socket()
    reader = EventReader(EVENT_SOCK)

    # Local source on r1 -> Type-5 + Type-3 (IR, leaf-info-required).
    mcast_tester = os.path.join(CWD, "../lib/mcast-tester.py")
    SENDER = tgen.gears["h1"].popen([mcast_tester, GRP, "h1-eth0", "--send", "0.7"])
    logger.info("started sender on h1: %s -> %s", SRC, GRP)

    # Each leaf's own join is what makes it answer with a Type-4 -- but only
    # against the Type-3s already in its RIB, so the fence comes first.
    _await_type3("r2")
    _await_type3("r3")
    _join("r2")
    _join("r3")

    events = reader.collect_leaf_events(2, timeout=90)
    reader.close()

    assert len(events) == 2, "expected 2 leaf records, got {}: {}".format(
        len(events), events
    )
    for ev in events:
        assert ev["event_type"] == "leaf_install", ev
        assert ev["source"] == SRC and ev["group"] == GRP, ev
        assert ev["route_type"] == ROUTE_TYPE_LEAF_AD, ev
        assert ev.get("leaf"), "leaf record carries no leaf originator: {}".format(ev)

    leaves = sorted(ev["leaf"] for ev in events)
    assert leaves == sorted([LEAF_R2, LEAF_R3]), (
        "leaf identities wrong; distinct receiving PEs must not collapse: "
        "{}".format(leaves)
    )

    # r1 must never bill itself. Its own Type-4 carries r1's router-id, and
    # emitting it would invoice the root for its own delivery.
    assert "10.0.0.1" not in leaves, "root emitted itself as a leaf: {}".format(leaves)


def test_leaf_withdraw_on_leave():
    """One leaf leaving closes that leaf's window and only that one."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reader = EventReader(EVENT_SOCK)
    # Drain the snapshot this fresh connection is offered, so what follows is
    # live lifecycle rather than replayed state.
    reader.collect_leaf_events(2, timeout=30)

    _leave("r3")

    events = reader.collect_leaf_events(1, timeout=90)
    reader.close()

    assert events, "no leaf record after r3 left"
    withdrawn = [ev for ev in events if ev["event_type"] == "leaf_withdraw"]
    assert withdrawn, "leaf departure produced no leaf_withdraw: {}".format(events)
    assert withdrawn[0]["leaf"] == LEAF_R3, (
        "wrong leaf withdrawn -- the remaining leaf would stop being billed: "
        "{}".format(withdrawn[0])
    )


def test_snapshot_replays_surviving_leaf_only():
    """A reconnecting consumer must be told the CURRENT leaf set.

    Without this a restarted settlement consumer bills nothing per-leaf until
    the next unrelated RIB change, and a departed leaf that was never replayed
    could be billed again on the next install.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reader = EventReader(EVENT_SOCK)
    events = reader.collect_leaf_events(1, timeout=60)
    reader.close()

    assert events, "reconnect replayed no leaf state at all"
    installs = [ev for ev in events if ev["event_type"] == "leaf_install"]
    assert installs, "snapshot carried no leaf_install: {}".format(events)

    replayed = {ev["leaf"] for ev in installs}
    assert LEAF_R2 in replayed, "surviving leaf missing from snapshot: {}".format(
        replayed
    )
    assert LEAF_R3 not in replayed, (
        "departed leaf replayed as installed; it would be billed again: "
        "{}".format(replayed)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
