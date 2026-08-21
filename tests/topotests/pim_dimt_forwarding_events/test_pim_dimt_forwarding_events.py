#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim_dimt_forwarding_events.py: DIMT PR 4 -- the two ADDITIVE settlement
event types, `forwarding_ready` and `forwarding_lost`, as they appear ON THE
WIRE (Paperclip BLO-27739, contract BLO-18774 D3/D4/D6).

WHY THIS IS A SEPARATE SUITE FROM pim_dimt_tunnel/
--------------------------------------------------
Two reasons, and both are about what counts as evidence.

1. `show ip pim dimt forwarding json` RECOMPUTES the readiness verdict on
   every read.  It is therefore right whenever anyone looks, and says nothing
   about whether an edge was ever relayed to bgpd -- so an assertion built on
   it passes with or without the code that relays it.  pim_dimt_tunnel/ says
   this out loud in test_second_sg_on_a_live_tunnel_is_announced_ready, and it
   is the whole reason BLO-28297 deferred its automated signal to this PR:
   until PR 4 there was no consumer of the zapi `forwarding` byte to assert
   against.  Every assertion in THIS file is made against the emitted JSON
   record.

2. An event stream is not re-readable.  A reader only sees what is emitted
   after it connects, so the join has to happen after the reader attaches --
   which is why r2/pimd.conf here carries no startup membership and
   pim_dimt_tunnel/r2/pimd.conf does.  Retrofitting that into a suite whose
   twelve stages are explicitly order-dependent, and whose earlier stages have
   already joined and left several times, would mean the reader could only
   ever see a snapshot -- and a snapshot deliberately does NOT carry readiness
   (D4 restart matrix).  The one framing that cannot show the thing under
   test.

Topology -- same shape as pim_dimt_tunnel/, plus the event socket on r2:

    h1 ---- s2 ---- r1 ---- s1 ---- r2 ---- s3 (receiver stub)
  (sender)      upstream PE      receiver PoP
                                    |
                                    +-- AF_UNIX settlement event socket

r2 is the receiver PoP: the membership lives there, so r2 is the PE that
locally originates the Type-7 and therefore the PE that runs the event socket.
r1 advertises 10.10.10.0/24 with `set extcommunity umh 10.99.0.1 pim`, where
10.99.0.1 is r1's *loopback* and r2 has no route to it -- so the DIMT netdev
is the only interface that can carry the pin.  The full reasoning for the
loopback UMH is in pim_dimt_tunnel/test_pim_dimt_tunnel.py; it is reproduced
in r1/zebra.conf and not re-argued here.

WHAT IS EVIDENCE HERE
---------------------
The emitted record, plus kernel state wherever the record makes a claim about
the data plane.  `forwarding_ready` names an `oif` and an `ifindex`; those are
checked against `ip -o link show` and /proc/net/ip_mr_cache, because a record
that names a netdev the kernel is not forwarding on is precisely the
disagreement class this contract exists to catch (G10).

WHAT IS ASSERTED, AND WHAT IS DELIBERATELY NOT
----------------------------------------------
Ordering, cardinality, joinability and shape are asserted exactly.

The `reason` STRING on a forwarding_lost is asserted as enum MEMBERSHIP, not
as one specific value, everywhere except where only one producer path can
reach it.  That is not laziness, it is the contract: on both a leave and an
origin change there are two independent paths that can close the readiness
interval, and which one wins is a race.

  - bgpd closes it itself, from bgp_mvpn_event_withdrawn() with reason
    "withdraw", or from the `changed` branch of bgp_mvpn_event_join_resolved()
    with reason "origin_change".
  - pimd can get there first.  Tearing down a membership evicts the MFC and
    can unpin the RPF before the DEL reaches bgpd; changing the UMH flushes
    the tunnel.  Either produces an ADD carrying a non-READY byte, and bgpd
    closes the interval with the specific cause pimd named --
    "mfc_evicted" / "rpf_unpinned" / "tunnel_removed".

The exactly-once latch means whichever arrives first is the ONLY
forwarding_lost, so the reason is genuinely race-determined.  Both answers are
honest; the contract (D4) requires the reason be a member of the stable
append-only enum and does not pin which cause an origin change must report.
Pinning one value here would produce a test that fails on a correct
implementation roughly whenever the scheduler ran differently, so the
cardinality and ordering claims -- which are NOT race-dependent -- carry the
weight instead.  This was raised as a contract question on BLO-27739 and has
since been ANSWERED: D4 does not pin it -- §D4 constrains enum membership and
stability only, and §D3/§D6 constrain ordering only.  If D4 is later tightened
to mandate a specific reason on these two paths, tighten FWD_LOST_REASONS_*
below to match.

D6 VERIFYING-SIGNAL COVERAGE (contract D6, quoted in BLO-27739)
---------------------------------------------------------------
  join -> ready ................. test_install_then_exactly_one_forwarding_ready
  second (S,G), no new trigger .. test_second_sg_gets_exactly_one_forwarding_ready
  snapshot: all installed, no
    readiness ................... test_snapshot_carries_all_installed_joins_and_no_readiness
  forward-compat ignore+advance . test_v1_only_consumer_ignores_and_advances
  leave ......................... test_forwarding_lost_precedes_withdraw
  UMH origin change ............. test_forwarding_lost_precedes_origin_change

NOT covered here, and where each one lives instead:
  injected create failure ....... pim_dimt_tunnel/
                                  test_create_failure_lands_in_failed_without_kernel_state
                                  proves the pimd half (FAIL_INSTALL, no
                                  kernel state).  Its bgpd-side claim -- that
                                  `install` IS present and no
                                  forwarding_ready follows -- is the same
                                  no-readiness-without-FWD_READY assertion the
                                  origin-change stage below makes, from a path
                                  that STRUCTURALLY cannot become ready, which
                                  is a stronger negative than racing an
                                  injected failure against a timeout.
  anti-recursion ................ zebra_dimt_tunnel/
                                  test_outer_remote_via_dimt_is_rejected.
                                  `anti_recursion_refused` is a RESERVED
                                  reason value in this PR and is never
                                  emitted: zebra's refusal reaches pimd only
                                  as FAIL_INSTALL, so bgpd cannot honestly
                                  distinguish it.  Documented as reserved in
                                  doc/mvpn-events-schema.md rather than
                                  fabricated here.
  bgpd restart / boot_epoch ..... bgp_mvpn_gtm_events/
                                  test_listener_restart_snapshots_active_join.
                                  The readiness-specific half of the restart
                                  matrix -- snapshot carries all installed
                                  joins and NO readiness -- is asserted here
                                  against a fresh subscriber, which exercises
                                  the same snapshot_replay_active path without
                                  a daemon bounce.

The tests are ORDER-DEPENDENT: each stage builds on the state the previous one
left, and several stages assert on the ABSENCE of further events, which is
only meaningful against a known-quiet stream.
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
from lib.kernel_state import (
    check_ip_mr_cache_iif,
    check_no_ip_mr_cache,
    link_ifindex,
    resolve_mr_vif,
)
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

LOCAL_AS = 65002

SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"
SRC_PREFIX = "10.10.10.0/24"
UMH = "10.99.0.1"

# A second (S,G) inside the same advertised source prefix, so it resolves to
# the same UMH and rides the tunnel that already exists.  BLO-28297's
# scenario.
SECOND_SOURCE = "10.10.10.11"
SECOND_GROUP = "232.1.1.11"

# The origin-change target.  Deliberately has no `dimt tunnel-endpoint` row on
# r2 and is configured nowhere -- see r1/bgpd.conf.
NEW_UMH = "10.99.0.9"

EVENT_SOCK = "/tmp/pim_dimt_fwd_events-r2-{}.sock".format(os.getpid())

# D4: the stable, append-only reason enum, in full.  Any value outside this
# set is a contract violation regardless of which producer path emitted it.
FWD_LOST_REASONS = frozenset(
    [
        "tunnel_fail_install",
        "tunnel_removed",
        "mfc_evicted",
        "rpf_unpinned",
        "anti_recursion_refused",
        "withdraw",
        "origin_change",
        "unknown",
    ]
)

# `unknown` is the mixed-version rendering: bgpd emits it
# (bgp_mvpn_events.c, for ZAPI_MVPN_SG_FWD_REASON_UNSPECIFIED) when a pimd
# predating the cause field supplies no cause, and doc/mvpn-events-schema.md
# documents it as such.  A same-version pimd cannot produce it -- every
# non-READY return in pim_dimt_forwarding_state() sets a specific cause -- so
# it is unreachable in this suite and is admitted for forward-compatibility,
# not because a stage here expects it.
#
# It is unioned in at the GATE rather than added to each per-path subset
# below, because a mixed-version producer can omit the cause on ANY path;
# threading it through every subset would also mean N edits for the next
# added value instead of one.
FWD_LOST_REASON_VERSION_DEPENDENT = frozenset(["unknown"])

# The subsets reachable on the two racing paths -- see the header.  Narrower
# than the full enum, so a reason from an unrelated cause still fails.
FWD_LOST_REASONS_ON_LEAVE = frozenset(["withdraw", "mfc_evicted", "rpf_unpinned"])
FWD_LOST_REASONS_ON_ORIGIN_CHANGE = frozenset(
    ["origin_change", "tunnel_removed", "rpf_unpinned", "mfc_evicted"]
)

# The three event types a schema-v1 consumer predating this PR recognises.
# `leaf_install` / `leaf_withdraw` are deliberately NOT here: the point of the
# forward-compat stage is a consumer that skips records it does not know,
# whatever they happen to be.
V1_EVENT_TYPES = frozenset(["install", "withdraw", "origin_change"])


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # s1: GRE underlay + the eBGP session.
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # s2: r1's source segment with host h1.
    tgen.add_host("h1", "10.10.10.10/24", "via 10.10.10.1")
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    # s3: r2's receiver stub, where the IGMP membership lives.
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])


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


def teardown_module(_mod):
    get_topogen().stop_topology()
    try:
        os.unlink(EVENT_SOCK)
    except OSError:
        pass


# --- the reader -----------------------------------------------------------


class EventReader:
    """Newline-delimited JSON off the settlement socket, in arrival order.

    Same wire protocol as bgp_mvpn_gtm_events/EventReader (subscribe, private
    snapshot, snapshot_ack, then the live broadcast).  Kept as a local copy
    rather than hoisted into tests/topotests/lib/: the two suites pin down the
    same contract from opposite ends, and a shared helper that one of them
    edits is a shared assumption neither would notice breaking.  The additions
    here are collect() and expect_quiet(), which exist because half of this
    suite's assertions are about events that must NOT appear.
    """

    def __init__(self, path, cursor=None, connect_timeout=30):
        # The listener can lag a beat behind bgpd's config apply, so retry
        # rather than single-shot (a bare connect races the bind and flakes
        # with ENOENT/ECONNREFUSED).
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

    def _next_buffered(self):
        nl = self.buf.find(b"\n")
        if nl < 0:
            return None
        line, self.buf = self.buf[:nl], self.buf[nl + 1 :]
        return json.loads(line.decode("utf-8"))

    def _fill(self):
        try:
            chunk = self.sock.recv(4096)
        except socket.timeout:
            return
        if not chunk:
            raise AssertionError("event socket closed by bgpd")
        self.buf += chunk

    def read_event(self, timeout=30):
        deadline = time.time() + timeout
        while True:
            event = self._next_buffered()
            if event is not None:
                return event
            if time.time() >= deadline:
                raise AssertionError(
                    "no event received within {}s (buffered: {!r})".format(
                        timeout, self.buf
                    )
                )
            self._fill()

    def collect(self, until=None, timeout=60, settle=8.0):
        """Events in arrival order, until `until` is satisfied then quiet.

        Two bounds, because liveness and cardinality are different questions
        and one window cannot answer both:

          - `timeout` bounds LIVENESS.  The join -> tunnel -> netlink ack ->
            kernel MFC -> pimd re-announce -> bgpd round trip is what separates
            an `install` from the `forwarding_ready` that follows it, and it is
            slow.  Sized like the run_and_expect() loops in pim_dimt_tunnel/
            (30s+), because a short window here does not report "too slow", it
            reports "no forwarding_ready was emitted" -- a false failure that
            looks exactly like the real bug.
          - `settle` bounds CARDINALITY, and only starts once `until` holds.
            A duplicate from a level-triggered emitter arrives on the NEXT
            redundant pimd re-ADD, i.e. strictly after the record it
            duplicates, so it is invisible to any collector that stops at the
            first match.  The window restarts on every record, so a slow burst
            is collected whole rather than cut in half.

        `until` is called with the events so far and must return True when the
        batch is complete enough to judge; None means "just settle", for the
        stages that expect nothing.
        """
        events = []
        hard_deadline = time.time() + timeout
        quiet_deadline = None

        while True:
            event = self._next_buffered()
            if event is not None:
                events.append(event)
                if quiet_deadline is not None:
                    quiet_deadline = time.time() + settle
            elif quiet_deadline is None and (until is None or until(events)):
                # Satisfied (or nothing to wait for): switch from waiting for
                # arrival to waiting for silence.
                quiet_deadline = time.time() + settle
            elif quiet_deadline is not None and time.time() >= quiet_deadline:
                return events
            elif quiet_deadline is None and time.time() >= hard_deadline:
                # Return what arrived and let the caller's assertion name the
                # missing record; raising here would bury it in a timeout.
                return events
            else:
                self._fill()

    def expect_quiet(self, settle=8.0):
        extra = self.collect(until=None, settle=settle)
        assert extra == [], "expected no further events, got {}".format(
            [(e.get("event_type"), e.get("source"), e.get("seq")) for e in extra]
        )

    def expect_none_of(self, event_types, settle=8.0):
        """Nothing of these types arrives, tolerating records that may.

        Used where the claim is about ONE event type rather than about silence.
        Tearing a DIMT-steered (S,G) off its upstream can legitimately trail a
        `withdraw` behind it -- pimd stops announcing an (S,G) whose RPF it can
        no longer pin -- so demanding total silence there would fail on
        correct behaviour while proving nothing extra about the type actually
        under test.
        """
        extra = self.collect(until=None, settle=settle)
        offending = [e for e in extra if e.get("event_type") in event_types]
        assert offending == [], "unexpected {}: {} (full trailing batch {})".format(
            "/".join(sorted(event_types)),
            [(e.get("event_type"), e.get("source"), e.get("seq")) for e in offending],
            [(e.get("event_type"), e.get("source"), e.get("seq")) for e in extra],
        )
        return extra

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


# Shared across the ordered stages.
reader = None
boot_epoch = None
last_seq = None
tunnel_if = None

# Every live (non-snapshot) record this suite has observed, in seq order.  The
# forward-compat stage replays THIS rather than a hand-written expectation, so
# its cursor arithmetic is checked against what the producer actually emitted.
observed = []


def record(events):
    """Append a collected batch to the observed stream and return it."""
    observed.extend(events)
    return events


# --- helpers --------------------------------------------------------------


def _membership(source, group, negate=False):
    """Join/leave (S,G) on the receiver stub, at runtime.

    Deliberately `join-group` and NOT `static-group`, even though the sibling
    DIMT suites all use `static-group`: those configure it in r2/pimd.conf at
    startup, and this one cannot (see the header note -- the reader has to be
    attached before the join).  That difference matters, because the two
    commands are only equivalent at startup:

      `static-group` -> pim_if_static_group_add() -> static_group_join(),
      which returns SILENTLY when the VIF is not ready
      (pim_iface.c:1484) or when tib_sg_gm_join() refuses
      (pim_iface.c:1491), leaving the membership to be picked up later by
      pim_if_static_group_replay().  That replay only runs from
      interface-up / neighbor-add / delete-on-noinfo -- never from a
      runtime config change.  So a runtime `static-group` that misses on
      its single attempt is a permanent no-op that reports success: config
      accepted, no membership, no upstream, no Type-7, empty event stream.

      `join-group` -> pim_if_gm_join_add() (pim_iface.c:1603) issues the
      kernel socket join immediately, has no VIF-readiness deferral and no
      DR check, and fails LOUDLY via ferr_cfg_invalid() rather than
      deferring to a replay that will not come.

    bgp_mvpn_gtm_events is the one sibling that also joins at runtime, and it
    uses `join-group` for this reason.
    """
    get_topogen().gears["r2"].vtysh_cmd(
        "conf t\ninterface r2-eth1\n{}ip igmp join-group {} {}".format(
            "no " if negate else "", group, source
        )
    )


def tunnel_ifname(router):
    """The DIMT netdev name pimd asked zebra to build, or None."""
    output = json.loads(router.vtysh_cmd("show ip pim dimt tunnel json"))
    entry = output.get(UMH)
    return entry.get("interface") if entry else None


def expect(func, count=30, wait=1.0):
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, result


def _summary(events):
    return [(e.get("event_type"), e.get("source"), e.get("seq")) for e in events]


def has(event_type, source=None):
    """An `until` predicate for collect(): this record has arrived."""

    def _check(events):
        return any(
            e.get("event_type") == event_type
            and (source is None or e.get("source") == source)
            for e in events
        )

    return _check


def both(first, second):
    def _check(events):
        return first(events) and second(events)

    return _check


def only(events, event_type, source=None):
    """Exactly one event of this type (and source), returned.

    Cardinality is asserted here rather than by reading a single event off the
    socket, because "exactly one" and "at least one" are different claims and
    read_event() can only ever prove the weaker one.  Every duplicate this
    contract can produce -- a level-triggered emitter re-announcing a
    still-READY (S,G) on each redundant pimd re-ADD -- arrives LATER, so it is
    invisible to a checker that stops at the first match.
    """
    matches = [
        e
        for e in events
        if e.get("event_type") == event_type
        and (source is None or e.get("source") == source)
    ]
    assert len(matches) == 1, "expected exactly one {}{}, got {}: stream {}".format(
        event_type,
        "" if source is None else " for {}".format(source),
        len(matches),
        _summary(events),
    )
    return matches[0]


def alive(events, event_type, source=None, why=""):
    """At least one, with a failure message about the ABSENCE.

    Called before only() on purpose.  only() proves "exactly one", but when the
    count is zero it fails complaining about arithmetic, and zero is the
    interesting failure: it is the vacuous pass a not-before assertion gives
    you when nothing was ever emitted (BLO-28092's carry-forward).  Naming that
    case separately is the difference between a test that reports "readiness
    was never announced" and one that reports "expected 1, got 0".
    """
    matches = [
        e
        for e in events
        if e.get("event_type") == event_type
        and (source is None or e.get("source") == source)
    ]
    assert matches, "no {} was ever emitted{}. Stream: {}".format(
        event_type, " -- " + why if why else "", _summary(events)
    )


def assert_no(events, event_type, source=None):
    matches = [
        e
        for e in events
        if e.get("event_type") == event_type
        and (source is None or e.get("source") == source)
    ]
    assert matches == [], "unexpected {}: {}".format(event_type, _summary(matches))


def assert_contiguous(events, first_seq):
    """seq is dense and ascending from `first_seq` across the whole batch.

    This is the property the schema's ignore-and-advance rule rests on: the
    additive forwarding_* records draw from the SAME counter as install /
    withdraw, so a consumer that skips one without advancing its cursor
    computes a phantom gap at the next install.  Asserting density over a batch
    that MIXES both kinds is what proves the counter is shared -- a per-type
    counter, or a forwarding record that failed to advance seq at all, both
    show up as a hole here.
    """
    seqs = [e["seq"] for e in events]
    assert seqs == list(
        range(first_seq, first_seq + len(events))
    ), "seq not contiguous from {}: {}".format(first_seq, seqs)
    return seqs[-1] if seqs else first_seq - 1


def assert_same_route_identity(a, b):
    """Two records annotate the same entitlement interval.

    D4's Shape clause requires a readiness record be "joinable to the
    entitlement interval containing it", and this is that join key.
    route_version equality is the load-bearing half -- D6 says verbatim that
    forwarding_ready "carries the same route_version as the install it
    follows", so a readiness record that minted a new generation would tell
    every consumer the entitlement window closed and reopened.
    """
    for field in ("source", "group", "source_as", "route_version", "vrf", "route_type"):
        assert a[field] == b[field], "{} differs: {!r} vs {!r} ({} vs {})".format(
            field, a[field], b[field], a.get("event_type"), b.get("event_type")
        )


def assert_ready_shape(event, oif, ifindex):
    """The `forwarding` object of a forwarding_ready, per D4 Shape."""
    fwd = event.get("forwarding")
    assert fwd is not None, "forwarding_ready carries no forwarding object: {}".format(
        event
    )
    assert fwd.get("state") == "ready", fwd
    # The proven oif is resolved by pimd -- bgpd has no view of the DIMT
    # netdev -- so a wrong name here means the two daemons disagree about which
    # device is carrying the traffic.
    assert fwd.get("oif") == oif, "oif is {}, kernel netdev is {}: {}".format(
        fwd.get("oif"), oif, fwd
    )
    # ifindex, not just the name: a netdev deleted and rebuilt under the same
    # name is a different device, and only the ifindex says so.
    assert fwd.get("ifindex") == ifindex, "ifindex is {}, kernel says {}: {}".format(
        fwd.get("ifindex"), ifindex, fwd
    )
    # Constants, not observations: READY is DEFINED as both acks having
    # happened, so naming them records WHICH proof was required.
    assert fwd.get("tunnel_ack") == "netlink", fwd
    assert fwd.get("mfc_ack") == "MRT_ADD_MFC", fwd


def assert_lost_shape(event, allowed_reasons):
    """The `forwarding` object of a forwarding_lost.

    `allowed_reasons` is a set, not a value -- see the header for why the
    reason is race-determined on the leave and origin-change paths.  It is
    always intersected with the full stable enum, so a reason outside the
    contract fails even if a caller passes a sloppy set.
    """
    fwd = event.get("forwarding")
    assert fwd is not None, "forwarding_lost carries no forwarding object: {}".format(
        event
    )
    assert fwd.get("state") == "lost", fwd
    reason = fwd.get("reason")
    assert reason in FWD_LOST_REASONS, (
        "reason {!r} is not a member of the stable D4 enum {}".format(
            reason, sorted(FWD_LOST_REASONS)
        )
    )
    allowed = frozenset(allowed_reasons) | FWD_LOST_REASON_VERSION_DEPENDENT
    assert reason in allowed, "reason is {}, expected one of {}: {}".format(
        reason, sorted(allowed), fwd
    )
    # A lost record names no oif: there is no proven forwarding path to name.
    assert "oif" not in fwd, fwd


def kernel_admits(router, source, group, ifname):
    """The kernel admits (S,G) on `ifname` as its INCOMING vif.

    iif, not oif: this router RECEIVES over the tunnel, so the DIMT vif is
    never an output interface here.
    """
    vif, error = resolve_mr_vif(router, ifname)
    if error:
        return error
    return check_ip_mr_cache_iif(router, source, group, vif)


# --- preconditions --------------------------------------------------------


def test_session_and_umh_route():
    """eBGP up and the UMH-bearing source route landed on r2.

    Ordered before the socket is configured so nothing in the reader's view is
    a consequence of BGP still converging: the reader must attach to a quiet
    stream, or expect_quiet() means nothing later.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _established():
        out = json.loads(r2.vtysh_cmd("show bgp neighbor 10.0.0.1 json"))
        return topotest.json_cmp(out, {"10.0.0.1": {"bgpState": "Established"}})

    expect(_established, count=60)

    # The UMH mapping is what makes the (S,G) DIMT-steered.  Without it the
    # join would originate with no upstream and no tunnel would ever be
    # requested, so every later stage would fail for the wrong reason.
    def _umh_learned():
        out = json.loads(r2.vtysh_cmd("show ip pim dimt umh json"))
        entry = out.get(SRC_PREFIX)
        if entry is None:
            return "r2 holds no DIMT UMH mapping for {}: {}".format(SRC_PREFIX, out)
        if entry.get("umh") != UMH:
            return "UMH is {}, expected {}: {}".format(entry.get("umh"), UMH, entry)
        return None

    expect(_umh_learned, count=60)


def test_event_socket_connects():
    """The listener comes up, and reports itself up.

    "Configured" is not "listening": a bind or listen failure would leave the
    running-config advertising a stream with nothing behind it, so the liveness
    surface is checked too.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r2.vtysh_cmd(
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

    expect(_connect)

    status = json.loads(r2.vtysh_cmd("show bgp mvpn events json"))
    assert status.get("listening") is True, status
    assert status.get("path") == EVENT_SOCK, status


# --- D6: join -> ready ----------------------------------------------------


def test_install_then_exactly_one_forwarding_ready():
    """`install` at join, then EXACTLY ONE `forwarding_ready` after the acks.

    Four claims, and the cardinality one is the one that has been getting away:

      1. `install` is emitted at join with its revision-1 shape -- ungated, and
         carrying NO forwarding object.  Revision 1 wanted to withhold it until
         forwarding was proven; that would shorten R, an eligibility input, and
         suppress payable bytes the contract entitles (D4 amendment record).
         So the ABSENCE of a new precondition is the assertion.
      2. `forwarding_ready` follows it, strictly after, in ARRIVAL order.
      3. EXACTLY ONE of them.  pimd re-ADDs the (S,G) on every event that could
         plausibly have moved readiness, so a level-triggered emitter emits a
         duplicate per redundant re-announce.
      4. It is joinable to the interval it annotates: same route_version as the
         install, and seq dense across both.
    """
    global reader, boot_epoch, last_seq, tunnel_if

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    reader = EventReader(EVENT_SOCK)
    snapshot, snapshot_end = reader.read_snapshot()
    # Nothing has joined yet -- r2/pimd.conf deliberately carries no startup
    # membership -- so an empty snapshot is the precondition for reading the
    # whole lifecycle off the live stream.
    assert snapshot == [], "expected a quiet baseline, got {}".format(
        _summary(snapshot)
    )
    assert snapshot_end["seq"] == 0, snapshot_end
    assert snapshot_end["cursor_status"] == "bootstrap", snapshot_end
    reader.acknowledge_snapshot(snapshot_end)
    boot_epoch = snapshot_end["boot_epoch"]

    _membership(SOURCE, GROUP)

    events = record(
        reader.collect(
            until=both(has("install", SOURCE), has("forwarding_ready", SOURCE))
        )
    )

    install = only(events, "install", source=SOURCE)
    assert install["route_type"] == 7, install
    assert install["group"] == GROUP, install
    assert install["upstream_peer"] == UMH, install
    assert install["route_version"] == "{}.1".format(boot_epoch), install
    # D4: install keeps its revision-1 shape.  A forwarding object on it would
    # mean the readiness verdict had been folded into the entitlement record.
    assert "forwarding" not in install, install

    alive(
        events,
        "forwarding_ready",
        source=SOURCE,
        why="readiness reached the kernel but was never announced to bgpd",
    )
    ready = only(events, "forwarding_ready", source=SOURCE)

    # Ordering in ARRIVAL order, not by seq: seq ordering would still hold if
    # the records were broadcast out of order, and the consumer reads the
    # socket, not the counter.
    assert events.index(install) < events.index(ready), _summary(events)

    tunnel_if = tunnel_ifname(r2)
    assert tunnel_if, "pimd created no DIMT tunnel for {}".format(UMH)

    # The record's data-plane claim, against the kernel.
    expect(lambda: kernel_admits(r2, SOURCE, GROUP, tunnel_if))
    ifindex = link_ifindex(r2, tunnel_if)
    assert ifindex is not None, "kernel holds no netdev {}".format(tunnel_if)
    assert_ready_shape(ready, tunnel_if, ifindex)

    # Joinability: the readiness record annotates the interval the install
    # opened, and did not mint a new generation.
    assert_same_route_identity(install, ready)

    last_seq = assert_contiguous(events, 1)

    # And no duplicate arrives late.
    reader.expect_quiet()


# --- BLO-28297: a second (S,G) on an already-INSTALLED tunnel -------------


def test_second_sg_gets_exactly_one_forwarding_ready():
    """A second (S,G) on the live tunnel: one install, one forwarding_ready,
    and NOTHING for the first (S,G).

    BLO-28297's automated verifying signal, which that ticket deferred to this
    PR because until now there was no consumer of the zapi forwarding byte to
    assert against.

    ON DISCRIMINATION, STATED PLAINLY: pim_dimt_tunnel's
    test_second_sg_on_a_live_tunnel_is_announced_ready already records that
    this scenario does NOT discriminate the announce hook it was written to
    guard -- the (S,G) does not reach JOINED, and so is not announced at all,
    until after its MFC is installed, so the announcing ADD already carries the
    right byte.  That finding was reached on `announcedForwarding`; this stage
    re-asks it of the emitted record, where two things are newly checkable and
    neither was before:

      - CARDINALITY on the wire.  One forwarding_ready for the second (S,G),
        not two.  `announcedForwarding` is last-value-wins and cannot count.
      - QUIET for the FIRST (S,G).  Readiness for the first join did not move,
        so a level-triggered emitter would re-announce it here.  There is no
        vtysh surface on which that is even visible.

    What this stage does NOT claim is that reverting
    pim_mroute_gtm_admission_changed() turns it red.  See BLO-27739 for the
    mutation-check result rather than assuming this stage proves that hook.
    """
    global last_seq

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    _membership(SECOND_SOURCE, SECOND_GROUP)

    events = record(
        reader.collect(
            until=both(
                has("install", SECOND_SOURCE), has("forwarding_ready", SECOND_SOURCE)
            )
        )
    )

    install = only(events, "install", source=SECOND_SOURCE)
    assert install["group"] == SECOND_GROUP, install
    assert install["upstream_peer"] == UMH, install
    assert "forwarding" not in install, install

    alive(
        events,
        "forwarding_ready",
        source=SECOND_SOURCE,
        why="the second (S,G) never had its readiness announced",
    )
    ready = only(events, "forwarding_ready", source=SECOND_SOURCE)
    assert events.index(install) < events.index(ready), _summary(events)

    # It rides the tunnel that already exists rather than minting a second
    # netdev, so the proven oif is the SAME device -- same name, same ifindex.
    assert tunnel_ifname(r2) == tunnel_if, "the second (S,G) changed the tunnel netdev"
    expect(lambda: kernel_admits(r2, SECOND_SOURCE, SECOND_GROUP, tunnel_if))
    ifindex = link_ifindex(r2, tunnel_if)
    assert ifindex is not None, "kernel holds no netdev {}".format(tunnel_if)
    assert_ready_shape(ready, tunnel_if, ifindex)
    assert_same_route_identity(install, ready)

    # Nothing at all for the first (S,G): its readiness did not move.
    assert_no(events, "forwarding_ready", source=SOURCE)
    assert_no(events, "forwarding_lost", source=SOURCE)
    assert_no(events, "origin_change", source=SOURCE)

    last_seq = assert_contiguous(events, last_seq + 1)
    reader.expect_quiet()


# --- D4 restart matrix: what a snapshot does and does not carry -----------


def test_snapshot_carries_all_installed_joins_and_no_readiness():
    """A fresh subscriber's snapshot: ALL installed joins, NO readiness.

    Both halves are load-bearing and they pull in opposite directions.

      - ALL installed, not ready-only.  Revision 1 wanted ready-only
        snapshots; that is wrong and MUST NOT be implemented, because omitting
        an installed-but-not-yet-ready join would silently truncate R.  Two
        joins are installed at this point and both must appear.
      - NO readiness.  Forwarding state is not in the snapshot: a restarted
        bgpd has no readiness state and must emit nothing until pimd
        re-reports.  A snapshot that synthesised forwarding_ready would be
        asserting a data-plane proof it never observed.

    Uses a second subscriber rather than bouncing bgpd: the snapshot is
    replayed per-subscriber through the same snapshot_replay_active path, so
    this exercises the same code without a daemon restart -- and, unlike a
    restart, it leaves the primary reader's cursor intact for the stages that
    follow.  boot_epoch durability across an actual restart is
    bgp_mvpn_gtm_events/test_listener_restart_snapshots_active_join.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    late = EventReader(EVENT_SOCK)
    snapshot, snapshot_end = late.read_snapshot()

    assert snapshot_end["boot_epoch"] == boot_epoch, snapshot_end

    installs = sorted(
        e["source"] for e in snapshot if e.get("event_type") == "install"
    )
    assert installs == sorted(
        [SOURCE, SECOND_SOURCE]
    ), "snapshot must re-emit ALL installed joins, not ready-only; got {}".format(
        _summary(snapshot)
    )

    for event in snapshot:
        assert event.get("event_type") not in (
            "forwarding_ready",
            "forwarding_lost",
        ), "forwarding state must not appear in a snapshot: {}".format(event)
        assert "forwarding" not in event, event

    # A snapshot is point-in-time framing at the current cursor baseline, not a
    # lifecycle transition, so replaying it must not have advanced seq -- which
    # is also why the primary reader's cursor is still valid below.
    assert snapshot_end["seq"] == last_seq, snapshot_end
    late.acknowledge_snapshot(snapshot_end)
    late.close()

    # The primary reader saw none of that: a snapshot is private to the
    # subscriber it was offered to.
    reader.expect_quiet()


# --- D4 forward compatibility: the ignore-and-advance red test ------------


def test_v1_only_consumer_ignores_and_advances():
    """A v1-only consumer must ignore forwarding_* AND advance across them.

    This is the hazard the schema amendment in this PR exists to close, as a
    red test rather than a footnote.  Ignoring alone is NOT sufficient: the
    forwarding_* records draw sequence numbers from the SAME counter as install
    / withdraw, so a consumer that skips an unrecognised record without
    advancing its persisted (boot_epoch, seq) cursor computes a phantom gap at
    the next install and quarantines -- turning a supposedly ignorable additive
    event into a settlement outage.

    BOTH consumer models are run and the assertion is the CONTRAST, because
    that contrast is the whole rule.  A test that only ran the correct consumer
    would pass just as well against a producer that never emitted forwarding_*
    at all.

    The input is `observed` -- the records the stages above actually collected,
    not a hand-written expectation -- so the arithmetic below cannot drift away
    from what the producer emits.
    """
    # Ignore-AND-advance: cursor tracks every record, recognised or not.
    correct_cursor = max(e["seq"] for e in observed)
    # Ignore-WITHOUT-advance: cursor only counts records it recognised, which
    # is the bug.  Taken as the highest recognised seq, i.e. exactly where such
    # a consumer's durable cursor would sit.
    recognised = [e for e in observed if e.get("event_type") in V1_EVENT_TYPES]
    unrecognised = [e for e in observed if e.get("event_type") not in V1_EVENT_TYPES]
    assert unrecognised, (
        "this stage is vacuous unless the stream actually contained records a "
        "v1 consumer does not recognise: {}".format(_summary(observed))
    )
    assert recognised, "no v1-recognised records to anchor the naive cursor"
    naive_cursor = max(e["seq"] for e in recognised)
    assert naive_cursor < correct_cursor, (
        "the naive cursor must lag -- otherwise no unrecognised record was "
        "ever the most recent one and the contrast is untestable: {}".format(
            _summary(observed)
        )
    )

    # The correct consumer resumes contiguous...
    correct = EventReader(EVENT_SOCK, cursor=(boot_epoch, correct_cursor))
    snapshot, snapshot_end = correct.read_snapshot()
    assert (
        snapshot_end["cursor_status"] == "contiguous"
    ), "an ignore-AND-advance consumer must resume contiguous, got {}: {}".format(
        snapshot_end.get("cursor_status"), snapshot_end
    )
    # ...and still receives the full installed set, so ignoring the additive
    # records cost it nothing.
    installs = sorted(
        e["source"] for e in snapshot if e.get("event_type") == "install"
    )
    assert installs == sorted([SOURCE, SECOND_SOURCE]), _summary(snapshot)
    correct.acknowledge_snapshot(snapshot_end)
    correct.close()

    # ...while the ignore-WITHOUT-advance consumer is told it has a gap, which
    # is a quarantine trigger.  Same producer, same stream, different cursor
    # discipline, different settlement outcome -- which is what makes the rule
    # non-optional rather than advisory.
    naive = EventReader(EVENT_SOCK, cursor=(boot_epoch, naive_cursor))
    _, naive_end = naive.read_snapshot()
    assert (
        naive_end["cursor_status"] == "gap"
    ), "a consumer that ignored without advancing must be seen as gapped -- otherwise the ignore-and-advance rule is unfalsifiable: {}".format(
        naive_end
    )
    naive.acknowledge_snapshot(naive_end)
    naive.close()

    reader.expect_quiet()


# --- D3 "Remove": forwarding_lost precedes the withdraw ------------------


def test_forwarding_lost_precedes_withdraw():
    """Leaving emits exactly one forwarding_lost, ORDERED BEFORE the withdraw.

    The ordering is the contract clause: a readiness interval must always close
    INSIDE the entitlement interval that contained it, so the close has to
    reach the stream before the record that ends the entitlement.  A consumer
    that sees them the other way round has a readiness interval extending past
    its own entitlement, which is unjoinable.

    The reason is asserted as membership in the leave-reachable subset, not as
    "withdraw" -- see the header: pimd can evict the MFC and unpin the RPF
    before the DEL reaches bgpd, and whichever path closes the interval first
    is the only one that gets to name a reason.  Ordering and cardinality do
    not depend on that race; the reason string does.
    """
    global last_seq

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    _membership(SECOND_SOURCE, SECOND_GROUP, negate=True)

    events = record(
        reader.collect(
            until=both(
                has("forwarding_lost", SECOND_SOURCE), has("withdraw", SECOND_SOURCE)
            )
        )
    )

    alive(
        events,
        "forwarding_lost",
        source=SECOND_SOURCE,
        why="a ready path left readiness without closing its interval",
    )
    lost = only(events, "forwarding_lost", source=SECOND_SOURCE)
    withdraw = only(events, "withdraw", source=SECOND_SOURCE)
    assert events.index(lost) < events.index(
        withdraw
    ), "forwarding_lost must precede the withdraw it accompanies: {}".format(
        _summary(events)
    )
    assert_lost_shape(lost, FWD_LOST_REASONS_ON_LEAVE)

    # The close carries the route_version of the interval it is closing; the
    # withdraw mints the next generation.  Equal versions would mean the close
    # landed in the wrong interval.
    assert lost["route_version"] != withdraw["route_version"], (lost, withdraw)

    # The surviving (S,G) is untouched: a shared tunnel losing one of its users
    # is not a readiness change for the other.
    assert_no(events, "forwarding_lost", source=SOURCE)
    assert_no(events, "withdraw", source=SOURCE)
    assert_no(events, "forwarding_ready", source=SOURCE)

    expect(lambda: check_no_ip_mr_cache(r2, SECOND_SOURCE, SECOND_GROUP))
    last_seq = assert_contiguous(events, last_seq + 1)
    reader.expect_quiet()


# --- D3 "Origin change" --------------------------------------------------


def test_forwarding_lost_precedes_origin_change():
    """A UMH change closes readiness BEFORE origin_change, and does not reopen
    it until the new path is proven.

    Three claims:

      1. forwarding_lost precedes origin_change.
         The readiness proof was established against the OLD upstream path;
         carrying it across a route_version boundary would make a readiness
         interval straddle two entitlement intervals.
      2. origin_change keeps its revision-1 timing and shape, including
         prior_route_version -- it is not gated on the new path forwarding.
      3. NO forwarding_ready for the new path.  10.99.0.9 has no
         `dimt tunnel-endpoint` row on r2, so it STRUCTURALLY cannot reach
         FWD_READY -- which makes this a stable negative rather than a race
         against a timeout.

    Ordered last: it is the only stage that mutates r1's redistribution, and
    the only one whose trigger travels through BGP rather than through pimd, so
    a failure here cannot contaminate the stages above.
    """
    global last_seq

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    # Swap the attached UMH by replacing the redistribution route-map IN PLACE.
    # A `no redistribute` / `redistribute` pair would withdraw 10.10.10.0/24 in
    # between, and r2 would see the join lose its upstream entirely rather than
    # change it -- a withdraw, not the origin change under test.
    r1.vtysh_cmd(
        """
configure terminal
router bgp 65001
 address-family ipv4 unicast
  redistribute connected route-map UMH2
"""
    )

    events = record(
        reader.collect(
            until=both(has("forwarding_lost", SOURCE), has("origin_change", SOURCE)),
            timeout=90,
            settle=12.0,
        )
    )

    alive(
        events,
        "origin_change",
        source=SOURCE,
        why="r1's UMH swap never reached r2 as an origin change",
    )
    alive(
        events,
        "forwarding_lost",
        source=SOURCE,
        why="the readiness proof against the OLD path was never closed",
    )
    lost = only(events, "forwarding_lost", source=SOURCE)
    change = only(events, "origin_change", source=SOURCE)
    assert events.index(lost) < events.index(
        change
    ), "forwarding_lost must precede the origin_change it accompanies: {}".format(
        _summary(events)
    )
    assert_lost_shape(lost, FWD_LOST_REASONS_ON_ORIGIN_CHANGE)

    # origin_change is ungated and keeps its revision-1 shape.
    assert change["upstream_peer"] == NEW_UMH, change
    assert change["prior_route_version"] == lost["route_version"], (lost, change)
    assert change["route_version"] != lost["route_version"], (lost, change)
    assert "forwarding" not in change, change

    last_seq = assert_contiguous(events, last_seq + 1)

    # The new path cannot be proven, so readiness must not reopen -- asserted
    # over the whole batch AND over the quiet period after it, because a
    # readiness record for the new path would arrive late by construction.
    #
    # expect_none_of(), not expect_quiet(): unpinning the RPF can legitimately
    # trail a `withdraw` for this (S,G), since pimd stops announcing an (S,G)
    # it can no longer pin to an upstream.  That is correct behaviour and
    # orthogonal to the claim being made here.
    assert_no(events, "forwarding_ready")
    reader.expect_none_of({"forwarding_ready"}, settle=12.0)

