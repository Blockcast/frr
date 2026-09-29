#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim_gre_ssm_static.py: normal PIM-SSM over a STATIC GRE netdev.

The SFMIX demo profile (BLO-36544): a Blockcast-run FRR appliance, a static
GRE tunnel, and ordinary PIM -- hellos ON, NOT `ip pim light`, no DIMT
signalling, no MVPN, no dynamic tunnel.  None of the 17 existing DIMT/MVPN
suites covers this shape: pim_dimt* all run PIM light or a zebra-built DIMT
netdev, and bgp_vpnv4_gre builds a static GRE but never runs PIM over it.

Topology:

    h1 --- s2 --- r1 ========= gre-sfmix0 ========= r2 --- s3 --- h2
  (source)     source PE  \\                     /  demo box    (receiver)
                           \\-- s1 underlay ---/
                              10.0.0.0/24

  SOURCE 10.10.10.10   GROUP 232.1.1.10 (FRR's default SSM range)
  underlay  r1 10.0.0.1   r2 10.0.0.2
  gre inner r1 10.99.1.1  r2 10.99.1.2      (outer 10.0.0.1 <-> 10.0.0.2)

The tunnel is named `gre-sfmix0`, deliberately OUTSIDE the `dimt-` prefix:
the epic requires the demo tunnel not be picked up by DIMT reconcile, whose
GC sweeps `dimt-*`.

WHAT IS EVIDENCE HERE
  Forwarding is decided by pimd's resolved RPF, so `show ip pim rpf json`
  (rpfInterface + rpfAddress) is the assertion of record, cross-checked
  against the kernel netdev via lib.kernel_state.check_gre_link.  Note the
  ticket's literal `show ip rpf <S>` does not exist: `show ip rpf` is an
  ALIAS_DEPRECATED of `show route` (zebra/zebra_vty.c:1938) taking NO
  address, and it reads the MRIB table only -- which is empty here, because
  the source prefix arrives by BGP into ipv4 UNICAST.  Asserting on it would
  have been vacuously true.  rpfAddress is the sharper signal anyway: it is
  10.99.1.1 (tunnel inner) or 10.0.0.1 (underlay), which names the winning
  BGP path directly.

THE RPF TIEBREAK (E15) -- the reason this suite exists
  r1 and r2 run TWO eBGP sessions: one over the underlay (peer 10.0.0.1) and
  one over the tunnel inner (peer 10.99.1.1).  r1 announces the source
  prefix ONLY over the tunnel, via an explicit outbound route-map
  (r1/bgpd.conf TUNNEL-ONLY-SRC).

  Remove that policy and the prefix arrives over BOTH sessions.  Every
  earlier bestpath step then ties -- same AS_PATH length, same origin, no
  MED, both eBGP, and both paths carry the SAME router-id 10.0.0.1 -- so
  selection falls through to LOWEST PEER ADDRESS.  10.0.0.1 < 10.99.1.1,
  so the underlay wins bestpath.  Whether RPF FOLLOWS bestpath off the
  tunnel is a separate question with a surprising answer; see BESTPATH
  DOES NOT DECIDE RPF below.  In this harness it does -- because r2 also
  sets `maximum-paths 1` -- and the stream then delivers ZERO packets,
  because r2-eth0 runs no PIM.

  That fall-through only happens because r2 sets `bgp bestpath
  compare-routerid`.  Without it, bestpath step 12 ("prefer the path
  received first", bgp_route.c:1738) decides first, and since the tunnel
  session has carried the prefix since setup the newer underlay path loses
  on AGE -- selection never reaches the address tiebreak at all.

  That is not merely a harness detail, it sharpens the hazard: in the
  field, where step 12 is live, WHICH SESSION WINS IS DECIDED BY SESSION
  ARRIVAL ORDER.  A tunnel flap that re-establishes the tunnel session
  after the underlay one moves RPF onto the underlay and silently delivers
  zero -- with no config change anywhere.  See r2/bgpd.conf.

  BESTPATH DOES NOT DECIDE RPF -- multipath does.  FRR enables eBGP
  multipath by default (bgpd/bgpd.c:4072 sets maxpaths_ebgp =
  multipath_num, not 1), so with the policy removed BOTH paths carry
  BGP_PATH_MULTIPATH and zebra gets BOTH nexthops.  pimd resolves RPF over
  that ECMP set and keeps the tunnel, because the underlay member is
  rejected for having no PIM (pim_rpf.c:85 neigh_needed).  r2 therefore
  also sets `maximum-paths 1`; see r2/bgpd.conf for why that is a demo-box
  finding and not just a knob.

  In lab row T1a the tunnel won that tiebreak only by accident of
  addressing.  The addressing here is chosen so the underlay wins
  bestpath, making the negative control deterministic instead of a coin
  flip.  What that control proves is scoped: ON THIS HARNESS, with
  `maximum-paths 1` installing bestpath alone, the policy is what pins RPF
  to the tunnel.  On a STOCK box it is PIM-capability that pins it -- the
  policy leak is survivable there, and that inversion is the field finding
  this suite exists to record.

MARKER INDEX
  No xfail markers.  The static profile is expected to pass on the unfixed
  fork (lab rows T1a/T1b); a failure here is a real regression, not a known
  gap.
"""

import functools
import json
import os
import re
import subprocess
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import shutdown_bringup_interface_in_kernel
from lib.kernel_state import check_gre_link, check_link_absent
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# mcast_traffic.payload() is imported rather than re-spelled so the sender
# and the byte-exact expectation cannot drift apart.
sys.path.append(CWD)
from mcast_traffic import PAYLOAD_LEN, digest  # noqa: E402

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"

TUNNEL = "gre-sfmix0"
TUNNEL_PEER = "10.99.1.1"  # r1's inner address: RPF here means "over the tunnel"
UNDERLAY_PEER = "10.0.0.1"  # r1's underlay address: RPF here means "off the tunnel"
SRC_PREFIX = "10.10.10.0/24"

PACKETS = 50
# 3s hello -> 10.5s holdtime (FRR derives holdtime as 3.5 x hello).  The
# flap below must stay under that; see test_tunnel_flap_under_holdtime.
HELLO = 3
HOLDTIME = 3.5 * HELLO
FLAP_SECONDS = 4.0


def build_topo(tgen):
    tgen.add_router("r1")  # source PE
    tgen.add_router("r2")  # demo box

    # s1: the GRE underlay (and the underlay eBGP session).
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # s2: the source LAN.
    tgen.add_host("h1", "10.10.10.10/24", "via 10.10.10.1")
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    # s3: the receiver stub.
    tgen.add_host("h2", "10.20.20.10/24", "via 10.20.20.1")
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["h2"])


def _build_tunnel(tgen):
    """Create the static GRE netdev on both ends BEFORE the daemons start.

    zebra must see an ordinary existing interface at startup, so that
    rN/zebra.conf's `interface gre-sfmix0` block binds to a real netdev
    rather than a pending one.  `ttl 64` is the demo profile's outer TTL --
    the DIMT on-demand path uses outer TTL 1, and confusing the two is how
    a tunnel silently stops forwarding past the first hop.

    `multicast on` is set explicitly and is NOT redundant: the kernel
    creates a point-to-point GRE netdev as NOARP/POINTOPOINT, and whether
    IFF_MULTICAST comes up set varies by kernel.  PIM hellos go to
    224.0.0.13, so a tunnel without it forms no adjacency and every
    assertion below fails for a reason that has nothing to do with PIM.
    Stating it costs one netlink call and removes the dependency on which
    kernel CI happens to boot.
    """
    for rname, local, remote in (
        ("r1", "10.0.0.1", "10.0.0.2"),
        ("r2", "10.0.0.2", "10.0.0.1"),
    ):
        for cmd in (
            "ip link add {} type gre ttl 64 dev {}-eth0 local {} remote {}".format(
                TUNNEL, rname, local, remote
            ),
            "ip link set dev {} multicast on".format(TUNNEL),
            "ip link set dev {} up".format(TUNNEL),
        ):
            logger.info("%s: %s", rname, cmd)
            logger.info("%s: %s", rname, tgen.net[rname].cmd(cmd))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    _build_tunnel(tgen)

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
    tgen = get_topogen()
    tgen.stop_topology()


def _json_cmd(rname, cmd):
    """vtysh JSON helper: returns None (NOT {}) on unparseable output, so
    a crashed/unresponsive daemon can never satisfy an absence-assertion
    vacuously -- every predicate must treat None as failure."""
    out = get_topogen().gears[rname].vtysh_cmd(cmd)
    try:
        return json.loads(out)
    except ValueError:
        return None


def expect(func, count=60, wait=1.0):
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, result


def _rpf(rname):
    """pimd's resolved RPF row for (S,G), or a diagnostic string."""
    data = _json_cmd(rname, "show ip pim rpf json")
    if data is None:
        return None, "{}: unparseable pim rpf JSON (pimd dead?)".format(rname)
    row = data.get(GROUP, {}).get(SOURCE, {})
    if not row:
        return None, "{}: no RPF row for ({}, {}): {}".format(
            rname, SOURCE, GROUP, data
        )
    return row, None


def _send(count=PACKETS, interval=0.05, receiver=None):
    """Send exactly `count` packets from h1 and wait for the sender to exit.

    Returns the sender's exit status.  Blocking on purpose: an assertion
    about what arrived is only meaningful once the send has finished.

    Pass `receiver` whenever the caller is going to read a report: every
    receiver is started BEFORE an expect() window it has to outlive, so a
    slow convergence can retire it before a packet is ever sent.  Its
    report then reads {"count": 0}, which the negative control accepts as
    proof that delivery stopped -- a pass for entirely the wrong reason,
    and the one site in this file where that failure is silent.  Checking
    liveness here, at the single choke point all sends route through,
    converts it into a named failure.
    """
    if receiver is not None:
        assert receiver.poll() is None, (
            "receiver expired before traffic was sent -- its report would "
            "read 0 packets for a reason that has nothing to do with "
            "forwarding; raise its --timeout above the expect() window"
        )
    tgen = get_topogen()
    helper = os.path.join(CWD, "mcast_traffic.py")
    proc = tgen.gears["h1"].popen(
        [
            helper,
            GROUP,
            "h1-eth0",
            "--send",
            str(count),
            "--interval",
            str(interval),
            "--ttl",
            "16",
        ]
    )
    proc.wait()
    return proc.returncode


def _start_receiver(count=PACKETS, timeout=90.0):
    """Start the SSM receiver on h2 and block until its join is in the kernel.

    Returns the Popen.  Waiting for the explicit {"event": "joined"} line
    removes the sleep-and-hope race where a slow join reads as lost packets.

    The default timeout is sized to outlive the longest window a receiver
    is ever asked to survive -- a full 60s expect() plus the send that
    follows it -- because every caller starts its receiver FIRST (the join
    is what creates the (S,G) whose RPF is then asserted).  It is still
    bounded well under _receiver_report's communicate() timeout, so the
    negative control's receiver reliably times out and PRINTS its zero
    rather than being killed without a report.
    """
    tgen = get_topogen()
    helper = os.path.join(CWD, "mcast_traffic.py")
    proc = tgen.gears["h2"].popen(
        [
            helper,
            GROUP,
            "h2-eth0",
            "--recv",
            str(count),
            "--source",
            SOURCE,
            "--timeout",
            str(timeout),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    line = proc.stdout.readline()
    if '"joined"' not in line:
        # Kill first, THEN drain stderr: read() blocks to EOF, and a helper
        # that merely printed something unexpected may still be running.
        # Without this the traceback that explains the failure (e.g.
        # RuntimeError from _iface_address) dies unread in the pipe and the
        # assertion reads a bare 'receiver did not join: '''.
        proc.kill()
        raise AssertionError(
            "receiver did not join: {!r} (stderr={!r})".format(
                line, proc.stderr.read()
            )
        )
    return proc


def _receiver_report(proc):
    """The receiver's JSON report.  A parse failure is a failure, never 0."""
    out, err = proc.communicate(timeout=120)
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if "count" in data:
            return data
    raise AssertionError(
        "receiver produced no JSON report (stdout={!r} stderr={!r})".format(out, err)
    )


def test_gre_netdev_and_pim_neighbor_up():
    """The static GRE exists with the demo profile's ttl 64 on both ends,
    and a normal PIM hello adjacency forms across it."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, local, remote in (
        ("r1", "10.0.0.1", "10.0.0.2"),
        ("r2", "10.0.0.2", "10.0.0.1"),
    ):
        router = tgen.gears[rname]
        error = check_gre_link(router, TUNNEL, local=local, remote=remote)
        assert error is None, error

        # ttl 64 is the demo profile; check_gre_link does not cover it.
        detail = router.run("ip -d link show dev {}".format(TUNNEL))
        assert re.search(r"\bttl\s+64\b", detail), "{}: {} is not ttl 64: {}".format(
            rname, TUNNEL, detail
        )
        # Checked separately from the adjacency below so that a kernel which
        # would not take MULTICAST fails HERE, naming the cause, instead of
        # surfacing as an unexplained missing PIM neighbor.
        assert "MULTICAST" in detail, (
            "{}: {} has no MULTICAST flag, so PIM hellos to 224.0.0.13 "
            "cannot be sent: {}".format(rname, TUNNEL, detail)
        )

    def _neighbor(rname, peer):
        data = _json_cmd(rname, "show ip pim neighbor json")
        if data is None:
            return "{}: unparseable pim neighbor JSON (pimd dead?)".format(rname)
        nbrs = data.get(TUNNEL, {})
        if peer not in nbrs:
            return "{}: no PIM neighbor {} on {}: {}".format(
                rname, peer, TUNNEL, data
            )
        return None

    expect(functools.partial(_neighbor, "r1", "10.99.1.2"))
    expect(functools.partial(_neighbor, "r2", TUNNEL_PEER))


def test_rpf_resolves_over_the_tunnel():
    """E15 positive: with the policy in place the source prefix reaches r2
    ONLY over the tunnel session, so RPF is the GRE netdev -- by
    construction, not by winning a tiebreak."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _only_tunnel_path():
        data = _json_cmd("r2", "show bgp ipv4 unicast {} json".format(SRC_PREFIX))
        if data is None:
            return "r2: unparseable bgp JSON (bgpd dead?)"
        paths = data.get("paths")
        if not paths:
            return "r2 has no path for {}: {}".format(SRC_PREFIX, data)
        peers = sorted(
            str(p.get("peer", {}).get("peerId")) for p in data.get("paths", [])
        )
        if peers != [TUNNEL_PEER]:
            return "r2 learned {} from {} (expected only the tunnel peer {})".format(
                SRC_PREFIX, peers, TUNNEL_PEER
            )
        return None

    expect(_only_tunnel_path)

    # The receiver's join is what creates the (S,G) whose RPF we assert.
    receiver = _start_receiver(count=1)
    try:

        def _rpf_on_tunnel():
            row, error = _rpf("r2")
            if error:
                return error
            if row.get("rpfInterface") != TUNNEL:
                return "r2 RPF is not the tunnel: {}".format(row)
            if row.get("rpfAddress") != TUNNEL_PEER:
                return "r2 RPF address is not the tunnel inner peer: {}".format(row)
            return None

        expect(_rpf_on_tunnel)
    finally:
        receiver.terminate()
        receiver.wait()


def test_no_join_delivers_nothing():
    """With no membership, 50 packets sent produce no (S,G) forwarding
    state on the demo box.

    The zero is guarded on both sides so it cannot pass vacuously: the
    sender must exit 0 having sent all 50, and the PIM adjacency must still
    be up.  Path present + traffic sent + nothing delivered is the only
    reading left."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Positive control 1: the path is up.
    def _neighbor_still_up():
        data = _json_cmd("r2", "show ip pim neighbor json")
        if data is None:
            return "r2: unparseable pim neighbor JSON (pimd dead?)"
        if TUNNEL_PEER not in data.get(TUNNEL, {}):
            return "r2 lost the tunnel PIM neighbor: {}".format(data)
        return None

    expect(_neighbor_still_up)

    # Precondition: the EARLIER tests' receivers have been terminated, but
    # the membership they created drains asynchronously (IGMP leave, then
    # prune).  Sending before that lands would let leftover state deliver
    # packets and fail this test for the wrong reason -- so wait for the
    # stub to actually be out of the OIL first.
    def _stub_not_in_oil():
        data = _json_cmd("r2", "show ip mroute json")
        if data is None:
            return "r2: unparseable mroute JSON (pimd dead?)"
        sg = data.get(GROUP, {}).get(SOURCE, {})
        if sg and "r2-eth1" in sg.get("oil", {}):
            return "r2 still has a stale membership in the OIL: {}".format(sg)
        return None

    expect(_stub_not_in_oil)

    # Positive control 2: the traffic really was sent.
    rc = _send()
    assert rc == 0, "sender exited {} (expected 0 after {} packets)".format(
        rc, PACKETS
    )

    # The assertion: no (S,G) forwarding toward the stub on r2.
    data = _json_cmd("r2", "show ip mroute json")
    assert data is not None, "r2: unparseable mroute JSON (pimd dead?)"
    sg = data.get(GROUP, {}).get(SOURCE, {})
    oil = sg.get("oil", {}) if sg else {}
    assert "r2-eth1" not in oil, "r2 forwarded to the stub with no join: {}".format(sg)


def test_ssm_join_delivers_50_of_50_byte_exact():
    """The whole point: an SSM join from h2 pulls exactly 50 of 50 packets
    across the GRE, with every byte intact.

    Byte-exactness is asserted, not just the count: a GRE tunnel is where an
    MTU mismatch silently truncates or fragments a stream, and a
    count-only check passes straight through that bug."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    receiver = _start_receiver(count=PACKETS)
    try:
        # RPF must be over the tunnel before the stream starts, or a slow
        # BGP convergence would read as lost packets.
        def _rpf_on_tunnel():
            row, error = _rpf("r2")
            if error:
                return error
            if row.get("rpfInterface") != TUNNEL:
                return "r2 RPF is not the tunnel: {}".format(row)
            return None

        expect(_rpf_on_tunnel)

        rc = _send(receiver=receiver)
        assert rc == 0, "sender exited {}".format(rc)

        report = _receiver_report(receiver)
    finally:
        if receiver.poll() is None:
            receiver.terminate()
            receiver.wait()

    assert report["corrupt"] == [], "h2 saw malformed packets: {}".format(report)
    assert report["count"] == PACKETS, "h2 received {} of {}: {}".format(
        report["count"], PACKETS, report
    )
    assert report["seqs"] == list(range(PACKETS)), (
        "h2 received the wrong packets (loss, duplication or reorder): "
        "{}".format(report["seqs"])
    )
    # Byte-exactness is established by `corrupt == []` above: the receiver
    # diverts into `corrupt` any packet whose bytes are not exactly
    # payload(seq) (mcast_traffic.py:129-134), so an empty list plus the
    # complete in-order `seqs` already pins every byte.  The digest below is
    # a redundant third statement of that, kept as a single value worth
    # printing in the log -- if one of these three ever has to go, delete
    # THIS one, not `corrupt`.
    assert report["sha256"] == digest(range(PACKETS)), (
        "h2's bytes differ from what h1 sent ({} bytes/packet expected): "
        "{}".format(PAYLOAD_LEN, report)
    )

    logger.info(
        "byte-exact: %d/%d packets, sha256 %s", PACKETS, PACKETS, report["sha256"]
    )


def test_rpf_negative_control_underlay_steals_rpf():
    """E15 negative control: remove the tunnel-only policy and the source
    prefix also arrives over the underlay, which wins the lowest-peer-address
    tiebreak.  RPF leaves the tunnel and delivery stops.

    RPF only follows bestpath here because r2 sets `maximum-paths 1`; with
    FRR's default eBGP multipath the tunnel keeps RPF on PIM-capability and
    the leak is survivable.  So this reproduces the T1a hazard as it behaves
    on a box whose underlay also runs PIM and that has not set
    `maximum-paths 1` -- reproduced here by a different route (this box has
    no usable member at all, rather than a usable one with no upstream); see
    r2/bgpd.conf.  The policy is
    restored at the end and the tunnel re-asserted, so later tests are not
    left on the broken path."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "conf t\n"
        "router bgp 65001\n"
        " address-family ipv4 unicast\n"
        "  no neighbor 10.0.0.2 route-map TUNNEL-ONLY-SRC out\n"
    )
    try:
        # Both sessions now carry the prefix, and -- the claim this suite
        # exists to prove -- the UNDERLAY path wins the tiebreak.
        def _both_paths():
            data = _json_cmd("r2", "show bgp ipv4 unicast {} json".format(SRC_PREFIX))
            if data is None:
                return "r2: unparseable bgp JSON (bgpd dead?)"
            paths = data.get("paths", [])
            peers = sorted(str(p.get("peer", {}).get("peerId")) for p in paths)
            if peers != sorted([UNDERLAY_PEER, TUNNEL_PEER]):
                return "r2 does not yet see both paths for {}: {}".format(
                    SRC_PREFIX, peers
                )
            # Positive evidence for E15, asserted at the BGP layer because
            # that is the only layer where it is observable.  _rpf_off_tunnel
            # below proves RPF is no longer on the tunnel, but r2-eth0 runs no
            # PIM, so the row cannot move to the underlay: it stays with
            # rpfInterface "<ifname?>", which names no winner.  That the
            # UNDERLAY won -- the documented mechanism -- is therefore visible
            # only here.  If bestpath ever landed on the tunnel, RPF would
            # stay put and the zero below would be measuring nothing.
            #
            # In PREFIX-DETAIL output `bestpath` is an OBJECT, not the bare
            # `true` the route-table listing uses, and its mere presence does
            # NOT mean selected: bgp_route.c:13318 also creates it carrying
            # only bestpathFromAs for a DMED-selected (per-AS best) path.
            # `overall` is added solely under BGP_PATH_SELECTED
            # (bgp_route.c:13334), so that is the only field that
            # discriminates.
            best = [p for p in paths if (p.get("bestpath") or {}).get("overall")]
            if len(best) != 1:
                return "r2 has {} bestpaths for {} (expected 1): {}".format(
                    len(best), SRC_PREFIX, paths
                )
            reason = best[0].get("bestpath", {}).get("selectionReason")
            chosen = str(best[0].get("peer", {}).get("peerId"))
            if chosen != UNDERLAY_PEER:
                return (
                    "r2 selected {} for {}, expected the underlay peer {} to "
                    "win the lowest-peer-address tiebreak (reason: {})".format(
                        chosen, SRC_PREFIX, UNDERLAY_PEER, reason
                    )
                )
            # selectionReason names WHICH bestpath step decided it; logged
            # rather than asserted so a future FRR that ties earlier fails on
            # the peer above, with the step it actually took printed here.
            logger.info("E15 tiebreak: %s selected, selectionReason=%r", chosen, reason)
            return None

        expect(_both_paths)

        # ...and RPF moves off the tunnel to the underlay peer.
        receiver = _start_receiver(count=PACKETS)
        try:

            def _rpf_off_tunnel():
                # r2-eth0 runs no PIM, so when the underlay path wins the row
                # does not move to the underlay: pim_nht_lookup_ecmp finds no
                # usable member and pim_upstream_rpf_clear (pim_rpf.c) clears
                # the nexthop.  Asserting rpfAddress == UNDERLAY_PEER was
                # unsatisfiable by construction.  The clear does NOT delete
                # the upstream, and pim_show_rpf (pim_cmd_common.c) prints a
                # row for every upstream, with rpfInterface "<ifname?>" when
                # it is unresolved -- so the row stays, off the tunnel.
                #
                # An ABSENT row therefore means the receiver started just
                # above has not reached pimd as an (S,G) upstream yet
                # (_start_receiver waits only for the kernel join), not that
                # RPF moved.  Accepting absence would let the first poll pass
                # before the join exists, so only a present, non-tunnel row
                # counts; _rpf reports absence as an error and expect()
                # retries.
                #
                # This is exactly what `maximum-paths 1` on r2 buys: without
                # it the underlay merely JOINS the tunnel in the ECMP set and
                # the tunnel member keeps winning, so the row never moves.
                row, error = _rpf("r2")
                if error:
                    return error
                if row.get("rpfInterface") == TUNNEL:
                    return "r2 RPF is still the tunnel: {}".format(row)
                return None

            expect(_rpf_off_tunnel)

            # And delivery fails: r2-eth0 runs no PIM, so the stream has no
            # path at all.  This is the silent zero.
            rc = _send(receiver=receiver)
            assert rc == 0, "sender exited {}".format(rc)
            # _send() already asserts liveness BEFORE the send, so the window
            # that needs closing here is the send ITSELF (~2.5s of blocking).
            # A receiver whose 90s deadline lands inside it reports 0 for a
            # reason that has nothing to do with forwarding, and the
            # assertion at the end of this test would accept that as proof
            # delivery stopped.  Bracketing the send is what makes the zero
            # below mean what it claims.
            assert receiver.poll() is None, (
                "receiver expired during the send -- the zero below would be "
                "measuring the timeout, not the RPF move"
            )
            report = _receiver_report(receiver)
        finally:
            if receiver.poll() is None:
                receiver.terminate()
                receiver.wait()

        assert report["count"] == 0, (
            "delivery survived RPF moving off the tunnel ({} packets) -- the "
            "negative control proves nothing if the stream still arrives: "
            "{}".format(report["count"], report)
        )
    finally:
        r1.vtysh_cmd(
            "conf t\n"
            "router bgp 65001\n"
            " address-family ipv4 unicast\n"
            "  neighbor 10.0.0.2 route-map TUNNEL-ONLY-SRC out\n"
        )

    # Restored: RPF must come back to the tunnel, or every later test is
    # measuring the broken path.
    def _rpf_back_on_tunnel():
        # The receiver below exists only to hold the (S,G) open.  If it
        # expired, the upstream would drain and _rpf would report "no RPF
        # row" -- an expect timeout naming the wrong cause.  Checked HERE
        # rather than after expect(): expect() asserts on timeout, so a
        # check placed after it never runs on the path it is meant to
        # explain.
        if receiver.poll() is not None:
            return (
                "the (S,G)-holding receiver expired -- the RPF row is "
                "draining, which is not RPF failing to return to the tunnel"
            )
        row, error = _rpf("r2")
        if error:
            return error
        if row.get("rpfInterface") != TUNNEL:
            return "r2 RPF did not return to the tunnel: {}".format(row)
        return None

    receiver = _start_receiver(count=1)
    try:
        expect(_rpf_back_on_tunnel)
    finally:
        receiver.terminate()
        receiver.wait()


def test_tunnel_flap_under_holdtime():
    """Flap the tunnel for less than 3.5 x the hello interval, and the
    delivery path comes back.

    NOTE on what is asserted.  A kernel link-down is an immediate
    interface-down event, so pimd drops the neighbor at once rather than
    ageing it out -- "the adjacency never expired" would be a false claim
    about a sub-holdtime flap.  What a sub-holdtime outage must guarantee is
    RECOVERY: neighbor back, RPF still the tunnel, and a full 50/50 stream
    afterwards."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    assert FLAP_SECONDS < HOLDTIME, "the flap must stay under the holdtime"

    shutdown_bringup_interface_in_kernel(tgen, "r2", TUNNEL, False)
    time.sleep(FLAP_SECONDS)
    shutdown_bringup_interface_in_kernel(tgen, "r2", TUNNEL, True)

    def _neighbor_back():
        data = _json_cmd("r2", "show ip pim neighbor json")
        if data is None:
            return "r2: unparseable pim neighbor JSON (pimd dead?)"
        if TUNNEL_PEER not in data.get(TUNNEL, {}):
            return "r2 PIM neighbor did not return after the flap: {}".format(data)
        return None

    expect(_neighbor_back)

    receiver = _start_receiver(count=PACKETS)
    try:

        def _rpf_on_tunnel():
            row, error = _rpf("r2")
            if error:
                return error
            if row.get("rpfInterface") != TUNNEL:
                return "r2 RPF is not back on the tunnel: {}".format(row)
            return None

        expect(_rpf_on_tunnel)

        rc = _send(receiver=receiver)
        assert rc == 0, "sender exited {}".format(rc)
        report = _receiver_report(receiver)
    finally:
        if receiver.poll() is None:
            receiver.terminate()
            receiver.wait()

    assert report["count"] == PACKETS, "post-flap delivery {} of {}: {}".format(
        report["count"], PACKETS, report
    )
    assert report["sha256"] == digest(range(PACKETS)), (
        "post-flap bytes differ from what h1 sent: {}".format(report)
    )


def test_source_netdev_delete_midstream():
    """Delete the source-side netdev while the stream is running.

    Destructive, so it runs last.  The regression this guards is a crash or
    a wedged daemon when an interface carrying an active (S,G) IIF
    disappears underneath it -- both routers must still answer vtysh
    afterwards, and r1's (S,G) must not keep claiming a netdev that is
    gone."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # The receiver holds r2's membership for the whole test, including the
    # release check below, so any (S,G) that disappears on r1 disappears
    # because of the delete and not because the stream was torn down.  It
    # has no lifetime budget to get wrong: an infinite --timeout leaves the
    # finally below as the only thing that ends it, however long the
    # expect() windows take (each costs count x (probe + wait), and the
    # probe is a vtysh round-trip of unbounded cost on a loaded runner).  It
    # shares the sender's packet count, and the delete is asserted to land
    # while the sender is still sending, so it cannot collect its count and
    # exit early either.  Its report is never read, so the bounded timeout
    # _receiver_report() relies on elsewhere does not apply.
    packets = 400
    receiver = _start_receiver(count=packets, timeout=float("inf"))
    sender = None
    try:
        helper = os.path.join(CWD, "mcast_traffic.py")
        # A slow, long stream so the delete really lands mid-flight.
        sender = tgen.gears["h1"].popen(
            [helper, GROUP, "h1-eth0", "--send", str(packets), "--interval", "0.1"]
        )

        def _r1_forwarding():
            data = _json_cmd("r1", "show ip mroute json")
            if data is None:
                return "r1: unparseable mroute JSON (pimd dead?)"
            sg = data.get(GROUP, {}).get(SOURCE, {})
            if sg.get("iif") != "r1-eth1":
                return "r1 (S,G) IIF is not the source LAN yet: {}".format(sg)
            return None

        expect(_r1_forwarding)

        # _r1_forwarding converges on mroute state that r2's SSM join holds
        # even with no traffic, so without this the test would still pass
        # if the stream had already ended, and the delete would then be a
        # quieter event than the one this test is named for.
        assert sender.poll() is None, (
            "sender finished before the delete -- this is no longer a "
            "midstream delete"
        )
        tgen.gears["r1"].run("ip link del r1-eth1")

        # Positive evidence the netdev is really gone -- check_link_absent
        # refuses to report absence from an unreadable link table.
        expect(lambda: check_link_absent(tgen.gears["r1"], "r1-eth1"), count=20)

        # And r1 must not still claim a netdev that no longer exists.  Given
        # time to converge: the point is that it settles, not that it is
        # instantaneous.  Checked HERE, while the receiver still holds the
        # membership, not after the finally tears the stream down: once the
        # stream is gone the (S,G) ages out on its own, and an absent entry
        # would then pass whether or not r1 released the netdev.
        #
        # An absent entry IS a legitimate release here, not only a
        # non-r1-eth1 IIF.  With r1-eth1 gone r1 has no route to the source,
        # r1 withdraws the source prefix, r2 loses its RPF and prunes, and
        # show ip mroute also skips an entry whose IIF no longer resolves
        # (it is not installed).  That is the delete being processed, and
        # _r1_forwarding above already proved the entry existed on r1-eth1.
        # A pimd that wedged on the delete would instead keep claiming
        # r1-eth1, which is the failure this catches.
        def _iif_released():
            if receiver.poll() is not None:
                return (
                    "the membership-holding receiver exited -- an absent "
                    "(S,G) would then prove nothing about the release"
                )
            data = _json_cmd("r1", "show ip mroute json")
            if data is None:
                return "r1: unparseable mroute JSON after the delete"
            sg = data.get(GROUP, {}).get(SOURCE, {})
            if sg.get("iif") == "r1-eth1":
                return "r1 still claims the deleted netdev as the (S,G) IIF: {}".format(
                    sg
                )
            return None

        expect(_iif_released, count=30)
    finally:
        if sender is not None and sender.poll() is None:
            sender.terminate()
            sender.wait()
        if receiver.poll() is None:
            receiver.terminate()
            receiver.wait()

    # The regression guard: both daemons are alive and answering.
    for rname in ("r1", "r2"):
        data = _json_cmd(rname, "show ip pim neighbor json")
        assert data is not None, "{}: pimd stopped answering after the delete".format(
            rname
        )
        data = _json_cmd(rname, "show ip route json")
        assert data is not None, "{}: zebra stopped answering after the delete".format(
            rname
        )

    assert not tgen.routers_have_failure(), tgen.errors


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
