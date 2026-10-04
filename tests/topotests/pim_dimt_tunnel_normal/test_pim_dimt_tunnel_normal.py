#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim_dimt_tunnel_normal.py: a NORMAL-mode DIMT pin -- hellos on, and the
Join/Prune addressed to the hello adjacency rather than to the UMH loopback.

The interop lab found that neither Junos nor EOS accepts a PIM Light join on
a tunnel, because both require a hello adjacency first: Junos discards it
silently (T1c-1/T1c-3) and EOS counts a Join/Prune receive error (T4e).  A
silent discard is the worst shape a bug can take -- from our side a working
pin and a dead one look identical -- so `pim-mode normal` exists, and this
suite is the assertion that would have caught it.

Topology (the pim_dimt_tunnel_jp underlay, reused verbatim):

    h1 --s2-- r1 --s1-- r3 --s3-- r2 --s4 (receiver stub)
  (sender)   UMH     transit    receiver PoP

THE ADDRESSING IS THE EXPERIMENT
--------------------------------
    UMH (settlement identity) .... 10.77.0.1   loopback on r1, on NO link
    r1's tunnel link address ..... 10.99.0.1   gre-n, peer 10.99.0.2
    r2's tunnel link address ..... 10.99.0.2   the pimd-built dimt-* netdev

In pim_dimt_tunnel_jp the UMH *is* the tunnel's ptp local address, so "the
Join names the UMH" and "the Join names the adjacency" produce identical
bytes -- that suite is structurally unable to tell them apart.  Here they are
different addresses, so F9 can assert which one is actually on the wire.

WHAT IS EVIDENCE HERE
---------------------
  - Hellos: a PIM Hello decoded out of the GRE on r1's side of the transit
    hop, sourced from r2's inner address, plus each router listing the other
    in `show ip pim neighbor`.  Light mode cannot produce any of that --
    pim_hello_send() returns early on a light interface.
  - The J/P upstream-neighbor field: read out of the captured packet's own
    dissection, not inferred.  FRR does not enforce RFC 7761 4.9 on receive,
    so r1 would accept a Join addressed to the loopback and hold join state
    for it -- r1's join table therefore CANNOT discriminate here, which is
    the whole reason this reads the wire.
  - Neighbour expiry: `show ip pim rpf json` reports up->rpf.rpf_addr
    directly.  `show ip pim upstream json` does NOT -- its "rpfAddress" is
    the source address for an (S,G) -- so it is the wrong command for this
    and is deliberately not used.

The tests are ORDER-DEPENDENT: each stage starts from the state the previous
one left.
"""

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
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"
SRC_PREFIX = "10.10.10.0/24"

# The UMH is a loopback and NOT r1's address on the tunnel.  Everything this
# suite exists to prove turns on those being two different addresses.
UMH = "10.77.0.1"
R1_LINK = "10.99.0.1"
R2_INNER = "10.99.0.2"
R1_OUTER = "10.255.0.1"
R2_OUTER = "10.0.2.2"
R1_TUNNEL_IF = "gre-n"

OUTER_TTL = 64

# r1's gre-n advertises `ip pim hello 2 6`, so r2 expires it 6 s after the
# last hello.  Waiting out the 30/105 default instead would cost ~105 s of
# real time per run on a shard that is already capacity-constrained.
HELLO_HOLDTIME = 6
EXPIRY_WAIT = HELLO_HOLDTIME + 6

# How long a triggered J/P may take to show up at r1: generous against a
# loaded CI host, still a quarter of the 60 s periodic interval a lost join
# falls back to, so the two cannot be confused.
PROMPT = 15

# `unresolved` as FRR renders it: %pPA of PIMADDR_ANY.
UNRESOLVED = "0.0.0.0"


def build_topo(tgen):
    for rname in ("r1", "r2", "r3"):
        tgen.add_router(rname)
    tgen.add_host("h1", "10.10.10.10/24", "via 10.10.10.1")

    # Link order fixes interface names: r1-eth0/r3-eth0 on s1, r1-eth1 on s2,
    # r3-eth1/r2-eth0 on s3, r2-eth1 on s4.
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # r1's UMH-side tunnel end: a static, operator-managed GRE with a fixed
    # ttl of its own, carrying a LINK address that is not the UMH.
    r1 = tgen.gears["r1"]
    r1.run(
        "ip link add {} type gre local {} remote {} ttl {}".format(
            R1_TUNNEL_IF, R1_OUTER, R2_OUTER, OUTER_TTL
        )
    )
    r1.run(
        "ip address add {} peer {}/32 dev {}".format(R1_LINK, R2_INNER, R1_TUNNEL_IF)
    )
    r1.run("ip link set {} up".format(R1_TUNNEL_IF))

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


# --- observation helpers -------------------------------------------------


def expect(func, count=30, wait=1.0):
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, result


def umh_entry(router):
    output = json.loads(router.vtysh_cmd("show ip pim dimt umh json"))
    return output.get(SRC_PREFIX)


def tunnel_ifname(router):
    output = json.loads(router.vtysh_cmd("show ip pim dimt tunnel json"))
    entry = output.get(UMH)
    assert entry and entry.get("interface"), "no DIMT tunnel row for {}: {}".format(
        UMH, entry
    )
    return entry["interface"]


def check_tunnel_installed(router):
    output = json.loads(router.vtysh_cmd("show ip pim dimt tunnel json"))
    entry = output.get(UMH)
    if entry is None:
        return "pimd holds no DIMT tunnel for UMH {}".format(UMH)
    if entry.get("state") != "installed" or not entry.get("interface"):
        return "DIMT tunnel for {} is not installed: {}".format(UMH, entry)
    return None


def neighbors(router, ifname):
    """The neighbour source addresses `router` holds on `ifname`."""
    output = json.loads(router.vtysh_cmd("show ip pim neighbor json"))
    return sorted(output.get(ifname, {}).keys())


def check_neighbors(router, ifname, want):
    got = neighbors(router, ifname)
    if got != want:
        return "{} holds {} on {}, expected {}".format(
            router.name, got, ifname, want
        )
    return None


def rpf_row(router, source=SOURCE, group=GROUP):
    """`show ip pim rpf json` row for the (S,G), or None.

    This is the command that reports up->rpf.rpf_addr.  `show ip pim upstream
    json` also has a field called "rpfAddress", but for an (S,G) it holds the
    SOURCE address -- see pim_show_upstream() -- so it says nothing at all
    about which address a Join would carry.
    """
    output = json.loads(router.vtysh_cmd("show ip pim rpf json"))
    return output.get(group, {}).get(source)


def check_pinned(router, ifname, rpf_addr):
    """The (S,G) is pinned to `ifname` with RPF' exactly `rpf_addr`."""
    entry = umh_entry(router)
    if not entry or entry.get("pinSource") != "tunnel":
        return "{} is not pinned to its DIMT tunnel: {}".format(SRC_PREFIX, entry)
    if entry.get("interface") != ifname:
        return "{} is pinned to {}, not {}".format(
            SRC_PREFIX, entry.get("interface"), ifname
        )

    row = rpf_row(router)
    if row is None:
        return "r2 has no RPF row for ({},{})".format(SOURCE, GROUP)
    if row.get("rpfInterface") != ifname:
        return "RPF interface is {}, not {}: {}".format(
            row.get("rpfInterface"), ifname, row
        )
    if row.get("rpfAddress") != rpf_addr:
        return "RPF' is {}, expected {}: {}".format(
            row.get("rpfAddress"), rpf_addr, row
        )
    return None


def check_r1_joined(want=True):
    r1 = get_topogen().gears["r1"]
    output = json.loads(r1.vtysh_cmd("show ip pim join json"))
    row = output.get(R1_TUNNEL_IF, {}).get(GROUP, {}).get(SOURCE)
    state = row.get("channelJoinName") if row else None
    if want and state != "JOIN":
        return "r1 has no Join({},{}) on {} (state {})".format(
            SOURCE, GROUP, R1_TUNNEL_IF, state
        )
    if not want and state == "JOIN":
        return "r1 still holds Join({},{}) on {}".format(SOURCE, GROUP, R1_TUNNEL_IF)
    return None


def set_static_group(router, present):
    router.vtysh_cmd(
        "conf t\ninterface r2-eth1\n{}ip igmp static-group {} {}".format(
            "" if present else "no ", GROUP, SOURCE
        )
    )


def set_r1_hellos(sending):
    """Start or stop hellos on r1's tunnel end.

    `ip pim light` is the switch because pim_hello_send() returns early on a
    light interface: it stops hellos and touches nothing else -- the link
    stays up, the GRE data path is untouched, and r1 still accepts r2's J/P.
    That is the shape of the failure we care about (a far-end pimd restart,
    or hello loss on a congested transit hop) rather than a link teardown,
    which is a different event and does unpin.
    """
    r1 = get_topogen().gears["r1"]
    r1.vtysh_cmd(
        "conf t\ninterface {}\n{}ip pim light".format(
            R1_TUNNEL_IF, "no " if sending else ""
        )
    )


class JPCapture:
    """Capture GRE on r1-eth0 -- the UMH side of the transit hop -- and decode
    the encapsulated PIM.

    Hellos and Join/Prunes are read from the same file by two different
    means.  The J/P side needs the upstream-neighbor field, and this reads it
    out of tshark's own dissection text (`-V`) rather than naming a field
    abbreviation: abbreviations drift between Wireshark releases, and a field
    that has been renamed yields an EMPTY column rather than an error, which
    would silently turn the central assertion of this suite into a no-op.  A
    label that stops matching fails loudly instead, with the dissection in
    the message.
    """

    def __init__(self, name):
        self.router = get_topogen().gears["r1"]
        self.path = "/tmp/dimt-normal-{}.pcapng".format(name)
        self.router.run("rm -f {}".format(self.path))
        self.proc = self.router.popen(
            ["dumpcap", "-q", "-i", "r1-eth0", "-f", "ip proto 47", "-w", self.path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # dumpcap writes the section header as soon as the capture is live.
        _, started = topotest.run_and_expect(
            lambda: self.router.run(
                "test -s {} && echo live".format(self.path)
            ).strip(),
            "live",
            count=20,
            wait=0.25,
        )
        assert started == "live", "dumpcap did not start on r1-eth0"
        self.hellos = []
        self.jp_text = ""
        self.joins = []
        self.prunes = []

    def stop(self):
        # Let the last packet of the stage reach the file before stopping.
        time.sleep(1)
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()

        # Hellos: type 0.  The inner source is all we need.
        out = self.router.run(
            "tshark -r {} -Y 'pim.type == 0' -T fields -E separator='|' "
            "-E aggregator=, -e ip.src 2>/dev/null".format(self.path)
        )
        for line in out.splitlines():
            addrs = [a for a in line.strip().split(",") if a]
            # outer src first, inner src second.
            if len(addrs) >= 2:
                self.hellos.append(addrs[1])

        # Join/Prune: type 3, read as dissection text.
        self.jp_text = self.router.run(
            "tshark -r {} -Y 'pim.type == 3' -V 2>/dev/null".format(self.path)
        )
        self.joins, self.prunes = self._parse_jp(self.jp_text)
        self.router.run("rm -f {}".format(self.path))

    @staticmethod
    def _parse_jp(text):
        """(upstream_neighbor, group, source) triples, split join vs prune.

        tshark -V prints one block per packet; inside a Join/Prune block the
        upstream-neighbor appears once, then per-group Join / Prune entries.
        Tracking the most recent upstream-neighbor and group is enough to
        attribute each source address, and does not depend on indentation.

        Wireshark 3.6.2 (Ubuntu 22.04) and 4.2.2 (24.04) print each group's
        entries under a count heading, one ``IP address:`` line per source
        (JP_TSHARK_TEXT below is their output, identical on both):

            Num Joins: 1
                IP address: 10.10.10.10/32 (S)
            Num Prunes: 0

        so a ``Num Joins`` / ``Num Prunes`` heading sets the kind for the
        ``IP address:`` lines under it.  An inline entry (``Join:
        10.10.10.10/32`` / ``Join 0: 10.10.10.10/32``) is accepted as well,
        in case a release prints that instead.
        """
        addr = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
        upstream_re = re.compile(r"^Upstream[- ]neighbor\b", re.I)
        group_re = re.compile(r"^Group\s+\d+\b", re.I)
        entry_re = re.compile(r"^(Join|Prune)\s*\d*\s*:", re.I)
        heading_re = re.compile(r"^Num\s+(Join|Prune)s\b", re.I)
        ipaddr_re = re.compile(r"^IP address\b", re.I)

        upstream = None
        kind = None
        group = None
        joins, prunes = [], []

        def add(src):
            (joins if kind == "join" else prunes).append((upstream, group, src))

        for raw in text.splitlines():
            line = raw.strip()
            if upstream_re.match(line):
                found = addr.search(line)
                upstream = found.group(1) if found else None
                kind = None
            elif group_re.match(line):
                found = addr.search(line)
                group = found.group(1) if found else None
                kind = None
            elif heading_re.match(line):
                kind = heading_re.match(line).group(1).lower()
            elif entry_re.match(line):
                kind = entry_re.match(line).group(1).lower()
                found = addr.search(line)
                if found:
                    add(found.group(1))
            elif kind and ipaddr_re.match(line):
                found = addr.search(line)
                if found:
                    add(found.group(1))
        return joins, prunes

    def sg(self, kind):
        """Entries for our (S,G), as (upstream_neighbor, group, source)."""
        rows = self.joins if kind == "join" else self.prunes
        return [r for r in rows if r[1] == GROUP and r[2] == SOURCE]

    def pim_text(self, limit=4000):
        """The dissection from the first PIM header on.  The Ethernet, IP
        and GRE layers in front of it fill a 4000-character excerpt by
        themselves and cut it off before the first Join entry."""
        start = max(self.jp_text.find("Protocol Independent Multicast"), 0)
        return self.jp_text[start:][:limit]


# tshark -V of one Join/Prune (upstream 10.99.0.1; 232.1.1.10 joins
# 10.10.10.10, 232.1.1.11 prunes it), as Wireshark 3.6.2 and 4.2.2 both print
# it, from "PIM Options" on.  Only the per-address flag lines are cut.
JP_TSHARK_TEXT = """\
    PIM Options
        Upstream-neighbor: 10.99.0.1
            Address Family: IPv4 (1)
            Encoding Type: Native (0)
            Unicast: 10.99.0.1
        Reserved byte(s): 00
        Num Groups: 2
        Holdtime: 210
        Group 0
            Group 0: 232.1.1.10/32
                Address Family: IPv4 (1)
                Encoding Type: Native (0)
                Masklen: 32
                Group: 232.1.1.10
            Num Joins: 1
                IP address: 10.10.10.10/32 (S)
                    Address Family: IPv4 (1)
                    Encoding Type: Native (0)
                    Masklen: 32
                    Source: 10.10.10.10
            Num Prunes: 0
        Group 1
            Group 1: 232.1.1.11/32
                Address Family: IPv4 (1)
                Encoding Type: Native (0)
                Masklen: 32
                Group: 232.1.1.11
            Num Joins: 0
            Num Prunes: 1
                IP address: 10.10.10.10/32 (S)
                    Address Family: IPv4 (1)
                    Encoding Type: Native (0)
                    Masklen: 32
                    Source: 10.10.10.10
"""


def test_parse_jp_reads_tsharks_layout():
    """_parse_jp reads the layout CI's tshark actually prints.

    It once accepted only an inline ``Join:`` entry, which no Wireshark in CI
    prints.  Every Join then parsed to nothing: F9's positive check could not
    pass, and F10's "no Join was sent" check could not fail.  The body is
    pure parsing; setup_module still builds the topology before it runs.
    """
    joins, prunes = JPCapture._parse_jp(JP_TSHARK_TEXT)
    assert joins == [("10.99.0.1", "232.1.1.10", "10.10.10.10")], joins
    assert prunes == [("10.99.0.1", "232.1.1.11", "10.10.10.10")], prunes


# --- F8 ------------------------------------------------------------------


def test_normal_mode_hellos_and_pin():
    """Hellos are sent on the pimd-built netdev, an adjacency forms, and the
    UMH pin lands on it -- none of which a light interface can do."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    capture = JPCapture("f8")
    set_static_group(r2, True)

    expect(lambda: check_tunnel_installed(r2))
    ifname = tunnel_ifname(r2)

    # Both ends see each other.  On a light interface r2 would send no hello
    # at all, and would only ever hold the synthetic light neighbour a
    # received J/P creates -- never one learned from a hello.
    r1 = tgen.gears["r1"]
    expect(lambda: check_neighbors(r2, ifname, [R1_LINK]))
    expect(lambda: check_neighbors(r1, R1_TUNNEL_IF, [R2_INNER]))

    expect(lambda: check_pinned(r2, ifname, R1_LINK))
    expect(lambda: check_r1_joined(True), count=PROMPT)

    capture.stop()
    assert R2_INNER in capture.hellos, (
        "no PIM Hello from {} crossed the transit hop; inner hello sources "
        "seen: {}".format(R2_INNER, capture.hellos)
    )


# --- F9 ------------------------------------------------------------------


def test_jp_upstream_is_hello_neighbor():
    """The Join(S,G) on the wire names r1's HELLO SOURCE, and explicitly not
    the UMH loopback.

    This is the assertion that would have caught the Junos silent drop in
    lab T1c-1/T1c-3.  It has to read the packet: FRR does not enforce RFC
    7761 4.9 on receive, so r1 accepts a Join naming the loopback and holds
    join state for it either way -- r1's join table is not evidence.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    capture = JPCapture("f9")
    # Bounce the membership so a fresh triggered Join goes out inside the
    # capture window rather than waiting on the 60 s periodic timer.  This
    # takes the tunnel's refcount to zero and back, so the netdev (and its
    # name) may be rebuilt -- which is why nothing here caches an ifname.
    set_static_group(r2, False)
    expect(lambda: check_r1_joined(False), count=PROMPT)
    set_static_group(r2, True)
    expect(lambda: check_r1_joined(True), count=PROMPT)
    capture.stop()

    rows = capture.sg("join")
    assert rows, (
        "no Join({},{}) decoded from the capture. If the dissection text has "
        "changed shape this parse is what broke, so here it is:\n{}".format(
            SOURCE, GROUP, capture.pim_text()
        )
    )

    upstreams = sorted({row[0] for row in rows})
    assert upstreams == [R1_LINK], (
        "Join({},{}) named upstream-neighbor {}, expected r1's hello source "
        "{}".format(SOURCE, GROUP, upstreams, R1_LINK)
    )
    # Stated separately and on purpose: this is the specific wrong answer the
    # whole ticket exists to make impossible, and it deserves its own failure
    # message rather than being implied by the equality above.
    assert UMH not in upstreams, (
        "Join({},{}) was addressed to the UMH loopback {} -- Junos discards "
        "that silently (T1c-1/T1c-3) and EOS counts a J/P Rx error "
        "(T4e)".format(SOURCE, GROUP, UMH)
    )


# --- F10 -----------------------------------------------------------------


def test_neighbor_expiry_with_pin_held():
    """The neighbour expires while the pin is held.

    Decided behaviour (CTO, BLO-36555; doc/user/pim.rst): the pin is
    config-derived, so it is HELD.  rpf_addr goes explicitly unresolved --
    never back to the UMH -- no J/P is generated while there is nobody to
    address one to, and no Prune is sent to the departing neighbour.  Hellos
    returning re-arm the pin with a triggered Join.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    expect(lambda: check_tunnel_installed(r2))
    ifname = tunnel_ifname(r2)

    expect(lambda: check_pinned(r2, ifname, R1_LINK))

    capture = JPCapture("f10-down")
    set_r1_hellos(False)

    expect(
        lambda: check_neighbors(r2, ifname, []),
        count=EXPIRY_WAIT,
    )

    # The pin is held, and RPF' is unresolved rather than the UMH.  Asserting
    # only "no Join was emitted" would pass even if rpf_addr had silently
    # fallen back to the UMH loopback -- i.e. it would miss exactly the bug
    # class this ticket exists to kill.
    expect(lambda: check_pinned(r2, ifname, UNRESOLVED))

    # Re-derive the pin from scratch with no adjacency present, by bouncing
    # the membership inside the down window.  Everything above this point
    # only ever observes an upstream that was ALREADY Joined -- the static
    # group is held across the expiry, so JoinDesired never flips and the
    # assertions below cannot see the NotJoined->Joined edge.  That edge is
    # the ordinary bootstrap shape (netdev adopted `pim-mode normal`, no
    # neighbour yet, downstream interest already there), and it is the only
    # way an unresolved RPF' reaches the J/P send path.  Nothing stops
    # pim_upstream_send_join() on that edge; the packet dies one level down
    # at the pim_addr_is_any() return in pim_jp_send() (pim_join.c).  That
    # guard is generic pimd code this feature does not own, so assert the
    # observable rather than trusting it to stay put.
    set_static_group(r2, False)
    expect(
        lambda: None
        if (umh_entry(r2) or {}).get("pinSource") != "tunnel"
        else "{} is still pinned to the tunnel".format(SRC_PREFIX),
        count=PROMPT,
    )
    set_static_group(r2, True)
    expect(lambda: check_tunnel_installed(r2), count=PROMPT)
    # Dropping to zero demand may have rebuilt the netdev under a new name.
    ifname = tunnel_ifname(r2)
    expect(lambda: check_pinned(r2, ifname, UNRESOLVED), count=PROMPT)

    # Give any errant periodic refresh a chance to show up before we look.
    time.sleep(5)
    capture.stop()

    assert not capture.sg("prune"), (
        "a Prune({},{}) was sent to the expiring neighbour: {}. The traffic "
        "is still wanted, and the neighbour is by definition not "
        "listening".format(SOURCE, GROUP, capture.sg("prune"))
    )
    assert not capture.sg("join"), (
        "a Join({},{}) went out with no neighbour to address it to: "
        "{}".format(SOURCE, GROUP, capture.sg("join"))
    )

    # ... and the pin re-arms on the neighbour's return.
    capture = JPCapture("f10-up")
    set_r1_hellos(True)

    expect(lambda: check_neighbors(r2, ifname, [R1_LINK]), count=PROMPT)
    expect(lambda: check_pinned(r2, ifname, R1_LINK), count=PROMPT)
    expect(lambda: check_r1_joined(True), count=PROMPT)
    capture.stop()

    rows = capture.sg("join")
    assert rows, (
        "no triggered Join({},{}) after hellos resumed; a pin that only "
        "recovers on the 60 s periodic timer is a blackhole, not a "
        "recovery. Dissection:\n{}".format(SOURCE, GROUP, capture.pim_text())
    )
    assert sorted({row[0] for row in rows}) == [R1_LINK], (
        "the re-armed Join named {}, expected {}".format(
            sorted({row[0] for row in rows}), R1_LINK
        )
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
