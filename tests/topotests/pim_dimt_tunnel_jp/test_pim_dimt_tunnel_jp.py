#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim_dimt_tunnel_jp.py: DIMT tunnel control plane across a MULTI-HOP
underlay -- outer TTL, triggered joins and prunes-before-teardown.

The interop lab (T4d-0/T4d-2/T4d-3) found three defects that every earlier
DIMT topotest was structurally unable to see, because in all of them the UMH
is one underlay hop away and nothing ever answers r2's joins:

  1. pimd-managed dimt-* netdevs were built with `ttl inherit`.  PIM and IGMP
     are link-local (inner TTL 1), so every control packet left with OUTER
     TTL 1 and died at the first transit router.  A one-hop lab hides it.
  2. A tunnel becoming forwarding-ready sent no triggered Join(S,G): the pin
     is made on the INSTALLED notify, before the netdev has its PIM socket,
     so the join was lost and the first one went out on the 60 s periodic
     timer -- a blackhole on every bring-up and every steer.
  3. Moving off a UMH (steer, endpoint removal) deleted the old tunnel
     without a Prune(S,G), so the old UMH kept forwarding into it for its
     full 210 s J/P holdtime.

Topology:

    h1 --s2-- r1 --s1-- r3 --s3-- r2 --s4 (receiver stub)
  (sender)   UMH     transit    receiver PoP

r1 is two underlay hops from r2.  It terminates each DIMT tunnel on a static
GRE netdev running `ip pim light` (gre-a for UMH 10.99.0.1, gre-b for UMH
10.99.0.5), so it holds (S,G) join state on that netdev exactly while r2's
joins arrive -- r1's join table is the far-end evidence that a J/P crossed
the transit hop, and when.

WHAT IS EVIDENCE HERE
---------------------
  - Outer TTL: `ip -d link show` of r2's netdev (kernel), AND the TTL of the
    encapsulated J/P as captured on r1's side of the transit hop -- 63 there
    means 64 left r2, and a packet that left with 1 never arrives at all.
  - Join promptness: r1's join state for the (S,G) appearing within PROMPT
    seconds, far inside the 60 s periodic interval.  Only a triggered join
    can do that.
  - Prune ordering: a GRE-encapsulated Prune(S,G) captured on r1-eth0 whose
    timestamp precedes the RTM_DELLINK of r2's netdev (`ip -ts monitor link`
    in r2's namespace), and r1's join state leaving within PROMPT rather
    than at holdtime expiry.  Both clocks are the one host clock.

The tests are ORDER-DEPENDENT: each stage starts from the state the previous
one left.
"""

import datetime
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
from lib.kernel_state import check_gre_link, check_link_absent
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"
SRC_PREFIX = "10.10.10.0/24"

# UMH -> (r1 terminating netdev, r1 outer address, r2 inner-local)
UMH_A = "10.99.0.1"
UMH_B = "10.99.0.5"
R1_TUNNEL = {UMH_A: "gre-a", UMH_B: "gre-b"}
R1_OUTER = {UMH_A: "10.255.0.1", UMH_B: "10.255.0.5"}
R2_INNER = {UMH_A: "10.99.0.2", UMH_B: "10.99.0.6"}
R2_OUTER = "10.0.2.2"

# The fixed outer TTL zebra builds DIMT netdevs with (ZEBRA_DIMT_TUNNEL_TTL),
# and what is left of it after r3 forwards the packet once.
OUTER_TTL = 64
OUTER_TTL_AT_R1 = OUTER_TTL - 1

# How long a triggered J/P may take to show up at r1.  Generous against a
# loaded CI host, and still a quarter of the 60 s periodic interval a lost
# join falls back to -- the two cannot be confused.
PROMPT = 15
PERIODIC = 60


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

    # r1's UMH-side tunnel ends: static, operator-managed GRE with a FIXED
    # ttl of their own (so the reverse direction is never the problem), the
    # UMH as local ptp address and r2's inner-local as peer.
    r1 = tgen.gears["r1"]
    for umh, ifname in R1_TUNNEL.items():
        r1.run(
            "ip link add {} type gre local {} remote {} ttl {}".format(
                ifname, R1_OUTER[umh], R2_OUTER, OUTER_TTL
            )
        )
        r1.run(
            "ip address add {} peer {}/32 dev {}".format(umh, R2_INNER[umh], ifname)
        )
        r1.run("ip link set {} up".format(ifname))

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


# --- observation helpers -------------------------------------------------


def expect(func, count=30, wait=1.0):
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, result


def umh_of_source(router):
    """The UMH r2's pimd currently maps the source prefix to, or None."""
    output = json.loads(router.vtysh_cmd("show ip pim dimt umh json"))
    entry = output.get(SRC_PREFIX)
    return entry.get("umh") if entry else None


def tunnel_entry(router, umh):
    output = json.loads(router.vtysh_cmd("show ip pim dimt tunnel json"))
    return output.get(umh)


def check_tunnel_installed(router, umh):
    entry = tunnel_entry(router, umh)
    if entry is None:
        return "pimd holds no DIMT tunnel for UMH {}".format(umh)
    if entry.get("state") != "installed" or not entry.get("interface"):
        return "DIMT tunnel for {} is not installed: {}".format(umh, entry)
    return None


def check_no_tunnel(router, umh):
    entry = tunnel_entry(router, umh)
    if entry is not None:
        return "pimd still holds a DIMT tunnel for {}: {}".format(umh, entry)
    return None


def tunnel_ifname(router, umh):
    entry = tunnel_entry(router, umh)
    assert entry and entry.get("interface"), "no DIMT tunnel row for {}: {}".format(
        umh, entry
    )
    return entry["interface"]


def r1_join_state(ifname):
    """r1's ifchannel state for the (S,G) on `ifname`, or None if absent."""
    r1 = get_topogen().gears["r1"]
    output = json.loads(r1.vtysh_cmd("show ip pim join json"))
    row = output.get(ifname, {}).get(GROUP, {}).get(SOURCE)
    return row.get("channelJoinName") if row else None


def check_r1_joined(ifname):
    state = r1_join_state(ifname)
    if state != "JOIN":
        return "r1 has no Join({},{}) on {} (state {})".format(
            SOURCE, GROUP, ifname, state
        )
    return None


def check_r1_not_joined(ifname):
    state = r1_join_state(ifname)
    if state == "JOIN":
        return "r1 still holds Join({},{}) on {}".format(SOURCE, GROUP, ifname)
    return None


def set_static_group(router, present):
    router.vtysh_cmd(
        "conf t\ninterface r2-eth1\n{}ip igmp static-group {} {}".format(
            "" if present else "no ", GROUP, SOURCE
        )
    )


def set_umh(umh):
    """Re-point r1's UMH extended community, then push it out right away.

    The soft-out skips the route-map delay timer so the stage times pimd,
    not bgpd's batching; the stage clock starts only when r2 has the new
    mapping anyway.
    """
    r1 = get_topogen().gears["r1"]
    r1.vtysh_cmd(
        "conf t\nroute-map UMH permit 10\nset extcommunity umh {} pim "
        "preference 5".format(umh)
    )
    r1.vtysh_cmd("clear bgp 10.0.2.2 soft out")


def set_endpoint(router, umh, present):
    router.vtysh_cmd(
        "conf t\n{}dimt tunnel-endpoint {} inner-local {} outer-local {} "
        "outer {} encap gre".format(
            "" if present else "no ", umh, R2_INNER[umh], R2_OUTER, R1_OUTER[umh]
        )
    )


class JPCapture:
    """Capture GRE on r1-eth0 (the UMH side of the transit hop) and decode
    the encapsulated PIM Join/Prunes."""

    FIELDS = (
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "ip.ttl",
        "pim.group",
        "pim.join_ip",
        "pim.prune_ip",
    )

    def __init__(self, name):
        self.router = get_topogen().gears["r1"]
        self.path = "/tmp/dimt-jp-{}.pcapng".format(name)
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
        self.packets = None

    def stop(self):
        # Let the last packet of the stage reach the file before stopping.
        time.sleep(1)
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        out = self.router.run(
            "tshark -r {} -Y 'pim.type == 3' -T fields -E separator='|' "
            "-E aggregator=, {} 2>/dev/null".format(
                self.path, " ".join("-e " + f for f in self.FIELDS)
            )
        )
        self.packets = []
        for line in out.splitlines():
            cols = line.split("|")
            if len(cols) != len(self.FIELDS):
                continue
            row = dict(zip(self.FIELDS, cols))
            self.packets.append(
                {
                    "time": float(row["frame.time_epoch"]),
                    "outer_dst": row["ip.dst"].split(",")[0],
                    "ttls": row["ip.ttl"].split(","),
                    "groups": row["pim.group"].split(","),
                    "joins": [a for a in row["pim.join_ip"].split(",") if a],
                    "prunes": [a for a in row["pim.prune_ip"].split(",") if a],
                }
            )
        self.router.run("rm -f {}".format(self.path))
        return self.packets

    def matching(self, kind, umh):
        """J/Ps carrying a join/prune for SOURCE toward UMH `umh`'s outer."""
        key = "joins" if kind == "join" else "prunes"
        return [
            p
            for p in self.packets
            if p["outer_dst"] == R1_OUTER[umh]
            and GROUP in p["groups"]
            and SOURCE in p[key]
        ]


class LinkMonitor:
    """`ip -ts monitor link` in r2's namespace: when did a netdev go away?"""

    STAMP = re.compile(r"^\[([0-9T:.\-]+)\]\s*Deleted\s+\d+:\s+([^:@\s]+)")

    def __init__(self):
        self.router = get_topogen().gears["r2"]
        self.proc = self.router.popen(
            ["ip", "-ts", "monitor", "link"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        # Give the monitor a moment to subscribe before the stage acts.
        time.sleep(0.5)
        self.output = ""

    def stop(self):
        self.proc.terminate()
        try:
            out, _ = self.proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, _ = self.proc.communicate()
        self.output = out.decode() if isinstance(out, bytes) else out

    def deleted_at(self, ifname):
        for line in self.output.splitlines():
            match = self.STAMP.match(line.strip())
            if match and match.group(2) == ifname:
                # `ip -ts` prints local time; this process shares the host's
                # clock and timezone, so the conversion round-trips.
                return datetime.datetime.fromisoformat(match.group(1)).timestamp()
        return None


def assert_prune_before_delete(capture, monitor, umh, ifname):
    prunes = capture.matching("prune", umh)
    assert prunes, (
        "no Prune({},{}) toward {} crossed the underlay before the tunnel was "
        "torn down; captured J/Ps: {}".format(SOURCE, GROUP, umh, capture.packets)
    )
    deleted = monitor.deleted_at(ifname)
    assert deleted is not None, "no RTM_DELLINK seen for {}: {}".format(
        ifname, monitor.output
    )
    assert prunes[0]["time"] <= deleted, (
        "the first prune toward {} ({:.6f}) arrived after {} was deleted "
        "({:.6f})".format(umh, prunes[0]["time"], ifname, deleted)
    )
    assert OUTER_TTL_AT_R1 == int(prunes[0]["ttls"][0]), prunes[0]


def assert_prompt_join(capture, umh, since):
    joins = [p for p in capture.matching("join", umh) if p["time"] >= since]
    assert joins, "no Join({},{}) toward {} captured: {}".format(
        SOURCE, GROUP, umh, capture.packets
    )
    delay = joins[0]["time"] - since
    assert delay < PROMPT, (
        "first Join toward {} took {:.1f}s -- that is the {}s periodic timer, "
        "not a triggered join".format(umh, delay, PERIODIC)
    )
    # 64 at r2, one transit hop: an inheriting tunnel would have sent 1 and
    # r3 would have dropped it, so this packet could not exist.
    assert int(joins[0]["ttls"][0]) == OUTER_TTL_AT_R1, joins[0]
    return delay


# --- stages --------------------------------------------------------------


def test_join_crosses_multihop_underlay_promptly():
    """Bugs 1 + 2: fixed outer TTL, and a triggered join on tunnel-up.

    Demand is created only once the UMH mapping is in place, so the tunnel
    is built on demand and the clock starts at a known instant.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    expect(lambda: None if umh_of_source(r2) == UMH_A else "no UMH mapping yet",
           count=60)

    capture = JPCapture("bringup")
    t0 = time.time()
    set_static_group(r2, True)

    expect(lambda: check_tunnel_installed(r2, UMH_A))
    ifname = tunnel_ifname(r2, UMH_A)

    # Bug 1, kernel side: the netdev pimd asked for carries a fixed TTL.
    expect(
        lambda: check_gre_link(
            r2, ifname, local=R2_OUTER, remote=R1_OUTER[UMH_A], ttl=OUTER_TTL
        )
    )

    # Bug 2, far end: r1 holds the join well inside the periodic interval.
    expect(lambda: check_r1_joined(R1_TUNNEL[UMH_A]), count=PROMPT, wait=1)
    capture.stop()
    delay = assert_prompt_join(capture, UMH_A, t0)
    topotest.logger.info("DIMT bring-up: first join at r1 %.2fs after demand", delay)


def steer(from_umh, to_umh):
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    expect(lambda: check_r1_joined(R1_TUNNEL[from_umh]))
    old_ifname = tunnel_ifname(r2, from_umh)

    capture = JPCapture("steer-{}".format(to_umh))
    monitor = LinkMonitor()
    # The stage clock starts BEFORE the re-point, so the measured delay also
    # carries bgpd's soft-out and the UMH relay: an upper bound on pimd's
    # share, which still has to come in far under the periodic interval.
    t_steer = time.time()
    set_umh(to_umh)

    expect(lambda: None if umh_of_source(r2) == to_umh else "mapping not moved",
           count=120, wait=0.25)

    expect(lambda: check_r1_joined(R1_TUNNEL[to_umh]), count=PROMPT, wait=1)
    # The old UMH must hear a prune, not wait out the 210 s holdtime.
    expect(lambda: check_r1_not_joined(R1_TUNNEL[from_umh]), count=PROMPT, wait=1)
    expect(lambda: check_no_tunnel(r2, from_umh))
    expect(lambda: check_link_absent(r2, old_ifname))

    monitor.stop()
    capture.stop()
    assert_prompt_join(capture, to_umh, t_steer)
    assert_prune_before_delete(capture, monitor, from_umh, old_ifname)
    expect(
        lambda: check_gre_link(
            r2,
            tunnel_ifname(r2, to_umh),
            local=R2_OUTER,
            remote=R1_OUTER[to_umh],
            ttl=OUTER_TTL,
        )
    )


def test_steer_prunes_old_umh_and_joins_new_promptly():
    """Bugs 2 + 3 in the lab's T4d-2/T4d-3 shape: re-point the UMH."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    steer(UMH_A, UMH_B)


def test_steer_back_prunes_and_joins_promptly():
    """The back-direction run the lab blackholed (T4d-3)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    steer(UMH_B, UMH_A)


def test_endpoint_removal_prunes_before_teardown():
    """Bug 3 with nowhere to move: the tunnel loses its endpoint row.

    Demand is counted per UMH *with a row*, so removing the row drops the
    refcount to 0 while the upstream is still pinned to the netdev -- no RPF
    move happens that could carry a prune.  The prune has to be sent from
    the teardown itself, before the DEL.  Restoring the row then rebuilds
    the tunnel, which must join promptly again.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    expect(lambda: check_r1_joined(R1_TUNNEL[UMH_A]))
    ifname = tunnel_ifname(r2, UMH_A)

    capture = JPCapture("endpoint-removal")
    monitor = LinkMonitor()
    set_endpoint(r2, UMH_A, False)

    expect(lambda: check_no_tunnel(r2, UMH_A))
    expect(lambda: check_link_absent(r2, ifname))
    expect(lambda: check_r1_not_joined(R1_TUNNEL[UMH_A]), count=PROMPT, wait=1)
    monitor.stop()

    t_restore = time.time()
    set_endpoint(r2, UMH_A, True)
    expect(lambda: check_tunnel_installed(r2, UMH_A))
    expect(lambda: check_r1_joined(R1_TUNNEL[UMH_A]), count=PROMPT, wait=1)
    capture.stop()

    assert_prune_before_delete(capture, monitor, UMH_A, ifname)
    assert_prompt_join(capture, UMH_A, t_restore)


def test_leave_prunes_before_teardown():
    """Bug 3, last-receiver leave: the prune precedes the netdev's deletion."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    expect(lambda: check_r1_joined(R1_TUNNEL[UMH_A]))
    ifname = tunnel_ifname(r2, UMH_A)

    capture = JPCapture("leave")
    monitor = LinkMonitor()
    set_static_group(r2, False)

    expect(lambda: check_no_tunnel(r2, UMH_A))
    expect(lambda: check_link_absent(r2, ifname))
    expect(lambda: check_r1_not_joined(R1_TUNNEL[UMH_A]), count=PROMPT, wait=1)
    monitor.stop()
    capture.stop()

    assert_prune_before_delete(capture, monitor, UMH_A, ifname)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
