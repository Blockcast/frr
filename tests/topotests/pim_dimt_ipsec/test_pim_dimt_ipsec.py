#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_pim_dimt_ipsec.py: `dimt tunnel-endpoint ... protect ipsec`.

A DIMT tunnel is GRE between two public outer addresses.  Anyone who can
send a packet with the far end's outer address as its source can put GRE
into the `dimt-` netdev, and from there into PIM and the RPF-checked data
path.  `protect ipsec` makes pimd keep the tunnel down until the kernel's
XFRM policy database requires ESP on the tunnel's outer flow, in both
directions.  The inbound policy is what stops a forged packet: the kernel
checks it before gre_rcv() runs, and with a template at `level required` a
cleartext packet fails the check.

Topology (the pim_dimt_tunnel one):

    h1 ---- s2 ---- r1 ---- s1 ---- r2 ---- s3 (receiver stub)

r1 also plays the off-path sender: it owns the outer address r2's tunnel
names as its far end, so a plain GRE link on r1 sends exactly the packets a
spoofer would.

No SAs are installed anywhere.  The stages assert the hold and the kernel's
drop, not encrypted forwarding: a tunnel whose policy is in place but whose
IKE has not come up yet is, correctly, protected and silent.

The stages are ORDER-DEPENDENT: each builds on the state the previous one
left.
"""

import json
import os
import re
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.kernel_state import (
    check_gre_link,
    check_link_absent,
    link_names,
    resolve_mr_vif,
)
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

SRC_PREFIX = "10.10.10.0/24"
UMH = "10.99.0.1"
OUTER_LOCAL = "10.0.0.2"
OUTER_REMOTE = "10.0.0.1"
ROW = (
    "dimt tunnel-endpoint 10.99.0.1 inner-local 10.99.0.2 "
    "outer-local 10.0.0.2 outer 10.0.0.1 encap gre"
)

# r2's policy pair for the tunnel's outer flow.
SEL_IN = "src {}/32 dst {}/32 proto gre dir in".format(OUTER_REMOTE, OUTER_LOCAL)
SEL_OUT = "src {}/32 dst {}/32 proto gre dir out".format(OUTER_LOCAL, OUTER_REMOTE)
TMPL_IN = "tmpl src {} dst {} proto esp mode transport".format(
    OUTER_REMOTE, OUTER_LOCAL
)
TMPL_OUT = "tmpl src {} dst {} proto esp mode transport".format(
    OUTER_LOCAL, OUTER_REMOTE
)

# The spoofer's GRE link on r1, and the inner subnet it sends into.
SPOOF_IF = "gspoof"
SPOOF_INNER = "10.98.0.1/30"
SPOOF_DEST = "10.98.0.2"
PROBES = 5


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    tgen.add_host("h1", "10.10.10.10/24", "via 10.10.10.1")
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # The policy database is reached through xfrm_user; a kernel without it
    # cannot run this suite at all.
    probe = tgen.gears["r2"].run("ip xfrm policy list >/dev/null 2>&1 && echo ok")
    if probe.strip() != "ok":
        tgen.stop_topology()
        pytest.skip("kernel has no XFRM netlink (xfrm_user)")

    for rname, router in tgen.routers().items():
        for daemon, conf in (
            (TopoRouter.RD_ZEBRA, "zebra.conf"),
            (TopoRouter.RD_PIM, "pimd.conf"),
            (TopoRouter.RD_BGP, "bgpd.conf"),
        ):
            router.load_config(daemon, os.path.join(CWD, rname, conf))

    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


# --- helpers ---------------------------------------------------------------


def expect(func, count=30, wait=1.0):
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, result


def tunnel_entry(router):
    return json.loads(router.vtysh_cmd("show ip pim dimt tunnel json")).get(UMH)


def tunnel_ifname(router):
    entry = tunnel_entry(router)
    assert entry and entry.get("interface"), "no DIMT tunnel row: {}".format(entry)
    return entry["interface"]


def check_tunnel(router, state, held=None, inbound=None, outbound=None):
    """None when the tunnel row matches; the mismatch otherwise."""
    entry = tunnel_entry(router)
    if entry is None:
        return "pimd holds no DIMT tunnel for {}".format(UMH)
    want = {"state": state}
    if held is not None:
        want["ipsecHeld"] = held
    if inbound is not None:
        want["ipsecInbound"] = inbound
    if outbound is not None:
        want["ipsecOutbound"] = outbound
    for key, value in want.items():
        if entry.get(key) != value:
            return "{} is {}, expected {}: {}".format(
                key, entry.get(key), value, entry
            )
    return None


def check_pin_source(router, source):
    umh = json.loads(router.vtysh_cmd("show ip pim dimt umh json")).get(SRC_PREFIX)
    if umh is None:
        return "pimd holds no UMH mapping for {}".format(SRC_PREFIX)
    if umh.get("pinSource") != source:
        return "pinSource is {}, expected {}: {}".format(
            umh.get("pinSource"), source, umh
        )
    return None


def check_held(router, inbound, outbound):
    """Held: the row says so, no netdev exists, nothing pins to it."""
    error = check_tunnel(router, "idle", True, inbound, outbound)
    if error:
        return error
    error = check_link_absent(router, tunnel_ifname(router))
    if error:
        return error
    return check_pin_source(router, "tunnel-unprotected")


def check_released(router):
    """Released: installed, the netdev is built, and it carries the pin."""
    error = check_tunnel(router, "installed", False, "protected", "protected")
    if error:
        return error
    error = check_gre_link(
        router, tunnel_ifname(router), local=OUTER_LOCAL, remote=OUTER_REMOTE
    )
    if error:
        return error
    return check_pin_source(router, "tunnel")


def xfrm(router, args):
    router.cmd_raises("ip xfrm policy {}".format(args))


def set_protect(router, on):
    router.vtysh_cmd("conf t\n{}{}".format(ROW, " protect ipsec" if on else ""))


def rx_packets(router, ifname):
    return int(router.run("cat /sys/class/net/{}/statistics/rx_packets".format(ifname)))


def tmpl_mismatch(router):
    """XfrmInTmplMismatch: inbound packets a policy's template refused.
    None without CONFIG_XFRM_STATISTICS."""
    match = re.search(
        r"^XfrmInTmplMismatch\s+(\d+)",
        router.run("cat /proc/net/xfrm_stat 2>/dev/null"),
        re.M,
    )
    return int(match.group(1)) if match else None


def spoof(r1):
    """Send PROBES cleartext GRE packets to r2's outer address."""
    r1.run(
        "ping -c {} -i 0.2 -W 1 -I {} {} >/dev/null 2>&1".format(
            PROBES, SPOOF_IF, SPOOF_DEST
        )
    )


# --- stages ------------------------------------------------------------------


def test_tunnel_up_without_protect():
    """Baseline: no knob, no policy, the tunnel builds as it always has."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    expect(lambda: check_tunnel(r2, "installed"), count=60)
    entry = tunnel_entry(r2)
    assert entry.get("protectIpsec") is False, entry
    assert "ipsecHeld" not in entry, entry
    expect(lambda: check_pin_source(r2, "tunnel"))


def test_cleartext_gre_reaches_an_unprotected_tunnel():
    """The attack: a cleartext GRE packet from the far end's outer address
    lands in the netdev.  This is the control for the next stage."""
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    ifname = tunnel_ifname(r2)

    r1.cmd_raises(
        "ip link add {} type gre local {} remote {} ttl 64".format(
            SPOOF_IF, OUTER_REMOTE, OUTER_LOCAL
        )
    )
    r1.cmd_raises("ip address add {} dev {}".format(SPOOF_INNER, SPOOF_IF))
    r1.cmd_raises("ip link set {} up".format(SPOOF_IF))

    before = rx_packets(r2, ifname)
    spoof(r1)
    after = rx_packets(r2, ifname)
    assert after - before >= PROBES, "netdev rx {} -> {}".format(before, after)


def test_required_policy_makes_the_kernel_drop_cleartext():
    """With an inbound policy at `level required`, the kernel refuses the
    same packets before they reach the netdev, and counts the refusal."""
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    ifname = tunnel_ifname(r2)

    xfrm(r2, "add {} priority 100 {} level required".format(SEL_IN, TMPL_IN))
    xfrm(r2, "add {} priority 100 {} level required".format(SEL_OUT, TMPL_OUT))

    rx_before, drop_before = rx_packets(r2, ifname), tmpl_mismatch(r2)
    spoof(r1)
    rx_after, drop_after = rx_packets(r2, ifname), tmpl_mismatch(r2)
    assert rx_after == rx_before, "netdev rx {} -> {}".format(rx_before, rx_after)
    if drop_before is not None:
        assert drop_after - drop_before >= PROBES, "XfrmInTmplMismatch {} -> {}".format(
            drop_before, drop_after
        )


def test_protect_keeps_a_protected_tunnel():
    """Turning the knob on over a correct policy pair changes nothing."""
    r2 = get_topogen().gears["r2"]
    ifindex_before = tunnel_entry(r2)["ifindex"]

    set_protect(r2, True)
    expect(lambda: check_released(r2))
    assert tunnel_entry(r2)["ifindex"] == ifindex_before, "netdev was rebuilt"
    assert "protect ipsec" in r2.vtysh_cmd("show running-config pimd")


def test_missing_inbound_policy_holds_the_tunnel():
    r2 = get_topogen().gears["r2"]

    xfrm(r2, "delete {}".format(SEL_IN))
    expect(lambda: check_held(r2, "no-policy", "protected"))


def test_level_use_does_not_release():
    """An optional template lets cleartext through, so it does not count."""
    r2 = get_topogen().gears["r2"]

    xfrm(r2, "add {} priority 100 {} level use".format(SEL_IN, TMPL_IN))
    # Long enough for several dumps; the hold must not move.
    time.sleep(2)
    expect(lambda: check_held(r2, "no-policy", "protected"), count=5)


def test_required_policy_releases_the_tunnel():
    r2 = get_topogen().gears["r2"]

    xfrm(r2, "update {} priority 100 {} level required".format(SEL_IN, TMPL_IN))
    expect(lambda: check_released(r2))


def test_higher_precedence_cleartext_policy_holds_the_tunnel():
    """A template-less policy that wins the kernel's lookup bypasses ESP.

    Priority is not part of a policy's identity, so the bypass needs its own
    selector: a /24 destination that still covers the tunnel's outer.
    """
    r2 = get_topogen().gears["r2"]
    bypass = "src {}/32 dst 10.0.0.0/24 proto gre dir in".format(OUTER_REMOTE)

    xfrm(r2, "add {} priority 50".format(bypass))
    expect(lambda: check_held(r2, "bypassed", "protected"))

    xfrm(r2, "delete {}".format(bypass))
    expect(lambda: check_released(r2))


def test_hard_expiry_holds_the_tunnel():
    """A hard policy expiry deletes the policy with no DELPOLICY event; only
    the expire group says it happened."""
    r2 = get_topogen().gears["r2"]

    xfrm(
        r2,
        "update {} priority 100 limit time-hard 3 {} level required".format(
            SEL_IN, TMPL_IN
        ),
    )
    expect(lambda: check_released(r2), count=2)
    expect(lambda: check_held(r2, "no-policy", "protected"), count=15)


def test_hold_strips_pim_when_zebra_cannot_delete():
    """With zebra gone the netdev cannot be deleted, so the hold must not
    depend on it: the netdev stays, but loses its vif and the pin at once."""
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    xfrm(r2, "add {} priority 100 {} level required".format(SEL_IN, TMPL_IN))
    expect(lambda: check_released(r2))
    ifname = tunnel_ifname(r2)

    kill_router_daemons(tgen, "r2", ["zebra"])
    xfrm(r2, "delete {}".format(SEL_IN))

    def stripped():
        error = check_tunnel(r2, "installed", True, "no-policy", "protected")
        if error:
            return error
        if ifname not in (link_names(r2) or ()):
            return "netdev {} is gone; this stage needs it kept".format(ifname)
        vif, _ = resolve_mr_vif(r2, ifname)
        if vif is not None:
            return "held netdev {} still has vif {}".format(ifname, vif)
        return check_pin_source(r2, "tunnel-unprotected")

    expect(stripped)

    # zebra back, policy back: the tunnel is released and adopted again.
    start_router_daemons(tgen, "r2", ["zebra"])
    xfrm(r2, "add {} priority 100 {} level required".format(SEL_IN, TMPL_IN))
    expect(lambda: check_released(r2), count=60)


def test_protect_off_releases_regardless_of_policy():
    r2 = get_topogen().gears["r2"]

    set_protect(r2, False)
    expect(lambda: check_tunnel(r2, "installed"))
    entry = tunnel_entry(r2)
    assert entry.get("protectIpsec") is False, entry
    expect(lambda: check_pin_source(r2, "tunnel"))
    assert "protect ipsec" not in r2.vtysh_cmd("show running-config pimd")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
