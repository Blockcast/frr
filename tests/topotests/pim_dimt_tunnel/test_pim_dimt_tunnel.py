#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim_dimt_tunnel.py: DIMT PR 3 -- the pimd-side tunnel request/ack state
machine and readiness aggregation (contract D3/D4, boundaries from D6).

PR 2 already proved the *zebra* half of this in `zebra_dimt_tunnel/`: that
suite drives ZAPI directly with a synthetic client and asserts zebra creates,
addresses, refuses and deletes the netdev.  This suite is the complement --
it drives the path from the top, through a real receiver join, and asserts
that *pimd* requests the tunnel, correlates the acknowledgement, and only
declares forwarding ready once the kernel says so.

Topology:

    h1 ---- s2 ---- r1 ---- s1 ---- r2 ---- s3 (receiver stub)
  (sender)      upstream PE      receiver PoP

r1 advertises 10.10.10.0/24 with `set extcommunity umh 10.99.0.1 pim`, where
10.99.0.1 is r1's *loopback*.  r2 then requests a GRE tunnel to reach it,
using s1 (10.0.0.0/24) as the outer underlay.

WHY THE UMH IS A LOOPBACK, AND WHY r2-eth0 IS NOT `ip pim light`
----------------------------------------------------------------
`pim_dimt_light_iface()` walks FOR_ALL_INTERFACES and returns the FIRST
pim-light interface with a connected address, or point-to-point destination,
that prefix-matches the UMH.  Readiness conjunct (2) then demands that the
pinned RPF interface be the tunnel itself.

zebra addresses the DIMT netdev point-to-point -- `IFA_LOCAL` = inner-local,
`IFA_ADDRESS` = the inner peer = the UMH, /32 (`zebra/if_netlink.c`, the
ZEBRA_DIMT_TUNNEL_ADDRESS phase) -- so the tunnel's `destination` is exactly
the UMH and it matches.  But so would any *other* pim-light interface whose
subnet happens to cover the UMH, and whichever one iteration reaches first
wins.  Had the UMH been r1's s1 address (10.0.0.1) with r2-eth0 pim-light,
r2-eth0's 10.0.0.2/24 would cover it and could shadow the tunnel: the pin
lands on the wrong interface, conjunct (2) never holds, and readiness sits
at `pending` forever with no error anywhere.

Putting the UMH on a loopback r2 has no route to, and leaving the underlay
out of pim-light, makes the tunnel the only candidate -- so this suite tests
the state machine rather than an interface-ordering coin flip.  The
shadowing hazard itself is real but out of scope here; it is filed
separately rather than papered over with a topology that hides it.

WHAT IS EVIDENCE HERE
---------------------
Kernel state is the evidence: `ip -d link show` for the netdev and
/proc/net/ip_mr_cache for the admitted incoming vif.  `show ip pim dimt
forwarding json` is read only to assert that pimd's *aggregation* agrees
with the kernel -- a disagreement between the two is precisely the bug class
this contract exists to catch (G10), and it is undetectable if only one side
is ever inspected.  No assertion in this file rests on pimd's word alone.

D6 BOUNDARY COVERAGE
--------------------
  1 join -> create ............... test_join_requests_tunnel_and_zebra_creates_it
                                   (re-entry: test_rejoin_rebuilds_the_tunnel_idempotently)
  2 injected FAIL_INSTALL ........ test_create_failure_lands_in_failed_without_kernel_state
  3 kernel OIL/iif admission ..... test_readiness_requires_kernel_admission
  4 leave ........................ test_leave_removes_mfc_and_tunnel
  5 restart re-derivation ........ test_pimd_restart_rederives_readiness_from_kernel_state
  6 anti-recursion ............... NOT covered end-to-end here.

Boundary 6 is deliberately left to `zebra_dimt_tunnel/
test_outer_remote_via_dimt_is_rejected`, which proves the refusal where it
is actually implemented.  Zebra reports that refusal *as* FAIL_INSTALL, so
the pimd-side half of boundary 6 -- correlating the refusal on the tunnel_id
cookie and landing in `failed` rather than hanging in `requested` -- is the
same code path boundary 2 exercises.  Driving a recursive outer from this
topology would need a second DIMT netdev to route the outer through and
would re-prove zebra's logic, not pimd's.  Stated rather than quietly
counted as 6/6.

The tests are ORDER-DEPENDENT: each stage builds on the state the previous
one left.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.kernel_state import (
    check_gre_link,
    check_ip_mr_cache_iif,
    check_link_absent,
    check_no_ip_mr_cache,
    resolve_mr_vif,
)
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"
SG = "(10.10.10.10,232.1.1.10)"
SRC_PREFIX = "10.10.10.0/24"
UMH = "10.99.0.1"
INNER_LOCAL = "10.99.0.2"
OUTER_LOCAL = "10.0.0.2"
OUTER_REMOTE = "10.0.0.1"
# Second outer for the endpoint re-point stage.  On the same underlay subnet as
# OUTER_REMOTE, so the only thing that changes is the value in the request.
NEW_OUTER_REMOTE = "10.0.0.9"


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


# --- observation helpers -------------------------------------------------
#
# Each returns None on match and a descriptive string on mismatch, the
# router_json_cmp convention the PR-2 helpers already follow, so they compose
# directly with topotest.run_and_expect().


def tunnel_entry(router):
    """The DIMT tunnel row for UMH, or None if pimd has not created one."""
    output = json.loads(router.vtysh_cmd("show ip pim dimt tunnel json"))
    return output.get(UMH)


def umh_entry(router):
    """The UMH mapping row for the advertised source prefix, or None.

    NOTE the keying difference from tunnel_entry(): `show ip pim dimt umh json`
    is keyed by the *source prefix* the mapping covers -- pim_dimt_show_umh()
    keys on `%pFX` of `umh->prefix` -- whereas `dimt tunnel json` is keyed by
    the UMH address.  The UMH is a field *inside* the umh row, so looking the
    UMH up as a key there silently never matches.
    """
    output = json.loads(router.vtysh_cmd("show ip pim dimt umh json"))
    return output.get(SRC_PREFIX)


def check_tunnel_state(router, state):
    entry = tunnel_entry(router)
    if entry is None:
        return "pimd holds no DIMT tunnel for UMH {}".format(UMH)
    if entry.get("state") != state:
        return "DIMT tunnel state is {}, expected {}: {}".format(
            entry.get("state"), state, entry
        )
    return None


def check_no_tunnel(router):
    entry = tunnel_entry(router)
    if entry is not None:
        return "pimd still holds a DIMT tunnel for {}: {}".format(UMH, entry)
    return None


def check_forwarding(router, expected):
    """pimd's readiness verdict for the (S,G)."""
    output = json.loads(router.vtysh_cmd("show ip pim dimt forwarding json"))
    entry = output.get(SG)
    if entry is None:
        return "pimd reports no DIMT-steered upstream for {}: {}".format(SG, output)
    if entry.get("forwarding") != expected:
        return "forwarding is {}, expected {}: {}".format(
            entry.get("forwarding"), expected, entry
        )
    return None


def tunnel_ifname(router):
    """The netdev name pimd asked zebra to build.

    Derived by zebra as dimt-%08x of the pimd-allocated tunnel_id, which is a
    jhash of the UMH -- deterministic but not worth reproducing in the test.
    Reading the name is not an assertion; every assertion that uses it is
    made against the kernel.
    """
    entry = tunnel_entry(router)
    assert entry is not None, "pimd created no DIMT tunnel for {}".format(UMH)
    name = entry.get("interface")
    assert name, "DIMT tunnel row carries no interface name: {}".format(entry)
    return name


def expect(func, count=30, wait=1.0):
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, result


# --- D6 boundary 1: join -> create ---------------------------------------


def test_join_requests_tunnel_and_zebra_creates_it():
    """A receiver-driven join makes pimd request a tunnel; zebra builds it.

    The static IGMP group on r2-eth1 creates the (S,G) upstream, the BGP UMH
    mapping makes it DIMT-steered, and the explicit D2 endpoint row supplies
    the outer -- so demand appears without any data-plane traffic.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    # The mapping has to arrive before anything else can be true.
    expect(lambda: None if umh_entry(r2) else "pimd has no UMH mapping yet")

    expect(lambda: check_tunnel_state(r2, "installed"))

    # The acknowledgement is only meaningful if the kernel agrees.
    ifname = tunnel_ifname(r2)
    expect(
        lambda: check_gre_link(
            r2, ifname, local=OUTER_LOCAL, remote=OUTER_REMOTE
        )
    )

    # zebra addresses the netdev point-to-point with the UMH as peer; that
    # is what lets pim_dimt_light_iface() resolve the pin onto the tunnel.
    address = r2.run("ip -o address show dev {}".format(ifname))
    assert "{} peer {}/32".format(INNER_LOCAL, UMH) in address, address


# --- D6 boundary 3: kernel OIL admission, and readiness on top of it ------


def test_readiness_requires_kernel_admission():
    """FWD_READY only once the kernel admits the (S,G) on the DIMT vif.

    Asserts the three D3 conjuncts separately: zebra's ack (tunnel state
    installed), pimd's RPF belief (the pinned interface), and the kernel's
    own admission (the incoming vif in /proc/net/ip_mr_cache).  The last is
    read from procfs rather than from `show ip mroute`, so it cannot be
    satisfied by pimd merely believing it programmed the route.
    """
    r2 = get_topogen().gears["r2"]
    ifname = tunnel_ifname(r2)

    # (3) the kernel's admitted INCOMING vif -- this router receives over
    # the tunnel, so the DIMT vif is the iif, never an oif.
    def kernel_admitted():
        vif, error = resolve_mr_vif(r2, ifname)
        if error:
            return error
        return check_ip_mr_cache_iif(r2, SOURCE, GROUP, vif)

    expect(kernel_admitted)

    # (2) pimd pinned RPF onto that same netdev, not onto the underlay.
    forwarding = json.loads(r2.vtysh_cmd("show ip pim dimt forwarding json"))
    assert forwarding[SG]["interface"] == ifname, forwarding

    # ...and only now does pimd aggregate to ready.
    expect(lambda: check_forwarding(r2, "ready"))


# --- D6 boundary 5: restart re-derives readiness from the kernel ---------


def test_pimd_restart_rederives_readiness_from_kernel_state():
    """A restarted pimd must not assume readiness from its own prior intent.

    The netdev deliberately survives -- zebra does not sweep DIMT links -- so
    a pimd that trusted pre-restart intent would come back declaring ready
    without ever having re-checked.  The tunnel_id is a hash of the UMH, so
    the re-derived request is byte-identical and zebra re-adopts the existing
    link rather than building a second one beside it.
    """
    tgen = get_topogen()
    r2 = tgen.gears["r2"]
    ifname_before = tunnel_ifname(r2)

    kill_router_daemons(tgen, "r2", ["pimd"])

    # The netdev survives the daemon that asked for it.
    assert check_link_absent(r2, ifname_before) is not None, (
        "DIMT netdev {} disappeared with pimd; it must survive".format(
            ifname_before
        )
    )

    start_router_daemons(tgen, "r2", ["pimd"])

    # Same UMH -> same tunnel_id -> same netdev name, re-adopted.
    expect(lambda: check_tunnel_state(r2, "installed"))
    assert tunnel_ifname(r2) == ifname_before, (
        "re-derived tunnel name changed: {} -> {}".format(
            ifname_before, tunnel_ifname(r2)
        )
    )

    # Readiness returns only after the kernel is re-observed.
    expect(lambda: check_forwarding(r2, "ready"))

    def kernel_still_admits():
        vif, error = resolve_mr_vif(r2, ifname_before)
        if error:
            return error
        return check_ip_mr_cache_iif(r2, SOURCE, GROUP, vif)

    expect(kernel_still_admits)

    # Exactly one DIMT netdev: a re-derived id that missed would have built
    # a parallel tunnel and stranded the original.
    links = r2.run("ip -o link show | grep -c 'dimt-' || true").strip()
    assert links == "1", "expected exactly one DIMT netdev, found {}".format(links)


# --- D6 boundary 4: leave tears down MFC and netdev ----------------------


def test_leave_removes_mfc_and_tunnel():
    """Dropping the last membership removes the OIL and the tunnel.

    Teardown is asserted with check_no_ip_mr_cache() rather than
    check_ip_mr_cache_iif(expected=False): the latter is vacuously true when
    the (S,G) is absent, so it cannot tell "torn down" from "never existed".
    """
    tgen = get_topogen()
    r2 = tgen.gears["r2"]
    ifname = tunnel_ifname(r2)

    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nno ip igmp static-group {} {}".format(
            GROUP, SOURCE
        )
    )

    # Demand is gone, so the kernel entry must go...
    expect(lambda: check_no_ip_mr_cache(r2, SOURCE, GROUP))
    # ...and the tunnel with it, through an acknowledged delete.
    expect(lambda: check_no_tunnel(r2))
    expect(lambda: check_link_absent(r2, ifname))


# --- D6 boundary 1 (re-entry): demand returning rebuilds the tunnel -------


def test_rejoin_rebuilds_the_tunnel_idempotently():
    """Re-adding the membership drives a fresh ADD and returns to ready.

    Guards the IDLE/REMOVING re-entry edges: the state machine must be
    re-drivable rather than one-shot, and it must get there on demand alone
    -- there is no timer or retry loop anywhere in it.
    """
    r2 = get_topogen().gears["r2"]

    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nip igmp static-group {} {}".format(
            GROUP, SOURCE
        )
    )

    expect(lambda: check_tunnel_state(r2, "installed"))
    expect(lambda: check_forwarding(r2, "ready"))

    ifname = tunnel_ifname(r2)

    def kernel_admitted():
        vif, error = resolve_mr_vif(r2, ifname)
        if error:
            return error
        return check_ip_mr_cache_iif(r2, SOURCE, GROUP, vif)

    expect(kernel_admitted)


# --- D6 boundary 2: injected create failure reports FAIL_INSTALL ----------


def test_create_failure_lands_in_failed_without_kernel_state():
    """When zebra cannot build the netdev, pimd must land in `failed`.

    The name is occupied by a dummy link before demand returns, so zebra's
    create fails and answers FAIL_INSTALL.  PR 2 proves zebra emits it; what
    is proved here is that pimd correlates it on the tunnel_id cookie and
    reports FWD_FAILED rather than sitting in `requested` forever.

    Readiness must NOT be `ready`, and the kernel must hold no MFC entry --
    a control-plane-only failure that still left forwarding state would be
    exactly the divergence the contract targets.
    """
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    ifname = tunnel_ifname(r2)

    # Drop demand so the tunnel is torn down, squat the name, then restore
    # demand so the next ADD collides.
    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nno ip igmp static-group {} {}".format(
            GROUP, SOURCE
        )
    )
    expect(lambda: check_no_tunnel(r2))
    expect(lambda: check_link_absent(r2, ifname))

    r2.run("ip link add {} type dummy".format(ifname))

    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nip igmp static-group {} {}".format(
            GROUP, SOURCE
        )
    )

    expect(lambda: check_tunnel_state(r2, "failed"))
    expect(lambda: check_forwarding(r2, "failed"))

    # The squatted link is still the dummy -- zebra built nothing over it.
    link = r2.run("ip -d link show {}".format(ifname))
    assert "dummy" in link and "gre remote" not in link, link

    expect(lambda: check_no_ip_mr_cache(r2, SOURCE, GROUP))

    r2.run("ip link del {}".format(ifname))


# --- Endpoint re-point: an edited row must reach the netdev ---------------


def set_endpoint(router, outer_remote):
    """Write the D2 endpoint row for UMH with the given outer remote.

    Entered at the top level, which is where the command is installed
    (CONFIG_NODE/VRF_NODE), matching r2/pimd.conf.
    """
    router.vtysh_cmd(
        "conf t\ndimt tunnel-endpoint {} inner-local {} outer-local {} "
        "outer {} encap gre".format(UMH, INNER_LOCAL, OUTER_LOCAL, outer_remote)
    )


def test_endpoint_change_repoints_the_live_tunnel():
    """Editing an endpoint row must re-point a tunnel already built from it.

    The regression this pins: pim_dimt_tunnel_build_req() is called only on the
    path that CREATES a tunnel, so for a UMH that already had one the edited row
    was accepted into the running config and never reached the netdev.  The
    kernel kept encapsulating to the OLD outer while `show running-config`
    displayed the new one -- and because none of the three readiness conjuncts
    inspects the outer address, readiness still reported `ready`.  A tunnel that
    reports healthy while pointing somewhere the operator has already moved away
    from is precisely the config-vs-kernel divergence D3 exists to prevent.

    zebra cannot absorb the change either: it memcmp()s the stored request and
    answers a differing re-ADD with FAIL_INSTALL rather than mutating the link,
    so the only correct path is DEL then ADD.

    The assertion is deliberately kernel-side (`ip -d link show` via
    check_gre_link) rather than `show ip pim dimt tunnel`: asking pimd whether
    pimd believes it re-pointed the tunnel is exactly the vacuous reading G10
    warns about -- and it is the reading under which the unfixed code passes,
    since pimd's endpoint list was updated correctly all along.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    # 1. Recover from the `failed` state the previous stage parked in, so the
    #    tunnel is genuinely INSTALLED with the original outer before the edit.
    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nno ip igmp static-group {} {}".format(
            GROUP, SOURCE
        )
    )
    expect(lambda: check_no_tunnel(r2))
    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nip igmp static-group {} {}".format(
            GROUP, SOURCE
        )
    )
    expect(lambda: check_tunnel_state(r2, "installed"))

    ifname = tunnel_ifname(r2)

    # 2. The kernel really does carry the ORIGINAL outer.  Without this the
    #    step-4 assertion could pass against a link that never had it.
    expect(
        lambda: check_gre_link(r2, ifname, OUTER_LOCAL, OUTER_REMOTE)
    )

    # 3. Re-point the row.  Same UMH, so the same tunnel_id and the same
    #    netdev name -- only the outer moves.  That is the case a re-ADD
    #    cannot express and the one the old code dropped on the floor.
    set_endpoint(r2, NEW_OUTER_REMOTE)

    # 4. The KERNEL must now carry the new outer.
    expect(lambda: check_gre_link(r2, ifname, OUTER_LOCAL, NEW_OUTER_REMOTE))

    # 5. And the tunnel must come back to a healthy, forwarding state rather
    #    than being left torn down by the rebuild.
    expect(lambda: check_tunnel_state(r2, "installed"))
    expect(lambda: check_forwarding(r2, "ready"))

    # 6. Restore the original row so later stages see the documented topology.
    set_endpoint(r2, OUTER_REMOTE)
    expect(lambda: check_gre_link(r2, ifname, OUTER_LOCAL, OUTER_REMOTE))
    expect(lambda: check_forwarding(r2, "ready"))


def test_endpoint_row_round_trips_through_running_config():
    """The written D2 row must parse back at the node it is installed at.

    `dimt tunnel-endpoint` is installed at CONFIG_NODE.  It was previously
    *written* indented, inside the `router pim` frame opened by
    pim_router_config_write() -- so the emitted config could not be read back
    at the node that produced it.

    That was not cosmetic.  On reload the line fails to match at PIM_NODE and
    command_config_read_one_line() retries at successive parents; reaching
    CONFIG_NODE pops the vty out of `router pim` as a side effect, so every
    following line in that block parses at the wrong node.  And because the
    handler's PIM_DECLVAR_CONTEXT_VRF resolves CONFIG_NODE to VRF_DEFAULT, a
    row written under `router pim vrf red` came back applied to the DEFAULT
    vrf -- silently, with the config file still displaying the operator's
    intent.

    The row is pure configuration; nothing can regenerate it (pim_vty.c says
    exactly that).  So "it round-trips" is the whole requirement.

    Asserted at column 0 rather than merely "present": an indented row still
    parses when fed to `conf t` on its own, so a presence-only check passes
    against the unfixed code.  The indentation IS the defect.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    running = r2.vtysh_cmd("show running-config")
    rows = [ln for ln in running.splitlines() if "dimt tunnel-endpoint" in ln]
    assert rows, "running-config carries no dimt tunnel-endpoint row:\n{}".format(
        running
    )

    for row in rows:
        assert not row.startswith(" "), (
            "dimt tunnel-endpoint is written indented (inside `router pim`), "
            "but the command is installed at CONFIG_NODE: {!r}".format(row)
        )

    # Corroborate by actually replaying the emitted config: feeding it back
    # must not produce a parse error for any line.
    r2.run("vtysh -c 'show running-config' > /tmp/dimt-rc.conf")
    out = r2.run("vtysh -f /tmp/dimt-rc.conf 2>&1")
    for bad in ("Unknown command", "% Unknown", "Invalid input"):
        assert bad not in out, "replaying running-config failed: {}".format(out)

    # And the row survived the replay with its values intact.
    running2 = r2.vtysh_cmd("show running-config")
    rows2 = [ln.strip() for ln in running2.splitlines()
             if "dimt tunnel-endpoint" in ln]
    assert sorted(rows2) == sorted(r.strip() for r in rows), (
        "endpoint rows changed across a running-config replay:\n"
        "before: {}\nafter:  {}".format(rows, rows2)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
