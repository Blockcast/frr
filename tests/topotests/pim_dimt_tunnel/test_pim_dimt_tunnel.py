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
`pim_dimt_light_iface()` resolves the pin from the DIMT tunnel list when a
tunnel exists for the UMH, and only falls back to a covering-subnet search
over pim-light interfaces when one does not.  Readiness conjunct (2) then
demands that the pinned RPF interface be the tunnel itself.

zebra addresses the DIMT netdev point-to-point -- `IFA_LOCAL` = inner-local,
`IFA_ADDRESS` = the inner peer = the UMH, /32 (`zebra/if_netlink.c`, the
ZEBRA_DIMT_TUNNEL_ADDRESS phase) -- so the tunnel's `destination` is exactly
the UMH.

The stages below keep the UMH on a loopback r2 has no route to, and leave the
underlay out of pim-light, so that the tunnel is the *only* candidate and each
stage tests the state machine rather than pin resolution.  The shadowing case
-- where a second, covering pim-light interface competes with the tunnel -- is
covered deliberately and last, by
test_covering_light_interface_does_not_shadow_the_tunnel, which constructs the
ambiguity on purpose.

Historically that resolver returned the FIRST pim-light interface whose
connected address or point-to-point destination prefix-matched the UMH, with no
preference for the tunnel, so a `/24` covering the UMH was exactly as good a
match as the tunnel's own `/32` peer and FOR_ALL_INTERFACES order decided which
won.  That order is by interface NAME -- `RB_FOREACH (ifp, if_name_head,
&vrf->ifaces_by_name)` in `lib/if.h` -- not by ifindex and not by the order
things were configured.  When a covering interface sorted before `dimt-%08x`
and won, the tunnel installed clean and never forwarded, silently (BLO-27869).

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

Pin determinism against a competing covering interface is not a D6 boundary; it
is the BLO-27869 regression guard, covered by the final stage.

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
    link_ifindex,
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
# A second (S,G) inside the same advertised source prefix, so it resolves to
# the same UMH and therefore rides the tunnel that already exists.
SECOND_SOURCE = "10.10.10.11"
SECOND_GROUP = "232.1.1.11"
SECOND_SG = "(10.10.10.11,232.1.1.11)"

# BLO-27869: a covering interface used to build the shadowing case on purpose.
# 10.99.0.3/24 covers the UMH 10.99.0.1 exactly the way a directly-connected UMH
# segment would.
#
# The NAME matters and is the whole point.  FOR_ALL_INTERFACES walks
# vrf->ifaces_by_name (lib/if.h), so the pre-fix resolver picked the
# alphabetically first covering interface.  `aaa0` sorts before `dimt-%08x`;
# `r2-eth0` does not, so using an existing interface here would let the tunnel
# win by luck and the stage would prove nothing.  Created as a dummy by the
# stage itself.
COVERING_ADDR = "10.99.0.3/24"
COVERING_IFACE = "aaa0"


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


def check_pin(router, interface, source, shadowed=None):
    """The resolved RPF pin for the UMH: target, which resolver won, who lost.

    `shadowed` is compared against `.get()`, so the default None asserts the
    key is ABSENT -- pim_dimt_show_umh() emits shadowedInterface only when a
    covering interface actually lost the pin, so its presence is itself the
    ambiguity signal.
    """
    entry = umh_entry(router)
    if entry is None:
        return "pimd holds no UMH mapping for {}".format(SRC_PREFIX)
    if entry.get("interface") != interface:
        return "pin interface is {}, expected {}: {}".format(
            entry.get("interface"), interface, entry
        )
    if entry.get("pinSource") != source:
        return "pinSource is {}, expected {}: {}".format(
            entry.get("pinSource"), source, entry
        )
    if entry.get("shadowedInterface") != shadowed:
        return "shadowedInterface is {}, expected {}: {}".format(
            entry.get("shadowedInterface"), shadowed, entry
        )
    return None


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

    # Walk the emitted config tracking the `router pim` frame, because "is the
    # row inside that frame" IS the invariant -- not merely "is the row
    # present".  An indented row still parses when fed to `conf t` on its own,
    # so a presence-only check passes against the unfixed code.
    rows = []
    offenders = []
    in_router_pim = False
    for line in running.splitlines():
        stripped = line.strip()
        if stripped.startswith("router pim"):
            in_router_pim = True
            continue
        if in_router_pim and stripped in ("exit", "end"):
            in_router_pim = False
            continue
        if "dimt tunnel-endpoint" not in line:
            continue
        rows.append(stripped)
        if in_router_pim or line.startswith((" ", "\t")):
            offenders.append((line, in_router_pim))

    assert rows, "running-config carries no dimt tunnel-endpoint row:\n{}".format(
        running
    )
    assert not offenders, (
        "dimt tunnel-endpoint is written inside the `router pim` frame or "
        "indented, but the command is installed at CONFIG_NODE -- on reload it "
        "matches only after the parent-node retry pops the vty out of `router "
        "pim`, and PIM_DECLVAR_CONTEXT_VRF then resolves it to VRF_DEFAULT: "
        "{}".format(offenders)
    )

    # Corroborate that the emitted text is actually a valid command (catches a
    # write that is correctly placed but malformed): drop the row and re-apply
    # the config exactly as written.
    row = rows[0]
    r2.vtysh_cmd("conf t\nno {}".format(row))
    expect(lambda: None if not umh_pin_row_present(r2) else "endpoint still set")

    r2.vtysh_cmd("conf t\n{}".format(row))
    running2 = r2.vtysh_cmd("show running-config")
    rows2 = [ln.strip() for ln in running2.splitlines()
             if "dimt tunnel-endpoint" in ln]
    assert sorted(rows2) == sorted(rows), (
        "the emitted row did not re-apply verbatim:\n"
        "before: {}\nafter:  {}".format(rows, rows2)
    )

    # And the tunnel is back, so the round-trip restored working state rather
    # than just matching text.
    expect(lambda: check_forwarding(r2, "ready"))


def umh_pin_row_present(router):
    """True while any dimt tunnel-endpoint row is in the running config."""
    return any(
        "dimt tunnel-endpoint" in ln
        for ln in router.vtysh_cmd("show running-config").splitlines()
    )


# --- D8.3: the verdict bgpd was given, not the one recomputed on read -----


def forwarding_entry(router, sg):
    output = json.loads(router.vtysh_cmd("show ip pim dimt forwarding json"))
    return output.get(sg)


def check_announced(router, sg, expected):
    """What pimd last SENT for this (S,G), not what it would compute now.

    `forwarding` is recalculated on every read of the show command, so it is
    right whenever anyone looks and says nothing about whether the edge was
    ever relayed.  `announcedForwarding` is the byte that actually left on
    the wire, which is the only thing bgpd can act on.
    """
    entry = forwarding_entry(router, sg)
    if entry is None:
        return "pimd reports no DIMT-steered upstream for {}".format(sg)
    if not entry.get("announced"):
        return "{} is not announced to bgpd yet: {}".format(sg, entry)
    if entry.get("announcedForwarding") != expected:
        return "{} was announced as {}, expected {}: {}".format(
            sg, entry.get("announcedForwarding"), expected, entry
        )
    return None


def test_second_sg_on_a_live_tunnel_is_announced_ready():
    """A later (S,G) shares the existing tunnel and is announced ready.

    Every earlier stage drives a single (S,G), so nothing pinned what happens
    when demand for a UMH arrives more than once: that the second join rides
    the tunnel already built (refcount, not a second netdev), that the kernel
    admits it on the same vif, and that bgpd is told it forwards.

    This is a regression guard, not the proof of a fix.  It was written to
    catch a suspected gap -- a second (S,G) getting neither a notify nor an
    interface event, and so never having its verdict relayed -- and it does
    not: removing the announce hooks that gap would need leaves this green,
    because the (S,G) does not reach JOINED (and so is not announced at all)
    until after its MFC is installed, and the announcing ADD therefore
    already carries the right byte.  The check is on `announcedForwarding`
    rather than `forwarding` regardless, since the latter is recomputed on
    every read and could not distinguish the two cases.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    # Precondition: the tunnel is up and serving the original (S,G).
    expect(lambda: check_tunnel_state(r2, "installed"))
    ifname = tunnel_ifname(r2)
    before = tunnel_entry(r2)

    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nip igmp static-group {} {}".format(
            SECOND_GROUP, SECOND_SOURCE
        )
    )

    # The kernel admits it on the same DIMT vif...
    vif, error = resolve_mr_vif(r2, ifname)
    assert error is None, error
    expect(
        lambda: check_ip_mr_cache_iif(r2, SECOND_SOURCE, SECOND_GROUP, vif)
    )

    # ...and bgpd is told so.
    expect(lambda: check_announced(r2, SECOND_SG, "ready"))

    # Riding the existing tunnel, not building a second one: same tunnel id,
    # so the refcount -- not a new netdev -- is what carried the new demand.
    after = tunnel_entry(r2)
    assert after["tunnelId"] == before["tunnelId"], (
        "the second (S,G) minted a new tunnel instead of sharing: "
        "{} -> {}".format(before, after)
    )

    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nno ip igmp static-group {} {}".format(
            SECOND_GROUP, SECOND_SOURCE
        )
    )
    expect(lambda: check_no_ip_mr_cache(r2, SECOND_SOURCE, SECOND_GROUP))


# --- D4: a zebra reconnect must not disturb a tunnel nobody stopped wanting


def test_zebra_reconnect_holds_demand_while_bgpd_is_away():
    """A zebra reconnect must not tear down a tunnel nobody stopped wanting.

    Re-subscribing to the UMH relay used to empty the mapping table first and
    recount demand from it.  An emptied table reads as zero demand, so the
    reconnect itself tore the tunnel down -- a control-plane event destroying
    a data plane that was never in question.

    bgpd is stopped first, which is what makes the difference observable.
    With bgpd running the replay lands within milliseconds and rebuilds
    everything, so both behaviours look alike from outside; with bgpd away
    nothing can rebuild, and only held demand keeps the tunnel up.  It also
    exercises the case the hold exists for: the mappings are still true, it
    is the daemon that can restate them that is missing.

    Then the other half, which is why holding is bounded: once the grace
    expires with no replay, the mappings really are gone and the tunnel is
    taken down rather than held forever.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    expect(lambda: check_tunnel_state(r2, "installed"))
    ifname = tunnel_ifname(r2)
    before = link_ifindex(r2, ifname)
    assert before is not None, "no kernel link {} before the restart".format(ifname)

    kill_router_daemons(tgen, "r2", ["bgpd"])

    kill_router_daemons(tgen, "r2", ["zebra"])
    start_router_daemons(tgen, "r2", ["zebra"])

    # Settle before asserting.  Polling immediately would read the state from
    # before the restart and pass without pimd having processed the reconnect
    # at all -- the tunnel row does not change until then, so an early match
    # proves nothing.  Well inside the grace period either way.
    topotest.sleep(8, "waiting for pimd to process the zebra reconnect")

    # Demand survived the reconnect, so the tunnel is re-requested from the
    # identity that was kept, and acked against the netdev already there.
    expect(lambda: check_tunnel_state(r2, "installed"), count=10)
    after = link_ifindex(r2, ifname)
    assert after == before, (
        "the DIMT netdev was replaced across the zebra restart "
        "(ifindex {} -> {})".format(before, after)
    )

    # ...and the hold is bounded: with no replay to reassert them, the
    # mappings expire and the tunnel goes away rather than lingering.
    expect(lambda: None if not umh_entry(r2) else "UMH mapping still held",
           count=60)
    expect(lambda: check_no_tunnel(r2), count=30)
    expect(lambda: check_link_absent(r2, ifname), count=30)

    # bgpd back: the mapping returns and so does the tunnel, so the sweep
    # cleared state rather than wedging it.
    start_router_daemons(tgen, "r2", ["bgpd"])
    expect(lambda: None if umh_entry(r2) else "UMH mapping did not return",
           count=60)
    expect(lambda: check_tunnel_state(r2, "installed"), count=60)
    expect(lambda: check_forwarding(r2, "ready"), count=60)


# --- BLO-27869: a covering pim-light interface must not shadow the tunnel ---


def test_covering_light_interface_does_not_shadow_the_tunnel():
    """A pim-light interface whose subnet covers the UMH must lose to the tunnel.

    This is the case the rest of the suite deliberately avoids by putting the
    UMH on a loopback (see the module docstring).  Here it is constructed on
    purpose: a dummy netdev gets 10.99.0.3/24 -- which covers the UMH 10.99.0.1
    -- plus `ip pim light`, so BOTH the DIMT netdev's /32 point-to-point peer
    and the dummy's /24 connected subnet prefix-match the UMH.

    ORDERING IS THE POINT, AND THE ORDER IS BY NAME.  `FOR_ALL_INTERFACES` is
    `RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name)` (`lib/if.h`), so the
    old resolver -- which had no preference for the tunnel and returned the
    FIRST covering match it reached -- was decided by interface *name*, not by
    ifindex and not by configuration order.

    Hence the dummy is named `aaa0`: it sorts before `dimt-%08x`, so the old
    resolver reaches it first and pins there.  Readiness conjunct (2) (rpf
    interface == tunnel ifindex) can then never hold, and forwarding sits at
    `pending` forever with no error and no log.  A covering interface named
    `r2-eth0` would NOT reproduce this -- `dimt-` sorts before `r2-`, so the
    tunnel would win by luck and the stage would pass against the unfixed
    resolver for the wrong reason.

    Step 2 asserts the covering interface genuinely resolves while no tunnel
    exists.  That keeps the test honest twice over: it proves the shadow
    candidate is real (so step 5 is not vacuous), and it proves the no-tunnel
    fallback still behaves as it did in Phase B.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    # 1. Drop demand so the tunnel row is released entirely, whatever state the
    #    preceding stage left it in (it is `installed` after the endpoint
    #    re-point stage, and was `failed` before that stage existed -- releasing
    #    demand reaches a known-empty state from either).
    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nno ip igmp static-group {} {}".format(
            GROUP, SOURCE
        )
    )
    expect(lambda: check_no_tunnel(r2))

    # 2. Build the ambiguity while no tunnel exists, and prove the covering
    #    interface really does resolve the pin on its own.  A dummy rather than
    #    an existing interface, because the name is what decides the old
    #    resolver and no interface in this topology sorts before `dimt-`.
    r2.run("ip link add {} type dummy".format(COVERING_IFACE))
    r2.run("ip link set {} up".format(COVERING_IFACE))
    r2.vtysh_cmd(
        "conf t\ninterface {}\nip address {}\nip pim\nip pim light".format(
            COVERING_IFACE, COVERING_ADDR
        )
    )
    expect(lambda: check_pin(r2, COVERING_IFACE, "light"))

    # 3. Now bring the tunnel back.  Its netdev is created *after* the covering
    #    interface is already a candidate, and sorts after it by name.
    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nip igmp static-group {} {}".format(
            GROUP, SOURCE
        )
    )
    expect(lambda: check_tunnel_state(r2, "installed"))
    ifname = tunnel_ifname(r2)

    # 4. The netdev still carries the UMH as its ptp peer, so the tunnel and
    #    the covering interface are both genuine prefix matches -- the
    #    ambiguity is real.
    address = r2.run("ip -o address show dev {}".format(ifname))
    assert "{} peer {}/32".format(INNER_LOCAL, UMH) in address, address

    # 5. The pin lands on the tunnel, and the covering interface is reported as
    #    the one that lost it -- the ambiguity is observable, not silent.
    expect(lambda: check_pin(r2, ifname, "tunnel", shadowed=COVERING_IFACE))

    # 6. Readiness follows, corroborated kernel-side: the admitted incoming vif
    #    must be the DIMT vif, not the covering interface's.  Per G10 the kernel
    #    is the evidence; the JSON above is only pimd's aggregation of it.
    def kernel_admitted():
        vif, error = resolve_mr_vif(r2, ifname)
        if error:
            return error
        return check_ip_mr_cache_iif(r2, SOURCE, GROUP, vif)

    expect(kernel_admitted)
    expect(lambda: check_forwarding(r2, "ready"))
    assert (
        json.loads(r2.vtysh_cmd("show ip pim dimt forwarding json"))[SG][
            "interface"
        ]
        == ifname
    )

    # 7. Put the ambiguity away.  This is the last stage today, but leaving a
    #    covering pim-light interface behind would silently change the premise
    #    of anything appended after it -- and the name was chosen to win the
    #    resolver, so it would win in stages that do not expect a competitor.
    r2.vtysh_cmd("conf t\nno interface {}".format(COVERING_IFACE))
    r2.run("ip link del {}".format(COVERING_IFACE))
    expect(lambda: check_pin(r2, ifname, "tunnel"))
    expect(lambda: check_forwarding(r2, "ready"))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
