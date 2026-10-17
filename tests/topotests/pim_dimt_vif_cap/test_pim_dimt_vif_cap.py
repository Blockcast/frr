#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim_dimt_vif_cap.py: the per-box DIMT tunnel cap and the vif-less pin
guard (BLO-36556).

Linux allows MAXVIFS (32) multicast vifs per MRT table.  Every DIMT netdev
needs one.  Past the ceiling zebra still builds the netdev but pimd never gets
it a vif, so the tunnel installs clean and the stream silently never arrives
-- and the pin could select that vif-less interface.  Two independent guards:

  * the cap: a tunnel request past `dimt tunnel-limit` (default: the vif
    budget) is refused before anything is built, loudly, once;
  * the pin: never onto an interface without a vif, whatever the reason it
    has none.  Asserted directly, on a covering pim-light interface that
    cannot get a vif because the table is full -- not inferred from the cap.

Topology (same shape as pim_dimt_tunnel/):

    r1 ---- s1 ---- r2 ---- s3 (receiver stub)
    |
    s2 (sources)

r1 advertises 10.10.N.0/24 with UMH 10.99.N.1 (N = 1..4).  r2 has endpoint
rows for UMHs 1-3 and `dimt tunnel-limit 2`, so exactly one of the three is
refused.  Which one depends on BGP arrival order, so the suite derives it
rather than assuming it.  UMH 4 has no endpoint row and never wants a tunnel.

Kernel state is the evidence for "nothing was built": `ip -o link show` and
/proc/net/ip_mr_vif.  pimd's `show ip pim dimt tunnel-limit json` is read to
assert it agrees.

The tests are ORDER-DEPENDENT: each stage builds on the previous one.
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
from lib.kernel_state import link_names, parse_ip_mr_vif
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

MAXVIFS = 32
LIMIT = 2
ENDPOINT_UMHS = ["10.99.1.1", "10.99.2.1", "10.99.3.1"]

# UMH 4: no endpoint row, so its pin can only come from a covering interface.
PIN_PREFIX = "10.10.4.0/24"
PIN_SOURCE = "10.10.4.10"
PIN_GROUP = "232.1.1.4"
# Sorts before every other candidate by name and covers 10.99.4.1.
COVERING_IFACE = "aaa0"
COVERING_ADDR = "10.99.4.3/24"


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])

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


def expect(func, count=30, wait=1.0):
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, result


def cap(router):
    return json.loads(router.vtysh_cmd("show ip pim dimt tunnel-limit json"))


def tunnels(router):
    return json.loads(router.vtysh_cmd("show ip pim dimt tunnel json"))


def kernel_vifs(router):
    return parse_ip_mr_vif(router.run("cat /proc/net/ip_mr_vif 2>&1"))


def kernel_dimt_links(router):
    names = link_names(router)
    assert names is not None, "could not enumerate kernel links"
    return sorted(n for n in names if n.startswith("dimt-"))


def refusal_log_count(router, umh):
    logfile = os.path.join(get_topogen().logdir, router.name, "pimd.log")
    with open(logfile) as f:
        log = f.read()
    return len(
        re.findall(r"refusing tunnel to UMH {}: ".format(re.escape(umh)), log)
    )


def check_capped(router):
    """LIMIT tunnels installed, the remaining endpoint UMH refused."""
    rows = tunnels(router)
    installed = [u for u in ENDPOINT_UMHS if rows.get(u, {}).get("state") == "installed"]
    if len(installed) != LIMIT:
        return "expected {} installed tunnels, have {}: {}".format(
            LIMIT, installed, rows
        )
    state = cap(router)
    if state.get("refusedUmhs") != [u for u in ENDPOINT_UMHS if u not in installed]:
        return "refused set does not match the uninstalled UMH: {}".format(state)
    return None


def refused_umh(router):
    refused = cap(router)["refusedUmhs"]
    assert len(refused) == 1, refused
    return refused[0]


# --- stages --------------------------------------------------------------


def test_cap_refuses_the_tunnel_past_the_limit():
    """LIMIT tunnels build; the next request is refused, logged, counted once."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r2 = tgen.gears["r2"]

    expect(lambda: check_capped(r2), count=60)

    umh = refused_umh(r2)
    state = cap(r2)
    assert state["configuredLimit"] == LIMIT, state
    assert state["limit"] == LIMIT, state
    assert state["tunnels"] == LIMIT, state
    # +1 exactly: one refusal for one refused UMH.
    assert state["refusals"] == 1, state
    assert umh not in tunnels(r2), tunnels(r2)
    assert refusal_log_count(r2, umh) == 1, "expected exactly one refusal warning"


def test_refused_peer_left_no_kernel_state():
    """The refusal built nothing: no netdev, no vif -- and it stays refused
    across further reconcile passes without counting again."""
    r2 = get_topogen().gears["r2"]
    umh = refused_umh(r2)

    links = kernel_dimt_links(r2)
    rows = tunnels(r2)
    assert links == sorted(r["interface"] for r in rows.values()), (links, rows)
    assert len(links) == LIMIT, links

    vifs_before = kernel_vifs(r2)
    dimt_vifs = sorted(v for v in vifs_before if v.startswith("dimt-"))
    assert dimt_vifs == links, (dimt_vifs, links)

    # Drive more reconcile passes: a demand edge on an admitted UMH.
    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nip igmp static-group 232.1.1.11 10.10.1.11"
    )
    r2.vtysh_cmd(
        "conf t\ninterface r2-eth1\nno ip igmp static-group 232.1.1.11 10.10.1.11"
    )
    expect(lambda: check_capped(r2))

    assert kernel_vifs(r2) == vifs_before, (kernel_vifs(r2), vifs_before)
    assert kernel_dimt_links(r2) == links
    state = cap(r2)
    assert state["refusals"] == 1, state
    assert refused_umh(r2) == umh
    assert refusal_log_count(r2, umh) == 1


def test_default_limit_is_the_vif_budget():
    """Unconfigured, the limit is MAXVIFS less every non-DIMT vif; with that
    much headroom the refused UMH is admitted."""
    r2 = get_topogen().gears["r2"]
    umh = refused_umh(r2)

    r2.vtysh_cmd("conf t\nno dimt tunnel-limit")

    def admitted():
        rows = tunnels(r2)
        if rows.get(umh, {}).get("state") != "installed":
            return "refused UMH {} not admitted: {}".format(umh, rows)
        if cap(r2)["refusedUmhs"]:
            return "refused set not drained: {}".format(cap(r2))
        return None

    expect(admitted)

    vifs = kernel_vifs(r2)
    non_dimt = [v for v in vifs if not v.startswith("dimt-")]
    # pimd reserves index 0 for pimreg whether or not it exists yet.
    reserved = len(non_dimt) + (0 if "pimreg" in non_dimt else 1)
    state = cap(r2)
    assert state["configuredLimit"] == 0, state
    assert state["maxVifs"] == MAXVIFS, state
    assert state["vifBudget"] == MAXVIFS - reserved, (state, vifs)
    assert state["limit"] == state["vifBudget"], state
    assert state["tunnels"] == len(ENDPOINT_UMHS), state
    # The earlier refusal is history, not re-counted by the admission.
    assert state["refusals"] == 1, state


def test_pin_skips_an_interface_without_a_vif():
    """A covering pim-light interface that cannot get a vif is never pinned.

    Fill the kernel vif table with plain pim interfaces, then add a covering
    pim-light interface for UMH 4.  It can get no vif.  Pre-fix the resolver
    pinned it anyway, programming an iif the kernel cannot admit.
    """
    r2 = get_topogen().gears["r2"]

    vifs = kernel_vifs(r2)
    # Index 0 is pimreg's even when pimreg does not exist yet.
    full = MAXVIFS if "pimreg" in vifs else MAXVIFS - 1
    for n in range(full - len(vifs)):
        ifname = "vf{}".format(n)
        r2.run("ip link add {} type dummy && ip link set {} up".format(ifname, ifname))
        r2.vtysh_cmd(
            "conf t\ninterface {}\nip address 10.250.{}.1/32\nip pim".format(ifname, n)
        )
    expect(
        lambda: None
        if len(kernel_vifs(r2)) == full
        else "vif table not full: {}".format(kernel_vifs(r2))
    )

    r2.run("ip link add {} type dummy".format(COVERING_IFACE))
    r2.run("ip link set {} up".format(COVERING_IFACE))
    r2.vtysh_cmd(
        "conf t\ninterface {}\nip address {}\nip pim\nip pim light".format(
            COVERING_IFACE, COVERING_ADDR
        )
    )

    # Precondition, or the stage proves nothing: it genuinely has no vif.
    assert COVERING_IFACE not in kernel_vifs(r2), kernel_vifs(r2)
    address = r2.run("ip -o address show dev {}".format(COVERING_IFACE))
    assert COVERING_ADDR in address, address

    def never_pinned():
        umh = json.loads(r2.vtysh_cmd("show ip pim dimt umh json")).get(PIN_PREFIX)
        if umh is None:
            return "no UMH mapping for {}".format(PIN_PREFIX)
        if umh.get("interface") == COVERING_IFACE:
            return "pin resolved onto vif-less {}: {}".format(COVERING_IFACE, umh)
        up = json.loads(r2.vtysh_cmd("show ip pim upstream json"))
        row = up.get(PIN_GROUP, {}).get(PIN_SOURCE)
        if row is None:
            return "no upstream ({},{})".format(PIN_SOURCE, PIN_GROUP)
        if row.get("inboundInterface") == COVERING_IFACE:
            return "upstream RPF pinned to vif-less {}: {}".format(
                COVERING_IFACE, row
            )
        return None

    # A wrong pin is an event, not a state we wait for: give the resolver
    # time to make it, then require it never happened.
    time.sleep(5)
    assert never_pinned() is None, never_pinned()


def test_freed_vif_admits_a_refused_umh():
    """Under the derived cap, a non-DIMT vif being freed re-admits a refused
    UMH by itself -- no demand edge, no `dimt tunnel-limit` change.

    Runs on the full vif table left by the pin stage.  Pre-fix nothing
    reconciled on a vif release, so the UMH stayed refused.
    """
    r2 = get_topogen().gears["r2"]
    umh = "10.99.4.1"

    # aaa0 has no vif but could take the freed one: remove it first so the
    # freed slot can only go to the refused tunnel.
    r2.vtysh_cmd("conf t\ninterface {}\nno ip pim".format(COVERING_IFACE))
    r2.run("ip link del {}".format(COVERING_IFACE))

    r2.vtysh_cmd(
        "conf t\ndimt tunnel-endpoint {} inner-local 10.99.4.2 outer-local "
        "10.0.0.2 outer 10.0.0.1 encap gre key 4".format(umh)
    )

    def refused():
        state = cap(r2)
        if state.get("refusedUmhs") != [umh]:
            return "UMH {} not refused on a full table: {}".format(umh, state)
        return None

    expect(refused)
    state = cap(r2)
    assert state["configuredLimit"] == 0, state
    assert state["refusals"] == 2, state
    assert umh not in tunnels(r2), tunnels(r2)

    # Free one non-DIMT vif.  Nothing else changes.
    r2.vtysh_cmd("conf t\ninterface vf0\nno ip pim")

    def admitted():
        rows = tunnels(r2)
        if rows.get(umh, {}).get("state") != "installed":
            return "refused UMH {} not admitted after a vif was freed: {}".format(
                umh, rows
            )
        if cap(r2)["refusedUmhs"]:
            return "refused set not drained: {}".format(cap(r2))
        return None

    expect(admitted)
    assert tunnels(r2)[umh]["interface"] in kernel_vifs(r2), kernel_vifs(r2)
    assert cap(r2)["refusals"] == 2, cap(r2)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
