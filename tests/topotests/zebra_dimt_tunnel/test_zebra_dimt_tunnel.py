#!/usr/bin/env python
# SPDX-License-Identifier: ISC

import json
import os
import subprocess
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.zebra]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_host("h1", "192.0.2.2/24", "via 192.0.2.1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    tgen.gears["r1"].load_frr_config(
        os.path.join(CWD, "r1/zebra.conf"), daemons=["zebra", "staticd"]
    )
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def request(action, tunnel_id, encap="gre"):
    client = os.path.join(CWD, "dimt_zapi_client.py")
    output = get_topogen().gears["r1"].run(
        "python3 {} {} {} --encap {}".format(client, action, tunnel_id, encap)
    )
    return json.loads(output)


def inject_netlink_syscall_failure(router, syscall, when):
    if not router.run("command -v strace").strip():
        pytest.skip("strace is required for netlink failure injection")
    zebra_pid = router.run("cat /var/run/frr/zebra.pid").strip()
    dplane_tid = router.run(
        f"for task in /proc/{zebra_pid}/task/*; do "
        '[ "$(cat $task/comm)" = zebra_dplane ] && basename "$task"; '
        "done"
    ).strip()
    if not dplane_tid:
        pytest.skip("zebra_dplane worker is required for netlink failure injection")
    tracer = router.popen(
        [
            "strace",
            "-qq",
            "-e",
            "trace={}".format(syscall),
            "-e",
            "inject={}:error=EIO:when={}".format(syscall, when),
            "-p",
            dplane_tid,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.2)
    if tracer.poll() is not None:
        _stdout, stderr = tracer.communicate()
        pytest.skip("strace attach failed: {}".format(stderr.decode().strip()))
    return tracer


def inject_netlink_send_failure(router, when):
    return inject_netlink_syscall_failure(router, "sendmsg", when)


def hold_dplane_worker(router, delay_usecs=6000000):
    """Hold only the dplane worker task at its event-loop wakeup.

    ptrace stops just the traced task, so zebra's main thread keeps
    processing ZAPI requests and netlink notifications while any context
    already handed to the dataplane provably stays queued until the tracer
    detaches.
    """
    if not router.run("command -v strace").strip():
        pytest.skip("strace is required to hold the dplane worker")
    worker = dplane_tid(router)
    if not worker:
        pytest.skip("zebra_dplane worker is required")
    tracer = router.popen(
        [
            "strace",
            "-qq",
            "-e",
            "trace=ppoll,poll",
            "-e",
            "inject=ppoll,poll:delay_exit={}".format(delay_usecs),
            "-p",
            worker,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.3)
    if tracer.poll() is not None:
        _stdout, stderr = tracer.communicate()
        pytest.skip("strace attach failed: {}".format(stderr.decode().strip()))
    return tracer


def stop_tracer(tracer):
    tracer.terminate()
    try:
        tracer.wait(timeout=2)
    except subprocess.TimeoutExpired:
        tracer.kill()
        tracer.wait(timeout=2)


def dplane_tid(router):
    zebra_pid = router.run("cat /var/run/frr/zebra.pid").strip()
    return router.run(
        f"for task in /proc/{zebra_pid}/task/*; do "
        '[ "$(cat $task/comm)" = zebra_dplane ] && basename "$task"; '
        "done"
    ).strip()


def gre_in_fou_supported(router):
    probe = router.run(
        "ip link del dimt-fou-probe 2>/dev/null || true; "
        "ip link add dimt-fou-probe type gre local 192.0.2.1 remote 192.0.2.2 "
        "encap fou encap-sport auto encap-dport 5555 2>/dev/null; "
        "rc=$?; [ $rc -ne 0 ] || ip link del dimt-fou-probe; echo $rc"
    )
    return probe.strip() == "0"


def test_acknowledged_gre_lifecycle_and_owner_reconnect():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router = tgen.gears["r1"]
    underlay = router.vtysh_cmd("show ip route 192.0.2.2")
    assert "r1-eth0" in underlay, underlay

    installed = request("add", 1)
    assert installed["result"] == 0, installed
    assert installed["ifindex"] > 0, installed
    link = router.run("ip -d link show dimt-00000001")
    assert "gre remote 192.0.2.2 local 192.0.2.1" in link, link
    address = router.run("ip -o address show dev dimt-00000001")
    assert "10.200.0.1 peer 10.200.0.2/32" in address, address

    # A fresh socket has a new owner session. The idempotent retry must be
    # answered on that session rather than the disconnected original.
    reconnected = request("add", 1)
    assert reconnected == installed, (installed, reconnected)

    removed = request("del", 1)
    assert removed["result"] == 2, removed
    _, result = topotest.run_and_expect(
        lambda: router.run("ip link show dimt-00000001 2>/dev/null"), "", count=10, wait=0.2
    )
    assert result == "", result


def test_create_failure_reports_fail_install_without_kernel_state():
    router = get_topogen().gears["r1"]
    router.run("ip link add dimt-00000004 type dummy")

    failed = request("add", 4)
    assert failed["result"] == 1, failed
    link = router.run("ip -d link show dimt-00000004")
    assert "dummy" in link and "gre remote" not in link, link

    router.run("ip link del dimt-00000004")


def test_outer_remote_via_dimt_is_rejected():
    router = get_topogen().gears["r1"]
    installed = request("add", 5)
    assert installed["result"] == 0, installed

    router.vtysh_cmd(
        "configure terminal\nip route 192.0.2.2/32 dimt-00000005\nend"
    )
    _, route_installed = topotest.run_and_expect(
        lambda: "dimt-00000005"
        in router.vtysh_cmd("show ip route 192.0.2.2/32"),
        True,
        count=10,
        wait=0.2,
    )
    assert route_installed, router.vtysh_cmd("show ip route 192.0.2.2/32")

    rejected = request("add", 6)
    assert rejected["result"] == 1, rejected
    assert router.run("ip link show dimt-00000006 2>/dev/null") == ""

    router.vtysh_cmd(
        "configure terminal\nno ip route 192.0.2.2/32 dimt-00000005\nend"
    )
    assert request("del", 5)["result"] == 2


def test_external_delete_does_not_reuse_stale_ifindex():
    router = get_topogen().gears["r1"]

    installed = request("add", 3)
    assert installed["result"] == 0, installed
    router.run("ip link del dimt-00000003")
    router.run("ip link add dimt-00000003 type dummy")

    stale_retry = request("add", 3)
    assert stale_retry["result"] == 1, stale_retry
    assert "dimt-00000003" in router.run("ip link show dimt-00000003")
    removed = request("del", 3)
    assert removed["result"] == 2, removed
    assert "dimt-00000003" in router.run("ip link show dimt-00000003")

    router.run("ip link del dimt-00000003")
    reinstalled = request("add", 3)
    assert reinstalled["result"] == 0, reinstalled
    assert request("del", 3)["result"] == 2


def test_address_failure_cleans_up_and_allows_tunnel_id_reuse():
    router = get_topogen().gears["r1"]
    tracer = inject_netlink_send_failure(router, 2)
    try:
        failed = request("add", 4)
    finally:
        stop_tracer(tracer)
    assert failed["result"] == 1, failed
    _, link = topotest.run_and_expect(
        lambda: router.run("ip link show dimt-00000004 2>/dev/null"),
        "",
        count=10,
        wait=0.2,
    )
    assert link == "", link

    installed = request("add", 4)
    assert installed["result"] == 0, installed
    assert request("del", 4)["result"] == 2


def test_delete_failure_retains_ownership_for_retry_and_reuse():
    router = get_topogen().gears["r1"]
    installed = request("add", 5)
    assert installed["result"] == 0, installed

    tracer = inject_netlink_send_failure(router, 1)
    try:
        failed = request("del", 5)
    finally:
        stop_tracer(tracer)
    assert failed["result"] == 3, failed
    assert "dimt-00000005" in router.run("ip link show dimt-00000005")

    assert request("del", 5)["result"] == 2
    reinstalled = request("add", 5)
    assert reinstalled["result"] == 0, reinstalled
    assert request("del", 5)["result"] == 2


def zebra_ifindex(router, name):
    try:
        data = json.loads(
            router.vtysh_cmd("show interface {} json".format(name))
        )
    except ValueError:
        return None
    entry = data.get(name)
    return entry.get("index") if entry else None


def test_queued_delete_does_not_remove_reused_ifindex():
    router = get_topogen().gears["r1"]
    installed = request("add", 6)
    assert installed["result"] == 0, installed

    # Hold only the dplane worker task: the delete context is provably
    # queued in the dataplane while zebra's main thread keeps processing
    # the netlink notifications for the replacement link. Only then is the
    # worker released to encode the delete against the updated tables.
    tracer = hold_dplane_worker(router)
    client = os.path.join(CWD, "dimt_zapi_client.py")
    try:
        pending = router.popen(
            ["python3", client, "del", "6", "--encap", "gre"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.3)
        router.run(
            "ip link del dimt-00000006; ip link add dimt-00000006 type dummy"
        )
        _, seen = topotest.run_and_expect(
            lambda: zebra_ifindex(router, "dimt-00000006")
            not in (None, installed["ifindex"]),
            True,
            count=15,
            wait=0.2,
        )
        assert seen, "zebra did not process the replacement link"
    finally:
        stop_tracer(tracer)
    stdout, stderr = pending.communicate(timeout=10)
    assert pending.returncode == 0, stderr.decode()
    assert json.loads(stdout.decode())["result"] == 2
    assert "dummy" in router.run("ip -d link show dimt-00000006")
    router.run("ip link del dimt-00000006")


def test_add_during_inflight_delete_is_rejected():
    router = get_topogen().gears["r1"]
    installed = request("add", 9)
    assert installed["result"] == 0, installed

    tracer = hold_dplane_worker(router)
    client = os.path.join(CWD, "dimt_zapi_client.py")
    try:
        pending = router.popen(
            ["python3", client, "del", "9", "--encap", "gre"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.3)
        # An identical ADD while the delete is in flight must be rejected
        # instead of rebinding ownership: the delete completion belongs to
        # the delete requester.
        readd = request("add", 9)
        assert readd["result"] == 1, readd
    finally:
        stop_tracer(tracer)
    stdout, stderr = pending.communicate(timeout=10)
    assert pending.returncode == 0, stderr.decode()
    assert json.loads(stdout.decode())["result"] == 2
    _, link = topotest.run_and_expect(
        lambda: router.run("ip link show dimt-00000009 2>/dev/null"),
        "",
        count=10,
        wait=0.2,
    )
    assert link == "", link

    reinstalled = request("add", 9)
    assert reinstalled["result"] == 0, reinstalled
    assert request("del", 9)["result"] == 2


def test_uncertain_create_result_reconciles_surviving_link():
    router = get_topogen().gears["r1"]
    # Fail the response read: the RTM_NEWLINK reaches the kernel but its
    # ack is lost, so the reported failure is not an authoritative verdict.
    tracer = inject_netlink_syscall_failure(router, "recvmsg", 1)
    try:
        failed = request("add", 8)
    finally:
        stop_tracer(tracer)
    assert failed["result"] == 1, failed
    # Zebra must adopt the surviving link and tear it down instead of
    # leaving it unmanaged to collide with a later ADD.
    _, link = topotest.run_and_expect(
        lambda: router.run("ip link show dimt-00000008 2>/dev/null"),
        "",
        count=25,
        wait=0.2,
    )
    assert link == "", link
    # The retained lifecycle entry converges over the standard cleanup
    # retry: at most one more explicit failure, then a clean install.
    retry = request("add", 8)
    assert retry["result"] in (0, 1), retry
    if retry["result"] == 1:
        retry = request("add", 8)
        assert retry["result"] == 0, retry
    assert request("del", 8)["result"] == 2


def test_zebra_restart_adopts_surviving_tunnel():
    tgen = get_topogen()
    router = tgen.gears["r1"]
    installed = request("add", 7)
    assert installed["result"] == 0, installed
    before = router.run("ip -d link show dimt-00000007")

    kill_router_daemons(tgen, "r1", ["zebra"])
    assert "dimt-00000007" in router.run("ip link show dimt-00000007")
    start_router_daemons(tgen, "r1", ["zebra"])

    _, underlay_ready = topotest.run_and_expect(
        lambda: "r1-eth0" in router.vtysh_cmd("show ip route 192.0.2.2"),
        True,
        count=10,
        wait=0.2,
    )
    assert underlay_ready, router.vtysh_cmd("show ip route 192.0.2.2")

    adopted = request("add", 7)
    assert adopted["result"] == 0, adopted
    assert adopted["ifindex"] == installed["ifindex"], (installed, adopted)
    assert router.run("ip -d link show dimt-00000007") == before
    assert request("del", 7)["result"] == 2


def test_acknowledged_gre_in_fou_lifecycle():
    router = get_topogen().gears["r1"]
    if not gre_in_fou_supported(router):
        pytest.skip("test kernel does not support GRE-in-FOU")
    installed = request("add", 2, "fou")
    assert installed["result"] == 0, installed
    link = router.run("ip -d link show dimt-00000002")
    assert "encap fou" in link and "encap-dport 5555" in link, link
    removed = request("del", 2)
    assert removed["result"] == 2, removed


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
