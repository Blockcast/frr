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
from lib.kernel_state import check_gre_link
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.zebra]

# These are failure-injection tests: a skipped one is indistinguishable from a
# passing one in the job conclusion, so for eight of them the absence of strace
# meant they never ran at all while CI stayed green (BLO-28043). strace is
# installed by docker/ubuntu-ci/Dockerfile, so its absence here means the test
# image regressed -- that is a failure, not a reason to stand down.
#
# This is deliberately strict by DEFAULT rather than gated on a CI env var: the
# topotest container is started with only TOPOTEST_WORKERS (and optionally
# MROUTE_VRF_MISSING) in its environment, so a check for CI/GITHUB_ACTIONS
# would never fire in CI and would silently reintroduce the same blind spot.
# A local run on a host without strace can opt out explicitly.
ALLOW_MISSING_STRACE = os.environ.get("TOPOTESTS_ALLOW_MISSING_STRACE") == "1"


def tracing_unavailable(reason):
    """Fail by default; skip only under the explicit local opt-out."""
    if ALLOW_MISSING_STRACE:
        pytest.skip(reason)
    pytest.fail(reason)


def require_strace(router):
    if not router.run("command -v strace").strip():
        tracing_unavailable(
            "strace not found in the test image -- it is required for netlink "
            "failure injection and for holding the dplane worker"
        )


# Nine of these tests execute for the first time now that strace is installed
# and require_strace() fails hard instead of skipping -- and nine of them fail.
# The causes are NOT all zebra defects; an earlier revision of this comment
# asserted that they were, and it was wrong:
#
#   BLO-28405  test_address_failure_cleans_up_and_allows_tunnel_id_reuse
#              injects EIO on the 2nd sendmsg of a create and expects
#              result=1; zebra answers result=0 with a live ifindex. Whether
#              that is a zebra defect is UNPROVEN. result=0 is only reachable
#              from the phase==ADDRESS success branch of
#              zebra_dimt_tunnel_dplane_result(), so the address-add sendmsg
#              must have succeeded -- meaning the injected EIO may have landed
#              on a syscall outside the create transaction, in which case
#              result=0 is correct and the injection index is the bug. The
#              strace trace file now recorded by inject_netlink_syscall_failure
#              is what settles it; read the evidence in the assert message
#              before removing this marker.
#
#              The cascade of seven further failures was NOT caused by zebra.
#              This test's own tunnel cleanup was a trailing statement after
#              the asserts, so a failed assert skipped it and leaked
#              dimt-00000004, which then collided -- on the (local, remote,
#              key) tuple, not the name -- with every later create. That is
#              fixed here: cleanup moved into the finally block.
#   BLO-28406  Reconciliation of the surviving link after a lost create ack.
#
# These are marked xfail rather than skipped so the harness fix can land now
# instead of waiting on the zebra questions -- a skip would recreate the
# very blind spot BLO-28043 exists to close. strict=True is load-bearing: the
# build FAILS the moment a defect is fixed and its test starts passing, which
# forces the marker off in the same PR that fixes it. Remove each marker in its
# blocker's fix PR, never in a separate cleanup change.
XFAIL_BLO_28405 = pytest.mark.xfail(
    strict=True,
    reason=(
        "BLO-28405: a DIMT create with EIO injected on the 2nd sendmsg is "
        "answered result=0 rather than result=1. Under investigation -- the "
        "injected errno may be landing outside the create transaction, which "
        "would make result=0 correct. Remove this marker in the BLO-28405 "
        "resolution PR."
    ),
)
XFAIL_BLO_28406 = pytest.mark.xfail(
    strict=True,
    reason=(
        "BLO-28406: zebra does not reconcile the surviving link after a lost "
        "create ack, so the retry cannot adopt it. Remove this marker in the "
        "BLO-28406 fix PR."
    ),
)


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


def trace_path(label):
    """Path for a strace log, inside the collected per-router log directory.

    topogen bind-mounts <logdir>/<router> at /tmp/gearlogdir, and that
    directory is what CI archives as the r1/ tree next to zebra.out. Writing
    the trace there means the syscall-level evidence for a failure-injection
    test survives in the job artifact instead of dying with the container.
    """
    current = os.environ.get("PYTEST_CURRENT_TEST", "unknown")
    test = current.split("::")[-1].split(" ")[0]
    return "/tmp/gearlogdir/strace-{}-{}.log".format(test, label)


def inject_netlink_syscall_failure(router, syscall, when, errno_name="EIO"):
    require_strace(router)
    zebra_pid = router.run("cat /var/run/frr/zebra.pid").strip()
    dplane_tid = router.run(
        f"for task in /proc/{zebra_pid}/task/*; do "
        '[ "$(cat $task/comm)" = zebra_dplane ] && basename "$task"; '
        "done"
    ).strip()
    if not dplane_tid:
        tracing_unavailable(
            "zebra_dplane worker not found -- netlink failure injection cannot run"
        )
    # -o is not optional. strace writes its per-syscall trace to stderr, and
    # nothing here reads that pipe until stop_tracer() terminates the process,
    # so a trace larger than the 64 KiB pipe buffer would block strace mid-write
    # while the dplane worker stays ptrace-stopped -- a hung test, not a failing
    # one. Routing the trace to a file keeps stderr down to attach diagnostics.
    # It is also the only record of WHICH syscall took the injected error, which
    # is what distinguishes "the transaction under test failed" from "the
    # injection landed on an unrelated syscall" (BLO-28405).
    trace_file = trace_path("inject-{}-when{}".format(syscall, when))
    router.run("rm -f {}".format(trace_file))
    tracer = router.popen(
        [
            "strace",
            "-qq",
            "-o",
            trace_file,
            "-e",
            "trace={}".format(syscall),
            "-e",
            "inject={}:error={}:when={}".format(syscall, errno_name, when),
            "-p",
            dplane_tid,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.2)
    if tracer.poll() is not None:
        _stdout, stderr = tracer.communicate()
        tracing_unavailable(
            "strace attach failed: {}".format(stderr.decode().strip())
        )
    return tracer, trace_file


def syscall_trace(router, trace_file):
    """Return the recorded syscalls, one per line, oldest first."""
    text = router.run("cat {} 2>/dev/null".format(trace_file))
    return [line for line in text.splitlines() if line.strip()]


def injected_call_index(router, trace_file, errno_name):
    """1-based index of the traced call that returned the injected errno.

    Returns (index, calls). index is None when the errno never appears, which
    means the injection did not fire on this thread at all.
    """
    calls = syscall_trace(router, trace_file)
    for position, line in enumerate(calls, start=1):
        if errno_name in line:
            return position, calls
    return None, calls


def inject_netlink_send_failure(router, when):
    return inject_netlink_syscall_failure(router, "sendmsg", when)


def inject_netlink_recv_failure(router, when):
    """Drop one netlink response read, simulating a lost ack.

    The errno is load-bearing and must stay EAGAIN. zebra tolerates only
    EWOULDBLOCK/EAGAIN/EMSGSIZE out of netlink_recv_msg()
    (zebra/kernel_netlink.c); every other errno is a deliberate upstream
    fatal path that logs "recvmsg overrun" and calls
    frr_exit_with_buffer_flush(-1), killing the daemon and every later
    test in this module rather than exercising anything.

    EAGAIN is exactly the semantics these callers want: netlink_recv_msg()
    returns 0, nl_batch_read_resp() drains the batch marking DIMT ADD/DEL
    contexts ZEBRA_DPLANE_REQUEST_FAILURE, and zebra survives. The request
    itself was already delivered by sendmsg, so the kernel applied it --
    the reported failure is a lost verdict, not an authoritative one, and
    the unread ack stays queued in the socket buffer to be discarded by
    sequence comparison on the next read. That is the lost-ack window.
    """
    return inject_netlink_syscall_failure(router, "recvmsg", when, errno_name="EAGAIN")


def hold_dplane_worker(router, delay_usecs=6000000):
    """Hold only the dplane worker task at its event-loop wakeup.

    ptrace stops just the traced task, so zebra's main thread keeps
    processing ZAPI requests and netlink notifications while any context
    already handed to the dataplane provably stays queued until the tracer
    detaches.
    """
    tracer, _trace_file = _hold_dplane_syscalls(
        router, "ppoll,poll", "delay_exit", delay_usecs
    )
    return tracer


def hold_dplane_sendmsg(router, delay_usecs=6000000):
    """Hold the dplane worker at sendmsg ENTRY.

    At that point the netlink message is fully encoded (all identity checks
    have run) but not yet delivered to the kernel -- the exact
    encode-to-kernel window. Returns (tracer, trace_file); the trace file
    records each sendmsg entry, so callers can positively synchronize on
    the syscall having been entered instead of guessing with sleeps.
    """
    return _hold_dplane_syscalls(router, "sendmsg", "delay_enter", delay_usecs)


def sendmsg_entered(router, trace_file):
    return "sendmsg(" in router.run("cat {} 2>/dev/null".format(trace_file))


def _hold_dplane_syscalls(router, syscalls, inject_kind, delay_usecs):
    require_strace(router)
    worker = dplane_tid(router)
    if not worker:
        tracing_unavailable(
            "zebra_dplane worker not found -- cannot hold the dplane worker"
        )
    # Always -o: tracing ppoll/poll on an event loop is high volume, and an
    # unread stderr pipe would deadlock strace (and so wedge the held dplane
    # worker) once the trace exceeded 64 KiB. See inject_netlink_syscall_failure.
    trace_file = trace_path("hold-{}".format(syscalls.replace(",", "-")))
    router.run("rm -f {}".format(trace_file))
    cmd = [
        "strace",
        "-qq",
        "-o",
        trace_file,
        "-e",
        "trace={}".format(syscalls),
        "-e",
        "inject={}:{}={}".format(syscalls, inject_kind, delay_usecs),
        "-p",
        worker,
    ]
    tracer = router.popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.3)
    if tracer.poll() is not None:
        _stdout, stderr = tracer.communicate()
        tracing_unavailable(
            "strace attach failed: {}".format(stderr.decode().strip())
        )
    return tracer, trace_file


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
    kernel_error = check_gre_link(
        router,
        "dimt-00000001",
        local="192.0.2.1",
        remote="192.0.2.2",
        mtu=1476,
    )
    assert kernel_error is None, kernel_error
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


@XFAIL_BLO_28405
def test_address_failure_cleans_up_and_allows_tunnel_id_reuse():
    router = get_topogen().gears["r1"]
    tracer, trace_file = inject_netlink_send_failure(router, 2)
    try:
        failed = request("add", 4)
    finally:
        # Read the trace before detaching: it names the syscall that actually
        # took the EIO, which is what separates "zebra swallowed a failed
        # create" from "the injection landed outside the create transaction".
        index, calls = injected_call_index(router, trace_file, "EIO")
        stop_tracer(tracer)
        # The tunnel is torn down here rather than after the asserts below.
        # A failed assert raises, so a trailing cleanup line would never run,
        # and the surviving dimt-00000004 would collide -- on the (local,
        # remote, key) tuple, not the name -- with every later create in this
        # module, turning one red into eight.
        request("del", 4)

    evidence = "injected EIO hit sendmsg #{} of {}: {}".format(
        index, len(calls), calls
    )
    assert failed["result"] == 1, (failed, evidence)
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


@XFAIL_BLO_28405
def test_delete_failure_retains_ownership_for_retry_and_reuse():
    router = get_topogen().gears["r1"]
    installed = request("add", 5)
    assert installed["result"] == 0, installed

    tracer, trace_file = inject_netlink_send_failure(router, 1)
    try:
        failed = request("del", 5)
    finally:
        index, calls = injected_call_index(router, trace_file, "EIO")
        stop_tracer(tracer)

    evidence = "injected EIO hit sendmsg #{} of {}: {}".format(
        index, len(calls), calls
    )
    assert failed["result"] == 3, (failed, evidence)
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


@XFAIL_BLO_28405
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


@XFAIL_BLO_28405
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


@XFAIL_BLO_28406
def test_uncertain_create_result_reconciles_surviving_link():
    router = get_topogen().gears["r1"]
    # Fail the response read: the RTM_NEWLINK reaches the kernel but its
    # ack is lost, so the reported failure is not an authoritative verdict.
    tracer, _trace_file = inject_netlink_recv_failure(router, 1)
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
    # retry. Stale-ack correlation poisoning is fixed (dropped by sequence
    # comparison); the only remaining variance is reconcile timing -- the
    # retry may land while the entry is still a cleanup tombstone.
    retry = request("add", 8)
    assert retry["result"] in (0, 1), retry
    if retry["result"] == 1:
        retry = request("add", 8)
        assert retry["result"] == 0, retry
    assert request("del", 8)["result"] == 2


@XFAIL_BLO_28405
def test_delete_encoded_before_replacement_binds_to_ifindex():
    router = get_topogen().gears["r1"]
    installed = request("add", 10)
    assert installed["result"] == 0, installed

    # Hold the worker at sendmsg ENTRY and positively synchronize on the
    # syscall having been entered: the RTM_DELLINK is then provably
    # encoded (identity validated) but not yet delivered. Replacing the
    # link in this window must not delete the auto-allocated same-name
    # replacement -- the delete is bound to the old ifindex, which
    # automatic allocation never reuses, so the kernel fails it with
    # ENODEV instead. (An actor explicitly claiming the freed index needs
    # CAP_NET_ADMIN plus a deliberate index claim and can delete any
    # interface directly; rtnetlink has no compare-and-delete to defend
    # against that.)
    tracer, trace_file = hold_dplane_sendmsg(router)
    client = os.path.join(CWD, "dimt_zapi_client.py")
    try:
        pending = router.popen(
            ["python3", client, "del", "10", "--encap", "gre"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _, entered = topotest.run_and_expect(
            lambda: sendmsg_entered(router, trace_file), True, count=20, wait=0.2
        )
        assert entered, "dplane worker never entered sendmsg for the delete"
        router.run(
            "ip link del dimt-0000000a; ip link add dimt-0000000a type dummy"
        )
    finally:
        stop_tracer(tracer)
    stdout, stderr = pending.communicate(timeout=15)
    assert pending.returncode == 0, stderr.decode()
    # The encode happened before the replacement (proven by the sendmsg
    # sync), so the pre-encode skip path is unreachable: the delete must
    # fail on the stale index and the replacement must survive.
    assert json.loads(stdout.decode())["result"] == 3, stdout
    assert "dummy" in router.run("ip -d link show dimt-0000000a")
    assert request("del", 10)["result"] == 2
    router.run("ip link del dimt-0000000a")


@XFAIL_BLO_28405
def test_lost_delete_ack_reconciles_instead_of_resurrecting():
    router = get_topogen().gears["r1"]
    installed = request("add", 11)
    assert installed["result"] == 0, installed

    # The kernel applies the delete but its ack is lost. The entry must
    # converge on reconciled interface state -- REMOVED now, or
    # REMOVE_FAIL then REMOVED on retry -- and never report INSTALLED for
    # a link that no longer exists.
    tracer, _trace_file = inject_netlink_recv_failure(router, 1)
    try:
        removed = request("del", 11)
    finally:
        stop_tracer(tracer)
    assert removed["result"] in (2, 3), removed
    _, link = topotest.run_and_expect(
        lambda: router.run("ip link show dimt-0000000b 2>/dev/null"),
        "",
        count=10,
        wait=0.2,
    )
    assert link == "", link
    if removed["result"] == 3:
        assert request("del", 11)["result"] == 2

    # An identical ADD must produce a real kernel link, never a phantom
    # INSTALLED. The stale delete ack still sitting in the socket buffer
    # must be discarded by sequence comparison -- not allowed to consume
    # the ADD's context -- so the first post-reconciliation ADD succeeds.
    readd = request("add", 11)
    assert readd["result"] == 0, readd
    link = router.run("ip -d link show dimt-0000000b")
    assert "gre remote 192.0.2.2 local 192.0.2.1" in link, link
    assert request("del", 11)["result"] == 2


@XFAIL_BLO_28405
def test_skipped_delete_result_survives_mixed_batch():
    router = get_topogen().gears["r1"]
    replaced = request("add", 12)
    assert replaced["result"] == 0, replaced
    normal = request("add", 13)
    assert normal["result"] == 0, normal

    # Queue the REAL delete first and the skipped one second: the
    # no-message context then sits behind the only correlatable response,
    # exactly where the end-of-responses drain used to flip its synthetic
    # success into a failure.
    tracer = hold_dplane_worker(router)
    client = os.path.join(CWD, "dimt_zapi_client.py")
    try:
        pending13 = router.popen(
            ["python3", client, "del", "13", "--encap", "gre"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.2)
        pending12 = router.popen(
            ["python3", client, "del", "12", "--encap", "gre"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.2)
        router.run(
            "ip link del dimt-0000000c; ip link add dimt-0000000c type dummy"
        )
        _, seen = topotest.run_and_expect(
            lambda: zebra_ifindex(router, "dimt-0000000c")
            not in (None, replaced["ifindex"]),
            True,
            count=15,
            wait=0.2,
        )
        assert seen, "zebra did not process the replacement link"
    finally:
        stop_tracer(tracer)
    out13, err13 = pending13.communicate(timeout=10)
    out12, err12 = pending12.communicate(timeout=10)
    assert pending13.returncode == 0, err13.decode()
    assert pending12.returncode == 0, err12.decode()
    assert json.loads(out13.decode())["result"] == 2, out13
    # The skipped delete must report REMOVED even though it shared the
    # batch with a real delete whose ack is the only response.
    assert json.loads(out12.decode())["result"] == 2, out12
    assert "dummy" in router.run("ip -d link show dimt-0000000c")
    router.run("ip link del dimt-0000000c")


@XFAIL_BLO_28405
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
