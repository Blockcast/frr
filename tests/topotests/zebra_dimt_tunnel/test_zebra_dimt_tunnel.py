#!/usr/bin/env python
# SPDX-License-Identifier: ISC

import ast
import json
import os
import pathlib
import re
import select
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
    """Skip only under the explicit local opt-out, and only for strace itself.

    Call this from require_strace() and nowhere else.  A missing zebra_dplane
    worker and a failed strace attach are not "strace is unavailable" -- the
    first is a zebra defect and the second usually is too -- and routing them
    through here let TOPOTESTS_ALLOW_MISSING_STRACE convert a real defect into
    a skip on any developer host that lacks strace.  The env var name already
    promises the narrower contract; those sites call pytest.fail directly.
    """
    if ALLOW_MISSING_STRACE:
        pytest.skip(reason)
    pytest.fail(reason)


def require_strace(router):
    if not router.run("command -v strace").strip():
        tracing_unavailable(
            "strace not found in the test image -- it is required for netlink "
            "failure injection and for holding the dplane worker"
        )


# Nine of these tests executed for the first time once strace was installed and
# require_strace() started failing hard instead of skipping -- and nine failed.
# Seven were one leaked link. Three tickets were filed: two for the failures
# outside that cascade, and BLO-29000 for a cascade test whose own window
# problem surfaced once the reaper unwedged it. Only one of the three was a
# zebra question, and all three are now closed. (The reasoning that
# reclassified them is in the commit log, not here.)
#
#   BLO-28405  HARNESS, not zebra. FIXED -- marker removed. The assertion is
#              unchanged; what changed is that the injection now lands on the
#              create it was always meant to fail. The thread-wide `when=N`
#              ordinal carried no socket qualifier, so it selected an ethtool
#              probe on the genetlink ge_netlink_cmd socket instead of the
#              RTM_NEWADDR sendmsg on the dplane route-netlink socket. Both
#              messages of the create therefore succeeded, and the test asserted
#              result=1 against a create that had correctly returned 0.
#              _route_netlink_fds() narrows the traced set to NETLINK_ROUTE,
#              which fixes the aim. result=0 was zebra behaving correctly
#              throughout -- the "zebra swallows a netlink sendmsg failure"
#              premise this entry used to carry is falsified, and no zebra
#              change was needed.
#
#   BLO-29583  zebra. FIXED -- marker removed, the test now asserts the real
#              behaviour. Reconciliation of the surviving link after a lost
#              create ack. Root cause was ordering in zebra/interface.c:
#              zebra_dimt_tunnel_if_update() ran BEFORE
#              interface_update_l2info() populated zif->l2info.gre, so the
#              zebra_dimt_if_matches() identity guard in the CLEANUP-tombstone
#              adoption branch compared against a zeroed struct and never
#              adopted the link. assert_injection_fired() stays: a SUCCESSFUL
#              lost-ack injection writes nothing to zebra.out (EAGAIN is the
#              normal batch terminator), so silence there is not evidence. It
#              raises Failed, not AssertionError, so an uninjected run fails
#              hard rather than passing for the wrong reason.
#
#   BLO-29000  HARNESS, not zebra. FIXED -- marker removed. The hold never
#              held anything. hold_dplane_worker() delayed ppoll/poll, but zebra
#              is built with USE_EPOLL, so every event loop -- the zebra_dplane
#              pthread's included -- blocks in epoll_pwait (lib/event.c
#              fd_poll) and the strace filter never matched. Every run was an
#              unheld race. Of 45 CI executions, 26 saw the del finish before
#              the guard sampled it, 9 saw the DEL reach zebra first (readd
#              rejected, "XPASS"), and 10 served the readd outside the window:
#              before the DEL reached zebra (the ORIGINAL ifindex came back) or
#              after it completed (a fresh create, ifindex+1). zebra answered
#              correctly for the state it was in every time -- an ADD against a
#              DELETING entry gets FAIL_INSTALL on every path. The test now
#              holds the dplane worker's route-netlink sendmsgs at entry and
#              proves, both before and after the readd, that the held one is
#              this link's RTM_DELLINK (dellink_state()).
#
# Why reap_stray_dimt_links() exists: the seven cascade failures were a GRE
# TUPLE collision on the shared 192.0.2.1 -> 192.0.2.2 endpoints, not a name
# collision -- those seven create ids 5, 6, 9, 10, 11 and 12, every one a
# different name from the leaked dimt-00000004, and all still died at their
# setup add() with `File exists`. A real name collision does occur here,
# deliberately and benignly:
# test_create_failure_reports_fail_install_without_kernel_state creates
# dimt-00000004 as a dummy on purpose and removes it on its last line. Do not
# read that early EEXIST as a leak.
#
# These were marked xfail rather than skipped so the harness fixes could land
# without waiting on the zebra work -- a skip would recreate the very blind spot
# BLO-28043 exists to close. None remain. Any new one follows the same rules.
# strict=True is load-bearing: the build FAILS the moment a defect is fixed and
# its test starts passing, which forces the marker off in the same PR that fixes
# it. Corollary worth keeping: anything that unwedges a marked test -- a fixture
# like the reaper below, as much as a zebra fix -- must remove that test's
# marker in the SAME commit, or strict turns the new pass into an XPASS failure.
#
# Remove a marker in its blocker's fix PR, never in a cleanup.
# raises= narrows each marker to the failure it actually predicts, so an
# unrelated topology error or a no-op injection surfaces as a hard failure
# instead of being absorbed as expected. Neither pytest.fail()'s Failed nor
# WindowNeverOpened is an AssertionError, which is what lets
# assert_injection_fired() and the precondition guards break out of an xfail
# rather than be swallowed by it.


class WindowNeverOpened(Exception):
    """A test's precondition never held, so its window was never exercised.

    Deliberately a bespoke type rather than pytest.fail()'s Failed. EVERY
    pytest.fail() in this module raises Failed -- the tracing_unavailable()
    funnel, both reap_stray_dimt_links() precondition failures, dplane_tid()
    ("zebra_dplane worker not found" / "not uniquely resolved" / "not
    parsed"), the two FD scans that aim an injection or a hold
    (_route_netlink_fds(), _dplane_in_fd()), both _await_strace_attached()
    failures ("strace attach failed", "strace never attached") and
    assert_injection_fired() -- so a marker written
    raises=pytest.fail.Exception absorbs all of them as a green xfail, a
    *setup-time* fixture failure included. No marker absorbs this class today
    either: a window that cannot be proven open fails the job, because a test
    that never opened its window has not run. It stays a bespoke type so that
    any future marker can be narrowed to exactly these guards, and a missing
    strace, a dirty kernel, a missing dplane worker or a failed attach still
    fails loudly instead of reading as "expected failure, blocker still open".

    It keeps the property that made pytest.fail() right in the first place: it
    is NOT an AssertionError, so a raises=AssertionError marker cannot swallow
    it either. Same escape reasoning as assert_injection_fired(), narrower
    blast radius.

    One asymmetry to know before wrapping a guard site in a handler: Failed
    derives from BaseException, not Exception, so `except Exception` does not
    catch it -- this class it would. Verified at the time of writing that the
    only try blocks enclosing the guards are bare try/finally with no
    handlers, so nothing swallows it today. Keep it that way, or re-narrow the
    handler.
    """


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


@pytest.fixture(autouse=True)
def reap_stray_dimt_links():
    """Delete leftover dimt-* links around every test.

    Without this, ONE test that leaks a link wedges every later create -- and
    not by name collision, which is the reading the link names invite.  The
    cascade tests create ids 5, 6, 9, 10, 11 and 12, all different names from
    the leaked dimt-00000004, and every one still died at its setup add() with
    `File exists`.  The collision is on the GRE tuple, not the name: tunnels
    here share the 192.0.2.1 -> 192.0.2.2 endpoints, so a single surviving link
    makes the kernel refuse the next create whatever it is called.  Measured
    directly -- a second `ip link add ... type gre local 192.0.2.1 remote
    192.0.2.2` is refused with `File exists` whether or not the first is up.

    Tunnel 13 is the one deliberate exception (BLO-29009): it is the only test
    needing two DIMT tunnels alive at once, so it carries its own outer remote.
    That is a property of that test, not a weakening of this reaping -- this
    reaps by the dimt- prefix, so it collects every id regardless of endpoints.

    That is why this reaps by prefix rather than by the id under test, and why
    it runs before as well as after: a link surviving from a previous MODULE, or
    from an interrupted run, wedges the first test just as effectively.

    The two call sites are NOT symmetric.  Teardown never raises: a cleanup
    failure must not convert a passing test into an error, nor mask the real
    failure of a failing one.  Setup is a PRECONDITION, so it asserts its
    postcondition -- a silent no-op there hands the test a dirty kernel, it
    dies at its setup add() with `File exists`, and that is precisely the
    cascade signature this fixture exists to erase.  Reintroducing it one
    layer down, unlogged, is how it gets misread as a zebra defect twice.
    """
    _reap_dimt_links()
    try:
        stray = _dimt_links()
    except LinkTableUnreadable as exc:
        pytest.fail(
            "cannot establish the clean-kernel precondition: {}. Refusing to "
            "run: an unreadable link table is indistinguishable from a clean "
            "one, and telling those apart is the entire job of this "
            "fixture.".format(exc)
        )
    if stray:
        pytest.fail(
            "stray DIMT links survived the pre-test reap: {}. Every tunnel in "
            "this module shares the 192.0.2.1 -> 192.0.2.2 endpoints, so the "
            "next create would fail with `File exists` for a reason that has "
            "nothing to do with the behaviour under test.".format(
                ", ".join(stray))
        )
    yield
    _reap_dimt_links()


class LinkTableUnreadable(RuntimeError):
    """r1's link table could not be read -- distinct from it being empty."""


_RC_MARKER = "__DIMT_LINK_RC__"


def _split_rc(out):
    """Split trailing `__DIMT_LINK_RC__=N` off command output.

    Returns (output_without_marker, rc).  A missing marker means the command
    did not run to completion, which is itself unreadable, so it is reported
    as a non-zero rc rather than silently treated as success.
    """
    lines = _text(out).splitlines()
    for i in range(len(lines) - 1, -1, -1):
        stripped = lines[i].strip()
        if stripped.startswith(_RC_MARKER + "="):
            del lines[i]
            try:
                return "\n".join(lines), int(stripped.split("=", 1)[1])
            except ValueError:
                break
    return "\n".join(lines), -1


def _dimt_links():
    """Names of the dimt-* links present on r1.

    Raises LinkTableUnreadable if the table cannot be read, and deliberately
    does NOT fall back to [].  "Could not read the link table" and "the link
    table is clean" are different answers, and collapsing them into [] makes
    the setup postcondition pass vacuously -- a guard that runs and reports
    success without having established anything, which is the same shape as
    the cascade this fixture exists to erase, one layer down.

    stderr is captured rather than discarded so the caller that cares can
    print the reason.  The two callers choose their own tolerance: teardown
    swallows this, setup does not.
    """
    tgen = get_topogen()
    if tgen is None:
        raise LinkTableUnreadable("no topology is running")
    router = tgen.gears.get("r1")
    if router is None:
        raise LinkTableUnreadable("router r1 is not in the topology")
    try:
        out = router.run("ip -o link show 2>&1; echo {}=$?".format(_RC_MARKER))
    except Exception as exc:
        raise LinkTableUnreadable("`ip -o link show` raised: {}".format(exc))
    out, rc = _split_rc(out)
    if rc != 0:
        raise LinkTableUnreadable(
            "`ip -o link show` exited {}: {}".format(rc, out.strip() or "(no output)")
        )
    names = []
    for line in out.splitlines():
        # `N: name@parent: <FLAGS> ...` -- the parent suffix is present on GRE
        # links, so strip it before matching.
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip().split("@", 1)[0]
        if name.startswith("dimt-"):
            names.append(name)
    return names


def _reap_dimt_links():
    tgen = get_topogen()
    if tgen is None:
        return
    router = tgen.gears.get("r1")
    if router is None:
        return
    try:
        names = _dimt_links()
    except LinkTableUnreadable:
        # Reaping is best-effort by design; the strict read lives in setup.
        return
    for name in names:
        try:
            router.run("ip link del {}".format(name))
        except Exception:
            pass


# Unused in the topology (r1 is 192.0.2.1, h1 is 192.0.2.2), so it gives
# tunnel 13 a GRE identity distinct from every other tunnel here.  It never
# has to be reachable: the kernel does not validate the remote at create time
# and this test asserts only on ZAPI results, never on traffic.
TUNNEL_13_OUTER_REMOTE = "192.0.2.3"


def request(action, tunnel_id, encap="gre", outer_remote=None, outer_local=None):
    """Drive one DIMT ZAPI add/del against r1.

    outer_remote overrides the GRE tunnel's remote endpoint.  It is only
    needed by a test that must hold two DIMT tunnels up at the same time --
    see TUNNEL_13_OUTER_REMOTE.  outer_local likewise, for the IPv6-outer
    (ip6gre) test.  del carries no endpoints, so both are add-only.
    """
    client = os.path.join(CWD, "dimt_zapi_client.py")
    command = "python3 {} {} {} --encap {}".format(client, action, tunnel_id, encap)
    if outer_remote is not None:
        command += " --outer-remote {}".format(outer_remote)
    if outer_local is not None:
        command += " --outer-local {}".format(outer_local)
    output = get_topogen().gears["r1"].run(command)
    return json.loads(output)


# Never requested by this module, so zebra holds no entry for it and answers
# its DEL REMOVED at once from the no-entry branch -- which is what makes it
# usable as dimt_zapi_client.py's --barrier: zebra serves one session's
# messages in order, so an answer to the request that arrives after the
# barrier's REMOVED was not zebra's direct reply to it.
BARRIER_TUNNEL_ID = 0xFFFFFFF0


def client_argv(*args):
    """argv for a dimt_zapi_client.py run under router.popen()."""
    client = os.path.join(CWD, "dimt_zapi_client.py")
    return ["python3", client] + [str(arg) for arg in args]


class NotifyReader:
    """The JSON lines a --follow/--barrier client prints, one at a time.

    communicate() waits for the client to exit, and the tests using this act
    between its lines. select() on the raw fd rather than readline(): a
    buffered reader can pull a second line into its buffer where select()
    cannot see it, and the wait for it would then time out with the line in
    hand.
    """

    def __init__(self, proc):
        self.fd = proc.stdout.fileno()
        self.buf = b""
        # Everything read so far, for assertion messages.
        self.lines = []

    def next(self, timeout):
        """The next line, parsed; None on timeout or once the client exits."""
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buf:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            ready, _, _ = select.select([self.fd], [], [], left)
            if not ready:
                return None
            chunk = os.read(self.fd, 4096)
            if not chunk:
                return None
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        text = line.decode("utf-8", "replace")
        self.lines.append(text)
        return json.loads(text)


def finish_client(proc, timeout=5):
    """Reap a popen'd client, killing it if it outlives `timeout`.

    Returns its stderr. A --follow client that is still waiting when its test
    is done -- because the notify it waits for never came -- must not be left
    holding an owner session into the next test.
    """
    try:
        _stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        _stdout, stderr = proc.communicate(timeout=timeout)
    return _text(stderr)


def kernel_ifindex(router, name):
    """The kernel's ifindex for `name`, or None if there is no such link."""
    out = router.run(
        "cat /sys/class/net/{}/ifindex 2>/dev/null".format(name)
    ).strip()
    return int(out) if out.isdigit() else None


def _route_netlink_fds(router, thread_id):
    """Return zebra's route-netlink FDs as an strace -e trace-fds= set.

    This scan does NOT narrow anything to the dplane thread, and reading it
    that way would credit it with a precision it does not have.  Linux
    threads share one descriptor table, so /proc/<tid>/fd is the whole of
    zebra's -- the returned set includes the main thread's netlink and
    netlink_cmd sockets alongside netlink_dplane_out/_in.  Confinement to
    the dplane comes from `strace -p <dplane_tid>`; all this scan does is
    exclude sockets that are not NETLINK_ROUTE, notably the genetlink
    ge_netlink_cmd (protocol 16) whose ethtool probes the old unnarrowed
    when=N ordinal was landing on (BLO-28405).

    thread_id serves both paths: /proc/<tid>/net is the thread's netns view
    and is identical to /proc/<pid>/net, so no separate zebra pid is needed.
    """
    command = (
        "for fd in /proc/{}/fd/*; do "
        "target=$(readlink \"$fd\" 2>/dev/null) || continue; "
        "case \"$target\" in socket:\\[*\\]) ;; *) continue ;; esac; "
        "inode=${{target#socket:[}}; inode=${{inode%]}}; "
        # /proc/net/netlink's Eth column is field 2; NETLINK_ROUTE is 0.
        "awk -v inode=\"$inode\" 'NR > 1 && $2 == 0 && $10 == inode "
        "{{ found=1 }} END {{ exit !found }}' "
        "/proc/{}/net/netlink >/dev/null 2>&1 && "
        "basename \"$fd\"; "
        "done"
    ).format(thread_id, thread_id)
    fds = router.run(command).split()
    if not fds:
        pytest.fail(
            "zebra_dplane route-netlink FD not found -- "
            "send-side failure injection cannot run"
        )
    return ",".join(fds)


def _await_strace_attached(router, worker, tracer):
    """Return once strace is tracing the dplane worker; fail if it never is.

    A fixed sleep after starting strace was the only sync, and under load
    strace attached after the worker's first sendmsg: with when=2 the
    address-add became the FIRST traced call, nothing was injected, and the
    test stopped on assert_injection_fired() as not having executed. The
    worker's TracerPid turns non-zero on PTRACE_SEIZE, which strace follows
    with its interrupt at once; the short settle covers that gap.
    """
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if tracer.poll() is not None:
            _stdout, stderr = tracer.communicate()
            pytest.fail(
                "strace attach failed: {}".format(_text(stderr).strip())
            )
        status = router.run(
            "awk '/^TracerPid:/ {{print $2}}' /proc/{}/status".format(worker)
        ).strip()
        if status not in ("", "0"):
            time.sleep(0.1)
            return
        time.sleep(0.05)
    pytest.fail("strace never attached to the zebra_dplane worker")


def inject_netlink_syscall_failure(
    router, syscall, when, errno_name="EIO", route_netlink_fds=False
):
    require_strace(router)
    worker = dplane_tid(router, "netlink failure injection cannot run")
    command = [
        "strace",
        "-qq",
        "-e",
        "trace={}".format(syscall),
    ]
    if route_netlink_fds:
        command.extend(
            ["-e", "trace-fds={}".format(_route_netlink_fds(router, worker))]
        )
    command.extend(
        [
            "-e",
            "inject={}:error={}:when={}".format(syscall, errno_name, when),
            "-p",
            worker,
        ],
    )
    tracer = router.popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _await_strace_attached(router, worker, tracer)
    # Derived from the same arguments that built the strace command, so the
    # diagnostic cannot drift from the injection.  It drifted once: the recv
    # site said EIO while inject_netlink_recv_failure() deliberately injects
    # EAGAIN, pointing a triager at the exact errno that helper exists to
    # keep out (EIO on the recv side takes zebra's fatal path).
    tracer.injection_label = "{} {} injection at when={}".format(
        syscall, errno_name, when
    )
    tracer.injection_tag = "(INJECTED)"
    return tracer


def inject_netlink_send_failure(router, when):
    """Fail the when'th route-netlink sendmsg issued by the dplane worker.

    `when` counts dplane route-netlink sendmsg CALLS, and nl_batch_send()
    packs several netlink messages per call -- so the ordinal is over
    BATCHES, not over operations.  when=2 lands on the address-add only
    because zebra must flush the link-create in its own batch (the address
    needs the resulting ifindex).  If batching ever coalesces the two, the
    ordinal silently re-points at a later operation and
    assert_injection_fired() still passes, because it only proves that
    SOME injection fired; the symptom would surface as
    `assert failed["result"] == 1` -- i.e. dressed up as a zebra defect.
    Re-derive the ordinal from the trace before believing that.
    """
    return inject_netlink_syscall_failure(
        router, "sendmsg", when, route_netlink_fds=True
    )


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


# topotest.run_and_expect() silently replaces any count*wait under 15s with its
# own defaults (count=20, wait=3), so a fine-grained poll has to budget at least
# 15s or it becomes a 3s poll. Granularity is load-bearing for the two
# held-DELETE syncs, which act inside the hold as soon as they resolve; the
# convergence polls around them share the budget so it is stated once. 80
# steps of 0.2s: 16s of sleep, above the longest runner stall seen in CI
# (~6.7s). That is not a wall-clock bound: each step also pays a vtysh round
# trip, so the real worst case is 80 x (0.2s + vtysh latency), and a timeout
# that must outlast a sync has to be sized well above 16s. It stays below
# HELD_DELETE_USECS for the vtysh latencies seen in CI, so a window that
# never opens is reported before the hold would have expired.
SYNC_POLL_COUNT = 80
SYNC_POLL_WAIT = 0.2


def hold_dplane_sendmsg(router, delay_usecs):
    """Hold the dplane worker at route-netlink sendmsg ENTRY.

    One of the module's two dplane holds, deliberately; the other is
    hold_dplane_in_recvmsg(), and both hold a syscall the worker is known to
    make. zebra is built with USE_EPOLL, so its event loops block in
    epoll_pwait; a hold on the worker's wakeup (the since-removed
    hold_dplane_worker() delayed ppoll/poll, which this build never calls)
    engages nothing, and would not help if it did: link notifications arrive
    on netlink_dplane_in, which this same pthread reads, so freezing it
    freezes main's view of the kernel too.

    At sendmsg entry the netlink message is fully encoded (all identity checks
    have run) but not yet delivered, so the kernel has not acted on it and no
    result exists -- zebra's main thread still holds the entry in the state it
    set before enqueueing. -e trace-fds= confines the hold to route-netlink
    sockets: unnarrowed, the ethtool probes zebra sends on the genetlink
    ge_netlink_cmd socket could be held instead of, or ahead of, the message a
    test is waiting for (2 of 36 CI runs synced on one, BLO-28405's mis-aim
    again). Returns (tracer, trace_file); the -o trace file records each
    decoded sendmsg, so callers synchronize positively with dellink_state()
    instead of guessing with sleeps.
    """
    trace_file = "/tmp/dimt-sendmsg-trace-{}.log".format(os.getpid())
    router.run("rm -f {}".format(trace_file))
    tracer = _hold_dplane_syscalls(
        router, "sendmsg", "delay_enter", delay_usecs, trace_file,
        trace_fds_for=_route_netlink_fds,
    )
    return tracer, trace_file


def dellink_state(router, trace_file, ifname, ifindex):
    """Where the dplane's RTM_DELLINK for `ifname` is: None, "held", "returned".

    strace -o writes a traced call's line at syscall ENTRY and completes it
    with ") = <ret>" only when the call returns; with a single traced task
    nothing interleaves, so a matching line with no ") = " is a delete that
    has entered sendmsg and is being held there (measured on strace 5.16 and
    6.8: the line stays open for the whole delay_enter hold, the link is still
    in the kernel throughout, and it closes as ") = 32 (DELAYED)" on release).
    "held" therefore proves main has already moved the entry to DELETING
    (zebra_dimt.c sets it before dplane_dimt_tunnel_del() enqueues) and that
    the kernel has not yet deleted the link, so no REMOVED can exist yet.

    In CI's trace lines strace names the link as if_nametoindex("<name>")
    while the index still resolves; the bare ifi_index=<n> form is matched
    too, anchored so ifi_index=2 cannot match ifi_index=20. If strace cannot
    tell the socket is NETLINK_ROUTE it prints nlmsg_type=0x11 and the
    ifinfomsg as raw bytes (seen in a container, never in CI); that matches
    nothing here, so a caller's sync times out and reports the trace rather
    than passing on a guess.
    """
    text = router.run("cat {} 2>/dev/null".format(trace_file))
    by_name = 'if_nametoindex("{}")'.format(ifname)
    by_index = re.compile(r"ifi_index={}(?![0-9])".format(int(ifindex)))
    state = None
    for line in text.splitlines():
        if "nlmsg_type=RTM_DELLINK" not in line:
            continue
        if by_name not in line and not by_index.search(line):
            continue
        state = "returned" if ") = " in line else "held"
    return state


def _trace_text(router, trace_file):
    return router.run("cat {} 2>/dev/null".format(trace_file)).strip()


def _dplane_in_fd(router, thread_id):
    """Return the FD of zebra's netlink_dplane_in socket, as a trace-fds= set.

    Of zebra's NETLINK_ROUTE sockets only netlink_dplane_in joins RTMGRP_LINK:
    kernel_init() (zebra/kernel_netlink.c) gives netlink-listen the route,
    rule and nexthop groups and netlink_cmd and netlink_dplane_out none. So it
    is the one whose /proc/net/netlink row -- protocol 0 (field 2), matching
    inode (field 10) -- has bit 0x1 set in the Groups column (field 4, the
    first 32 groups in hex). The same FD-table caveat as _route_netlink_fds()
    applies: confinement to the dplane pthread comes from strace -p, not from
    this scan.

    Exactly one must match. None means zebra's socket layout changed; more
    than one means a second NETLINK_ROUTE socket now joins the link group,
    and holding either alone would no longer freeze main's view of links.
    Both are harness errors, so pytest.fail rather than WindowNeverOpened.
    """
    command = (
        "for fd in /proc/{}/fd/*; do "
        "target=$(readlink \"$fd\" 2>/dev/null) || continue; "
        "case \"$target\" in socket:\\[*\\]) ;; *) continue ;; esac; "
        "inode=${{target#socket:[}}; inode=${{inode%]}}; "
        "groups=$(awk -v inode=\"$inode\" 'NR > 1 && $2 == 0 && "
        "$10 == inode {{ print $4 }}' /proc/{}/net/netlink 2>/dev/null); "
        "[ -n \"$groups\" ] && [ $(( 0x$groups & 1 )) -ne 0 ] && "
        "basename \"$fd\"; "
        "done"
    ).format(thread_id, thread_id)
    fds = router.run(command).split()
    if len(fds) != 1:
        pytest.fail(
            "expected exactly one zebra NETLINK_ROUTE socket in RTMGRP_LINK "
            "(netlink_dplane_in), found {}: {} -- the dplane_in hold cannot "
            "be aimed".format(len(fds), fds or "none")
        )
    return fds[0]


def hold_dplane_in_recvmsg(router, delay_usecs):
    """Hold the dplane worker at netlink_dplane_in recvmsg ENTRY.

    Link notifications reach main only through this socket, so while the hold
    is engaged main keeps listing a deleted link at its old ifindex -- the
    REMOVED-before-RTM_DELLINK gap (BLO-38034) held open. Everything else the
    worker does is untouched, and must be: a DIMT delete's own ACK is read on
    netlink_dplane_out. The worker hands that result to main either in the
    dplane_thread_loop() pass that read the ACK or, if that pass yields, in
    the rescheduled one: event_should_yield() is checked after the kernel
    provider's dp_fp and before its out queue is dequeued, and any delete
    slower than the 10ms slot passes it. The reschedule is a queued event,
    and event_fetch() moves queued events to the ready list before it polls
    for I/O, so the rescheduled pass runs before any dplane_in read. That
    holds for one yield, not two: the zero-timeout poll after the first
    yield finds dplane_in readable (the delete's own notifications are
    queued by then) and appends the read behind the rescheduled pass, and
    if that pass yields again -- slower than the slot, under load -- the
    read runs first and the hold catches it before the result reaches main.
    Callers recognise that shape (no REMOVED, one recvmsg held) and retry
    rather than report it as the regression. Holding any other route-netlink
    FD would hold the ACK too, and the gap would never open.

    strace -o writes recvmsg's line at entry and completes it with ") = "
    only on return; the buffer is an output argument, so the open line cannot
    say WHICH notification it is about to read. held_recvmsg_lines() counts
    them; callers prove the rest from zebra's and the kernel's own state.
    Returns (tracer, trace_file).
    """
    trace_file = "/tmp/dimt-recvmsg-trace-{}.log".format(os.getpid())
    router.run("rm -f {}".format(trace_file))
    tracer = _hold_dplane_syscalls(
        router, "recvmsg", "delay_enter", delay_usecs, trace_file,
        trace_fds_for=_dplane_in_fd,
    )
    return tracer, trace_file


def held_recvmsg_lines(router, trace_file):
    """(open, returned) counts of the recvmsg lines in a dplane_in trace."""
    lines = [
        line
        for line in _trace_text(router, trace_file).splitlines()
        if line.startswith("recvmsg(")
    ]
    returned = sum(1 for line in lines if ") = " in line)
    return len(lines) - returned, returned


def _hold_dplane_syscalls(router, syscalls, inject_kind, delay_usecs,
                          trace_file=None, trace_fds_for=None):
    # trace_fds_for(router, worker) aims the hold at the worker's FDs. It is
    # applied to the one TID resolved here, so the narrowing and the -p target
    # cannot come from two different resolves: a caller-side lookup that missed
    # while this one succeeded used to arm the hold unnarrowed (BLO-28405).
    require_strace(router)
    worker = dplane_tid(router, "cannot hold the dplane worker")
    trace_fds = trace_fds_for(router, worker) if trace_fds_for else None
    cmd = [
        "strace",
        "-qq",
        "-e",
        "trace={}".format(syscalls),
    ]
    if trace_fds:
        cmd.extend(["-e", "trace-fds={}".format(trace_fds)])
    cmd.extend(
        [
            "-e",
            "inject={}:{}={}".format(syscalls, inject_kind, delay_usecs),
            "-p",
            worker,
        ]
    )
    if trace_file:
        cmd[1:1] = ["-o", trace_file]
    tracer = router.popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _await_strace_attached(router, worker, tracer)
    # Same contract as inject_netlink_syscall_failure() above, and derived from
    # the same arguments that built the command for the same anti-drift reason:
    # a diagnostic that names the hold cannot drift from the hold.
    tracer.injection_label = "{} {}={} hold".format(
        syscalls, inject_kind, delay_usecs
    )
    # NOT "(INJECTED)" -- strace tags a delay "(DELAYED)". See
    # assert_injection_fired() for the measurement.
    #
    # Published for symmetry, but a hold site must NOT feed stop_tracer()'s
    # output to assert_injection_fired(): with -o the trace goes to the file,
    # so stderr is empty by construction, and a hold released early by
    # stop_tracer() never completes its line at all. Measured on strace 5.16 and
    # 6.8 in a privileged container: terminating strace mid-delay releases the
    # tracee at once, for delay_enter and delay_exit alike. The hold sites
    # prove the hold from the trace file instead, with dellink_state().
    tracer.injection_tag = "(DELAYED)"
    return tracer


def _text(data):
    """popen output is str under some topotest/python combinations and bytes
    under others.  Four tests died on AttributeError: 'str' object has no
    attribute 'decode' -- a harness bug that had been sitting under the
    since-removed BLO-28405 xfail, attributed to zebra.
    """
    if data is None:
        return ""
    return data if isinstance(data, str) else data.decode("utf-8", "replace")


def stop_tracer(tracer):
    """Stop the tracer and return what strace wrote to stderr.

    The stderr pipe was opened and never read, which is why a no-op injection
    was indistinguishable from a fired one.  That matters most on the RECV
    side: EAGAIN is the normal batch terminator, so a SUCCESSFUL lost-ack
    injection writes nothing to zebra.out at all -- it is invisible by
    construction, and there has never been positive proof it fired.  strace
    tags injected calls `(INJECTED)`, so its own output is the only evidence
    available.  Reading it also removes a latent deadlock: wait() on a process
    with a full stderr pipe blocks forever.
    """
    tracer.terminate()
    try:
        err = tracer.communicate(timeout=2)[1]
    except subprocess.TimeoutExpired:
        tracer.kill()
        err = tracer.communicate(timeout=2)[1]
    if not err:
        return ""
    return err if isinstance(err, str) else err.decode("utf-8", "replace")


def assert_injection_fired(trace_output, what, tag="(INJECTED)"):
    """Refuse to assert on a run whose injection may never have happened.

    Deliberately pytest.fail() rather than assert: it raises Failed, not
    AssertionError, so it escapes the raises=AssertionError xfail markers
    instead of being absorbed by them as an expected failure.  A marker that
    swallows "the injection did not fire" is exactly how a test can appear to
    confirm a defect it never exercised.

    `tag` is which strace annotation counts as proof, because strace does NOT
    use one word for both injection kinds -- measured on strace 6.8:

        -e inject=write:error=EIO       -> "= -1 EIO (...) (INJECTED)"
        -e inject=write:delay_enter=N   -> "= 6 (DELAYED)"

    So an error injection is proved by "(INJECTED)" and a delay/hold by
    "(DELAYED)". Pass tracer.injection_tag rather than hardcoding either;
    both tracer-returning helpers set it beside injection_label.
    """
    if tag not in trace_output:
        pytest.fail(
            "{}: strace reported no {} syscall, so anything asserted "
            "below would describe an UNINJECTED run. Treat this as the test "
            "not having executed, not as evidence about zebra.\n"
            "strace stderr was:\n{}".format(
                what, tag, trace_output.strip() or "(empty)")
        )


def dplane_tid(router, purpose):
    """The zebra_dplane pthread's TID. Anything but exactly one numeric TID
    is a harness error: pytest.fail() names which, then `purpose`.

    router.run() returns stderr with stdout, so each read here discards its
    own. A zebra thread that exits between the task glob and its comm read
    used to make `cat` print its error into the result, and _dplane_in_fd()
    then spliced "<tid>\\ncat: ..." into its shell loop, which died as a bash
    syntax error near `cat:' instead of naming the problem.

    None and several are told apart the way _dplane_in_fd() tells apart its
    own none-vs-several, so a second dplane thread would not read as a
    missing one.
    """
    zebra_pid = router.run("cat /var/run/frr/zebra.pid 2>/dev/null").strip()
    if not zebra_pid.isdigit():
        pytest.fail(
            "zebra_dplane worker not found: no zebra pid (read {!r}) -- "
            "{}".format(zebra_pid, purpose)
        )
    tids = router.run(
        f"for task in /proc/{zebra_pid}/task/*; do "
        '[ "$(cat $task/comm 2>/dev/null)" = zebra_dplane ] && basename "$task"; '
        "done"
    ).split()
    if not tids:
        pytest.fail(
            "zebra_dplane worker not found: zebra {} has no zebra_dplane "
            "thread -- {}".format(zebra_pid, purpose)
        )
    if not all(tid.isdigit() for tid in tids):
        pytest.fail(
            "zebra_dplane worker not parsed: the task scan of zebra {} "
            "returned {}, not TIDs -- {}".format(zebra_pid, tids, purpose)
        )
    if len(tids) != 1:
        pytest.fail(
            "zebra_dplane worker not uniquely resolved: expected one "
            "zebra_dplane TID in zebra {}, found {}: {} -- {}".format(
                zebra_pid, len(tids), tids, purpose)
        )
    return tids[0]


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
    # ttl=64: a DIMT netdev never inherits its outer TTL.  Inheriting copies
    # the inner TTL 1 of every link-local PIM/IGMP packet onto the outer
    # header, so control traffic dies at the first transit router of a
    # multi-hop underlay (zebra/zebra_dplane.h, ZEBRA_DIMT_TUNNEL_TTL).
    kernel_error = check_gre_link(
        router,
        "dimt-00000001",
        local="192.0.2.1",
        remote="192.0.2.2",
        mtu=1476,
        ttl=64,
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
        lambda: router.run("ip link show dimt-00000001 2>/dev/null"),
        "",
        count=10,
        wait=0.2,
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
    # Act only once zebra has processed both. Until it has, it still lists the
    # deleted link at its old ifindex, so the identical retry below would be
    # answered INSTALLED from the entry, for the ordinary reason. Once it has,
    # the entry is gone: processing an out-of-band delete forgets an INSTALLED
    # entry outright (BLO-38034, test_out_of_band_delete_tells_the_owner), so
    # the retry is a fresh create and its FAIL_INSTALL is the kernel refusing
    # the exclusive create on the dummy's name. It used to come from
    # zebra_dimt_tunnel_resolve_ifindex() missing on the vanished index.
    _, seen = topotest.run_and_expect(
        lambda: zebra_ifindex(router, "dimt-00000003")
        not in (None, 0, installed["ifindex"]),
        True,
        count=SYNC_POLL_COUNT,
        wait=SYNC_POLL_WAIT,
    )
    assert seen, "zebra did not process the replacement link"

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


# The owner sessions below stay open across an out-of-band event and wait for
# zebra to report it. The client's per-wait socket timeout sits well above
# the SYNC_POLL_* sync that runs before each wait -- 16s of sleep plus a vtysh
# round trip per step, see SYNC_POLL_COUNT -- so a client cannot give up while
# the test is still synchronizing. A --follow 1 client exits on the notify it
# waits for, so the bound costs nothing when zebra answers.
OWNER_FOLLOW_TIMEOUT = 60


@pytest.mark.parametrize("configured", [False, True], ids=["learned", "configured"])
def test_out_of_band_delete_tells_the_owner(configured):
    """An out-of-band delete of an INSTALLED DIMT link answers the owner REMOVED.

    BLO-38034: zebra's old if_del hook never matched. if_delete_update() resets
    the ifindex to IFINDEX_INTERNAL and clears the l2info before if_delete()
    fires the hook, and a CONFIGURED interface never reaches if_delete() at
    all -- hence the second case, which configures the name in zebra first so
    the ifp outlives the link. Either way the entry stayed INSTALLED on the
    vanished index and pimd was never told: an operator `ip link del` or a
    netns teardown left it believing the tunnel was up.

    The configured case only tests that if the name really is configured, so
    it goes through plain vtysh -- `interface` is a mgmtd command, and mgmtd
    pushes it to zebra; `vtysh -d zebra` would drop it silently, since zebra
    has no interface node of its own -- and zebra must list it as a
    pseudoInterface before the ADD. After the delete each case must leave its
    own shape: the learned ifp freed ("{}"), the configured one kept with no
    index. zebra_dropped_interface() accepts either, so it cannot say which
    path ran.

    That strict check is also the positive control: zebra has processed the
    RTM_DELLINK, so a REMOVED that has not arrived by then never will. The
    deciding assertion is the add after it: with the entry forgotten it is a
    fresh create, INSTALLED on the new link's index. Before the fix it was
    answered FAIL_INSTALL, when zebra_dimt_tunnel_resolve_ifindex() missed on
    the stale index.
    """
    router = get_topogen().gears["r1"]
    tunnel_id = 19 if configured else 18
    name = "dimt-{:08x}".format(tunnel_id)
    removed_config = None
    if configured:
        router.vtysh_cmd("configure terminal\ninterface {}\nend".format(name))
    try:
        if configured:
            _, kept = topotest.run_and_expect(
                lambda: zebra_kept_configured_interface(router, name),
                True,
                count=SYNC_POLL_COUNT,
                wait=SYNC_POLL_WAIT,
            )
            assert kept, "zebra never listed configured {}: {}".format(
                name, zebra_interface_entry(router, name))
        owner = router.popen(
            client_argv("add", tunnel_id, "--follow", 1,
                        "--timeout", OWNER_FOLLOW_TIMEOUT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        reader = NotifyReader(owner)
        try:
            installed = reader.next(timeout=15)
            assert installed is not None and installed.get("result") == 0, (
                installed, reader.lines)
            ifindex = installed["ifindex"]
            assert ifindex > 0, installed

            router.run("ip link del {}".format(name))

            # Not zebra_dropped_interface(): it accepts both shapes, so a
            # configured ifp freed on the delete -- the path this case exists
            # to avoid -- would pass as "dropped".
            def gone():
                if configured:
                    return zebra_kept_configured_interface(router, name)
                return zebra_interface_entry(router, name) is None

            _, dropped = topotest.run_and_expect(
                gone, True, count=SYNC_POLL_COUNT, wait=SYNC_POLL_WAIT
            )
            assert dropped, "zebra did not drop {} as {}: {}".format(
                name, "configured" if configured else "learned",
                zebra_interface_entry(router, name))
            # zebra notifies in the same pass that drops the interface, so the
            # notify is on its way by now; the wait only covers delivery.
            vanished = reader.next(timeout=10)
            assert vanished == {
                "tunnel_id": tunnel_id, "ifindex": 0, "result": 2
            }, (vanished, reader.lines)
        finally:
            stderr = finish_client(owner)
        assert owner.returncode == 0, stderr

        readd = request("add", tunnel_id)
        assert readd["result"] == 0, readd
        assert readd["ifindex"] != ifindex, (installed, readd)
        assert readd["ifindex"] == kernel_ifindex(router, name), readd
        assert request("del", tunnel_id)["result"] == 2
    finally:
        if configured:
            # `no interface` refuses an interface that is still active, so the
            # link has to be gone from zebra's table first.
            router.run("ip link del {} 2>/dev/null".format(name))
            topotest.run_and_expect(
                lambda: zebra_dropped_interface(router, name),
                True,
                count=SYNC_POLL_COUNT,
                wait=SYNC_POLL_WAIT,
            )
            router.vtysh_cmd(
                "configure terminal\nno interface {}\nend".format(name)
            )
            _, removed_config = topotest.run_and_expect(
                lambda: zebra_interface_entry(router, name) is None,
                True,
                count=SYNC_POLL_COUNT,
                wait=SYNC_POLL_WAIT,
            )
    # Outside the finally so it cannot mask the failure that got us there.
    if configured:
        assert removed_config, "`no interface {}` left: {}".format(
            name, zebra_interface_entry(router, name))


# Within IFNAMSIZ and carrying the dimt- prefix, so the reaper collects it.
RENAMED_DIMT_LINK = "dimt-renamed"
# How long the owner session listens for a REMOVED that must not come. Well
# above the rename sync's real worst case (16s of sleep plus a vtysh round
# trip per step, see SYNC_POLL_COUNT), but not relied on: the test checks the
# session was still listening when the sync succeeded, because a session that
# had stopped would make silence vacuous. The silence is paid in full on
# every pass, so it is not raised further.
RENAME_OWNER_TIMEOUT = 45
# Delivery slack for a REMOVED zebra would have queued in the rename's pass:
# the session must have this much of its timeout left when the sync succeeds.
RENAME_LISTEN_MARGIN = 5


def test_rename_is_not_reported_removed():
    """A rename keeps the netdev, so it must not tell the owner REMOVED.

    zebra sees a rename as RTM_NEWLINK for a known index under a new name, and
    set_ifindex() retires the old-name interface through the same
    if_delete_update() an out-of-band delete takes. Only a deletion proves the
    netdev gone, so only it may report REMOVED (BLO-38034); reporting it here
    would have pimd rebuild a tunnel whose link is still in the kernel, and
    collide with it on the GRE tuple.

    The owner session is the evidence: zebra would notify it in the same pass
    that renames the interface, which the zebra_ifindex() sync below waits
    for. The test then proves the session was still listening at that point
    -- the client restarts its per-recv timeout only after printing
    INSTALLED, so its deadline is no earlier than RENAME_OWNER_TIMEOUT after
    that print; at least RENAME_LISTEN_MARGIN of it is left, the client is
    running and nothing has arrived -- so a REMOVED would have been seen;
    otherwise it raises WindowNeverOpened rather than pass on silence. The later DEL is
    answered REMOVED
    because zebra_dimt_tunnel_resolve_ifindex() misses on the name, with no
    dataplane operation -- the renamed link is not ours by name any more and
    is left alone.
    """
    router = get_topogen().gears["r1"]
    name = "dimt-00000015"
    owner = router.popen(
        client_argv("add", 21, "--follow", 1,
                    "--timeout", RENAME_OWNER_TIMEOUT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    reader = NotifyReader(owner)
    try:
        installed = reader.next(timeout=15)
        # The client's next recv starts after it prints this line, and each
        # recv restarts its timeout, so its deadline is no earlier than
        # RENAME_OWNER_TIMEOUT after the print. t_installed trails the print
        # only by the reader's wake-up latency, which RENAME_LISTEN_MARGIN
        # covers.
        t_installed = time.monotonic()
        assert installed is not None and installed.get("result") == 0, (
            installed, reader.lines)
        ifindex = installed["ifindex"]

        renamed = router.run(
            "ip link set {0} down && ip link set {0} name {1} && "
            "echo RENAMED".format(name, RENAMED_DIMT_LINK)
        )
        assert "RENAMED" in renamed, renamed
        _, seen = topotest.run_and_expect(
            lambda: zebra_ifindex(router, RENAMED_DIMT_LINK) == ifindex,
            True,
            count=SYNC_POLL_COUNT,
            wait=SYNC_POLL_WAIT,
        )
        assert seen, "zebra did not process the rename"
        # The REMOVED this test guards against is sent in the pass that
        # processed the rename, so it is on its way now. Prove the session
        # was still there to read it: with time left on its recv, a line
        # here is the regression itself (asserted below), and a session
        # already gone would make the silence prove nothing.
        listened = time.monotonic() - t_installed
        early = reader.next(timeout=0.1)
        if (listened >= RENAME_OWNER_TIMEOUT - RENAME_LISTEN_MARGIN
                or (early is not None and "tunnel_id" not in early)
                or (early is None and owner.poll() is not None)):
            raise WindowNeverOpened(
                "the owner session may have stopped listening before zebra "
                "processed the rename ({:.1f}s of its {}s timeout used, "
                "line={!r}, rc={}), so silence would prove nothing".format(
                    listened, RENAME_OWNER_TIMEOUT, early, owner.poll()))
        assert early is None, (
            "zebra told the owner of a renamed link it was removed: {}".format(
                reader.lines))

        removed = request("del", 21)
        assert removed == {"tunnel_id": 21, "ifindex": 0, "result": 2}, removed
        # The DEL moved ownership to its own session, so nothing more is owed
        # to this one: the only line it may print is its own timeout.
        quiet = reader.next(timeout=RENAME_OWNER_TIMEOUT + 10)
        assert quiet == {"timeout": True}, (quiet, reader.lines)
    finally:
        finish_client(owner)
    assert "gre remote 192.0.2.2 local 192.0.2.1" in router.run(
        "ip -d link show {}".format(RENAMED_DIMT_LINK)
    )
    router.run("ip link del {}".format(RENAMED_DIMT_LINK))


def test_address_failure_cleans_up_and_allows_tunnel_id_reuse():
    router = get_topogen().gears["r1"]
    tracer = inject_netlink_send_failure(router, 2)
    try:
        failed = request("add", 4)
    finally:
        trace = stop_tracer(tracer)
    assert_injection_fired(trace, tracer.injection_label)
    # Only the TRACER used to be protected, so back when this assertion fired --
    # under the since-removed BLO-28405 xfail, before the injection was aimed at
    # the route-netlink socket -- the `del` at the end of the test never ran and
    # dimt-00000004 survived.  The autouse reaper now covers that regardless,
    # but the assertion still belongs after the tracer stop and before anything
    # that depends on the create having failed.
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
        trace = stop_tracer(tracer)
    # Same reasoning as the recv sites: under a no-op injection the delete
    # simply succeeds, and while the result assertion below would then fail, it
    # fails as "expected 3, got 2" -- which reads as a zebra defect. This says
    # "the injection never fired" instead, which is what actually happened.
    assert_injection_fired(trace, tracer.injection_label, tracer.injection_tag)
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


# Distinct from None ("{}", no such interface) so a caller can never read an
# unparseable vtysh reply as an answer.
UNPARSEABLE = object()


def zebra_interface_entry(router, name):
    """zebra's `show interface` JSON entry for `name`.

    None when zebra answers "{}", UNPARSEABLE when the reply is not JSON.
    """
    try:
        data = json.loads(
            router.vtysh_cmd("show interface {} json".format(name))
        )
    except ValueError:
        return UNPARSEABLE
    return data.get(name)


def zebra_kept_configured_interface(router, name):
    """True only for a configured `name` that zebra holds with no link.

    if_dump_vty_json() writes "pseudoInterface": true and returns before any
    "index" for an interface at IFINDEX_INTERNAL.
    """
    entry = zebra_interface_entry(router, name)
    return (
        isinstance(entry, dict)
        and entry.get("pseudoInterface") is True
        and "index" not in entry
    )


def zebra_dropped_interface(router, name):
    """True only once zebra's own table no longer holds `name` at an index.

    Not `zebra_ifindex() in (None, 0)`: that maps unparseable vtysh output (a
    connection error, a banner, a partial read) to None and so would read as
    "dropped" before zebra processed anything. Here only parsed JSON counts:
    "{}" (no such interface), or an entry with no "index" -- a configured
    interface zebra keeps at IFINDEX_INTERNAL is dumped as "pseudoInterface"
    and if_dump_vty_json() returns before writing any index.
    """
    try:
        data = json.loads(
            router.vtysh_cmd("show interface {} json".format(name))
        )
    except ValueError:
        return False
    entry = data.get(name)
    return entry is None or "index" not in entry


def test_queued_delete_does_not_remove_reused_ifindex():
    """A delete must not remove a same-name link that replaced ours.

    The link is replaced out-of-band first, and the DEL is sent only once
    zebra has processed the replacement. Processing the delete half already
    forgot the entry: it was INSTALLED, so zebra_dimt_tunnel_if_delete() told
    its owner REMOVED (that session is long closed) and dropped it
    (BLO-38034, test_out_of_band_delete_tells_the_owner). The DEL therefore
    finds no entry and is answered REMOVED from the no-entry branch with no
    dataplane operation -- leaving the same-name dummy alone. Before that fix
    the entry stayed INSTALLED on the vanished index and the same answer came
    from zebra_dimt_tunnel_resolve_ifindex() missing on it. Everything here
    runs on zebra's main thread, so it is deterministic.

    What this does NOT cover, despite the name it has kept: a delete already
    QUEUED in the dataplane when the replacement lands, reaching the pre-encode
    identity skip in netlink_put_dimt_tunnel_msg(). The test used to claim it,
    through hold_dplane_worker(), which never held anything (BLO-29000). No
    dplane hold can open that window deterministically either. Link
    notifications are read on the zebra_dplane pthread itself
    (netlink_dplane_in), so main learns of the replacement only when that
    thread runs; whether it has by the time the queued delete is encoded then
    depends on the order that thread's event loop services the two (queued
    events are posted before a pass's I/O, and one notification read makes at
    most five recvmsg() calls), which a syscall hold cannot pin. The skip
    path itself is covered without a kernel by tests/zebra/test_dimt_netlink.c:
    case (a) put-skip calls netlink_put_dimt_tunnel_msg() with a
    delete_ifindex the namespace does not list, cases C-F run it through
    kernel_update_multi(), and case J pins the encode-time recheck. The
    encoded-before-replacement half is covered for real by
    test_delete_encoded_before_replacement_binds_to_ifindex.
    """
    router = get_topogen().gears["r1"]
    installed = request("add", 6)
    assert installed["result"] == 0, installed

    router.run(
        "ip link del dimt-00000006; ip link add dimt-00000006 type dummy"
    )
    _, seen = topotest.run_and_expect(
        lambda: zebra_ifindex(router, "dimt-00000006")
        not in (None, 0, installed["ifindex"]),
        True,
        count=SYNC_POLL_COUNT,
        wait=SYNC_POLL_WAIT,
    )
    assert seen, "zebra did not process the replacement link"

    removed = request("del", 6)
    assert removed["result"] == 2, removed
    assert "dummy" in router.run("ip -d link show dimt-00000006")
    router.run("ip link del dimt-00000006")


# For the tests that hold a DIMT delete at sendmsg entry and act inside the
# hold. Longer than any runner stall seen in CI (~6.7s) plus the sync that
# detects the hold (SYNC_POLL_*: 80 x 0.2s steps, 16s of sleep plus a vtysh
# round trip each) and the action taken inside it, for the vtysh latencies
# seen in CI, so the hold cannot expire first; stop_tracer() ends it as soon as
# the test is done, so the bound costs nothing on the normal path. The held del
# client's socket timeout sits above it so the client cannot give up first.
HELD_DELETE_USECS = 30000000
HELD_DELETE_CLIENT_TIMEOUT = 45


def test_add_during_inflight_delete_is_rejected():
    router = get_topogen().gears["r1"]
    installed = request("add", 9)
    assert installed["result"] == 0, installed

    tracer, trace_file = hold_dplane_sendmsg(
        router, delay_usecs=HELD_DELETE_USECS
    )
    client = os.path.join(CWD, "dimt_zapi_client.py")
    try:
        pending = router.popen(
            ["python3", client, "del", "9", "--encap", "gre",
             "--timeout", str(HELD_DELETE_CLIENT_TIMEOUT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # The whole test is "an ADD *while a DELETE is in flight*", so prove
        # the delete is in flight before asserting anything about the ADD. A
        # held RTM_DELLINK for this link means main has set DELETING and the
        # kernel has not acted (see dellink_state()). Without this proof a
        # readd served before the DEL reaches zebra (INSTALLED, original
        # ifindex) or after it completes (fresh create, ifindex+1) returns 0
        # for the ORDINARY reason; both happened in CI under the old no-op
        # hold and read as a zebra defect. WindowNeverOpened, not assert: the
        # test did not run, which is not evidence about zebra.
        _, state = topotest.run_and_expect(
            lambda: dellink_state(
                router, trace_file, "dimt-00000009", installed["ifindex"]
            ),
            "held",
            count=SYNC_POLL_COUNT,
            wait=SYNC_POLL_WAIT,
        )
        if state != "held" or pending.poll() is not None:
            raise WindowNeverOpened(
                "no RTM_DELLINK for dimt-00000009 was held (state={}, del "
                "client rc={}), so nothing was in flight for the readd to "
                "race.\ntrace:\n{}".format(
                    state, pending.poll(), _trace_text(router, trace_file)))
        readd = request("add", 9)
        # ...and prove it was STILL in flight when zebra answered the readd:
        # the reply is in hand, so a delete still held now was held then.
        after = dellink_state(
            router, trace_file, "dimt-00000009", installed["ifindex"]
        )
        if after != "held":
            raise WindowNeverOpened(
                "the RTM_DELLINK hold ended (state={}) before the readd's reply "
                "was in hand, so the readd may have been served after the "
                "delete completed. readd={}\ntrace:\n{}".format(
                    after, readd, _trace_text(router, trace_file)))
        # An identical ADD while the delete is in flight must be rejected
        # instead of rebinding ownership: the delete completion belongs to
        # the delete requester. The ifindex is the entry's, untouched.
        assert readd["result"] == 1, readd
        assert readd["ifindex"] == installed["ifindex"], readd
    finally:
        stop_tracer(tracer)
        router.run("rm -f {}".format(trace_file))
    stdout, stderr = pending.communicate(timeout=15)
    assert pending.returncode == 0, _text(stderr)
    assert json.loads(_text(stdout))["result"] == 2
    _, link = topotest.run_and_expect(
        lambda: router.run("ip link show dimt-00000009 2>/dev/null"),
        "",
        count=10,
        wait=0.2,
    )
    assert link == "", link
    # No wait for zebra to drop the link first: a reinstall landing after
    # REMOVED but before main has processed the RTM_DELLINK is parked until it
    # has, then served as a fresh create (BLO-38034,
    # test_add_after_removed_before_dellink_is_parked). Either way it must be a
    # new link.
    reinstalled = request("add", 9)
    assert reinstalled["result"] == 0, reinstalled
    assert reinstalled["ifindex"] != installed["ifindex"], reinstalled
    assert "gre remote 192.0.2.2 local 192.0.2.1" in router.run(
        "ip -d link show dimt-00000009"
    )
    assert request("del", 9)["result"] == 2


def _prove_dellink_unread(router, name, ifindex, trace_file, when):
    """Raise WindowNeverOpened unless the REMOVED-before-RTM_DELLINK gap is open.

    Open means: the kernel has deleted the link, zebra still lists it at its
    old index (main has not processed the RTM_DELLINK), and the dplane_in
    trace holds exactly one recvmsg, entered and not returned -- the worker is
    parked in front of the notification. A returned recvmsg means a hold
    already expired and main may have read the notification since.
    """
    in_kernel = router.run("ip link show {} 2>/dev/null".format(name)).strip()
    listed = zebra_ifindex(router, name)
    held, returned = held_recvmsg_lines(router, trace_file)
    if in_kernel or listed != ifindex or held != 1 or returned:
        raise WindowNeverOpened(
            "{}: the gap between REMOVED and zebra processing {}'s "
            "RTM_DELLINK is not open (kernel={!r}, zebra ifindex={} want {}, "
            "dplane_in recvmsg held={} returned={}).\ntrace:\n{}".format(
                when, name, in_kernel, listed, ifindex, held, returned,
                _trace_text(router, trace_file)))


def _run_client(router, argv):
    """Run one dimt_zapi_client.py; (stdout text, returncode, stderr text),
    the order its callers return.

    A client still waiting after 15s is killed, so a reply that never comes
    cannot hold the test past the hold that is waiting on it. If even the
    killed client has not exited 5s later, its stdout is given up as empty,
    its stderr says so and its returncode is None: the caller's assertion on
    the reply then fails on what the client did, instead of a second
    TimeoutExpired replacing that failure with a traceback. The stderr marker
    matters because a held dplane worker also leaves the DEL unanswered, and
    the messages that blame it print stderr.
    """
    proc = router.popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = None, "<client did not exit 5s after SIGKILL>"
    return _text(stdout), proc.returncode, _text(stderr).strip()


def _held_delete(router, tunnel_id):
    """DEL `tunnel_id`; (parsed reply or None, returncode, stderr text)."""
    stdout, rc, stderr = _run_client(router, client_argv("del", tunnel_id))
    try:
        removed = json.loads(stdout)
    except ValueError:
        removed = None
    return removed, rc, stderr


def _direct_answer(router, action, tunnel_id, *extra):
    """Send one request with a barrier; (answers, rest, returncode, stderr).

    `answers` are the tunnel's notifies printed before {"barrier": true} --
    zebra's direct reply to the request (see dimt_zapi_client.py's
    --barrier) -- and `rest` is everything printed from the barrier on, so a
    caller can tell a refused request from one that went unanswered.
    """
    stdout, rc, stderr = _run_client(
        router,
        client_argv(action, tunnel_id, "--barrier", BARRIER_TUNNEL_ID, *extra),
    )
    lines = [json.loads(line) for line in stdout.splitlines() if line]
    cut = next((i for i, line in enumerate(lines) if line == {"barrier": True}),
               len(lines))
    return lines[:cut], lines[cut:], rc, stderr


def _held_before_delete_result(router, name, trace_file, removed):
    """Why the hold caught the worker before the DEL's result reached main.

    No reply to the DEL and one recvmsg entered and not returned. With the
    link still in the kernel, the worker was parked in front of some other
    dplane_in notification (neighbour, address, netconf) before it ran the
    DEL. With the link gone, it ran the DEL but its pass yielded twice, so
    the delete's own notification was read before the result was handed to
    main (see hold_dplane_in_recvmsg()). Neither opens the window under
    test. Returns a description of the shape, or None for any other shape --
    a reply of any kind included -- which is a real failure.
    """
    if removed is not None:
        return None
    held, returned = held_recvmsg_lines(router, trace_file)
    if held != 1 or returned:
        return None
    in_kernel = router.run("ip link show {} 2>/dev/null".format(name)).strip()
    if in_kernel:
        return ("an unrelated dplane_in notification was held before the "
                "DEL reached the worker ({} still in the kernel)".format(name))
    return ("the DEL ran but its own notification was held before its result "
            "reached main ({} gone from the kernel)".format(name))


def _redo_after_frozen_delete(router, tunnel_id, name):
    """Let a DEL frozen behind the hold finish, then reinstall `tunnel_id`.

    The hold is released, so the DEL runs or its result is handed over.
    zebra dropping the interface usually means the DEL's result reached main
    first, but after a double yield the RTM_DELLINK can be processed just
    ahead of it, and an ADD served in between is rejected against the
    in-flight delete (see test_add_during_inflight_delete_is_rejected). So
    the reinstall is retried until zebra serves it as a fresh create.
    """
    _, gone = topotest.run_and_expect(
        lambda: (
            router.run("ip link show {} 2>/dev/null".format(name)).strip()
            == ""
            and zebra_interface_entry(router, name) is None
        ),
        True,
        count=SYNC_POLL_COUNT,
        wait=SYNC_POLL_WAIT,
    )
    assert gone, "the released DEL did not remove {}: kernel={!r} zebra={}".format(
        name, router.run("ip link show {} 2>/dev/null".format(name)),
        zebra_interface_entry(router, name))
    attempts = []

    def reinstalled():
        attempts.append(request("add", tunnel_id))
        return attempts[-1]["result"] == 0

    _, ok = topotest.run_and_expect(
        reinstalled, True, count=SYNC_POLL_COUNT, wait=SYNC_POLL_WAIT
    )
    assert ok, "tunnel {} was never reinstalled: {}".format(tunnel_id, attempts)
    return attempts[-1]


def test_add_after_removed_before_dellink_is_parked():
    """An ADD between REMOVED and the RTM_DELLINK is parked, not answered.

    zebra answers a DEL REMOVED when the dataplane result reaches main, but
    main learns the link is gone only when the zebra_dplane pthread reads the
    RTM_DELLINK from netlink_dplane_in. pimd re-adds on REMOVED at once, so an
    ADD landing in that gap is an ordinary production sequence, and before
    BLO-38034 it took the fresh-create path, found the dead link still listed
    by name with its address still queued, and was answered INSTALLED on the
    vanished ifindex.

    hold_dplane_in_recvmsg() holds the gap open: armed before the DEL, it
    lets the delete and its ACK through and parks the worker in front of the
    notification. _prove_dellink_unread() shows it open before the re-add and
    again once the re-add's barrier is in hand. The re-add runs with
    --barrier: zebra serves one session in order, so nothing may arrive for
    the tunnel before the barrier's REMOVED -- before the fix, INSTALLED with
    the dead index did. Released, the parked ADD must be served as a fresh
    create, on the new link's index.

    While the ADD is parked, a second PIM client (instance 1) sends an ADD
    and then a DEL for the same tunnel. The tombstone belongs to the owner,
    so each must be refused at once -- FAIL_INSTALL and REMOVE_FAIL, before
    its barrier -- and neither may touch the parked ADD. Without the owner
    check at the top of zebra_dimt_tunnel_park(), the stranger's ADD would
    replace the parked one unanswered and its DEL would be told REMOVED and
    drop it, so the owner's replay would never come.
    """
    router = get_topogen().gears["r1"]
    tunnel_id = 20
    name = "dimt-00000014"
    installed = request("add", tunnel_id)
    assert installed["result"] == 0, installed
    ifindex = installed["ifindex"]

    tracer = trace_file = None
    readd = None
    try:
        try:
            # dplane_in carries neighbour, address and netconf notifications
            # too, and the hold takes every recvmsg on it. One of those
            # arriving after the hold is armed but before the DEL reaches
            # the worker freezes the worker in front of it, and the DEL
            # never runs; and a dplane pass that yields twice lets the DEL's
            # own notification be read before its result reaches main. Neither
            # is the window under test, so they are classified and the whole
            # held sequence retried once.
            for attempt in (1, 2):
                tracer, trace_file = hold_dplane_in_recvmsg(
                    router, delay_usecs=HELD_DELETE_USECS
                )
                removed, rc, stderr = _held_delete(router, tunnel_id)
                # Only a dataplane result carries a non-zero ifindex in
                # REMOVED, so this one is the DEL's own result, handed to
                # main with the dplane_in notification still unread.
                if removed == {
                    "tunnel_id": tunnel_id, "ifindex": ifindex, "result": 2
                }:
                    break
                frozen = _held_before_delete_result(
                    router, name, trace_file, removed
                )
                trace = _trace_text(router, trace_file)
                stop_tracer(tracer)
                tracer = None
                router.run("rm -f {}".format(trace_file))
                if not frozen:
                    raise WindowNeverOpened(
                        "the DEL was not answered REMOVED on ifindex {} while "
                        "dplane_in was held (got {!r}, rc={}, stderr={!r}).\n"
                        "trace:\n{}".format(
                            ifindex, removed, rc, stderr, trace))
                if attempt == 2:
                    raise WindowNeverOpened(
                        "twice, the hold caught the worker before the DEL's "
                        "result reached main; the second time {} (no REMOVED, "
                        "rc={}, stderr={!r}). The window was never "
                        "opened.\ntrace:\n{}".format(frozen, rc, stderr, trace))
                installed = _redo_after_frozen_delete(router, tunnel_id, name)
                ifindex = installed["ifindex"]
            _prove_dellink_unread(
                router, name, ifindex, trace_file, "after the DEL's REMOVED"
            )

            readd = router.popen(
                client_argv("add", tunnel_id,
                            "--barrier", BARRIER_TUNNEL_ID, "--follow", 1,
                            "--timeout", HELD_DELETE_CLIENT_TIMEOUT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            reader = NotifyReader(readd)
            early = []
            while True:
                line = reader.next(timeout=10)
                if line is None or "tunnel_id" not in line:
                    break
                early.append(line)
            _prove_dellink_unread(
                router, name, ifindex, trace_file,
                "after the re-add's barrier",
            )
            assert line == {"barrier": True}, (line, reader.lines)
            assert not early, (
                "zebra answered an ADD landing before it processed the "
                "RTM_DELLINK instead of parking it: {}".format(early)
            )

            # The tombstone answers only its owner (BLO-38883). The owner
            # key is proto + instance and every request is pinned to PIM,
            # so the stranger is PIM instance 1.
            #
            # A refusal must carry the dead link's index: the tombstone
            # keeps it until main processes the RTM_DELLINK. Had the hold
            # lapsed and the owner's ADD replayed, a live entry would
            # refuse with the same codes but with 0 (still creating) or the
            # new link's index, so the index is what proves these came
            # from the tombstone -- without another vtysh round trip
            # inside the hold.
            for action, refused in (("add", 1), ("del", 3)):
                answers, rest, rc, stderr = _direct_answer(
                    router, action, tunnel_id, "--instance", 1
                )
                assert rc == 0 and rest == [{"barrier": True}], (
                    action, answers, rest, rc, stderr)
                assert answers == [{
                    "tunnel_id": tunnel_id, "ifindex": ifindex,
                    "result": refused,
                }], ("a non-owner {} against the tombstone was not refused "
                     "before its barrier: {}".format(action, answers))
        finally:
            if tracer is not None:
                stop_tracer(tracer)
            if trace_file is not None:
                router.run("rm -f {}".format(trace_file))
        replayed = reader.next(timeout=20)
        assert replayed is not None and replayed.get("result") == 0, (
            replayed, reader.lines)
        assert replayed["ifindex"] != ifindex, (installed, replayed)
        assert replayed["ifindex"] == kernel_ifindex(router, name), replayed
    finally:
        if readd is not None:
            readd_stderr = finish_client(readd)
    assert readd.returncode == 0, readd_stderr
    _, converged = topotest.run_and_expect(
        lambda: zebra_ifindex(router, name) == replayed["ifindex"],
        True,
        count=SYNC_POLL_COUNT,
        wait=SYNC_POLL_WAIT,
    )
    assert converged, "zebra lists {} at {}, not {}".format(
        name, zebra_ifindex(router, name), replayed["ifindex"])
    assert "gre remote 192.0.2.2 local 192.0.2.1" in router.run(
        "ip -d link show {}".format(name)
    )
    assert request("del", tunnel_id)["result"] == 2


def test_uncertain_create_result_reconciles_surviving_link():
    router = get_topogen().gears["r1"]
    # Fail the response read: the RTM_NEWLINK reaches the kernel but its
    # ack is lost, so the reported failure is not an authoritative verdict.
    tracer = inject_netlink_recv_failure(router, 1)
    try:
        failed = request("add", 8)
    finally:
        trace = stop_tracer(tracer)
    # This assertion is what kept BLO-29583 honest. Every early observation ran
    # with the leaked dimt-00000004 present, and under that condition `add 8`
    # fails with `File exists` from the shared-tuple collision -- which
    # satisfies the result==1 check below, the empty-link check after it
    # (nothing was ever created), and the retry returning 1 twice, all with zero
    # zebra involvement. Proving the recv injection fired is what separates the
    # defect from that phantom. Keep it: without it this test would pass for the
    # wrong reason the moment the injection stopped perturbing anything, which
    # is the silent-skip regression BLO-28043 exists to kill.
    assert_injection_fired(trace, tracer.injection_label)
    assert failed["result"] == 1, failed
    # Zebra must adopt the surviving link and tear it down instead of
    # leaving it unmanaged to collide with a later ADD.
    _, link = topotest.run_and_expect(
        lambda: router.run("ip link show dimt-00000008 2>/dev/null"),
        "",
        count=SYNC_POLL_COUNT,
        wait=SYNC_POLL_WAIT,
    )
    assert link == "", link
    # The kernel deleting the link is not zebra processing its RTM_DELLINK.
    # Until it does, the tombstone still lists the link, so under load both
    # retries below could land on it and be answered FAIL_INSTALL.
    _, dropped = topotest.run_and_expect(
        lambda: zebra_dropped_interface(router, "dimt-00000008"),
        True,
        count=SYNC_POLL_COUNT,
        wait=SYNC_POLL_WAIT,
    )
    assert dropped, "zebra still lists dimt-00000008 after the cleanup"
    # The retained lifecycle entry converges over the standard cleanup
    # retry. Stale-ack correlation poisoning is fixed (dropped by sequence
    # comparison); the only remaining variance is reconcile timing -- the
    # retry may land while the cleanup delete's result is still in flight.
    retry = request("add", 8)
    assert retry["result"] in (0, 1), retry
    if retry["result"] == 1:
        retry = request("add", 8)
        assert retry["result"] == 0, retry
    assert request("del", 8)["result"] == 2


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
    tracer, trace_file = hold_dplane_sendmsg(
        router, delay_usecs=HELD_DELETE_USECS
    )
    client = os.path.join(CWD, "dimt_zapi_client.py")
    try:
        # --follow 1: this session owns the tunnel once its DEL is read, and is
        # the only live one when the original link vanishes; see below.
        pending = router.popen(
            ["python3", client, "del", "10", "--encap", "gre",
             "--follow", "1",
             "--timeout", str(HELD_DELETE_CLIENT_TIMEOUT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _, state = topotest.run_and_expect(
            lambda: dellink_state(
                router, trace_file, "dimt-0000000a", installed["ifindex"]
            ),
            "held",
            count=SYNC_POLL_COUNT,
            wait=SYNC_POLL_WAIT,
        )
        if state != "held":
            raise WindowNeverOpened(
                "no RTM_DELLINK for dimt-0000000a was held (state={}), so the "
                "replacement below would not land inside the encode-to-kernel "
                "window.\ntrace:\n{}".format(
                    state, _trace_text(router, trace_file)))
        # The replacement must land INSIDE the window: the original link is
        # still there to delete (the held RTM_DELLINK has not reached the
        # kernel), and the hold is still in place once it is done. If the hold
        # had expired first the original would already be gone, the kernel
        # would have deleted it by ifindex, and REMOVED (2) below would read as
        # "the delete was not bound to the ifindex".
        removed = router.run("ip link del dimt-0000000a && echo REMOVED")
        if "REMOVED" not in removed:
            raise WindowNeverOpened(
                "the original dimt-0000000a was already gone when the "
                "replacement ran ({!r}), so the held delete had reached the "
                "kernel.\ntrace:\n{}".format(
                    removed.strip(), _trace_text(router, trace_file)))
        added = router.run(
            "ip link add dimt-0000000a type dummy && echo ADDED"
        )
        assert "ADDED" in added, "replacement create failed: {!r}".format(
            added.strip())
        after = dellink_state(
            router, trace_file, "dimt-0000000a", installed["ifindex"]
        )
        if after != "held":
            raise WindowNeverOpened(
                "the RTM_DELLINK hold ended (state={}) before the replacement "
                "was in place.\ntrace:\n{}".format(
                    after, _trace_text(router, trace_file)))
    finally:
        stop_tracer(tracer)
        router.run("rm -f {}".format(trace_file))
    # Long enough for a client still waiting on its second notify to time out
    # and say so, rather than for communicate() to raise past it.
    stdout, stderr = pending.communicate(
        timeout=HELD_DELETE_CLIENT_TIMEOUT + 15
    )
    lines = [json.loads(line) for line in _text(stdout).splitlines()]
    # The encode happened before the replacement (proven by the held
    # RTM_DELLINK), so the pre-encode skip path is unreachable: the delete must
    # fail on the stale index and the replacement must survive. Either way the
    # owner -- this session -- ends with REMOVED on no index. Before BLO-38034
    # it heard REMOVE_FAIL and nothing more, and the entry stayed INSTALLED on
    # an index no link has.
    removed = {"tunnel_id": 10, "ifindex": 0, "result": 2}
    if lines and lines[0].get("result") == 3:
        # The usual order. The held sendmsg passes the 10ms yield slot, so
        # the failed delete's result is handed to main in the rescheduled
        # dplane pass, which event_fetch() runs before the dplane_in read the
        # out-of-band delete made ready. main sees the ENODEV while it still
        # lists the original link, restores the entry INSTALLED on that index
        # and sends REMOVE_FAIL; the RTM_DELLINK is processed next and,
        # finding an INSTALLED entry on the vanished index, zebra sends
        # REMOVED and forgets it.
        assert pending.returncode == 0, (lines, _text(stderr))
        assert lines[1:] == [removed], lines
    else:
        # If that rescheduled pass yields again, the dplane_in read runs
        # first (see hold_dplane_in_recvmsg()): the RTM_DELLINK clears the
        # DELETING entry's ifindex, and the ENODEV result then finds no link
        # and answers REMOVED and forgets. One notify, so the follow times
        # out.
        assert lines == [removed, {"timeout": True}], (lines, _text(stderr))
        assert pending.returncode == 3, (lines, _text(stderr))
    assert "dummy" in router.run("ip -d link show dimt-0000000a")
    # ...so this DEL finds no entry and is answered from the no-entry branch,
    # with no dataplane operation to touch the dummy.
    assert request("del", 10)["result"] == 2
    router.run("ip link del dimt-0000000a")


def test_lost_delete_ack_reconciles_instead_of_resurrecting():
    router = get_topogen().gears["r1"]
    installed = request("add", 11)
    assert installed["result"] == 0, installed

    # The kernel applies the delete but its ack is lost. The entry must
    # converge on reconciled interface state -- REMOVED now, or
    # REMOVE_FAIL then REMOVED on retry -- and never report INSTALLED for
    # a link that no longer exists.
    tracer = inject_netlink_recv_failure(router, 1)
    try:
        removed = request("del", 11)
    finally:
        trace = stop_tracer(tracer)
    # Without this the test is a permanent green pass on an unverified window:
    # under a no-op injection the ack is not lost, the delete simply completes,
    # and every assertion below is satisfied for the ordinary reason. A
    # SUCCESSFUL recv injection writes nothing to zebra.out either (EAGAIN is
    # the normal batch terminator), so strace's own output is the only evidence
    # that exists -- and it was being discarded.
    assert_injection_fired(trace, tracer.injection_label)
    assert removed["result"] in (2, 3), removed
    _, link = topotest.run_and_expect(
        lambda: router.run("ip link show dimt-0000000b 2>/dev/null"),
        "",
        count=10,
        wait=0.2,
    )
    assert link == "", link
    # The kernel has deleted the link, but zebra may not have processed its
    # RTM_DELLINK yet. A REMOVE_FAIL (3) above restored the entry INSTALLED on
    # the still-listed index, and a retry served before that notification
    # would resolve it and send a second, doomed delete. Once zebra has
    # dropped the link, the INSTALLED entry is forgotten (BLO-38034), so the
    # retry and the readd below both see a tunnel zebra no longer tracks.
    _, dropped = topotest.run_and_expect(
        lambda: zebra_dropped_interface(router, "dimt-0000000b"),
        True,
        count=SYNC_POLL_COUNT,
        wait=SYNC_POLL_WAIT,
    )
    assert dropped, "zebra still lists dimt-0000000b after the delete"
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


def test_skipped_delete_result_survives_mixed_batch():
    """A delete with no link left and a real delete, together, both REMOVED.

    Tunnel 12's link is replaced out-of-band and zebra is left to process that
    first, which forgets 12's entry (see
    test_queued_delete_does_not_remove_reused_ifindex) while 13's link is
    live. The two DELs are then issued together: 13's is a real dataplane
    delete, and 12's is answered at once from the no-entry branch. Both must
    report REMOVED, and 12's must leave the same-name dummy alone.

    What this does NOT cover, despite the name it has kept: a SKIPPED delete
    sharing one dataplane batch with a real one, the case where the
    end-of-responses drain used to flip the no-message context's synthetic
    success into a failure. That needs 12's delete queued behind 13's and then
    skipped at encode time, and no dplane hold can arrange it: see
    test_queued_delete_does_not_remove_reused_ifindex. The test used to claim
    it through hold_dplane_worker(), which never held anything (BLO-29000), so
    both deletes simply ran one after the other. That case is covered without
    a kernel by tests/zebra/test_dimt_netlink.c cases G (the [real, skipped]
    order, which is the only one the old drain flipped), H and I (the
    read-failure drain).
    """
    router = get_topogen().gears["r1"]
    replaced = request("add", 12)
    assert replaced["result"] == 0, replaced
    # BLO-29009: this is the ONLY test in the module needing two DIMT GRE
    # tunnels alive at once, so tunnel 13 must not share tunnel 12's outer
    # (local, remote) tuple -- that pair is the tunnel's kernel identity, and
    # a second create on it is refused with EEXIST whatever the link is named
    # and whether or not the first is up.  Measured: `ip link add ... local
    # 192.0.2.1 remote 192.0.2.2` twice -> `RTNETLINK answers: File exists`;
    # varying the remote alone -> both create and both come up.  Without this
    # the test dies at its own setup and never reaches the mixed batch it
    # exists to exercise, which reads as a zebra defect and was filed as one.
    normal = request("add", 13, outer_remote=TUNNEL_13_OUTER_REMOTE)
    assert normal["result"] == 0, normal

    router.run(
        "ip link del dimt-0000000c; ip link add dimt-0000000c type dummy"
    )
    _, seen = topotest.run_and_expect(
        lambda: zebra_ifindex(router, "dimt-0000000c")
        not in (None, 0, replaced["ifindex"]),
        True,
        count=SYNC_POLL_COUNT,
        wait=SYNC_POLL_WAIT,
    )
    assert seen, "zebra did not process the replacement link"

    client = os.path.join(CWD, "dimt_zapi_client.py")
    pending13 = router.popen(
        ["python3", client, "del", "13", "--encap", "gre"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    pending12 = router.popen(
        ["python3", client, "del", "12", "--encap", "gre"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out13, err13 = pending13.communicate(timeout=15)
    out12, err12 = pending12.communicate(timeout=15)
    assert pending13.returncode == 0, _text(err13)
    assert pending12.returncode == 0, _text(err12)
    assert json.loads(_text(out13))["result"] == 2, out13
    assert json.loads(_text(out12))["result"] == 2, out12
    assert "dummy" in router.run("ip -d link show dimt-0000000c")
    _, link = topotest.run_and_expect(
        lambda: router.run("ip link show dimt-0000000d 2>/dev/null"),
        "",
        count=10,
        wait=0.2,
    )
    assert link == "", link
    router.run("ip link del dimt-0000000c")


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


# IPv6 outer for the ip6gre case.  On r1-eth0 (r1/zebra.conf); h1 carries no
# IPv6 address, which is fine -- nothing here sends traffic, and zebra only
# needs a connected route to the outer remote to accept the request.
V6_OUTER_LOCAL = "2001:db8:2::1"
V6_OUTER_REMOTE = "2001:db8:2::2"


def test_ip6gre_tunnel_carries_fixed_outer_header():
    """An IPv6-outer DIMT tunnel gets the fixed hop limit AND `encaplimit none`.

    ip6gre inherits exactly like gre when IFLA_GRE_TTL is absent (hop_limit 0
    copies the inner packet's), so the fix has to cover both kinds -- a v4-only
    fix would leave every IPv6 underlay with the multi-hop blackhole.

    The encap limit is the ip6gre-only half.  Without
    IP6_TNL_F_IGN_ENCAP_LIMIT the kernel prepends a Tunnel Encapsulation Limit
    destination option to every outer packet, and because ip6gre_newlink
    memsets its parms the limit it prepends is *0* -- which RFC 2473 s5.1
    turns into an instruction to every transit router to discard any packet it
    would have to encapsulate again, and which costs 8 bytes of MTU besides.
    Same class of blackhole as an inherited TTL, same invisibility in a
    one-hop lab.
    """
    router = get_topogen().gears["r1"]
    _, ready = topotest.run_and_expect(
        lambda: "r1-eth0"
        in router.vtysh_cmd("show ipv6 route {}".format(V6_OUTER_REMOTE)),
        True,
        count=20,
        wait=0.5,
    )
    assert ready, router.vtysh_cmd("show ipv6 route {}".format(V6_OUTER_REMOTE))

    installed = request(
        "add", 15, outer_local=V6_OUTER_LOCAL, outer_remote=V6_OUTER_REMOTE
    )
    assert installed["result"] == 0, installed
    link = router.run("ip -d link show dimt-0000000f")
    assert "link/gre6" in link, link
    kernel_error = check_gre_link(
        router,
        "dimt-0000000f",
        local=V6_OUTER_LOCAL,
        remote=V6_OUTER_REMOTE,
        ttl=64,
        encaplimit="none",
    )
    assert kernel_error is None, kernel_error
    assert request("del", 15)["result"] == 2


def test_stale_ip6gre_encap_limit_link_is_replaced_not_adopted():
    """An ip6gre of ours with the default encap limit is rebuilt, not adopted.

    The ip6gre half of the upgrade case that
    test_stale_ttl_link_is_replaced_not_adopted() covers for gre, and it is
    not redundant: the TTL is already correct on this link, so only the encap
    limit distinguishes it.  A zebra that checked the outer TTL alone would
    re-adopt it, re-notify INSTALLED, and leave the encapsulation blackhole in
    place on exactly the IPv6 underlays DIMT is being rolled out onto.

    This is also what makes the rollout staged rather than a sweep: zebra
    never walks the DIMT links looking for stale ones.  Each pre-fix netdev is
    replaced only when its own tunnel is next requested (here) or changes in
    place, so an upgraded PoP converts one tunnel at a time, driven by pimd's
    own demand edges.
    """
    router = get_topogen().gears["r1"]
    name = "dimt-00000010"
    # A DIFFERENT outer remote from tunnel 15: two GRE links may not share an
    # (outer local, outer remote) tuple, and ordering between these two tests
    # is not something this file should depend on.  Still inside the connected
    # 2001:db8:2::/64 on r1-eth0, so the outer-remote route check passes.
    stale_remote = "2001:db8:2::3"
    _, ready = topotest.run_and_expect(
        lambda: "r1-eth0"
        in router.vtysh_cmd("show ipv6 route {}".format(stale_remote)),
        True,
        count=20,
        wait=0.5,
    )
    assert ready, router.vtysh_cmd("show ipv6 route {}".format(stale_remote))

    # hoplimit 64 is already right here -- the encap limit is the ONLY thing
    # wrong, which is the whole point of this test.
    router.run(
        "ip link add {} type ip6gre local {} remote {} hoplimit 64 "
        "encaplimit 4".format(name, V6_OUTER_LOCAL, stale_remote)
    )
    stale = check_gre_link(
        router,
        name,
        local=V6_OUTER_LOCAL,
        remote=stale_remote,
        expected_up=False,
        ttl=64,
        encaplimit=4,
    )
    assert stale is None, stale
    _, seen = topotest.run_and_expect(
        lambda: zebra_ifindex(router, name) is not None, True, count=20, wait=0.2
    )
    assert seen, "zebra never learned the pre-existing {}".format(name)
    stale_ifindex = zebra_ifindex(router, name)

    installed = request(
        "add", 16, outer_local=V6_OUTER_LOCAL, outer_remote=stale_remote
    )
    assert installed["result"] == 0, installed
    assert installed["ifindex"] != stale_ifindex, (
        "zebra adopted the encaplimit-4 ip6gre (ifindex {}) instead of "
        "replacing it: {}".format(stale_ifindex, installed)
    )
    kernel_error = check_gre_link(
        router,
        name,
        local=V6_OUTER_LOCAL,
        remote=stale_remote,
        ttl=64,
        encaplimit="none",
    )
    assert kernel_error is None, kernel_error

    assert request("del", 16)["result"] == 2
    _, gone = topotest.run_and_expect(
        lambda: router.run("ip link show {} 2>/dev/null".format(name)),
        "",
        count=10,
        wait=0.2,
    )
    assert gone == "", gone


def test_request_without_mtu_warns():
    """A request with no MTU option is accepted, and says so in the log.

    dimt_zapi_client.py sends options=0, so every ADD in this file takes the
    no-MTU path: the netdev inherits the kernel default, which does not
    subtract the outer header, and full-size payloads then fragment or drop.
    zebra cannot invent an MTU it was not given, so the warning is the whole
    remedy -- and a silent warning is the same as no warning.
    """
    tgen = get_topogen()
    router = tgen.gears["r1"]
    # Self-contained: issue the MTU-less ADD here rather than relying on an
    # earlier test in this file having run.
    mtuless_remote = "2001:db8:2::4"
    _, ready = topotest.run_and_expect(
        lambda: "r1-eth0"
        in router.vtysh_cmd("show ipv6 route {}".format(mtuless_remote)),
        True,
        count=20,
        wait=0.5,
    )
    assert ready, router.vtysh_cmd("show ipv6 route {}".format(mtuless_remote))
    installed = request(
        "add", 17, outer_local=V6_OUTER_LOCAL, outer_remote=mtuless_remote
    )
    assert installed["result"] == 0, installed
    assert request("del", 17)["result"] == 2

    logs = sorted(pathlib.Path(tgen.logdir).glob("**/zebra.log"))
    assert logs, "no zebra.log under {}; the warning is unproven, not absent".format(
        tgen.logdir
    )
    text = "".join(log.read_text(errors="replace") for log in logs)
    assert text.strip(), "zebra.log(s) empty: {}".format(logs)
    assert "no MTU in the request" in text, (
        "zebra accepted MTU-less DIMT ADDs without warning; searched {}".format(
            [str(log) for log in logs]
        )
    )


def test_stale_ttl_link_is_replaced_not_adopted():
    """A same-identity link with the wrong outer TTL is rebuilt, not adopted.

    This is the upgrade case: a pre-TTL build left dimt-%08x links with
    `ttl inherit`, and zebra deliberately never sweeps DIMT links, so they are
    still there when the fixed zebra starts.  The name, endpoints, key and
    encapsulation all match -- by the old identity test it is "ours" and would
    be re-adopted and re-notified INSTALLED, keeping the multi-hop blackhole
    alive indefinitely.

    Nor may zebra merely refuse it: a refusal is FAIL_INSTALL, and pimd never
    retries a failed tunnel on a timer, so the upgraded router would sit with
    no tunnel at all.  The required behaviour is replacement: the stale link
    is deleted and a fresh one created, so the ifindex changes and the kernel
    shows the fixed TTL -- all inside one acknowledged ADD.
    """
    router = get_topogen().gears["r1"]
    name = "dimt-0000000e"
    router.run(
        "ip link add {} type gre local 192.0.2.1 remote 192.0.2.2 "
        "ttl inherit".format(name)
    )
    stale = check_gre_link(
        router, name, local="192.0.2.1", remote="192.0.2.2",
        expected_up=False, ttl="inherit",
    )
    assert stale is None, stale
    # zebra must have learned the link before the ADD, or the request would
    # take the plain-create path and fail EXCL instead of exercising the
    # replacement.
    _, seen = topotest.run_and_expect(
        lambda: zebra_ifindex(router, name) is not None, True, count=20, wait=0.2
    )
    assert seen, "zebra never learned the pre-existing {}".format(name)
    stale_ifindex = zebra_ifindex(router, name)

    installed = request("add", 14)
    assert installed["result"] == 0, installed
    assert installed["ifindex"] != stale_ifindex, (
        "zebra adopted the ttl-inherit link (ifindex {}) instead of "
        "replacing it: {}".format(stale_ifindex, installed)
    )
    kernel_error = check_gre_link(
        router, name, local="192.0.2.1", remote="192.0.2.2", ttl=64
    )
    assert kernel_error is None, kernel_error
    address = router.run("ip -o address show dev {}".format(name))
    assert "10.200.0.1 peer 10.200.0.2/32" in address, address

    assert request("del", 14)["result"] == 2
    _, gone = topotest.run_and_expect(
        lambda: router.run("ip link show {} 2>/dev/null".format(name)),
        "",
        count=10,
        wait=0.2,
    )
    assert gone == "", gone


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



def test_pytest_fail_owners_are_documented():
    """WindowNeverOpened's docstring lists every function here that calls
    pytest.fail(), because its argument (that a raises=pytest.fail.Exception
    marker would absorb them all) depends on the list being complete. The
    list went stale once already; a new pytest.fail() owner missing from it
    fails here instead of falsifying the docstring silently.
    """
    with open(__file__) as source:
        tree = ast.parse(source.read())
    owners = {
        fn.name
        for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        for call in ast.walk(fn)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "fail"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "pytest"
    }
    documented = " ".join(WindowNeverOpened.__doc__.split())
    missing = sorted(name for name in owners if name + "()" not in documented)
    assert owners and not missing, (
        "pytest.fail() owners missing from WindowNeverOpened's docstring: "
        "{}".format(missing))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
