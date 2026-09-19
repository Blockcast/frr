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
# Seven were one leaked link; three tickets remain, and only two of those are
# zebra questions. (The reasoning that reclassified them is in the commit log,
# not here.)
#
#   BLO-28405  zebra. The injection genuinely fires -- r1/zebra.out carries
#              `netlink_send_msg error: Input/output error` exactly once, inside
#              this test's TEST-START/TEST-END -- so the live question is only
#              whether result=0 is correct for a create whose second sendmsg was
#              injected. test_address_failure_cleans_up_and_allows_tunnel_id_reuse
#              asserts that, and keeps its marker.
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
#   BLO-29000  HARNESS, not zebra. hold_dplane_worker() does not hold the
#              `del 9` client: it exits with result=2 (REMOVED) before the readd
#              runs, so the test has never opened the window it is named for.
#              The zebra defect first filed here -- "readd returns result=0" --
#              was a phantom: a post-delete ADD succeeding is correct, and this
#              test's own tail asserts exactly that. The two observables are
#              bit-for-bit identical, which is why the precondition guard is the
#              only thing that can tell them apart.
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
# These are marked xfail rather than skipped so the harness fix could land
# without waiting on the zebra work -- a skip would recreate the very blind spot
# BLO-28043 exists to close. strict=True is load-bearing: the build FAILS the
# moment a defect is fixed and its test starts passing, which forces the marker
# off in the same PR that fixes it. Corollary worth keeping: anything that
# unwedges a marked test -- a fixture like the reaper below, as much as a zebra
# fix -- must remove that test's marker in the SAME commit, or strict turns the
# new pass into an XPASS failure.
#
# Remove each REMAINING marker in its blocker's fix PR, never in a cleanup.
# raises= narrows each marker to the failure it actually predicts, so an
# unrelated topology error or a no-op injection surfaces as a hard failure
# instead of being absorbed as expected. Neither pytest.fail()'s Failed nor
# WindowNeverOpened is an AssertionError, which is what lets
# assert_injection_fired() and the precondition guard break out of an xfail
# rather than be swallowed by it.


class WindowNeverOpened(Exception):
    """A test's precondition never held, so its window was never exercised.

    Deliberately a bespoke type rather than pytest.fail()'s Failed. EVERY
    pytest.fail() in this module raises Failed -- the tracing_unavailable()
    funnel, both reap_stray_dimt_links() precondition failures, both
    inject_netlink_syscall_failure() setup paths, both _hold_dplane_syscalls()
    paths ("zebra_dplane worker not found", "strace attach failed") and
    assert_injection_fired() -- so a marker written raises=pytest.fail.Exception
    absorbs all of them as a green xfail, a *setup-time* fixture failure
    included. Only this class can reach XFAIL_BLO_29000, so a missing strace, a
    dirty kernel, a missing dplane worker or a failed attach still fails the job
    loudly instead of reading as "expected failure, blocker still open".

    It keeps the property that made pytest.fail() right in the first place: it
    is NOT an AssertionError, so a raises=AssertionError marker cannot swallow
    it either. Same escape reasoning as assert_injection_fired(), narrower
    blast radius.

    One asymmetry to know before wrapping a guard site in a handler: Failed
    derives from BaseException, not Exception, so `except Exception` does not
    catch it -- this class it would. Verified at the time of writing that the
    only try enclosing the guard is a bare try/finally with no handlers, so
    nothing swallows it today. Keep it that way, or re-narrow the handler.
    """


# raises=WindowNeverOpened -- NOT AssertionError, and deliberately NOT
# pytest.fail.Exception: the expected failure here is the precondition guard,
# and exactly one site raises that type, so nothing else can be absorbed. The
# behavioural assertion below the guard is an AssertionError and is NOT
# absorbed, so if the hold ever starts working and zebra then misbehaves, that
# surfaces as a hard failure rather than hiding under this marker. See
# WindowNeverOpened for why Failed was too wide.
XFAIL_BLO_29000 = pytest.mark.xfail(
    strict=True,
    raises=WindowNeverOpened,
    reason=(
        "BLO-29000: this test does not currently exercise its own window -- "
        "hold_dplane_worker() does not hold the `del 9` client, which exits "
        "with result=2 (REMOVED) before the readd runs. Measured, not "
        "inferred: the pending.poll() guard fires. The zebra defect originally "
        "filed here was a phantom -- a post-delete ADD succeeding is correct, "
        "and this test's own tail asserts it. Remove this marker when the hold "
        "works and the guard stops firing."
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


def request(action, tunnel_id, encap="gre", outer_remote=None):
    """Drive one DIMT ZAPI add/del against r1.

    outer_remote overrides the GRE tunnel's remote endpoint.  It is only
    needed by a test that must hold two DIMT tunnels up at the same time --
    see TUNNEL_13_OUTER_REMOTE.  del carries no endpoints, so it is add-only.
    """
    client = os.path.join(CWD, "dimt_zapi_client.py")
    command = "python3 {} {} {} --encap {}".format(client, action, tunnel_id, encap)
    if outer_remote is not None:
        command += " --outer-remote {}".format(outer_remote)
    output = get_topogen().gears["r1"].run(command)
    return json.loads(output)


def _route_netlink_fds(router, zebra_pid, thread_id):
    """Return route-netlink FDs in the target thread's descriptor table."""
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
    ).format(thread_id, zebra_pid)
    fds = router.run(command).split()
    if not fds:
        pytest.fail(
            "zebra_dplane route-netlink FD not found -- "
            "send-side failure injection cannot run"
        )
    return ",".join(fds)


def inject_netlink_syscall_failure(
    router, syscall, when, errno_name="EIO", trace_fds=None
):
    require_strace(router)
    zebra_pid = router.run("cat /var/run/frr/zebra.pid").strip()
    dplane_tid = router.run(
        f"for task in /proc/{zebra_pid}/task/*; do "
        '[ "$(cat $task/comm)" = zebra_dplane ] && basename "$task"; '
        "done"
    ).strip()
    if not dplane_tid:
        pytest.fail(
            "zebra_dplane worker not found -- netlink failure injection cannot run"
        )
    command = [
        "strace",
        "-qq",
        "-e",
        "trace={}".format(syscall),
    ]
    if trace_fds is not None:
        command.extend(["-e", "trace-fds={}".format(trace_fds)])
    command.extend(
        [
            "-e",
            "inject={}:error={}:when={}".format(syscall, errno_name, when),
            "-p",
            dplane_tid,
        ],
    )
    tracer = router.popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.2)
    if tracer.poll() is not None:
        _stdout, stderr = tracer.communicate()
        pytest.fail(
            "strace attach failed: {}".format(_text(stderr).strip())
        )
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
    zebra_pid = router.run("cat /var/run/frr/zebra.pid").strip()
    dplane_tid = router.run(
        f"for task in /proc/{zebra_pid}/task/*; do "
        '[ "$(cat $task/comm)" = zebra_dplane ] && basename "$task"; '
        "done"
    ).strip()
    if not dplane_tid:
        pytest.fail(
            "zebra_dplane worker not found -- netlink failure injection cannot run"
        )
    route_fds = _route_netlink_fds(router, zebra_pid, dplane_tid)
    return inject_netlink_syscall_failure(
        router, "sendmsg", when, trace_fds=route_fds
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


def hold_dplane_worker(router, delay_usecs=6000000):
    """Hold only the dplane worker task at its event-loop wakeup.

    ptrace stops just the traced task, so zebra's main thread keeps
    processing ZAPI requests and netlink notifications while any context
    already handed to the dataplane provably stays queued until the tracer
    detaches.
    """
    return _hold_dplane_syscalls(router, "ppoll,poll", "delay_exit", delay_usecs)


def hold_dplane_sendmsg(router, delay_usecs=6000000):
    """Hold the dplane worker at sendmsg ENTRY.

    At that point the netlink message is fully encoded (all identity checks
    have run) but not yet delivered to the kernel -- the exact
    encode-to-kernel window. Returns (tracer, trace_file); the trace file
    records each sendmsg entry, so callers can positively synchronize on
    the syscall having been entered instead of guessing with sleeps.
    """
    trace_file = "/tmp/dimt-sendmsg-trace-{}.log".format(os.getpid())
    router.run("rm -f {}".format(trace_file))
    tracer = _hold_dplane_syscalls(
        router, "sendmsg", "delay_enter", delay_usecs, trace_file
    )
    return tracer, trace_file


def sendmsg_entered(router, trace_file):
    return "sendmsg(" in router.run("cat {} 2>/dev/null".format(trace_file))


def _hold_dplane_syscalls(router, syscalls, inject_kind, delay_usecs,
                          trace_file=None):
    require_strace(router)
    worker = dplane_tid(router)
    if not worker:
        pytest.fail(
            "zebra_dplane worker not found -- cannot hold the dplane worker"
        )
    cmd = [
        "strace",
        "-qq",
        "-e",
        "trace={}".format(syscalls),
        "-e",
        "inject={}:{}={}".format(syscalls, inject_kind, delay_usecs),
        "-p",
        worker,
    ]
    if trace_file:
        cmd[1:1] = ["-o", trace_file]
    tracer = router.popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.3)
    if tracer.poll() is not None:
        _stdout, stderr = tracer.communicate()
        pytest.fail(
            "strace attach failed: {}".format(_text(stderr).strip())
        )
    # Same contract as inject_netlink_syscall_failure() above, and derived from
    # the same arguments that built the command for the same anti-drift reason.
    # Without it, any hold site that adopts assert_injection_fired() -- the
    # natural next step, since strace tags delay injections (INJECTED) too --
    # gets AttributeError instead of a diagnostic.
    tracer.injection_label = "{} {}={} hold".format(
        syscalls, inject_kind, delay_usecs
    )
    # NOT "(INJECTED)" -- strace tags a delay "(DELAYED)". See
    # assert_injection_fired() for the measurement.
    #
    # Published so a hold site CAN adopt assert_injection_fired(), but the hold
    # sites deliberately do not yet: unlike an error injection, strace emits the
    # line when the delayed syscall RETURNS, so whether "(DELAYED)" is already
    # in stderr when the test terminates the tracer is a timing property that
    # was NOT confirmed. It could not be measured outside CI -- attaching with
    # -p needs root or ptrace_scope=0, and the dev host has ptrace_scope=1, so
    # the attempt produced an empty trace that proves nothing either way.
    # Asserting on an unconfirmed tag would trade a silent pass for a flake.
    # The hold sites synchronize on observable effects instead
    # (sendmsg_entered() reading the -o trace file, and "zebra did not process
    # the replacement link").
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
        trace = stop_tracer(tracer)
    assert_injection_fired(trace, tracer.injection_label)
    # Only the TRACER used to be protected, so when this assertion fired -- as
    # it does today, see the marker above -- the `del` at the end of the test
    # never ran and dimt-00000004 survived.  The autouse reaper now covers that
    # regardless, but the assertion still belongs after the tracer stop and
    # before anything that depends on the create having failed.
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
    assert pending.returncode == 0, _text(stderr)
    assert json.loads(_text(stdout))["result"] == 2
    assert "dummy" in router.run("ip -d link show dimt-00000006")
    router.run("ip link del dimt-00000006")


@XFAIL_BLO_29000
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
        # The whole test is "an ADD *while a DELETE is in flight*". If the
        # worker hold silently no-ops, the del completes during the sleep above
        # and the add below then succeeds for the ORDINARY reason -- which this
        # test's own tail asserts is correct post-delete behaviour. That failure
        # is bit-for-bit the same observable as the defect BLO-29000 claims, and
        # raises=AssertionError would absorb it into a green xfail. So establish
        # the precondition before asserting on it.
        #
        # raise WindowNeverOpened, not assert and not pytest.fail(): it is not
        # an AssertionError, so the marker this guard exists to keep honest
        # cannot swallow it; and unlike Failed exactly this one site raises it,
        # so XFAIL_BLO_29000 cannot absorb a missing strace, a dirty kernel, a
        # missing dplane worker or a failed attach.
        if pending.poll() is not None:
            out, err = pending.communicate(timeout=5)
            raise WindowNeverOpened(
                "the `del 9` client already exited (rc={}), so nothing was in "
                "flight when the readd below ran. The dplane worker hold did "
                "not take, and anything asserted past this point describes an "
                "ordinary post-delete ADD, not an ADD racing a live DELETE. "
                "Treat this as the test not having executed.\nstdout: {}\n"
                "stderr: {}".format(pending.returncode,
                                    _text(out).strip() or "(empty)",
                                    _text(err).strip() or "(empty)"))
        # An identical ADD while the delete is in flight must be rejected
        # instead of rebinding ownership: the delete completion belongs to
        # the delete requester.
        readd = request("add", 9)
        assert readd["result"] == 1, readd
    finally:
        stop_tracer(tracer)
    stdout, stderr = pending.communicate(timeout=10)
    assert pending.returncode == 0, _text(stderr)
    assert json.loads(_text(stdout))["result"] == 2
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
    assert pending.returncode == 0, _text(stderr)
    # The encode happened before the replacement (proven by the sendmsg
    # sync), so the pre-encode skip path is unreachable: the delete must
    # fail on the stale index and the replacement must survive.
    assert json.loads(_text(stdout))["result"] == 3, stdout
    assert "dummy" in router.run("ip -d link show dimt-0000000a")
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
    assert pending13.returncode == 0, _text(err13)
    assert pending12.returncode == 0, _text(err12)
    assert json.loads(_text(out13))["result"] == 2, out13
    # The skipped delete must report REMOVED even though it shared the
    # batch with a real delete whose ack is the only response.
    assert json.loads(_text(out12))["result"] == 2, out12
    assert "dummy" in router.run("ip -d link show dimt-0000000c")
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
