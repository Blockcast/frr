# BLO-15579 — Junos GTM-SSM MVPN interoperability matrix

One command, one artifact. Per the CTO ruling on
[BLO-15579](https://paperclip.blockcast.net/BLO/issues/BLO-15579) (2026-10-09): the
matrix is **not** an interactive session per cell — operator attention is the scarcest
input here, so the whole matrix is a single non-interactive idempotent run that emits a
sanitized tarball plus a pass/fail table.

## For the operator — the one command

Run this on a host that **already has an L3 route to the vJunos** (pve1, or VM 9210 if
Docker is not acceptable on a hypervisor). No new network grant is needed, and no
agent-pod route to the lab subnet is requested.

The lab endpoint, key path and jump host are **not** stored in this repo — git objects
are content-addressed, so unlike a ticket comment they cannot be redacted afterwards.
Take the current values from
[BLO-15630](https://paperclip.blockcast.net/BLO/issues/BLO-15630) and export them:

```sh
git clone https://github.com/Blockcast/frr.git && cd frr
git checkout <the SHA named in the run request>

export JUNOS_HOST=...        # the vJunos address            (BLO-15630)
export JUNOS_KEY=...         # path to the lab SSH key       (BLO-15630)
export JUNOS_LAN_IFL=...     # Junos receiver-stub ifl, e.g. ge-0/0/1.0
export JUNOS_JUMP=...        # ONLY if this host is not the jump host itself

./tests/junos-interop/mvpn-gtm-interop.sh
```

The script refuses to start if any required value is missing, naming the one it wants —
so a missed export costs a second, not a lab round-trip.

It prints a verdict table and leaves `blo15579-artifact-<ts>.tar.gz` in the working
directory. That tarball is the whole deliverable — send it back and nothing else is
needed. Expect roughly 15–20 minutes, most of it the 10-minute step-0 soak.

Everything in the tarball is sanitized, `run.log` included (the console output is not).
The rendered configs that carry the real lab addresses are what gets loaded, so they live
in a private temp directory outside the artifact and are deleted on exit.

Exit status is 0 only if every cell passed.

### If something is already running on the box

Each Junos step is its own SSH call with its own `configure exclusive`, so the config
lock is held per commit, not for the run: a step fails fast if another session holds the
lock at that moment, but another session can still commit between two of ours. That is
why the restore below is an absolute snapshot rather than a count of commits. It is safe
to re-run.

Two *harness* runs against one box is the case `configure exclusive` does not cover, so
G2 refuses to start while another run's `/var/tmp/blo15579-baseline-*.conf` is present.
Without that the second run would capture the first run's harness config as its own
"baseline", restore the box to that, and report `junos-left-unchanged` **PASS** over a
box that is still mutated. If a crashed run left a stale file, check the box is actually
back on its real config, then delete the file.

## What it does to the Junos, and how you can check

- Every commit is `commit confirmed $CONFIRM_MIN`, derived from `HOLD_SECONDS` and
  `SETTLE` so the window outlives the soak (22 min at the defaults; an override
  shorter than that floor is refused at startup). If the script is killed (`^C`, a
  dropped SSH session, `kill -9`), the box **reverts itself within that window** with
  no further action from anyone.
- Before its first commit (gate G2) it saves the running config on the box as
  `/var/tmp/blo15579-baseline-<run timestamp>.conf`; on exit it restores that with
  `load override` and `commit`, transcript in `junos-cleanup.txt`. A `rollback <n>` would
  name the wrong revision if anything else committed in between. The flip side: a commit
  another session makes during the run is undone too.
- **If the restore point is not on the box, cleanup refuses to commit at all.** The Junos
  CLI does not abort a stdin script when a line errors, so a `commit` following a failed
  `load override` would commit an *unchanged* candidate — which is exactly how a pending
  `commit confirmed` gets **confirmed**, turning the auto-revert safety net into the thing
  that makes the harness config permanent. Letting the timer fire is strictly better. The
  summary then says `NOT RESTORED` and names the file to `load override` by hand; it never
  claims a restore it did not verify.

- It then re-downloads the running config and **diffs it against the baseline it captured
  before touching anything**. That diff is in the artifact as `junos-config.diff`, and
  `junos-left-unchanged` is a cell in the verdict table like any other.

That last point is deliberate: "nothing was committed" is a claim, a diff is a receipt.
The BLO-15630 probe could assert it because it only ran `commit check`; a matrix that
holds a real BGP session cannot — it has to commit, so it proves the revert instead.

**The physical MX204 is out of scope. vJunos only.** Nothing here targets it and nothing
here should be pointed at it without a linked maintenance approval.

## Step 0 is a gate, not a warm-up

If a gate fails the matrix does not run. That is the intended behaviour — discovering a
licensing or filter problem in cell 30 of 40 costs an operator round-trip, which is the
expensive thing.

| gate | question |
|---|---|
| G1 | Does TCP/**179** actually reach the Junos? TCP/22 reachability does not imply it. |
| G2 | Baseline config + `show system commit` + `show system license` + `show version` captured, and the running config saved on the box as the restore point. No restore point, no commits. |
| G3 | Does `junos-base.set` survive `commit check`? Nothing is committed in this gate. |
| G4 | Does iBGP come up with **both** MCAST-VPN AFs *negotiated* — not merely configured? |
| G5 | Does the session survive a 10-minute soak? |

G5 exists because the board operator flagged `show system license` reporting
*L2 and L3 Filters: used 1, installed 0, licenses installed: none*. That did not block
`commit check`, but `commit check` is not a sustained session. If the entitlement bites,
it bites here, cheaply, with the license output already in the artifact.

G4 has one deliberate soft failure: if **only** the IPv6 AF fails to negotiate, the v4
matrix still runs and the v6 cells are recorded `SKIP`. Banking the v4 result beats
holding everything for v6.

## Where FRR runs

In its own container network namespace — plain `docker run`, **not** `--network host`.
The container initiates the iBGP session outbound and Docker NATs it, so Junos peers with
this host's address. Consequences, all intended:

- IGMP/MLD joins and the `rx0` receiver stub live inside the container, so the matrix
  never mutates a hypervisor's forwarding state;
- iBGP (not eBGP) because it is NAT- and multihop-tolerant without TTL games;
- there is deliberately **no PIM adjacency** to the Junos. GTM's `neigh_needed=false`
  path is part of what is under test: the join crosses the fabric as BGP or not at all.

The FRR build is pinned by `FRR_SHA` / `FRR_IMAGE`. The image is produced by
`.github/workflows/gtm-image-build.yml` (`workflow_dispatch`, `ref=<sha>`), which tags
`harbor.blockcast.net/blockcast/frr:gtm-<shortsha>`. The resolved SHA is written into
every transcript header and into `summary.md`.

## The matrix

| cell | what it proves |
|---|---|
| `type1-ipmsi-bidir` | Intra-AS I-PMSI A-D in both directions |
| `type1-pmsi-ir-label` | PMSI Tunnel attribute, Ingress Replication, label as Junos reads it |
| `type5-v4-frr-to-junos` / `-junos-to-frr` | Source Active, both directions; `-junos-to-frr` needs a Type-5 FRR *received*, not its own `(local)` one |
| `type7-v4-frr-to-junos` / `-junos-to-frr` | Source Tree Join from a real IGMPv3 (S,G), both directions; `-junos-to-frr` needs a Type-7 FRR *received*, not its own `(local)` one (see Known limits) |
| `type5-v6-…`, `type7-v6-…` | the IPv6 mirrors, MLDv2, `ff3e::/32` |
| `withdraw-type7-v4-leave`, `withdraw-type7-v6-leave` | the route is **gone** after both sides leave (FRR `no … join-group`, Junos `delete … static group`) |
| `withdraw-type5-v4` | the Source Active is **gone** after `no bgp mvpn source-active` |
| `restart-bgpd` | routes replay after a daemon restart |
| `restart-session` | routes replay after a deliberate session clear |
| `junos-left-unchanged` | the config diff above |

Every cell captures the same evidence bundle from **both** sides verbatim — FRR `vtysh`
and Junos CLI — into `cells/<cell>.txt`, sanitized. Cells therefore compare directly, and
a cell only declares what it *changed* and what it *expects*.

The Junos bundle includes `show route table bgp.mvpn.0 hidden detail` and its
`bgp.mvpn6.0` twin. A route Junos received but did not import (no matching route-target,
for example) shows up only there, so a cell whose expected Junos route is hidden fails as
`junos:hidden(...)` rather than `junos:missing(...)`: arrived-but-rejected and
never-arrived need different fixes. A hidden route never satisfies a presence check; an
absence check (withdraw cells) reads both views, since a withdrawn route is gone, not
hidden.

Every cell except the two `restart-*` ones also asserts the BGP session did not reset,
by reading `connectionsEstablished` before and after. That is the "zero unexpected
session resets" acceptance criterion, measured rather than eyeballed. A counter that
cannot be read fails the cell (or G4, or G5) instead of reading as 0, which would match
a 0 baseline and pass.

## Self-check

```sh
./tests/junos-interop/mvpn-gtm-interop.sh --dry-run
```

No lab, no Docker, no network. It runs the real cell loop, verdict logic, sanitizer and
packaging against fixtures **twice**: once where everything is present (expect every cell
to pass) and once where the session is up but no MVPN route is active (expect every
positive-assertion cell to fail). In that second pass Junos holds some of the routes
hidden, and those cells must fail as `hidden`, not pass. A harness whose pass path is
tested and whose fail path is not will cheerfully report green on an empty capture.

Four further passes inject failures via `DRY_FAIL_CMD` (a stubbed command matching that
regex exits 1): a rejected FRR config line, a failing `show` in a withdraw cell, an
unreadable Junos config, and an unreadable session counter (in one cell, at G4, and
after the G5 soak). Each must end in FAIL rows. The show and config cases must also
still produce the tarball, since under `set -e` they used to abort first; the counter
case used to read as 0 and pass. A failed `show` fails its cell, since the hole it
leaves would otherwise read as a proven withdrawal.

The stubbed Junos models `load set` merging: each committed IGMP/MLD static join adds a
Type-7 to the stubbed `bgp.mvpn` tables until a later cell deletes it. One assertion
requires those joins to be absent at G4 and present in the `type7-*-junos-to-frr` cells,
so a join moved back into `junos-base.set` (where it would turn the join cells into
no-ops) fails the self-check, and a withdraw cell that forgets its `delete` fails its cell.

The stubbed FRR shows each committed Junos join as a received Type-7, and a committed
`source-active-advertisement` as a received Type-5, with no `(local)` tag; its own
Type-5 and Type-7 sit in the fixture throughout as `(local)` paths. One more
pass sets `DRY_DROP_JUNOS='static group|source-active-advertisement'`, so the Junos lines
of the three `*-junos-to-frr` cells never reach the box; those cells must then FAIL.
They would pass if FRR's own `(local)` paths satisfied them.

The same model backs the config commands: G2's `display set` and `save`, the cleanup's
`load override`, and the final read-back. It starts with a config of its own and offers
no `rollback`, so `junos-left-unchanged` passes only if cleanup restores the saved
snapshot. One more assertion keeps `junos-base.set` free of `system` statements (the box
is shared) and of IPv6 prefixes in the IPv4 `ssm-groups` list.

Both halves are mutation-tested: deleting the withdraw fixtures turns exactly the three
withdraw cells red, and neutering `sanitize()` turns exactly the four sanitizer
assertions red. If you change the verdict logic, re-run both mutations; a guard with no
failing mutation is a comment.

## Files

| file | |
|---|---|
| `mvpn-gtm-interop.sh` | the harness; `--dry-run` for the self-check |
| `junos-base.set` | **the Junos config — read this one.** It is the single Junos-syntax risk in the harness, which is why gate G3 `commit check`s it before anything is built or committed. A rejected stanza is reported verbatim with its Junos error, so one edit here fixes it without going through the bash. |
| `frr-base.conf` | FRR config, shaped after `tests/topotests/bgp_mvpn_gtm/r1`+`r2` so a failure is attributable to interop rather than to a novel config |
| `fixtures/` | canned captures for `--dry-run` only |

## Known limits

- `junos-base.set` has **not** been validated against a live box. GTM on Junos 26.2R1.7
  wants `mvpn-mode spt-only` in the master instance with no routing-instance; that is the
  intent, and G3 is what confirms the syntax. Treat the first G3 failure as expected
  cost, not as a surprise.
- Junos-side Type-5 origination is driven by a static discard route plus
  `source-active-advertisement`. If that is not how 26.2 wants it expressed, the
  `type5-v4-junos-to-frr` cell is the one that fails and the fix is in `junos-base.set`.
  That cell only counts a Type-5 FRR received: FRR's own `(local)` one from the cell
  before stays up until `withdraw-type5-v4` and would otherwise satisfy it.
- **Open topology question for the owner: can Junos send FRR a Type-7 here at all?** C-S
  sits behind the Junos: `junos-base.set` has a static discard route for it and
  `frr-base.conf` points FRR's RPF for it at the Junos. For the static join in
  `type7-*-junos-to-frr`, Junos is therefore its own upstream, and UMH selection
  (RFC 6513 Section 5.1) gives it no remote PE to send a C-multicast join to. Expect both
  cells to FAIL as `frr:missing(...)` on a live box, so the run exits non-zero even if
  every other cell passes. They are strict on purpose: matching FRR's own `(local)`
  Type-7 would let them pass with no Junos join at all. A real Junos->FRR Type-7 needs
  a C-S behind FRR: a source FRR advertises to Junos in unicast, carrying the VRF Route
  Import extended community UMH selection reads (RFC 6514 Section 7), with no
  Junos-local route for it. That is a topology change, left to the owner.
- The matrix proves control-plane exchange. It does not forward data-plane traffic, so
  IR data-path behaviour (Plan 4) is explicitly out of scope.
