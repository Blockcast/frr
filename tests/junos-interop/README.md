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

Exit status is 0 only if every cell passed.

### If something is already running on the box

The script takes the Junos config lock (`configure exclusive`) and will fail fast rather
than interleave with another session. It is safe to re-run.

## What it does to the Junos, and how you can check

- Every commit is `commit confirmed 10`. If the script is killed — `^C`, a dropped SSH
  session, `kill -9` — the box **reverts itself within 10 minutes** with no further
  action from anyone.
- On normal exit it rolls back exactly the number of commits it made.
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
| G2 | Baseline config + `show system commit` + `show system license` + `show version` captured. |
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
| `type5-v4-frr-to-junos` / `-junos-to-frr` | Source Active, both directions |
| `type7-v4-frr-to-junos` / `-junos-to-frr` | Source Tree Join from a real IGMPv3 (S,G), both directions |
| `type5-v6-…`, `type7-v6-…` | the IPv6 mirrors, MLDv2, `ff3e::/32` |
| `withdraw-type7-v4-leave`, `withdraw-type7-v6-leave` | the route is **gone** after a leave |
| `withdraw-type5-v4` | the Source Active is **gone** after `no bgp mvpn source-active` |
| `restart-bgpd` | routes replay after a daemon restart |
| `restart-session` | routes replay after a deliberate session clear |
| `junos-left-unchanged` | the config diff above |

Every cell captures the same evidence bundle from **both** sides verbatim — FRR `vtysh`
and Junos CLI — into `cells/<cell>.txt`, sanitized. Cells therefore compare directly, and
a cell only declares what it *changed* and what it *expects*.

Every cell except the two `restart-*` ones also asserts the BGP session did not reset,
by reading `connectionsEstablished` before and after. That is the "zero unexpected
session resets" acceptance criterion, measured rather than eyeballed.

## Self-check

```sh
./tests/junos-interop/mvpn-gtm-interop.sh --dry-run
```

No lab, no Docker, no network. It runs the real cell loop, verdict logic, sanitizer and
packaging against fixtures **twice**: once where everything is present (expect every cell
to pass) and once where the session is up but no MVPN routes exist (expect every
positive-assertion cell to fail). A harness whose pass path is tested and whose fail path
is not will cheerfully report green on an empty capture.

Both halves are mutation-tested — deleting the withdraw fixtures turns exactly the three
withdraw cells red, and neutering `sanitize()` turns exactly the three sanitizer
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
- The matrix proves control-plane exchange. It does not forward data-plane traffic, so
  IR data-path behaviour (Plan 4) is explicitly out of scope.
