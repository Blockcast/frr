# MVPN Type-7 Settlement Event Schema (BLO-17645)

**Status:** Implemented and verified by the `bgp_mvpn_gtm_events` topotest;
pending downstream FlowSource consumption (BLO-17650)

**Paperclip:** [BLO-17645](https://paperclip.blockcast.net/BLO/issues/BLO-17645)

**Parent:** [BLO-17642](https://paperclip.blockcast.net/BLO/issues/BLO-17642)
(MVPN Replication Billing epic)

**Normative reference:** `Blockcast/trafficcontrol`
`docs/designs/mvpn-settlement-contract-v1.md`
([BLO-17643](https://paperclip.blockcast.net/BLO/issues/BLO-17643)). This
document is the wire-format companion to that contract for exactly the
fields bgpd is the source of truth for: Type-7 lifecycle, `route_version`,
and `lc_umh_origin`. Where the two disagree, the settlement contract wins and
this document is wrong.

## Why this exists

`vtysh show bgp ipv4/ipv6 mvpn json` polling is dev-mode and reconciliation
cross-check only. It is not, and must never become, the production claim
source: poll artifacts becoming billing artifacts was the finding that
motivated this issue. This event stream is the settlement-readiness gate --
the one thing downstream of it (the amt-astats MVPN FlowSource, BLO-17650)
is allowed to build claims from.

## Transport

- `bgp mvpn event-socket PATH` (instance-wide, `router bgp` node) opens an
  `AF_UNIX SOCK_STREAM` listener at `PATH` when configured; `no bgp mvpn
  event-socket` (or omitting the knob) means the feature is off. Opt-in,
  like the other GTM MVPN knobs (`bgp mvpn ipmsi-label`, `bgp mvpn
  umh-large-community`).
- A client first sends `{"type":"subscribe","schema_version":1}`. Every
  subscribed client receives a private `install` snapshot of every currently
  active local Type-7 join before joining the live broadcast stream. Snapshot
  construction is serialized between clients so replay cannot mutate the
  producer's join state concurrently, but a missing acknowledgment does not
  block later subscribers: once one client's `snapshot_end` is queued, the next
  private replay is offered. This is the epoch handoff: old clients were
  disconnected when the prior listener stopped, and the snapshot opens replacement
  entitlement windows without turning a debug/reconciliation poll into a
  billing artifact. A client's snapshot remains pending until it sends
  `{"type":"snapshot_ack","boot_epoch":N,"seq":M}` after receiving the
  `{"type":"snapshot_end",...}` frame. Snapshot install records carry
  `"snapshot":true` and a one-based `snapshot_index`; they retain the current
  global `seq` baseline rather than consuming lifecycle sequence numbers. The
  `snapshot_end` frame carries that baseline and `snapshot_count`. A
  connect-only health probe or a client that disconnects before acknowledgment
  cannot consume the snapshot; a reconnect receives its own replay. Empty
  snapshots still end with `snapshot_end` and require acknowledgment. Live
  records may be queued while that acknowledgment is pending, but AF_UNIX stream
  ordering guarantees they follow `snapshot_end` for that client. No timeout is
  required, and one non-acknowledging client cannot starve another subscriber.
- Wire format: one JSON object per line (`\n`-terminated, no pretty-printing)
  per event. Live lifecycle events are broadcast identically to every
  client whose private `snapshot_end` has been queued (by socket ordering);
  queued clients receive no live records before their baseline. Snapshot records
  are private to the handoff owner.
- A client that falls behind by more than 8MiB of unflushed output is
  disconnected rather than buffered without bound. This is deliberate, not a
  bug: an unbounded queue would turn a stalled consumer into unbounded bgpd
  memory growth on a settlement-critical path. The client's own gap
  detection (below) turns the resulting reconnect into an explicit,
  observable gap rather than silent loss.

## Durable cursor and gap detection

Every lifecycle event and snapshot frame carries `boot_epoch` and `seq`:

- `seq` is a per-listener-instance, in-memory monotonic counter starting at
  1. It is **not** fsynced per event, and it resets to 1 whenever the listener
  is (re)created (which always also advances `boot_epoch` -- see below -- so
  the `(boot_epoch, seq)` *pair* stays strictly ordered; do not rely on `seq`
  alone across an epoch change).
- Snapshot records do not advance `seq`: they describe current state at the
  `snapshot_end.seq` baseline (zero when no live event has occurred in the new
  epoch). After durably applying and acknowledging the snapshot, the consumer
  persists that baseline; the next live event must be exactly `seq + 1`.
- `boot_epoch` is a small integer persisted under `$frr_runstatedir` (e.g.
  `/var/run/frr/bgpd-mvpn-events-default.epoch`) and incremented on every
  listener start, under an exclusive lock separate from the atomically-renamed
  state file. Invalid state or any lock/write/fsync/rename failure prevents the
  listener from starting. A bare `bgpd` process restart
  is the common cause, but reconfiguring the socket (`no bgp mvpn
  event-socket` then re-adding it, or changing the path) within one running
  process also starts a new listener and therefore bumps `boot_epoch`. Either
  way the new listener's events are tagged with a strictly higher `boot_epoch`
  than anything emitted before.

A consumer implements the durable cursor described in BLO-17645 ("a durable
cursor so a restarted consumer can detect gaps") by persisting `(boot_epoch,
seq)` of the last event it has fully processed, on its own side (this is the
consumer's responsibility -- see BLO-17650's restart-checkpoint
requirement). On reconnect, or on the next event after any connection, the
consumer compares each incoming live event's `(boot_epoch, seq)` to its
persisted cursor. Snapshot records are applied as a framed set through
`snapshot_end`, not run through the live-event increment check:

- `boot_epoch` unchanged, `seq == last_seq + 1`: contiguous, no gap.
- `boot_epoch` unchanged, `seq > last_seq + 1`: a genuine gap (the connection
  that carried the missing events was dropped for backlog, or similar).
  **Quarantine the interval, do not fill it from
  `show bgp mvpn json` polling** (Section header above) -- resync by
  re-deriving current state from a fresh dev-mode poll if you must, but the
  gap itself is billing-relevant and must not be silently absorbed.
- `boot_epoch` increased: the producer's listener restarted -- a `bgpd`
  restart, or an operator reconfiguring the event socket within one process
  (see "Durable cursor" above). Treat it as a boot boundary either way: every
  join in the new epoch's per-consumer `install` snapshot is a fresh route-entitlement
  interval (Section 6 of the settlement contract): the consumer's prior
  windows for this instance should be closed out at the last event of the old
  epoch it saw, and new windows opened from the new epoch's events.

`route_version` is the opaque string `"<boot_epoch>.<generation>"`, where
`generation` is scoped to one `(source, group)` join identity (not global)
and increments on every `install`, `withdraw`, and `origin_change` for that
join -- matching the settlement contract's rule that `route_version` changes
on any install/withdraw/LC-UMH-origin change. `generation` is never reused
across a leave/rejoin cycle within one `boot_epoch`: a withdrawn join that
rejoins later gets a strictly higher `route_version`, not a restart from 1.

## Event types

| `event_type` | Emitted when |
| --- | --- |
| `install` | A local (pimd-driven) Type-7 join is originated for a `(source, group)` this sink has not seen installed before (first join, or a rejoin after a prior withdraw). |
| `withdraw` | The local Type-7 join for a `(source, group)` this sink previously observed installed is removed. |
| `origin_change` | An already-installed join's resolved `(source_as, upstream_peer)` changes -- typically because the unicast route toward C-S changed (a new best path, a new/changed route-import RT or UMH large community, and so on). No withdraw/re-join occurs on the wire; the Type-7 route is re-originated in place. |

A redundant re-resolution that produces the *same* `(source_as,
upstream_peer)` as last emitted (for example, an unrelated unicast churn
that re-triggers `bgp_mvpn_reresolve_joins_for_route` without actually
changing this join's resolved values) emits nothing.

## Fields

| Field | Type | Present on | Meaning |
| --- | --- | --- | --- |
| `schema_version` | int | all output records | `1`. Bump on any breaking wire-format change. |
| `type` | string | `snapshot_end` only | `snapshot_end`; distinguishes the framing record from lifecycle-shaped snapshot installs. |
| `event_type` | string | live lifecycle and snapshot install records | `install` \| `withdraw` \| `origin_change`. Snapshot records are always `install`. |
| `boot_epoch` | int | all output records | See "Durable cursor" above. |
| `seq` | int | all output records | Live lifecycle sequence, starting at 1. Snapshot records and `snapshot_end` retain the current baseline, which may be 0 before the first live event. Use the `(boot_epoch, seq)` pair, not `seq` alone, for gap detection. |
| `snapshot` | bool | snapshot install records only | `true`; identifies a private point-in-time install rather than a live lifecycle transition. |
| `snapshot_index` | int | snapshot install records only | One-based position of this install in the current snapshot frame. |
| `snapshot_count` | int | `snapshot_end` only | Number of snapshot install records preceding this frame. |
| `time_ns` | int | live lifecycle and snapshot install records | `CLOCK_REALTIME` nanoseconds since the Unix epoch, at emission time. |
| `route_type` | int | live lifecycle and snapshot install records | `7` (RFC 6514 C-multicast Source Tree Join). Fixed today; present so a future record kind sharing this socket is distinguishable. |
| `source` | string | live lifecycle and snapshot install records | C-S, canonical text (v4 or v6). |
| `group` | string | live lifecycle and snapshot install records | C-G, canonical text (v4 or v6). |
| `source_as` | int | live lifecycle and snapshot install records | RFC 6514 Section 4.6 Source AS from the Type-7 NLRI key (falls back to the local AS per RFC 6514 Section 4.6 when the source route carries no Source-AS community). |
| `route_version` | string | live lifecycle and snapshot install records | Opaque, per-join monotonic. See above. |
| `prior_route_version` | string | `origin_change` only | The join's `route_version` immediately before this transition -- lets a consumer close the old billing window and open a new one at the same instant. |
| `lc_umh_origin` | string | when an upstream PE was resolved | `"<sourceAS>:1:<UMH-u32>"`, byte-for-byte the settlement contract's `SessionLease.lc_umh_origin` format. The literal function code point `1` here is a settlement-contract convention for the resolved-origin attestation; it is independent of the operator-configured `bgp mvpn umh-large-community <function>` decode knob, which selects which function code point bgpd itself trusts on the wire. Absent when no upstream PE could be resolved (RT-less origination; see `bgp_mvpn_source_tree_join_set()`). |
| `upstream_peer` | string | when an upstream PE was resolved | The resolved upstream PE's IPv4 address (the RFC 7716 upstream-node-identifying Route Target's Global Administrator, or the large-community UMH when `bgp mvpn umh-large-community` is configured). This is the "peer/leaf next-hop" BLO-17645 and BLO-17650 refer to for counter identity. |
| `ipmsi_label` | int | live lifecycle and snapshot install records | This bgp instance's configured `bgp mvpn ipmsi-label` (0 = unlabeled GTM tunnel, RFC 6514 Section 5). The "MPLS label" BLO-17650's counter-identity key refers to. |
| `vrf` | string | live lifecycle and snapshot install records | The bgp instance name, or `default`. |

## Example

Install, with a resolved upstream:

```json
{"schema_version":1,"event_type":"install","boot_epoch":7,"seq":1,"time_ns":1785000000000000,"route_type":7,"source":"10.10.10.10","group":"232.1.1.1","source_as":65001,"route_version":"7.1","lc_umh_origin":"65001:1:167772162","upstream_peer":"10.0.0.2","ipmsi_label":100,"vrf":"default"}
```

Origin change carrying both route versions:

```json
{"schema_version":1,"event_type":"origin_change","boot_epoch":7,"seq":4,"time_ns":1785000004000000,"route_type":7,"source":"10.10.10.10","group":"232.1.1.1","source_as":65001,"route_version":"7.4","prior_route_version":"7.3","lc_umh_origin":"65001:1:167772163","upstream_peer":"10.0.0.3","ipmsi_label":100,"vrf":"default"}
```

Withdraw (no `lc_umh_origin`/`upstream_peer` reported -- the join is gone,
not re-resolved):

```json
{"schema_version":1,"event_type":"withdraw","boot_epoch":7,"seq":2,"time_ns":1785000001000000,"route_type":7,"source":"10.10.10.10","group":"232.1.1.1","source_as":65001,"route_version":"7.2","ipmsi_label":100,"vrf":"default"}
```

## Implementation

`bgpd/bgp_mvpn_events.{c,h}`. Emission call sites are centralized in
`bgp_mvpn_source_tree_join_set()` (the existing pimd-driven join/leave path,
covering both the direct receiver-join case and the
`bgp_mvpn_reresolve_joins_for_route()` re-origination case) --
per BLO-17645, "emission is purely event-driven from the existing join_set/
remove code path", no timers, no defaults.

## Verification and remaining gap

- The locally built `frrouting/topotests:latest` image completed a full FRR
  build and `bgp_mvpn_gtm_events/test_bgp_mvpn_gtm_events.py` passed all eight
  tests, including event-after-RIB ordering, failure-atomic listener
  replacement, fail-closed epoch persistence, and acknowledged active-join
  snapshot replay after listener reconfiguration.
- A full bgpd process restart's `boot_epoch` bump remains asserted by the
  persisted-counter implementation and code inspection. The automated test
  covers the equivalent listener restart/path-change boundary, but does not
  restart bgpd itself mid-topotest.
