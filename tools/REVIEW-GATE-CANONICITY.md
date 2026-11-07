# Ally review gate — which copy is canonical

Decision record for `.github/scripts/require-ally-review.py` and the workflows
around it, which are vendored by hand into several Blockcast repositories.

Filed against [PEN-5925]. All measurements in this document were taken
2026-11-07 against each repository's default branch and are stamped; re-measure
before relying on a number, and prefer re-running the commands over trusting
the tables.

## 1. The decision

**There are two lineages, both legitimate, and they are not merged.**

| lineage | canonical copy | consumers |
|---|---|---|
| **fleet** | `Blockcast/frr` — this repo | trafficcontrol, FFmpeg, shaka-player, multicast, moqtail-private, linux-amt, Network-Operator-Portal |
| **onprem-k8s** | `Blockcast/onprem-k8s` — itself | nobody; it is not a sync source and not a sync target |

`Blockcast/onprem-k8s` has been **removed from `DEFAULT_FLEET`** in
`tools/sync-review-gate.sh`. That is the whole of the operative change; the
rest of this section is why.

### Why not "onprem-k8s is just ahead, make it canonical"

Because it is not ahead of the fleet copy — it is **beside** it. Measured
2026-11-07, comparing the set of `def`/`class` names each file defines:

- onprem-k8s defines **288** names frr does not.
- frr defines **43** names onprem-k8s does not, with **zero textual occurrence**
  in onprem-k8s under any spelling.
- The two share **8%** of their definitions (Jaccard over definition names) —
  and that 8% is the original common ancestor: `decide`, `main`,
  `self_review_signal`, `attests_head`, `set_commit_status`, `fetch_paginated`.

Each has grown a subsystem the other has never had:

| subsystem | frr line | onprem-k8s |
|---|---:|---:|
| deferral (`deferral`, `trusted_deferrals`, `deferral_comment_is_unedited`) | 147 occurrences | **0** |
| redaction (`redact`) | 4 | **0** |
| finding ledger (`finding_ledger`, `fold_finding_history`, `PRIOR_MIRROR_PATTERN`) | **0** | 42 / 7 / 4 |
| disposition (`disposition`, `dispositioned`) | 2 | 354 / 45 |

Making either one canonical and syncing deletes the other's subsystem. There is
no copy that is a superset, so there is no sync direction that is safe. A merge
of the two is a real engineering project with a real review cost, and nobody has
asked for it; until someone does, the honest state is two lineages, named.

### Why frr keeps the fleet, rather than moving canonical to onprem-k8s

The fleet repos run the frr lineage. Their copies differ from frr's by
hundreds of lines, not thousands, and share 93–100% of their definition names
with it — they are stale descendants of frr, and a frr→fleet sync is the
operation they were set up for. onprem-k8s shares 8%. Pushing onprem-k8s into
them would delete the deferral and redaction subsystems from seven repos, which
is the same fault in the other direction.

### What makes onprem-k8s the upstream of the gate's development

It is where the work happens, and by a wide margin:

| repo | commits ever touching `require-ally-review.py` | last sync FROM frr | local commits since |
|---|---:|---|---:|
| onprem-k8s | **193** | 2026-07-29 (`frr@554f3bdbe6`) | **192** |
| frr | 16 | — | — |

onprem-k8s took exactly one sync, on its second day, and has been developed
independently ever since. It was never a downstream.

## 2. The fleet, enumerated (2026-11-07)

`require-ally-review.py` on each default branch, and what
`tools/review-gate-sync-guard.sh` says about overwriting it from frr's 3,499-line
copy (last committed 2026-10-15T20:58:05Z):

| repo | lines | last sync | local commits since | defs frr lacks | guard verdict |
|---|---:|---|---:|---:|---|
| **frr** (canonical) | 3,499 | — | — | — | — |
| trafficcontrol | 3,403 | 2026-10-07 | 0 | 0 | **SAFE** |
| FFmpeg | 3,247 | 2026-09-24 | 0 | 0 | **SAFE** |
| linux-amt | 3,203 | 2026-09-22 | 0 | 0 | **SAFE** |
| shaka-player | 3,224 | 2026-09-21 | 1 | 0 | REFUSE — copy newer than canonical |
| multicast | 1,949 | 2026-08-17 | 2 | 0 | REFUSE — copy newer than canonical |
| moqtail-private | 1,804 | 2026-08-01 | 4 | 5 | REFUSE — newer, and 5 local definitions |
| Network-Operator-Portal | *absent* | never landed | — | — | SAFE (first rollout) |
| onprem-k8s | 18,133 | 2026-07-29 | 192 | 288 | REFUSE — all three checks |

**What each stale repo is missing, as a list rather than a byte delta.** The
frr lineage is a clean generational ladder, so staleness is cumulative:

- **trafficcontrol, FFmpeg, linux-amt, shaka-player** carry the frr lineage's
  substantive subsystems — deferral, redaction, collaborator-permission map,
  login variants, finding content ids, masked blocking ambiguity. What they lack
  is what frr added after their last sync. Only `trafficcontrol` is close
  enough to carry `is_self_review_author` and `_read_bounded_response`; `FFmpeg`,
  `linux-amt` and `shaka-player` have neither. `dispatch_gate_for_pull` exists
  in frr alone, so every one of the seven lacks it.
- **multicast** and **moqtail-private** are a *generation* behind, not a few
  commits: both lack the collaborator-permission map
  (`fetch_collaborator_permission_map`), `trusted_deferrals`,
  `qualifying_ally_bodies_for_head`, `ally_login_variants` and
  `finding_content_id`. **multicast and moqtail-private have no deferral
  subsystem at all** (0 occurrences against frr's 147). moqtail additionally
  lacks `redact`. These two are the "running a gate with a known hole" cases;
  the other four are "stale but sound".
- **Network-Operator-Portal** has no copy (see §5).

⚠️ This enumeration is by **definition name**, which detects an absent subsystem
reliably and a changed *behaviour* not at all. A repo marked "stale but sound"
may still carry a fixed bug that frr has not taken. Nobody has diffed the
bodies.

### Every target that has committed locally has diverged

Four of the seven fleet repos have had a local commit on the gate since their
last sync — `fix(ci): run the Ally review gate only for comments it can read`,
`fix(review-gate): port the seat-reduction and verdict-contradiction guards`
(BLO-40912), `fix(review-gate): split concurrency per job` (BLO-40894). None of
that work came through frr, and a sync would have deleted all of it. The
vendoring model has not held anywhere it was tested; it has held only where
nobody touched the file.

## 3. The guard

`tools/review-gate-sync-guard.sh` screens every target before
`tools/sync-review-gate.sh` copies anything. Three checks, each failing
**closed**, each overridable only by an explicit flag that is echoed into the
generated pull request body:

| check | refuses when | override |
|---|---|---|
| **A — definition loss** | the target defines a `def`/`class` name canonical does not | `--allow-definition-loss` |
| **B — net size** | the sync removes more than 100 net lines (tunable) | `--max-net-added N` |
| **C — recency** | the target's copy was committed later than canonical's, **or either date is unknown or unparseable** | `--allow-older-canonical` |

Check A is the decisive one and the only one that catches onprem-k8s on its own
evidence; B and C are defence in depth for work that reuses canonical's names,
and for the general shape of propagating something older than what it replaces.

Two paths skip all three, and both are cases where nothing can be lost:

- **First rollout** — the target carries no copy at all.
- **Target byte-identical to canonical** — the overwrite is a no-op on that
  file. This is the *routine* propagation path, not an edge case: a synced
  target's gate-script date is its own sync commit's, which is always later
  than the canonical commit it copied, so without this short-circuit check C
  would refuse every canonical change that touches a workflow rather than the
  gate script — exactly the kind frr made on 2026-10-18 and 2026-10-31 while
  the script last moved on 2026-10-15. The only way through would have been the
  blanket `--allow-older-canonical`, and a guard that makes operators reach for
  the override on the routine path has taught them to reach for it on the
  dangerous one. A target edited after its sync has a newer date *and*
  differing content, so it does not reach this short-circuit and stays refused.

`--dry-run` now clones and screens every target and writes nothing, rather than
echoing the canonical sha. A dry run that does not read the target cannot answer
the only question worth asking of it.

## 4. Disposition on the composite-action note

`tools/sync-review-gate.sh` has carried this since the first rollout:

> The durable fix is a shared composite action — revisit once the rollout proves
> the logic stable across repos.

**Disposition: not built. Vendored copies are the accepted steady state, and the
guards in §3 are the permanent mitigation, not a stopgap.**

The note's own precondition was never met and cannot now be met on its terms:
the rollout did not prove the logic stable across repos, it proved the opposite
(§2). But the measurement also undercuts the remedy. A composite action
centralises a *single* implementation, and there are demonstrably **two** —
onprem-k8s's 18,133-line ledger program and frr's 3,499-line deferral program —
which a shared action would have to merge before it could exist. That merge is
the expensive part, and it is unchanged whether the result ships as an action or
as a file.

A composite action would also move a merge control from a file each repo's
branch protection can see into a reference each repo resolves at run time, which
is a change in the gate's trust model and wants its own review. Revisit if and
when someone funds the two-lineage merge; that is the blocking work, and this
note is not a reason to start it.

## 5. `Network-Operator-Portal` and `penstock-vault-node`

Both were asked about on [PEN-5925]. They resolve differently, and only one of
them is in the fleet at all.

- **`Network-Operator-Portal` — in `DEFAULT_FLEET`; the rollout never landed.**
  It has no `require-ally-review.py` at any path. It carries one related file,
  `.github/workflows/review-gate-sweep.yml`. Its `ci/ally-review-gate-sync`
  branch exists, is **1 commit ahead and 1,020 behind** `main`, and its tip is
  `ci: sync Ally review gate from Blockcast/frr@d4c608ebb5` dated
  **2026-07-31** — the first rollout attempt, never merged, no open PR. So: the
  sync was offered once, 3+ months ago, and nobody took it. The guard treats
  the repo as a first rollout and will pass it; whether the gate *should* be
  deployed there is a decision for that repo's owners, not something this script
  should keep re-offering.
- **`penstock-vault-node` — NOT in `DEFAULT_FLEET`, and not a vendored copy.**
  PEN-5925 lists it as a fleet member that is missing its copy; that is a filing
  error. It is absent from `DEFAULT_FLEET` and always has been. It has its own,
  differently-designed review-gate implementation —
  `.github/workflows/review-gate.yml`,
  `.github/workflows/review-gate-strand-watchdog.yml`,
  `.github/workflows/review-gate-action-smoke.yml`,
  `scripts/detect-stranded-review-gate.py` — which shares no file with this
  lineage. Nothing to sync, nothing missing.

PEN-5925 also enumerates seven copies. There are **eight**: `Blockcast/linux-amt`
is in `DEFAULT_FLEET`, carries a 3,203-line copy, and was not probed.

## 6. Two defects found while measuring this, both fixed here

- **`CANON_FILES` was missing `.github/workflows/review-gate-relay.yml`.**
  `review-gate.yml` names it in `workflow_run: workflows: [review-gate-relay]`,
  so a repo synced without it receives no formal-review events at all — a
  merge control that is silently absent, which is the failure the gate exists to
  close. The relay landed in frr on 2026-10-31 (`481bf44`) and was never added
  to the sync set. It also broke the canonical suite's `TestWorkflowRunRelay`
  when run from `$CANON_TMP`, which means **`sync-review-gate.sh` has refused to
  propagate anything since that date** — it exits on `canonical suite is RED`.
  That failure was fail-closed and therefore harmless, but it is also why the
  fleet's last syncs all predate 2026-10-15.
- **The `runs-on` rewrite had been dead since the same commit.** The script
  rewrites `^    runs-on: default$`; frr's canonical workflows moved to the
  block form (`group: default-tools` / `labels: arc-light`) and that pattern now
  matches **zero** lines. A repo asking for its own runner label was silently
  given frr's ARC group instead, and the generated PR body asserted the label
  had been applied. Every current fleet entry asks for `default`, so nothing has
  actually mis-shipped. The script now **refuses** a non-`default` request it
  cannot satisfy, instead of claiming it did. Teaching the rewrite to emit the
  block form is a design question and is left open.

## 7. Re-measuring

```sh
# Per-repo copy and its history
for r in frr onprem-k8s trafficcontrol FFmpeg shaka-player multicast \
         moqtail-private linux-amt Network-Operator-Portal; do
  db=$(gh api "repos/Blockcast/$r" --jq .default_branch)
  gh api -H "Accept: application/vnd.github.raw" \
    "repos/Blockcast/$r/contents/.github/scripts/require-ally-review.py?ref=$db" > "$r.py" 2>/dev/null \
    && echo "$r $(wc -l < "$r.py")" || echo "$r absent"
done

# Definition-set divergence between any two copies
defs() { grep -oE '^[[:space:]]*(def|class) [A-Za-z_][A-Za-z_0-9]*' "$1" |
         sed -E 's/^[[:space:]]*(def|class) //' | sort -u; }
comm -3 <(defs frr.py) <(defs onprem-k8s.py)

# What a sync would do to every target, writing nothing
tools/sync-review-gate.sh --dry-run
```

[PEN-5925]: https://paperclip.blockcast.net/PEN/issues/PEN-5925
