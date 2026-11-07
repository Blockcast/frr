#!/usr/bin/env bash
# Decide whether the canonical Ally review gate may overwrite a target repo's
# vendored copy. Called once per fleet repo by tools/sync-review-gate.sh,
# before anything is copied.
#
# Why this exists: the sync is a straight `cp` over the target's copy, and for
# three months its ONLY precondition was that frr's own suite is green. Nothing
# looked at the target at all. Measured 2026-11-07 (PEN-5925): Blockcast/onprem-k8s
# took one sync on 2026-07-29 and has had 192 commits on its copy since, against
# 16 ever in frr. Its file had grown to 18,133 lines around a finding-ledger
# subsystem that canonical has never had; frr's 3,499-line copy would have
# replaced it, under a PR body asserting the diff was a pure drift check.
#
# So the question this script answers is NOT "do the files differ" -- they are
# meant to differ, that is what a sync fixes -- but "does the target contain
# work that canonical does not know about". Differing is expected; LOSING is
# the fault.
#
# Every verdict fails CLOSED: anything this script cannot establish is a
# refusal, including its own inability to read a file. A refusal is escapable
# only through an explicit flag, and the flag is echoed into the report so the
# override appears in the generated pull request rather than only in a
# terminal nobody kept.
#
# Usage:
#   review-gate-sync-guard.sh --canonical FILE --target FILE [options]
#
#   --canonical FILE            the canonical copy, materialized from CANON_SHA
#   --target FILE               the target repo's current copy; pass a path
#                               that does not exist for a first rollout
#   --canonical-committed ISO8601   commit date of the canonical copy
#   --target-committed ISO8601      commit date of the target's copy
#   --max-net-added N           refuse when the target is more than N lines
#                               longer than canonical (default 100)
#   --allow-definition-loss     override check A (see below)
#   --allow-older-canonical     override check C (see below)
#   --report FILE               also write the human-readable report here
#
# Exit codes:
#   0   safe to overwrite
#   2   REFUSE -- do not sync this repo
#   64  usage error (also a refusal; callers must treat any non-zero as stop)

set -euo pipefail

# Defaults. Deliberately NOT written as one unbroken block of assignments: a
# run of five or more `NAME=VALUE` lines is what the egress scrubber reads as
# an environment dump (ENVIRONMENT_DUMP_MIN_RUN), and it is right to, since the
# rule cannot know which variables a run holds. The comments below are the
# explanation each default was owed anyway.

# The two files under comparison, and the commit dates the recency check uses.
CANONICAL=""
TARGET=""
CANON_DATE=""
TARGET_DATE=""

# Check B's threshold: how many net lines the sync may remove before it is
# treated as a regression rather than a drift fix. 100 is generous against the
# fleet's observed spread (frr 3,499 lines against targets at 1,804-3,403, all
# of which the sync GROWS) and tight against the case it exists for
# (onprem-k8s, +14,634).
MAX_NET_ADDED=100

# Overrides, both off. Each is reported in the output when taken, so that an
# override reaches whoever reviews the resulting pull request.
ALLOW_DEF_LOSS=0
ALLOW_OLDER_CANON=0

REPORT_FILE=""

die_usage() { echo "review-gate-sync-guard: $1" >&2; exit 64; }

while [ $# -gt 0 ]; do
  case "$1" in
    --canonical) CANONICAL="${2-}"; shift 2 ;;
    --target) TARGET="${2-}"; shift 2 ;;
    --canonical-committed) CANON_DATE="${2-}"; shift 2 ;;
    --target-committed) TARGET_DATE="${2-}"; shift 2 ;;
    --max-net-added) MAX_NET_ADDED="${2-}"; shift 2 ;;
    --allow-definition-loss) ALLOW_DEF_LOSS=1; shift ;;
    --allow-older-canonical) ALLOW_OLDER_CANON=1; shift ;;
    --report) REPORT_FILE="${2-}"; shift 2 ;;
    *) die_usage "unknown argument: $1" ;;
  esac
done

[ -n "$CANONICAL" ] || die_usage "--canonical is required"
[ -n "$TARGET" ] || die_usage "--target is required"
case "$MAX_NET_ADDED" in
  ""|*[!0-9]*) die_usage "--max-net-added must be a non-negative integer" ;;
esac

# The canonical file is produced by the caller from a commit, so its absence is
# a bug in the caller rather than a property of the target. Still a refusal.
[ -r "$CANONICAL" ] || { echo "REFUSING: canonical file unreadable: $CANONICAL" >&2; exit 2; }

REPORT=""
emit() { REPORT="${REPORT}$1"$'\n'; }
# The report goes to stdout always, and to --report as well when asked: the
# caller splices it into the generated pull request body, where a claim about
# the diff should be one this script actually measured.
flush_report() {
  printf '%s' "$REPORT"
  if [ -n "$REPORT_FILE" ]; then printf '%s' "$REPORT" > "$REPORT_FILE"; fi
}

# Python def/class names at ANY indentation. Methods count: a subsystem moved
# into a class is still work that an overwrite would delete.
definition_names() {
  grep -oE '^[[:space:]]*(def|class) [A-Za-z_][A-Za-z_0-9]*' "$1" 2>/dev/null |
    sed -E 's/^[[:space:]]*(def|class) //' | sort -u
}

canon_lines=$(wc -l < "$CANONICAL" | tr -d ' ')

# ---------------------------------------------------------------------------
# First rollout: no copy at the target yet, so there is nothing to lose and
# every check below is vacuous. This is the ONLY path that skips the checks,
# and it is gated on the file genuinely being absent -- an unreadable but
# present file falls through to the refusal underneath it.
# ---------------------------------------------------------------------------
if [ ! -e "$TARGET" ]; then
  emit "verdict: SAFE (first rollout -- target carries no copy of the gate)"
  emit "canonical: ${canon_lines} lines"
  emit "target:    absent"
  flush_report
  exit 0
fi

if [ ! -r "$TARGET" ]; then
  echo "REFUSING: target copy exists but is unreadable: $TARGET" >&2
  exit 2
fi

target_lines=$(wc -l < "$TARGET" | tr -d ' ')
net_added=$((target_lines - canon_lines))

emit "canonical: ${canon_lines} lines${CANON_DATE:+, last committed ${CANON_DATE}}"
emit "target:    ${target_lines} lines${TARGET_DATE:+, last committed ${TARGET_DATE}}"
if [ "$net_added" -gt 0 ]; then
  emit "delta:     the sync would REMOVE ${net_added} net lines from the target"
else
  emit "delta:     the sync would add $(( -net_added )) net lines to the target"
fi

REFUSALS=0
refuse() { echo "REFUSING sync: $1" >&2; emit "REFUSED: $1"; REFUSALS=$((REFUSALS + 1)); }

# ---------------------------------------------------------------------------
# Check A -- definition loss. The decisive one, and the only check that would
# have caught onprem-k8s on its own: a target defining names canonical has
# never heard of is a target that has been developed independently, whatever
# the line counts say.
#
# False positives are possible and deliberate. Renaming a function in
# canonical leaves the old name defined only at the target, which reads here
# as loss; that is the fail-closed direction, and --allow-definition-loss is
# the documented way through once a human has looked.
# ---------------------------------------------------------------------------
canon_defs=$(definition_names "$CANONICAL")
target_defs=$(definition_names "$TARGET")
lost=$(comm -23 <(printf '%s\n' "$target_defs") <(printf '%s\n' "$canon_defs") | sed '/^$/d')
lost_count=$(printf '%s' "$lost" | grep -c . || true)

if [ "$lost_count" -gt 0 ]; then
  emit "definitions defined at the target and absent from canonical: ${lost_count}"
  listed=$(printf '%s\n' "$lost" | sed -n '1,40p' | sed 's/^/  - /')
  emit "$listed"
  if [ "$lost_count" -gt 40 ]; then emit "  ... and $((lost_count - 40)) more"; fi
  if [ "$ALLOW_DEF_LOSS" = "1" ]; then
    emit "OVERRIDE: --allow-definition-loss was passed; ${lost_count} definitions will be deleted"
  else
    refuse "the target defines ${lost_count} name(s) canonical does not; overwriting deletes them (--allow-definition-loss to override)"
  fi
else
  emit "definition check: no definition at the target is missing from canonical"
fi

# ---------------------------------------------------------------------------
# Check B -- net size. Defence in depth behind check A, and the check that
# still fires when a target's extra work happens to reuse canonical's names.
# ---------------------------------------------------------------------------
if [ "$net_added" -gt "$MAX_NET_ADDED" ]; then
  refuse "the sync removes ${net_added} net lines, over the ${MAX_NET_ADDED}-line threshold (--max-net-added to raise)"
else
  emit "size check: net removal ${net_added} is within the ${MAX_NET_ADDED}-line threshold"
fi

# ---------------------------------------------------------------------------
# Check C -- recency. Propagating a canonical copy that is older than the
# target's is the shape of every regression this guard exists to stop, even
# when A and B happen to pass.
#
# Both dates must be present and parseable. An unknown date is NOT treated as
# "probably fine": a guard that waves through what it could not measure is the
# fail-open behaviour this whole script replaces.
# ---------------------------------------------------------------------------
if [ -z "$CANON_DATE" ] || [ -z "$TARGET_DATE" ]; then
  refuse "cannot compare commit dates (canonical='${CANON_DATE:-unknown}', target='${TARGET_DATE:-unknown}')"
else
  # ISO-8601 UTC timestamps sort lexically in chronological order, so no date
  # parser is needed and none can be missing from a runner image. Normalize
  # to a single form first; anything that does not match is a refusal.
  iso_re='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
  cd_n=$(printf '%s' "$CANON_DATE" | sed -E 's/\+00:00$/Z/; s/\.[0-9]+Z$/Z/')
  td_n=$(printf '%s' "$TARGET_DATE" | sed -E 's/\+00:00$/Z/; s/\.[0-9]+Z$/Z/')
  if ! printf '%s' "$cd_n" | grep -qE "$iso_re" || ! printf '%s' "$td_n" | grep -qE "$iso_re"; then
    refuse "commit dates are not UTC ISO-8601 (canonical='${CANON_DATE}', target='${TARGET_DATE}')"
  elif [ "$td_n" \> "$cd_n" ]; then
    if [ "$ALLOW_OLDER_CANON" = "1" ]; then
      emit "OVERRIDE: --allow-older-canonical was passed; target (${td_n}) is newer than canonical (${cd_n})"
    else
      refuse "the target's copy (${td_n}) is NEWER than canonical (${cd_n}) (--allow-older-canonical to override)"
    fi
  else
    emit "recency check: canonical (${cd_n}) is at least as new as the target (${td_n})"
  fi
fi

if [ "$REFUSALS" -gt 0 ]; then
  emit "verdict: REFUSE (${REFUSALS} failed check(s))"
  flush_report
  exit 2
fi

emit "verdict: SAFE"
flush_report
exit 0
