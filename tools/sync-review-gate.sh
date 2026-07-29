#!/usr/bin/env bash
# Sync the canonical Ally review gate from this repo to the org's other
# Ally-reviewed repos, opening one advisory PR per repo.
#
# Canonical source (this repo):
#   .github/scripts/require-ally-review.py
#   .github/scripts/test_require_ally_review.py
#   .github/workflows/review-gate.yml          (runs-on rewritten per repo)
#   .github/workflows/review-gate-selftest.yml (runs-on rewritten per repo)
#
# Nine vendored copies of one merge control WILL drift; this script makes
# re-syncing one command instead of nine hand-edits. The durable fix is a
# shared composite action -- revisit once the rollout proves the logic stable
# across repos.
#
# Advisory-first: the gate only POSTS the review/ally-complete status. Making
# it a required check is a per-repo branch-protection change done manually
# after that repo shows correct pending/success behaviour on real PRs --
# and only after the gate workflow is on the repo's default branch, because
# pull_request_target runs base-branch workflows: requiring a context the
# base branch cannot yet produce deadlocks every PR including the rollout PR.
#
# Usage:
#   tools/sync-review-gate.sh [--dry-run] [repo[:runs-on] ...]
# With no repos listed, syncs the default fleet below.

set -euo pipefail

# repo:runs-on. Runner labels are NOT uniform across the org (verified
# 2026-07-28); default to the ARC 'default' pool unless a repo is known to
# use hosted runners.
DEFAULT_FLEET=(
  "Blockcast/onprem-k8s:ubuntu-latest"
  "Blockcast/trafficcontrol:default"
  "Blockcast/Network-Operator-Portal:default"
  "Blockcast/multicast:default"
  "Blockcast/shaka-player:default"
  "Blockcast/moqtail-private:default"
  "Blockcast/FFmpeg:default"
  "Blockcast/linux-amt:default"
)

BRANCH="ci/ally-review-gate-sync"
CANON_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DRY_RUN=0
FLEET=()
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    *) FLEET+=("$arg") ;;
  esac
done
[ ${#FLEET[@]} -gt 0 ] || FLEET=("${DEFAULT_FLEET[@]}")

for f in .github/scripts/require-ally-review.py \
         .github/scripts/test_require_ally_review.py \
         .github/workflows/review-gate.yml \
         .github/workflows/review-gate-selftest.yml; do
  [ -f "$CANON_ROOT/$f" ] || { echo "canonical file missing: $f" >&2; exit 1; }
done

# The canonical suite must be green before it is propagated anywhere.
python3 -m unittest discover -s "$CANON_ROOT/.github/scripts" -p 'test_*.py' >/dev/null 2>&1 || {
  echo "canonical suite is RED; refusing to propagate" >&2; exit 1; }

CANON_SHA=$(git -C "$CANON_ROOT" rev-parse HEAD)

for entry in "${FLEET[@]}"; do
  repo="${entry%%:*}"
  runner="${entry#*:}"
  [ "$runner" != "$entry" ] || runner="default"
  echo "=== $repo (runs-on: $runner) ==="

  if [ "$DRY_RUN" = "1" ]; then
    echo "  dry-run: would sync gate @ ${CANON_SHA:0:10}"
    continue
  fi

  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  gh repo clone "$repo" "$work/repo" -- --depth 1 >/dev/null 2>&1
  (
    cd "$work/repo"
    git checkout -B "$BRANCH" >/dev/null

    mkdir -p .github/scripts .github/workflows
    cp "$CANON_ROOT/.github/scripts/require-ally-review.py" .github/scripts/
    cp "$CANON_ROOT/.github/scripts/test_require_ally_review.py" .github/scripts/
    # Rewrite only the runs-on label; everything else ships verbatim so a
    # diff against canonical is a pure drift check.
    sed "s/^    runs-on: default$/    runs-on: ${runner}/" \
      "$CANON_ROOT/.github/workflows/review-gate.yml" > .github/workflows/review-gate.yml
    sed "s/^    runs-on: default$/    runs-on: ${runner}/" \
      "$CANON_ROOT/.github/workflows/review-gate-selftest.yml" > .github/workflows/review-gate-selftest.yml

    # Stage BEFORE the emptiness check: in a fresh clone every synced file
    # is untracked, and `git diff --quiet` ignores untracked files entirely
    # -- the unstaged check reported "already in sync" for repos that had no
    # gate at all (2026-07-29, first rollout attempt, all 8 repos skipped).
    # -f: the FFmpeg fork inherits upstream's gitignore covering .github/,
    # but demonstrably commits and runs workflow files anyway.
    git add -f .github/scripts .github/workflows
    if git diff --cached --quiet; then
      echo "  already in sync"
      exit 0
    fi

    git -c user.name="$(git -C "$CANON_ROOT" config user.name)" \
        -c user.email="$(git -C "$CANON_ROOT" config user.email)" \
        commit -s -m "ci: sync Ally review gate from Blockcast/frr@${CANON_SHA:0:10}

Vendored copy of the canonical review/ally-complete gate. Advisory:
posts the status only; branch protection is a separate manual step per
repo. Do not hand-edit -- change Blockcast/frr and re-run
tools/sync-review-gate.sh." >/dev/null

    # Fetch the remote sync branch first (if any) so re-runs are safe:
    # without a fetched lease ref, --force-with-lease from a fresh clone
    # refuses and set -e killed the whole rollout on the first re-run
    # (2026-07-29). The depth-1 clone's refspec is single-branch, so the
    # fetch lands only in FETCH_HEAD. Tree-identical = nothing to do.
    if git fetch origin "$BRANCH" >/dev/null 2>&1; then
      if [ "$(git rev-parse 'FETCH_HEAD^{tree}')" = "$(git rev-parse "$BRANCH^{tree}")" ]; then
        echo "  sync branch already up to date on remote"
        gh pr list --repo "$repo" --head "$BRANCH" --json url --jq '.[0].url // "  (no open PR -- open one manually or re-run after closing)"'
        exit 0
      fi
      git update-ref "refs/remotes/origin/$BRANCH" FETCH_HEAD
    fi
    git push -u origin "$BRANCH" --force-with-lease >/dev/null 2>&1
    gh pr create --repo "$repo" --head "$BRANCH" \
      --title "ci: sync Ally review gate from Blockcast/frr@${CANON_SHA:0:10}" \
      --body "Vendored sync of the canonical \`review/ally-complete\` gate from Blockcast/frr@${CANON_SHA} (see frr PR #31 for the seven review rounds behind it).

Advisory-first: this only POSTS the status. Making \`review/ally-complete\` required is a per-repo branch-protection step taken manually after the gate shows correct \`pending\`/\`success\` on real PRs here — and only after this lands on the default branch, since \`pull_request_target\` runs base-branch workflows.

Runner label for this repo: \`${runner}\`. Everything except that label is byte-identical to canonical, so \`diff\` against frr is a pure drift check." 2>/dev/null \
      || gh pr list --repo "$repo" --head "$BRANCH" --json url --jq '.[0].url'
  )
  rm -rf "$work"
  trap - EXIT
done
echo "done"
