#!/usr/bin/env bash
# Sync the canonical Ally review gate from this repo to the org's other
# Ally-reviewed repos, opening one advisory PR per repo.
#
# Canonical source (this repo, materialized from a COMMIT, never the
# working tree):
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
# Every commit this automation pushes to $BRANCH starts with this subject
# prefix; it doubles as the ownership marker the force-push guard checks.
SYNC_SUBJECT_PREFIX="ci: sync Ally review gate from Blockcast/frr@"
CANON_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CANON_FILES=(
  .github/scripts/require-ally-review.py
  .github/scripts/test_require_ally_review.py
  .github/workflows/review-gate.yml
  .github/workflows/review-gate-selftest.yml
)

DRY_RUN=0
FLEET=()
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    *) FLEET+=("$arg") ;;
  esac
done
[ ${#FLEET[@]} -gt 0 ] || FLEET=("${DEFAULT_FLEET[@]}")

CANON_SHA=$(git -C "$CANON_ROOT" rev-parse HEAD)

# Materialize the canonical files FROM THE COMMIT the rollout is attributed
# to, never from the working tree: local staged/unstaged edits must not ship
# to eight repos under a false source revision. The suite runs against these
# exact bytes for the same reason.
CANON_TMP=$(mktemp -d)
trap 'rm -rf "$CANON_TMP"' EXIT
for f in "${CANON_FILES[@]}"; do
  mkdir -p "$CANON_TMP/$(dirname "$f")"
  git -C "$CANON_ROOT" show "${CANON_SHA}:${f}" > "$CANON_TMP/$f" 2>/dev/null || {
    echo "canonical file missing from ${CANON_SHA:0:10}: $f" >&2; exit 1; }
done

# The canonical suite must be green before it is propagated anywhere.
python3 -m unittest discover -s "$CANON_TMP/.github/scripts" -p 'test_*.py' >/dev/null 2>&1 || {
  echo "canonical suite is RED at ${CANON_SHA:0:10}; refusing to propagate" >&2; exit 1; }

FAILED_REPOS=()
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
  if ! (
    cd "$work"
    gh repo clone "$repo" repo -- --depth 1 >/dev/null 2>&1
    cd repo
    git checkout -B "$BRANCH" >/dev/null

    mkdir -p .github/scripts .github/workflows
    cp "$CANON_TMP/.github/scripts/require-ally-review.py" .github/scripts/
    cp "$CANON_TMP/.github/scripts/test_require_ally_review.py" .github/scripts/
    # Rewrite only the runs-on label; everything else ships verbatim so a
    # diff against canonical is a pure drift check.
    sed "s/^    runs-on: default$/    runs-on: ${runner}/" \
      "$CANON_TMP/.github/workflows/review-gate.yml" > .github/workflows/review-gate.yml
    sed "s/^    runs-on: default$/    runs-on: ${runner}/" \
      "$CANON_TMP/.github/workflows/review-gate-selftest.yml" > .github/workflows/review-gate-selftest.yml

    # Stage BEFORE the emptiness check: in a fresh clone every synced file
    # is untracked, and `git diff --quiet` ignores untracked files entirely
    # -- the unstaged check reported "already in sync" for repos that had no
    # gate at all (2026-07-29, first rollout attempt, all 8 repos skipped).
    # -f: the FFmpeg fork inherits upstream's gitignore covering .github/,
    # but demonstrably commits and runs workflow files anyway.
    git add -f .github/scripts .github/workflows
    need_push=1
    if git diff --cached --quiet; then
      echo "  default branch already carries the gate"
      need_push=0
    else
      git -c user.name="$(git -C "$CANON_ROOT" config user.name)" \
          -c user.email="$(git -C "$CANON_ROOT" config user.email)" \
          commit -s -m "${SYNC_SUBJECT_PREFIX}${CANON_SHA:0:10}

Vendored copy of the canonical review/ally-complete gate. Advisory:
posts the status only; branch protection is a separate manual step per
repo. Do not hand-edit -- change Blockcast/frr and re-run
tools/sync-review-gate.sh." >/dev/null

      # Fetch the remote sync branch first (if any) so re-runs are safe:
      # without a fetched lease ref, --force-with-lease from a fresh clone
      # refuses and set -e killed the whole rollout on the first re-run
      # (2026-07-29). The depth-1 clone's refspec is single-branch, so the
      # fetch lands only in FETCH_HEAD.
      if git fetch origin "$BRANCH" >/dev/null 2>&1; then
        if [ "$(git rev-parse 'FETCH_HEAD^{tree}')" = "$(git rev-parse "$BRANCH^{tree}")" ]; then
          echo "  sync branch already up to date on remote"
          need_push=0
        else
          # Force-push guard: only overwrite commits THIS automation made.
          # A human iterating on the sync branch must not lose work to a
          # re-run; the subject prefix is the ownership marker.
          remote_subject=$(git log -1 --format=%s FETCH_HEAD)
          case "$remote_subject" in
            "$SYNC_SUBJECT_PREFIX"*) ;;
            *)
              echo "  REFUSING force-push: remote $BRANCH tip is not automation-owned" >&2
              echo "  remote subject: $remote_subject" >&2
              exit 2
              ;;
          esac
          git update-ref "refs/remotes/origin/$BRANCH" FETCH_HEAD
        fi
      fi
      if [ "$need_push" = "1" ]; then
        git push -u origin "$BRANCH" --force-with-lease >/dev/null 2>&1
      fi
    fi

    # The review artifact is an OPEN PR; finishing without one is a failure,
    # not a success with a hint. gh pr list only returns open PRs, so a
    # closed/merged prior PR correctly falls through to create.
    url=$(gh pr list --repo "$repo" --head "$BRANCH" --json url --jq '.[0].url // empty')
    if [ -z "$url" ] && [ "$need_push" = "1" ] || { [ -z "$url" ] && git rev-parse -q --verify FETCH_HEAD >/dev/null 2>&1; }; then
      url=$(gh pr create --repo "$repo" --head "$BRANCH" \
        --title "${SYNC_SUBJECT_PREFIX}${CANON_SHA:0:10}" \
        --body "Vendored sync of the canonical \`review/ally-complete\` gate from Blockcast/frr@${CANON_SHA} (see frr PR #31 for the eight review rounds behind it).

Advisory-first: this only POSTS the status. Making \`review/ally-complete\` required is a per-repo branch-protection step taken manually after the gate shows correct \`pending\`/\`success\` on real PRs here — and only after this lands on the default branch, since \`pull_request_target\` runs base-branch workflows.

Runner label for this repo: \`${runner}\`. Everything except that label is byte-identical to canonical, so \`diff\` against frr is a pure drift check." 2>/dev/null) || true
    fi
    if [ -n "$url" ]; then
      echo "  $url"
    elif [ "$need_push" = "0" ] && ! git rev-parse -q --verify FETCH_HEAD >/dev/null 2>&1; then
      # Gate already on the default branch and no sync branch exists: the
      # rollout for this repo is COMPLETE, no PR needed.
      echo "  gate already landed; nothing to do"
    else
      echo "  ERROR: no open PR exists for $BRANCH and none could be created" >&2
      exit 2
    fi
  ); then
    FAILED_REPOS+=("$repo")
    echo "  FAILED: $repo (continuing with the rest)" >&2
  fi
  rm -rf "$work"
done

if [ ${#FAILED_REPOS[@]} -gt 0 ]; then
  echo "FAILED repos: ${FAILED_REPOS[*]}" >&2
  exit 1
fi
echo "done"
