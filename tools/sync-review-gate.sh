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
# shared composite action -- see tools/REVIEW-GATE-CANONICITY.md for the
# 2026-11-07 disposition on that note (PEN-5925): not built, and the guards
# below are the accepted mitigation rather than a stopgap.
#
# Drift is NOT hypothetical and NOT symmetric. Measured 2026-11-07, every
# target that has had a local commit since its last sync carries work that is
# in no other copy, and Blockcast/onprem-k8s had diverged into a different
# program -- 18,133 lines, 192 local commits, 288 definitions canonical has
# never had -- which a run of this script would have replaced with frr's
# 3,499. onprem-k8s is no longer a target; it owns its copy outright. Every
# remaining target is screened by tools/review-gate-sync-guard.sh BEFORE
# anything is copied, and that guard fails closed.
#
# Advisory-first: the gate only POSTS the review/ally-complete status. Making
# it a required check is a per-repo branch-protection change done manually
# after that repo shows correct pending/success behaviour on real PRs --
# and only after the gate workflow is on the repo's default branch, because
# pull_request_target runs base-branch workflows: requiring a context the
# base branch cannot yet produce deadlocks every PR including the rollout PR.
#
# Usage:
#   tools/sync-review-gate.sh [options] [repo[:runs-on] ...]
#
#   --dry-run                 clone and SCREEN every target, report what the
#                             sync would do, write nothing. The screen is the
#                             point: a dry run that only echoed the canonical
#                             sha could not have told anyone about onprem-k8s.
#   --max-net-added N         raise the guard's net-removal threshold
#   --allow-definition-loss   sync a target that defines names canonical lacks
#   --allow-older-canonical   sync a target whose copy is newer than canonical
#
# The three override flags are blanket, not per-repo: they apply to every
# target in the run. Pass the one repo you mean on the command line when you
# use them.
#
# With no repos listed, syncs the default fleet below.

set -euo pipefail

# repo:runs-on. Runner labels are NOT uniform across the org (verified
# 2026-07-28); default to the ARC 'default' pool unless a repo is known to
# use hosted runners.
#
# Blockcast/onprem-k8s is deliberately ABSENT. It took exactly one sync
# (2026-07-29, frr@554f3bdbe6) and has had 192 commits on its copy since,
# against 16 ever in frr; it is the upstream of this gate's development, not a
# downstream of it. Re-adding it here is a decision to delete that work --
# tools/REVIEW-GATE-CANONICITY.md records why, and the guard would refuse it
# anyway (PEN-5925).
DEFAULT_FLEET=(
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
  # review-gate.yml carries `workflow_run: workflows: [review-gate-relay]`, so
  # a target that gets the gate without the relay never receives a formal
  # review event at all -- a silent hole in the control, which is the exact
  # failure the gate exists to close. It was added to frr on 2026-10-31
  # (481bf44) and NOT added here, which also made the canonical suite's
  # TestWorkflowRunRelay fail from $CANON_TMP and left this whole script
  # refusing to propagate anything since. (PEN-5925)
  .github/workflows/review-gate-relay.yml
)
# Split CANON_FILES by destination: workflows get the runner-label rewrite,
# scripts ship verbatim. Both lists are DERIVED rather than written out again,
# so adding a file above cannot leave a copy loop behind -- which is exactly
# how review-gate-relay.yml went missing.
CANON_WORKFLOWS=()
CANON_SCRIPTS=()
for f in "${CANON_FILES[@]}"; do
  case "$f" in
    .github/workflows/*) CANON_WORKFLOWS+=("$f") ;;
    .github/scripts/*) CANON_SCRIPTS+=("$f") ;;
    *) echo "CANON_FILES entry has no known destination: $f" >&2; exit 1 ;;
  esac
done

DRY_RUN=0
FLEET=()
# Guard overrides. Each one is forwarded to tools/review-gate-sync-guard.sh and
# echoed into the generated pull request body, so an override taken on the
# command line is visible to whoever reviews the result rather than only in the
# terminal that ran it.
GUARD_FLAGS=()
GUARD="$(cd "$(dirname "$0")" && pwd)/review-gate-sync-guard.sh"
next_is_threshold=0
for arg in "$@"; do
  if [ "$next_is_threshold" = "1" ]; then
    GUARD_FLAGS+=(--max-net-added "$arg"); next_is_threshold=0; continue
  fi
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --allow-definition-loss|--allow-older-canonical) GUARD_FLAGS+=("$arg") ;;
    --max-net-added) next_is_threshold=1 ;;
    --max-net-added=*) GUARD_FLAGS+=(--max-net-added "${arg#*=}") ;;
    -*) echo "unknown option: $arg" >&2; exit 64 ;;
    *) FLEET+=("$arg") ;;
  esac
done
[ "$next_is_threshold" = "0" ] || { echo "--max-net-added needs a value" >&2; exit 64; }
[ -x "$GUARD" ] || { echo "guard missing or not executable: $GUARD" >&2; exit 1; }
[ ${#FLEET[@]} -gt 0 ] || FLEET=("${DEFAULT_FLEET[@]}")

CANON_SHA=$(git -C "$CANON_ROOT" rev-parse HEAD)
# The guard compares this against each target's own last-commit date. Taken
# from the commit that last touched the GATE SCRIPT at CANON_SHA, not from
# CANON_SHA itself: syncing from a HEAD whose latest commit was an unrelated
# routing change must not read as "canonical moved". Normalized to UTC because
# %cI carries the committer's offset and the guard requires a UTC stamp.
CANON_GATE_PATH=.github/scripts/require-ally-review.py
canon_epoch=$(git -C "$CANON_ROOT" log -1 --format=%ct "$CANON_SHA" -- "$CANON_GATE_PATH")
CANON_DATE=$(date -u -d "@${canon_epoch:-0}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)
[ -n "$canon_epoch" ] && [ -n "$CANON_DATE" ] || {
  echo "cannot date canonical $CANON_GATE_PATH at ${CANON_SHA:0:10}" >&2; exit 1; }

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
  # The label is interpolated into sed replacements below and inside the
  # subshell; restrict it to characters that are inert there AND valid in
  # YAML scalars so a stray '/', '&', or '\' cannot corrupt the workflows.
  case "$runner" in
    ""|*[!A-Za-z0-9._-]*)
      echo "=== $repo ===" >&2
      echo "  invalid runner label: '$runner'" >&2
      FAILED_REPOS+=("$repo")
      continue
      ;;
  esac
  echo "=== $repo (runs-on: $runner) ==="

  # NOTE: --dry-run does NOT skip ahead from here. It clones and screens the
  # target like a real run and stops just before the first write, because the
  # question an operator asks a dry run is "what would this do to the target",
  # and only the target's own copy can answer it.

  work=$(mktemp -d)
  # Run the per-repo body as a PLAIN subshell, never as an `if !` condition:
  # bash ignores errexit everywhere inside a condition context -- including
  # a `set -e` issued within it -- so `if ! ( ... )` silently swallowed
  # failed clones, commits, and pushes whenever a later command in the body
  # succeeded, reporting a stale rollout as complete. Outer errexit is
  # suspended only around the status capture.
  set +e
  (
    set -euo pipefail
    cd "$work"
    gh repo clone "$repo" repo -- --depth 1 >/dev/null 2>&1
    cd repo
    # Recorded before the sync branch is created: the ancestry proof in
    # the force-push guard needs to name the target default branch.
    default_branch=$(git symbolic-ref --short HEAD)
    git checkout -B "$BRANCH" >/dev/null

    # A committed symlink at any destination component would make the
    # writes below follow it outside this checkout under the operator's
    # credentials. Refuse rather than chase links.
    for p in .github .github/scripts .github/workflows "${CANON_FILES[@]}"; do
      if [ -L "$p" ]; then
        echo "  REFUSING sync: '$p' is a symlink in $repo" >&2
        exit 2
      fi
    done
    # Screen the target's EXISTING copy before overwriting it. This runs
    # against the checkout's pre-sync state, so it must come before the first
    # cp -- after it there is nothing left to compare. The guard fails closed:
    # any non-zero exit, including one it took because it could not read
    # something, stops this repo and leaves it untouched.
    #
    # The target's date comes from the API rather than the checkout because
    # the clone is --depth 1: `git log -- <path>` there reports the tip
    # commit, not the commit that last touched the gate, so a shallow read
    # would compare the wrong two instants and quietly pass.
    # `.[0]` on an empty array renders the literal string "null", which would
    # reach the guard as a malformed date and be refused there. Correct, but it
    # reports "not UTC ISO-8601" for what is really "this path has no commits",
    # so normalize it to empty and let the guard say which of its inputs it did
    # not get.
    target_gate_date=$(gh api \
      "repos/$repo/commits?path=${CANON_GATE_PATH}&per_page=1" \
      --jq '.[0].commit.committer.date' 2>/dev/null) || target_gate_date=""
    [ "$target_gate_date" != "null" ] || target_gate_date=""
    set +e
    guard_report=$("$GUARD" \
      --canonical "$CANON_TMP/$CANON_GATE_PATH" \
      --target "$CANON_GATE_PATH" \
      --canonical-committed "$CANON_DATE" \
      ${target_gate_date:+--target-committed "$target_gate_date"} \
      "${GUARD_FLAGS[@]+"${GUARD_FLAGS[@]}"}" 2>&1)
    guard_rc=$?
    set -e
    printf '%s\n' "$guard_report" | sed 's/^/  /'
    if [ "$guard_rc" -ne 0 ]; then
      echo "  REFUSING sync for $repo: guard exit ${guard_rc}; target left untouched" >&2
      exit 2
    fi

    if [ "$DRY_RUN" = "1" ]; then
      echo "  dry-run: would sync gate @ ${CANON_SHA:0:10} (screen passed; nothing written)"
      exit 0
    fi

    mkdir -p .github/scripts .github/workflows
    for f in "${CANON_SCRIPTS[@]}"; do
      cp "$CANON_TMP/$f" "$f"
    done
    # Rewrite only the runs-on label; everything else ships verbatim.
    #
    # This substitution is NO LONGER A NO-OP WHEN IT MATCHES NOTHING. frr's
    # canonical workflows moved from `runs-on: default` to the block form
    # (`group: default-tools` / `labels: arc-light`) on 2026-10-31 (481bf44),
    # and this pattern has matched zero lines since. A repo asking for its own
    # runner label was therefore silently shipped frr's ARC group instead --
    # and a gate job that never starts because its runner group does not
    # resolve is a merge control that is quietly absent. So: when a label
    # other than `default` is requested and nothing changed, refuse. Repos
    # that ask for `default` are unaffected; they are asking for canonical's
    # own runner, which is what they now get. (PEN-5925)
    for f in "${CANON_WORKFLOWS[@]}"; do
      sed "s/^    runs-on: default$/    runs-on: ${runner}/" "$CANON_TMP/$f" > "$f"
      if [ "$runner" != "default" ] && cmp -s "$CANON_TMP/$f" "$f" &&
         grep -q '^[[:space:]]*runs-on:' "$CANON_TMP/$f"; then
        echo "  REFUSING sync: runner label '${runner}' could not be applied to $f;" >&2
        echo "  canonical no longer carries a 'runs-on: default' line to rewrite." >&2
        exit 2
      fi
    done
    # Normalize modes to the canonical tree entries so the generated
    # commit is byte- AND mode-deterministic (cp inherits checkout modes,
    # redirection inherits the umask); the force-push guard verifies both.
    for f in "${CANON_FILES[@]}"; do
      case "$(git -C "$CANON_ROOT" ls-tree "$CANON_SHA" -- "$f" | awk '{print $1}')" in
        100755) chmod 755 "$f" ;;
        *) chmod 644 "$f" ;;
      esac
    done

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

      # Fetch the remote sync branch first (if any) so re-runs are safe.
      # The depth-1 clone's refspec is single-branch, so the fetch lands
      # only in FETCH_HEAD. depth=2 pulls the tip's parent as well, which
      # the ownership verification below diffs against.
      # An empty expected value means "remote ref must NOT exist" -- the
      # correct first-rollout expectation when the fetch below finds no
      # remote sync branch.
      lease="$BRANCH:"
      if git fetch --depth=2 origin "$BRANCH" >/dev/null 2>&1; then
        # A bare --force-with-lease maps the pushed ref through the fetch
        # refspec; in this single-branch clone that mapping does not exist,
        # so the lease degenerates to "remote ref must be ABSENT" and every
        # legitimate re-sync is rejected with "stale info" (2026-07-31, all
        # four re-run repos). Pin the lease to the exact tip the guard
        # verified instead -- strictly safer than a tracking ref anyway.
        lease="$BRANCH:$(git rev-parse FETCH_HEAD)"
        if [ "$(git rev-parse 'FETCH_HEAD^{tree}')" = "$(git rev-parse "$BRANCH^{tree}")" ]; then
          echo "  sync branch already up to date on remote"
          need_push=0
        else
          # Force-push guard: only overwrite commits THIS automation
          # provably made. The subject prefix alone is spoofable -- a human
          # amending the generated commit with --no-edit keeps the subject
          # while adding their own work -- so the remote tip must also
          # MATCH reconstructed automation output for the canonical sha its
          # subject records: it may touch only the four gate paths, and
          # each path's blob must hash to exactly what this script would
          # have generated. Anything else refuses; the operator rescues the
          # human work and deletes the remote branch to re-enable syncing.
          remote_subject=$(git log -1 --format=%s FETCH_HEAD)
          case "$remote_subject" in
            "$SYNC_SUBJECT_PREFIX"*) ;;
            *)
              echo "  REFUSING force-push: remote $BRANCH tip is not automation-owned" >&2
              echo "  remote subject: $remote_subject" >&2
              echo "  rescue the human work, delete the remote branch, re-run" >&2
              exit 2
              ;;
          esac
          claimed_sha=${remote_subject#"$SYNC_SUBJECT_PREFIX"}
          # The generated commit records only paths that DIFFER from the
          # default branch, so a legitimate sync that changed one canonical
          # file touches one path. Require a non-empty SUBSET of the gate
          # paths; every tip blob is still verified in full below.
          if ! touched=$(git diff-tree --no-commit-id --name-only -r FETCH_HEAD 2>/dev/null) ||
             [ -z "$touched" ]; then
            echo "  REFUSING force-push: cannot enumerate remote $BRANCH tip's changes" >&2
            echo "  (empty or merge commit, or unreadable parent); rescue any human work," >&2
            echo "  delete the remote branch, re-run" >&2
            exit 2
          fi
          while IFS= read -r p; do
            case " ${CANON_FILES[*]} " in
              *" $p "*) ;;
              *)
                echo "  REFUSING force-push: remote $BRANCH tip touches '$p' outside the" >&2
                echo "  gate files; rescue any human work, delete the remote branch, re-run" >&2
                exit 2
                ;;
            esac
          done <<< "$touched"
          for f in "${CANON_FILES[@]}"; do
            if ! remote_blob=$(git rev-parse -q --verify "FETCH_HEAD:$f"); then
              echo "  REFUSING force-push: $f missing from remote $BRANCH tip" >&2
              exit 2
            fi
            # Tree-entry MODE is part of ownership: a mode-only human
            # amendment (e.g. chmod +x) keeps every blob id identical.
            remote_mode=$(git ls-tree FETCH_HEAD -- "$f" | awk '{print $1}')
            expect_mode=$(git -C "$CANON_ROOT" ls-tree "${claimed_sha}" -- "$f" 2>/dev/null |
              awk '{print $1}')
            [ -n "$expect_mode" ] || expect_mode=unverifiable
            if [ "$remote_mode" != "$expect_mode" ]; then
              echo "  REFUSING force-push: remote $f mode ($remote_mode) differs from" >&2
              echo "  automation output for frr@${claimed_sha} ($expect_mode); rescue any" >&2
              echo "  human work, delete the remote branch, re-run" >&2
              exit 2
            fi
            case "$f" in
              .github/workflows/*)
                expect_blob=$(git -C "$CANON_ROOT" show "${claimed_sha}:${f}" 2>/dev/null |
                  sed "s/^    runs-on: default$/    runs-on: ${runner}/" |
                  git hash-object --stdin) || expect_blob=unverifiable
                ;;
              *)
                expect_blob=$(git -C "$CANON_ROOT" show "${claimed_sha}:${f}" 2>/dev/null |
                  git hash-object --stdin) || expect_blob=unverifiable
                ;;
            esac
            if [ "$remote_blob" != "$expect_blob" ]; then
              echo "  REFUSING force-push: remote $f does not match automation output" >&2
              echo "  for frr@${claimed_sha} (hand edit, unknown source sha, or a runner" >&2
              echo "  label change); rescue any human work, delete the remote branch, re-run" >&2
              exit 2
            fi
          done
          # Tip content alone says nothing about ANCESTRY: an
          # automation-shaped tip stacked on branch-only human commits
          # would still delete that history. Prove the tip's parent is on
          # the default branch (ahead_by 0 in a compare against it), so
          # the branch carries exactly the one generated commit.
          if ! parent_sha=$(git rev-parse -q --verify FETCH_HEAD^ 2>/dev/null); then
            echo "  REFUSING force-push: remote $BRANCH tip's parent is unreadable" >&2
            exit 2
          fi
          ahead=$(gh api "repos/$repo/compare/${default_branch}...${parent_sha}" \
                    --jq .ahead_by 2>/dev/null) || ahead=unknown
          if [ "$ahead" != "0" ]; then
            echo "  REFUSING force-push: remote $BRANCH carries history beyond the single" >&2
            echo "  generated commit (parent is ${ahead} commit(s) off $default_branch);" >&2
            echo "  rescue any human work, delete the remote branch, re-run" >&2
            exit 2
          fi
        fi
      fi
      if [ "$need_push" = "1" ]; then
        git push -u origin "$BRANCH" --force-with-lease="$lease" >/dev/null 2>&1
      fi
    fi

    # The review artifact is an OPEN PR; finishing without one is a failure,
    # not a success with a hint. gh pr list only returns open PRs, so a
    # closed/merged prior PR correctly falls through to create. The lookup
    # is pinned to the intended artifact: base = the default branch and
    # head repository = the target repo itself -- owner AND name, since
    # GitHub permits same-org forks, so owner alone would accept a PR whose
    # head lives in a sibling Blockcast repository reusing the branch name.
    # Values enter the filter as jq --arg bindings, never by interpolation.
    url=$(gh pr list --repo "$repo" --head "$BRANCH" --base "$default_branch" \
      --json url,headRepositoryOwner,headRepository |
      jq -r --arg owner "${repo%%/*}" --arg name "${repo#*/}" \
        '.[] | select(.headRepositoryOwner.login == $owner
                      and .headRepository.name == $name) | .url' |
      head -n1)
    if [ -z "$url" ] && [ "$need_push" = "1" ] || { [ -z "$url" ] && git rev-parse -q --verify FETCH_HEAD >/dev/null 2>&1; }; then
      url=$(gh pr create --repo "$repo" --head "$BRANCH" --base "$default_branch" \
        --title "${SYNC_SUBJECT_PREFIX}${CANON_SHA:0:10}" \
        --body "Vendored sync of the canonical \`review/ally-complete\` gate from Blockcast/frr@${CANON_SHA} (see frr PR #31 for the eight review rounds behind it).

Advisory-first: this only POSTS the status. Making \`review/ally-complete\` required is a per-repo branch-protection step taken manually after the gate shows correct \`pending\`/\`success\` on real PRs here — and only after this lands on the default branch, since \`pull_request_target\` runs base-branch workflows.

Requested runner label for this repo: \`${runner}\`. Where canonical still carries a rewritable \`runs-on: default\` line that is the only intended difference from canonical; where it does not, canonical's own runner block ships verbatim and a non-\`default\` request is refused rather than silently dropped.

This PR was screened by \`tools/review-gate-sync-guard.sh\` against this repo's copy as it stood at branch time. The screen is what the sync measured; it is NOT a claim that the result is byte-identical to canonical, which this automation does not verify after the fact:

\`\`\`
${guard_report}
\`\`\`" 2>/dev/null) || true
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
  )
  repo_status=$?
  set -e
  rm -rf "$work"
  if [ "$repo_status" -ne 0 ]; then
    FAILED_REPOS+=("$repo")
    echo "  FAILED: $repo, exit $repo_status (continuing with the rest)" >&2
  fi
done

if [ ${#FAILED_REPOS[@]} -gt 0 ]; then
  echo "FAILED repos: ${FAILED_REPOS[*]}" >&2
  exit 1
fi
echo "done"
