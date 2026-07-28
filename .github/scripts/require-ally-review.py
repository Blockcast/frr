#!/usr/bin/env python3
"""Post a `review/ally-complete` commit status reflecting Ally's review of the
CURRENT pull-request head.

Why this exists: Ally reviews are event-driven and can silently never happen
for a given push. Without a gate the PR then shows all-green CI and looks
reviewed, so a missing review is indistinguishable from a clean one. This
script turns that silence into a visible `pending` status on the exact head.

Ported from Blockcast/hang-mmt-fec scripts/require-ally-review.mjs. Keep the
two in behavioural lockstep; the accompanying test_require_ally_review.py
pins every branch below.

Reads the workflow event from GITHUB_EVENT_PATH, needs GITHUB_TOKEN with
`statuses: write`.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_ALLY_LOGINS = ["allyblockcast[bot]", "app/allyblockcast", "allyblockcast"]
TRUSTED_REVIEWER_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}

# author_association on a review is computed relative to the *requesting
# token's* visibility of org membership, not the reviewer's actual repo
# access. The workflow's default GITHUB_TOKEN carries no `members:read` scope,
# so a genuine org MEMBER can be reported as the lower CONTRIBUTOR association
# even though the same reviewer shows MEMBER to a personal PAT -- causing the
# gate to intermittently reject a valid distinct-reviewer approval. The
# collaborator-permission endpoint reflects the reviewer's actual repo-level
# grant directly and is not requester-view-dependent, so it is the primary
# trust signal; association stays a fallback for when that lookup itself fails.
TRUSTED_COLLABORATOR_PERMISSIONS = {"admin", "maintain", "write"}

STATUS_CONTEXT = os.environ.get("STATUS_CONTEXT") or "review/ally-complete"

# Sentinel (not a GitHub status state): a COMMENTED Ally review carrying no
# blocking findings. Ally only ever COMMENTs -- never APPROVEs -- so this is
# its "looks good". It is NOT an auto-pass: it stays overridable so the
# review-gate-override label can clear it, but without the label the gate
# posts `pending` (and so still blocks merge).
CLEAN_COMMENTED_STATUS = "clean-commented"

# A loose keyword scan over prose is unsafe: a *positive* review that merely
# discusses security ("blocks a real security gap", "unsafe RBAC", "finding")
# must not be read as a changes-requested verdict. Failure is therefore only
# inferred from (a) an explicit changes-requested verdict marker, or (b) a
# machine-readable issue count > 0 -- never from incidental vocabulary.
ACTION_REQUIRED_COMMENT_PATTERN = re.compile(
    r"\b(changes requested|request changes|action required|"
    r"critical issues? \([1-9]\d*\)|important issues? \([1-9]\d*\))",
    re.IGNORECASE,
)

# Explicit, machine-readable verdict markers. When any is present in an Ally
# body we trust it over heuristics. Precedence: an explicit changes-requested
# verdict beats an explicit merge verdict (fail-safe).
EXPLICIT_CHANGES_REQUESTED_PATTERN = re.compile(
    r"^\s*(?:_|\*|#|>|-|\s)*ally-verdict:\s*changes-requested\b", re.IGNORECASE | re.MULTILINE
)
EXPLICIT_MERGE_VERDICT_PATTERN = re.compile(
    r"^\s*(?:_|\*|#|>|-|\s)*ally-verdict:\s*pass\b", re.IGNORECASE | re.MULTILINE
)
# The current Ally prose verdict line ("Recommended Action\nMerge." or
# "Recommended Action: Merge"). Anchored to the verdict section, not free prose.
RECOMMENDED_MERGE_PATTERN = re.compile(
    r"recommended action[:\s]*\n?\s*(?:_|\*|>|-|\s)*merge\b", re.IGNORECASE
)
RECOMMENDED_CHANGES_PATTERN = re.compile(
    r"recommended action[:\s]*\n?\s*(?:_|\*|>|-|\s)*"
    r"(?:request changes|❌|changes? requested|do not merge|block)\b",
    re.IGNORECASE,
)


def explicit_verdict(body):
    """Classify an Ally body by its EXPLICIT verdict, preferring
    machine-readable markers over keyword heuristics.

    Returns "pass" | "changes-requested" | None (None => no explicit verdict,
    fall back to count/keyword heuristics).
    """
    # An explicit changes-requested marker is authoritative and fail-safe.
    if EXPLICIT_CHANGES_REQUESTED_PATTERN.search(body) or RECOMMENDED_CHANGES_PATTERN.search(body):
        return "changes-requested"
    if EXPLICIT_MERGE_VERDICT_PATTERN.search(body) or RECOMMENDED_MERGE_PATTERN.search(body):
        return "pass"
    return None


def parse_list(value, fallback):
    raw = value if value else ",".join(fallback)
    return [item.strip() for item in raw.split(",") if item.strip()]


def short_sha(sha):
    return sha[:7]


def extract_issue_count(body, label):
    match = re.search(r"%s \((\d+)\)" % re.escape(label), body)
    return int(match.group(1)) if match else None


def has_blocking_count(body):
    critical = extract_issue_count(body, "Critical Issues")
    important = extract_issue_count(body, "Important Issues")
    return (critical is not None and critical > 0) or (important is not None and important > 0)


def contains_head_sha(body, head_sha):
    """Require the FULL 40-character OID.

    A 7-character prefix is 28 bits of entropy and therefore grindable: an
    attacker who can get any commit into the repo could aim a stale clean Ally
    comment at a later head via a prefix collision. Ally's own consolidated
    comments carry the full OID ("Reviewed head: <40 hex>"), so demanding the
    whole thing costs nothing against real traffic.
    """
    return head_sha in body


def is_consolidated_ally_comment_for_head(body, head_sha):
    return (
        body.startswith("## Ally")
        and "Consolidated PR Review" in body
        and contains_head_sha(body, head_sha)
    )


def is_issue_link_ally_comment_for_head(body, head_sha):
    return (
        body.startswith("Links Paperclip issues:")
        and re.search(r"\bBLO-\d+\b", body) is not None
        and contains_head_sha(body, head_sha)
    )


def self_review_signal(at, author, head_sha):
    """A clean self-review (the PR was authored by an Ally identity, and Ally
    is reviewing its own PR) is not authoritative: Ally's own prose says
    "formal review/approval must come from a human or a distinct reviewer
    identity". Demoted to a non-authoritative "pending"; machine-readable
    blocking findings are classified before reaching here and still fail
    closed.
    """
    return {
        "at": str(at or ""),
        "author": author,
        "description": (
            "Ally self-review on head %s is not authoritative; "
            "needs a human or distinct reviewer." % short_sha(head_sha)
        ),
        "kind": "self-review",
        "status": "pending",
    }


def review_signals_for_head(reviews, head_sha, ally_logins, is_self_review):
    ally = set(ally_logins)
    signals = []

    for review in reviews:
        login = (review.get("user") or {}).get("login")
        if not isinstance(login, str) or login not in ally:
            continue
        if review.get("commit_id") != head_sha or review.get("state") == "DISMISSED":
            continue

        at = str(review.get("submitted_at") or "")
        state = review.get("state")
        body = str(review.get("body") or "")

        # Self-review cannot approve its own PR, but its machine-readable
        # blocking findings must still fail closed and stay un-overridable.
        if state == "COMMENTED" and has_blocking_count(body):
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "description": "Ally review flagged blocking findings on head %s."
                    % short_sha(head_sha),
                    "kind": "formal-review",
                    "status": "failure",
                }
            )
            continue

        # Demote before reading the verdict so a bot review of its own PR can
        # neither hard-pass (APPROVED) nor hard-fail (CHANGES_REQUESTED).
        if is_self_review:
            signals.append(self_review_signal(at, login, head_sha))
            continue

        if state == "APPROVED":
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "description": "Ally approved head %s." % short_sha(head_sha),
                    "kind": "formal-review",
                    "status": "success",
                }
            )
            continue

        # The canonical distinct-reviewer negative verdict. Stays red
        # regardless of body prose or the override label.
        if state == "CHANGES_REQUESTED":
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "description": "Ally requested changes on head %s." % short_sha(head_sha),
                    "kind": "formal-review",
                    "status": "failure",
                }
            )
            continue

        if state == "COMMENTED":
            verdict = explicit_verdict(body)
            # An explicit changes-requested verdict, OR a machine-readable
            # count > 0, is a real negative -- stays red, label or not.
            # Incidental security/"blocking" prose does NOT match.
            if verdict == "changes-requested" or (
                verdict is None and ACTION_REQUIRED_COMMENT_PATTERN.search(body)
            ):
                signals.append(
                    {
                        "at": at,
                        "author": login,
                        "description": "Ally review flagged blocking findings on head %s."
                        % short_sha(head_sha),
                        "kind": "formal-review",
                        "status": "failure",
                    }
                )
                continue
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "description": "Ally reviewed head %s with no blocking findings."
                    % short_sha(head_sha),
                    "kind": "clean-commented-review",
                    "status": CLEAN_COMMENTED_STATUS,
                }
            )

    return signals


def distinct_reviewer_candidate_logins(reviews, head_sha, ally_logins, pr_author_login):
    """Structural-only pass (no trust check): every login that would qualify as
    a distinct reviewer for this head if it turns out to be trusted. Scopes the
    collaborator-permission lookups to the logins that matter.
    """
    ally = set(ally_logins)
    logins = set()
    for review in reviews:
        user = review.get("user") or {}
        login = user.get("login")
        is_distinct = (
            isinstance(login, str)
            and login != pr_author_login
            and (login not in ally or user.get("type") == "User")
        )
        if is_distinct and review.get("commit_id") == head_sha and review.get("state") != "DISMISSED":
            logins.add(login)
    return logins


def distinct_reviewer_signals_for_head(
    reviews,
    head_sha,
    ally_logins,
    pr_author_login,
    permission_trusted_logins,
    permission_resolved_logins=None,
):
    ally = set(ally_logins)
    permission_resolved_logins = permission_resolved_logins or set()
    signals = []

    for review in reviews:
        user = review.get("user") or {}
        login = user.get("login")
        association = str(review.get("author_association") or "")

        # A reviewer counts as "distinct" from the PR author when its login
        # differs AND it is a genuinely separate actor. Two cases qualify:
        #   (a) a login outside the Ally set -- an ordinary trusted human; or
        #   (b) a real GitHub *User* seat inside the Ally set, e.g. the
        #       `allyblockcast` maintainer user, a distinct actor from the
        #       `app/allyblockcast` App that authors agent PRs.
        # Bot/App Ally identities stay excluded (case (b) requires
        # type == "User"), so the App can never self-clear the gate.
        is_distinct = (
            isinstance(login, str)
            and login != pr_author_login
            and (login not in ally or user.get("type") == "User")
        )
        # The permission lookup is AUTHORITATIVE when it completed. Falling
        # back to author_association unconditionally (an OR) meant a
        # collaborator holding only `read` or `triage` -- whose lookup
        # succeeded and said "not trusted" -- was still trusted via the
        # COLLABORATOR association, letting a read-only account clear an
        # Ally-authored PR. association is only consulted when the lookup
        # itself failed and we have nothing better.
        if isinstance(login, str) and login in permission_resolved_logins:
            is_trusted = login in permission_trusted_logins
        else:
            is_trusted = association in TRUSTED_REVIEWER_ASSOCIATIONS
        if not (
            is_distinct
            and is_trusted
            and review.get("commit_id") == head_sha
            and review.get("state") != "DISMISSED"
        ):
            continue

        at = str(review.get("submitted_at") or "")
        if review.get("state") == "APPROVED":
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "description": "%s approved head %s as a distinct reviewer."
                    % (login, short_sha(head_sha)),
                    "kind": "distinct-reviewer-approval",
                    "status": "success",
                }
            )
        elif review.get("state") == "CHANGES_REQUESTED":
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "description": "%s requested changes on head %s."
                    % (login, short_sha(head_sha)),
                    "kind": "distinct-reviewer-changes-requested",
                    "status": "failure",
                }
            )

    return signals


def comment_signals_for_head(comments, head_sha, ally_logins, is_self_review):
    ally = set(ally_logins)
    short_head = short_sha(head_sha)
    signals = []

    for comment in comments:
        login = (comment.get("user") or {}).get("login")
        body = str(comment.get("body") or "")
        if not isinstance(login, str) or login not in ally:
            continue
        if not (
            is_consolidated_ally_comment_for_head(body, head_sha)
            or is_issue_link_ally_comment_for_head(body, head_sha)
        ):
            continue

        at = str(comment.get("created_at") or "")

        # Self-review cannot approve its own PR, but machine-readable blocking
        # findings must still fail closed and remain impossible to override.
        if has_blocking_count(body):
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "description": "Ally comment requested action on head %s." % short_head,
                    "kind": "consolidated-comment",
                    "status": "failure",
                }
            )
            continue

        if is_self_review:
            signals.append(self_review_signal(at, login, head_sha))
            continue

        verdict = explicit_verdict(body)
        # FAILURE only on an actual changes-requested verdict: an explicit
        # marker, a machine-readable count > 0, or the legacy action-required
        # phrasing. A positive review that merely *mentions* security /
        # "blocking" / "unsafe" / "finding" never fails here.
        if verdict == "changes-requested" or (
            verdict is None and ACTION_REQUIRED_COMMENT_PATTERN.search(body)
        ):
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "description": "Ally comment requested action on head %s." % short_head,
                    "kind": "consolidated-comment",
                    "status": "failure",
                }
            )
            continue

        # Otherwise non-blocking: an explicit "Merge" verdict, an issue-link
        # comment, or explicit zero counts. Absence of a count heading is not
        # treated as guilt.
        signals.append(
            {
                "at": at,
                "author": login,
                "description": "Ally clean comment on head %s." % short_head,
                "kind": "ally-comment",
                "status": "success",
            }
        )

    return signals


def latest_signal(signals):
    if not signals:
        return None
    return sorted(signals, key=lambda entry: str(entry.get("at")), reverse=True)[0]


def reduce_distinct_reviewer_signals(signals):
    """Reduce to each reviewer's CURRENT state, then fail if any reviewer is
    currently requesting changes.

    Taking the single globally-latest signal is wrong with more than one
    reviewer: reviewer B approving after reviewer A requested changes would
    erase A's still-active objection and clear the gate. GitHub itself treats
    an outstanding CHANGES_REQUESTED as blocking regardless of who reviewed
    later, and so does this.
    """
    latest_by_author = {}
    for signal in signals:
        current = latest_by_author.get(signal["author"])
        if current is None or str(signal["at"]) > str(current["at"]):
            latest_by_author[signal["author"]] = signal

    current_states = list(latest_by_author.values())
    blocking = [s for s in current_states if s["status"] == "failure"]
    if blocking:
        return latest_signal(blocking)
    return latest_signal(current_states)


def decide(
    reviews,
    comments,
    head_sha,
    ally_logins,
    pr_author_login,
    labels,
    override_label,
    permission_trusted_logins=None,
    permission_resolved_logins=None,
):
    """Pure decision core: returns (state, description).

    Split out from main() so the whole policy is testable without network.
    """
    permission_trusted_logins = permission_trusted_logins or set()
    # A login cannot be trusted without its lookup having completed, so treat
    # trusted as implying resolved. Keeps the authoritative-lookup rule correct
    # even if a caller supplies only the trusted set.
    permission_resolved_logins = (permission_resolved_logins or set()) | permission_trusted_logins
    is_self_review = isinstance(pr_author_login, str) and pr_author_login in set(ally_logins)

    ally_signals = review_signals_for_head(
        reviews, head_sha, ally_logins, is_self_review
    ) + comment_signals_for_head(comments, head_sha, ally_logins, is_self_review)

    distinct_signals = (
        distinct_reviewer_signals_for_head(
            reviews,
            head_sha,
            ally_logins,
            pr_author_login,
            permission_trusted_logins,
            permission_resolved_logins,
        )
        if is_self_review
        else []
    )

    # A trusted distinct-reviewer approval only supersedes Ally's own signal
    # when Ally's signal for this head is the non-authoritative self-review
    # demotion (or absent) -- never when Ally already flagged blocking findings
    # on this exact head.
    ally_has_failure = any(entry["status"] == "failure" for entry in ally_signals)
    if is_self_review and distinct_signals and not ally_has_failure:
        # Per-reviewer reduction: one reviewer's later approval must not erase
        # another's outstanding change request.
        signal = reduce_distinct_reviewer_signals(distinct_signals)
    else:
        signal = latest_signal(ally_signals)

    has_override = bool(override_label) and override_label in labels

    # Escape hatch: Ally does not reliably auto-review, so a "Waiting for Ally
    # review" pending can deadlock a PR forever. A maintainer can apply an
    # explicit override label -- but the override NEVER bypasses a review that
    # flagged issues: a `failure` on the current head stays red even with the
    # label. It only rescues the reviewer-never-ran case.
    if has_override and (signal is None or signal["status"] != "failure"):
        return (
            "success",
            "Ally review gate overridden by '%s' label on head %s."
            % (override_label, short_sha(head_sha)),
        )

    if signal is None:
        return "pending", "Waiting for Ally review of head %s." % short_sha(head_sha)

    # A clean COMMENTED review (override didn't fire => no label) is not a
    # GitHub status state. Not blocked by findings, but not an auto-pass
    # either: stay `pending` and tell the maintainer to apply the label.
    if signal["status"] == CLEAN_COMMENTED_STATUS:
        return (
            "pending",
            "Ally reviewed head %s with no blocking findings; apply '%s' to merge."
            % (short_sha(head_sha), override_label),
        )

    return signal["status"], signal["description"]


def _request(url, token, method="GET", payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", "Bearer %s" % token)
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as response:
        body = response.read()
        return json.loads(body) if body else None


def fetch_paginated(api_base_url, path, token):
    items = []
    page = 1
    while True:
        url = "%s%s?per_page=100&page=%d" % (api_base_url.rstrip("/"), path, page)
        batch = _request(url, token)
        if not isinstance(batch, list):
            raise RuntimeError("GitHub API returned a non-array paginated payload")
        items.extend(batch)
        if len(batch) < 100:
            return items
        page += 1


def fetch_collaborator_permission(api_base_url, owner, repo, username, token):
    """Requester-view-independent trust lookup: the actual repo-level
    permission grant for a login. Returns None when not a collaborator (404).
    """
    url = "%s/repos/%s/%s/collaborators/%s/permission" % (
        api_base_url.rstrip("/"),
        owner,
        repo,
        urllib.parse.quote(username),
    )
    try:
        body = _request(url, token)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    permission = (body or {}).get("permission")
    return permission if isinstance(permission, str) else None


def fetch_trusted_permission_logins(api_base_url, owner, repo, token, candidate_logins):
    """Return (trusted, resolved).

    `resolved` is the set of logins whose lookup actually COMPLETED -- including
    a 404 "not a collaborator", which is a real answer of "no permission". Only
    a login missing from `resolved` (the lookup itself errored) falls back to
    author_association; otherwise the lookup is authoritative, so a read-only
    collaborator cannot be rescued by a COLLABORATOR association.
    """
    trusted = set()
    resolved = set()
    for login in candidate_logins:
        try:
            permission = fetch_collaborator_permission(api_base_url, owner, repo, login, token)
            print("collaborator-permission: %s -> %s" % (login, permission or "(not a collaborator)"))
            resolved.add(login)
            if permission in TRUSTED_COLLABORATOR_PERMISSIONS:
                trusted.add(login)
        except Exception as error:  # noqa: BLE001 - non-fatal by design
            print(
                "collaborator-permission: lookup failed for %s, falling back to "
                "author_association: %s" % (login, error),
                file=sys.stderr,
            )
    return trusted, resolved


def set_commit_status(api_base_url, owner, repo, sha, token, state, description, target_url):
    url = "%s/repos/%s/%s/statuses/%s" % (api_base_url.rstrip("/"), owner, repo, sha)
    _request(
        url,
        token,
        method="POST",
        payload={
            "context": STATUS_CONTEXT,
            "description": description,
            "state": state,
            "target_url": target_url,
        },
    )


def main():
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        raise RuntimeError("GITHUB_EVENT_PATH is required")
    with open(event_path, encoding="utf8") as handle:
        event = json.load(handle)

    full_name = os.environ.get("GITHUB_REPOSITORY") or (event.get("repository") or {}).get(
        "full_name"
    )
    if not full_name or "/" not in full_name:
        raise RuntimeError("GITHUB_REPOSITORY or event.repository.full_name must be owner/repo")

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required")

    owner, repo = full_name.split("/", 1)
    api_base_url = os.environ.get("GITHUB_API_URL") or "https://api.github.com"

    pull_request = event.get("pull_request")
    if not pull_request:
        # issue_comment fires on PR comments too, but its payload carries an
        # `issue` (with a `pull_request` link) rather than the PR itself. The
        # policy treats Ally issue comments as signals, so without resolving
        # here that fallback could never re-evaluate and the head status would
        # stay stale until some unrelated PR event happened to fire.
        issue = event.get("issue") or {}
        if issue.get("pull_request") and issue.get("number"):
            pull_request = _request(
                "%s/repos/%s/%s/pulls/%d"
                % (api_base_url.rstrip("/"), owner, repo, issue["number"]),
                token,
            )
        if not pull_request:
            print("No pull_request payload found; nothing to gate.")
            return

    if pull_request.get("draft"):
        print("PR is a draft; nothing to gate.")
        return

    head_sha = (pull_request.get("head") or {}).get("sha")
    if not head_sha:
        raise RuntimeError("pull_request.head.sha is required")

    pull_number = pull_request["number"]
    ally_logins = parse_list(os.environ.get("ALLY_REVIEWER_LOGINS"), DEFAULT_ALLY_LOGINS)
    pr_author_login = (pull_request.get("user") or {}).get("login")
    is_self_review = isinstance(pr_author_login, str) and pr_author_login in set(ally_logins)

    reviews = fetch_paginated(api_base_url, "/repos/%s/%s/pulls/%d/reviews" % (owner, repo, pull_number), token)
    comments = fetch_paginated(api_base_url, "/repos/%s/%s/issues/%d/comments" % (owner, repo, pull_number), token)

    print("Fetched %d review(s) for PR #%d @ head %s:" % (len(reviews), pull_number, short_sha(head_sha)))
    for review in reviews:
        user = review.get("user") or {}
        commit_id = review.get("commit_id")
        print(
            "  review: login=%s type=%s assoc=%s state=%s commit=%s submitted_at=%s"
            % (
                user.get("login", "?"),
                user.get("type", "?"),
                review.get("author_association", "?"),
                review.get("state", "?"),
                short_sha(commit_id) if commit_id else "?",
                review.get("submitted_at", "?"),
            )
        )
    print("Fetched %d issue comment(s) for PR #%d." % (len(comments), pull_number))

    permission_trusted_logins = set()
    permission_resolved_logins = set()
    if is_self_review:
        candidates = distinct_reviewer_candidate_logins(
            reviews, head_sha, ally_logins, pr_author_login
        )
        if candidates:
            (
                permission_trusted_logins,
                permission_resolved_logins,
            ) = fetch_trusted_permission_logins(api_base_url, owner, repo, token, candidates)

    override_label = (os.environ.get("REVIEW_GATE_OVERRIDE_LABEL") or "review-gate-override").strip()
    raw_labels = pull_request.get("labels")
    labels = []
    if isinstance(raw_labels, list):
        for label in raw_labels:
            name = label if isinstance(label, str) else (label or {}).get("name")
            if name:
                labels.append(name)

    state, description = decide(
        reviews=reviews,
        comments=comments,
        head_sha=head_sha,
        ally_logins=ally_logins,
        pr_author_login=pr_author_login,
        labels=labels,
        override_label=override_label,
        permission_trusted_logins=permission_trusted_logins,
        permission_resolved_logins=permission_resolved_logins,
    )

    set_commit_status(
        api_base_url,
        owner,
        repo,
        head_sha,
        token,
        state,
        description,
        os.environ.get("STATUS_TARGET_URL"),
    )
    print("%s: %s" % (STATUS_CONTEXT, description))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001 - surface message, non-zero exit
        print(str(error), file=sys.stderr)
        sys.exit(1)
