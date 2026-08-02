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

# Best-known status-write coordinates, kept current by main() as each fact is
# learned (token/repo first, payload head next, refetched head last). The
# top-level handler in run() uses them to turn a crash into an `error` status
# on the head instead of a silent non-zero exit: a run that dies before its
# first write leaves an earlier same-head `success` standing as the visible
# truth, which is the one direction a merge control must not fail.
_STATUS_TARGET = {}

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

# Negated forms CONTAIN the affirmative phrases as substrings, so the raw
# pattern above read an all-clear ("No action required", "No changes
# requested") as a changes-requested verdict -- the exact false-positive
# direction the keyword scan's own comment promises to avoid. Negated forms
# are masked out first; only text that survives the mask may count as
# affirmative, so "No action required for X. Action required: fix Y." still
# fails on the second, un-negated phrase. The mask must cover every phrase
# family the affirmative pattern matches (action AND changes, with an
# optional adjective/adverb slot: "no IMMEDIATE action required", "no
# FURTHER changes requested", "no ADDITIONAL APPLICATION SOURCE CODE
# changes requested" -- any number of modifier words, because the span is
# a NEGATED NOUN PHRASE rather than a counted window. Three bounds keep it
# one, and each is load-bearing for fail-closed behavior:
#   1. Separators admit only horizontal whitespace: "\s+" would let a bare
#      "No" on its own paragraph swallow a real "Action required:" verdict
#      on the next line, erasing a blocking signal.
#   2. Modifiers admit only word characters, so punctuation ends the span
#      and a standalone "No." cannot swallow a separate affirmative
#      sentence.
#   3. Modifiers exclude the span-breaker words below: adversative and
#      discourse pivots flip the polarity of what follows ("No reviewer
#      responded BUT action required"), and auxiliary/copular verbs end
#      any noun phrase ("no reviewer HAS responded ..."), so hitting one
#      means the affirmative that follows is NOT under the negation.
# A regex cannot fully parse English -- an exotic pivot outside the list
# would still be consumed -- but the residual exposure is narrow because
# the affirmative pattern requires its words ADJACENT: the mask only ever
# erases a real verdict when a pivot immediately precedes it, and the
# common pivots (and every auxiliary verb form) are listed. Errors from
# over-listing fall in the safe direction: an unmasked negation can at
# worst BLOCK a clean review, never pass a blocking one, because deletion
# only removes text and no affirmative phrase can be created by removing
# a negated one.
_NEGATION_SPAN_BREAKERS = (
    "but|yet|however|though|although|whereas|while|nevertheless|"
    "nonetheless|instead|otherwise|rather|therefore|hence|thus|"
    "consequently|accordingly|because|since|so|then|meanwhile|"
    "is|are|was|were|be|been|being|has|have|had|do|does|did|not"
)
NO_ACTION_REQUIRED_PATTERN = re.compile(
    r"\bno(?:[ \t]+(?!(?:" + _NEGATION_SPAN_BREAKERS + r")\b)\w+)*"
    r"[ \t]+(?:action|changes?)[ \t]+"
    r"(?:is[ \t]+|are[ \t]+|was[ \t]+|were[ \t]+)?(?:required|requested|needed)\b",
    re.IGNORECASE,
)


# The "request changes" affirmative family (scanned above) has its own
# negated shapes the noun-phrase mask cannot reach: an infinitive after a
# negated noun phrase ("no need to request changes") and direct verb
# negation ("we do not request changes", "we won't request changes").
# Same clause bounds as the main mask; same fail-closed footing -- under
# the authorization inversion a mask error can only cause a false
# failure-or-pending, never a false green.
NO_REQUEST_CHANGES_PATTERN = re.compile(
    r"(?:\bno(?:[ \t]+(?!(?:" + _NEGATION_SPAN_BREAKERS + r")\b)\w+)*"
    r"[ \t]+to[ \t]+request[ \t]+changes?\b"
    r"|\b(?:do|does|did|would|will|shall|should|could|can|must|may|might)"
    r"[ \t]+not[ \t]+request[ \t]+changes?\b"
    r"|\b(?:don't|doesn't|didn't|won't|wouldn't|shan't|shouldn't|couldn't|can't|cannot|mustn't)"
    r"[ \t]+request[ \t]+changes?\b)",
    re.IGNORECASE,
)


def has_action_required_language(body):
    masked = NO_ACTION_REQUIRED_PATTERN.sub(" ", body)
    masked = NO_REQUEST_CHANGES_PATTERN.sub(" ", masked)
    return ACTION_REQUIRED_COMMENT_PATTERN.search(masked) is not None

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
# "Recommended Action: Merge"). Anchored to the verdict section, not free
# prose, and the verdict must be a COMPLETE standalone "Merge" -- anything
# trailing it ("Merge only after requested changes are addressed", "Merge
# after fixes") is a qualified verdict, and an explicit pass here suppresses
# the fallback action-required scan, so a loose match would launder a
# qualified negative into a clean signal. Qualified verdicts fall through to
# None and land pending, never success.
RECOMMENDED_MERGE_PATTERN = re.compile(
    r"recommended action[:\s]*\n?\s*(?:_|\*|>|-|[ \t])*merge[.!]?[ \t]*(?:\r?\n|$)",
    re.IGNORECASE,
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
    """Max across every matching heading, not the first.

    A body carrying contradictory counts ("Critical Issues (0)" early,
    "Critical Issues (2)" later -- a re-edited or concatenated consolidated
    body) must fail closed. First-match returned the 0 and the findings
    vanished. Ported from hang-mmt-fec's gate.
    """
    matches = re.findall(r"%s \((\d+)\)" % re.escape(label), body)
    if not matches:
        return None
    return max(int(count) for count in matches)


def has_blocking_count(body):
    critical = extract_issue_count(body, "Critical Issues")
    important = extract_issue_count(body, "Important Issues")
    return (critical is not None and critical > 0) or (important is not None and important > 0)


# The immutable head attestation Ally writes into every consolidated body:
# a standalone "Reviewed head: <40 lowercase hex>" line. This is what binds a
# signal to a revision -- NOT review.commit_id, and NOT a substring scan.
REVIEWED_HEAD_PATTERN = re.compile(
    r"^[ \t]*Reviewed head:[ \t]*([0-9a-f]{40})[ \t]*$", re.IGNORECASE | re.MULTILINE
)


def parse_reviewed_head(body):
    """Return the single attested head OID, or None.

    Requires EXACTLY ONE standalone attestation line. Zero means the body makes
    no claim about which revision it covers; more than one is ambiguous. Both
    fail closed -- the caller treats them as "not a signal for this head",
    which leaves the gate pending rather than clearing it.
    """
    matches = REVIEWED_HEAD_PATTERN.findall(body or "")
    if len(matches) != 1:
        return None
    return matches[0].lower()


def attests_head(body, head_sha):
    """Exact equality against the parsed attestation.

    Deliberately not a substring test: a body that reviewed revision X but
    happens to mention revision Y in prose ("superseded by Y") must not count
    as a signal for Y.
    """
    attested = parse_reviewed_head(body)
    return attested is not None and attested == head_sha.lower()


def contains_head_sha(body, head_sha):
    """Kept only for the issue-link comment shape, which carries no
    attestation line. Requires the FULL 40-character OID -- a 7-character
    prefix is 28 bits and grindable.
    """
    return head_sha in body


def is_consolidated_ally_comment_for_head(body, head_sha):
    return (
        body.startswith("## Ally")
        and "Consolidated PR Review" in body
        and attests_head(body, head_sha)
    )


def is_issue_link_ally_comment_for_head(body, head_sha):
    """An informational "Links Paperclip issues:" comment.

    Recognised so it is not mistaken for an unrelated comment, but it carries
    NO review verdict -- see comment_signals_for_head, where it is deliberately
    not a success signal.
    """
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


def review_signal_time(review):
    """Effective ordering key for a formal review: the later of submitted_at
    and last_edited_at.

    GitHub keeps submitted_at immutable across body edits, so ordering on it
    alone lets an older review edited to ADD blocking findings keep losing to
    a newer clean signal -- the same defect comments had before
    comment_signal_time(). The REST reviews payload carries no edit timestamp;
    main() enriches each review with `last_edited_at` from GraphQL. Absent
    (never edited, or a pure-decide fixture), this degrades to submitted_at.

    ISO-8601 UTC strings sort correctly as plain strings.
    """
    submitted = str(review.get("submitted_at") or "")
    edited = str(review.get("last_edited_at") or "")
    return max(submitted, edited)


def review_signals_for_head(reviews, head_sha, ally_logins, is_self_review):
    ally = set(ally_logins)
    signals = []

    for review in reviews:
        login = (review.get("user") or {}).get("login")
        if not isinstance(login, str) or login not in ally:
            continue
        if review.get("state") == "DISMISSED":
            continue

        body = str(review.get("body") or "")
        # Attestation gates CLEARING the gate, never BLOCKING it.
        #
        # Binding positive signals to the body attestation is the hardening:
        # commit_id is GitHub-managed state about the review, while the
        # attestation is text Ally itself wrote naming the revision it
        # examined. But applying it symmetrically is a regression -- an
        # unattested CHANGES_REQUESTED would stop counting and the gate would
        # fall back to pending, which is weaker than the red it replaced.
        # hang-mmt-fec's suite caught exactly that. So blocking signals bind on
        # commit_id, and only the positive branches additionally require the
        # attestation.
        attested = attests_head(body, head_sha)
        if review.get("commit_id") != head_sha and not attested:
            continue

        at = review_signal_time(review)
        state = review.get("state")

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
            if not attested:
                continue
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
                verdict is None and has_action_required_language(body)
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
            if not attested:
                continue
            # AUTHORIZATION INVERSION (review round 5): free prose never
            # authorizes green. A clean-commented review counts only with a
            # machine-readable all-clear -- an explicit pass verdict or
            # BOTH zero-count sections. This removes the fail-open class
            # where the negation mask over-consumed a real blocking phrase:
            # a masked-away affirmative can now at worst leave the body
            # unauthorized (pending), never authorize it. The masks' only
            # remaining job is preventing false FAILURE from negated
            # prose, so every mask error lands fail-closed.
            has_zero_counts = (
                extract_issue_count(body, "Critical Issues") == 0
                and extract_issue_count(body, "Important Issues") == 0
            )
            if verdict != "pass" and not has_zero_counts:
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
        # commit_id match OR a body attestation of this head: the signal pass
        # accepts either as head-relevance, so the permission lookup must cover
        # both or an attested-but-drifted approval could never become trusted.
        matches_head = review.get("commit_id") == head_sha or attests_head(
            str(review.get("body") or ""), head_sha
        )
        if is_distinct and matches_head and review.get("state") != "DISMISSED":
            logins.add(login)
    return logins


def distinct_reviewer_signals_for_head(
    reviews,
    head_sha,
    ally_logins,
    pr_author_login,
    permission_trusted_logins,
    permission_resolved_logins=None,
    head_authorized_logins=None,
):
    ally = set(ally_logins)
    permission_resolved_logins = permission_resolved_logins or set()
    head_authorized_logins = head_authorized_logins or set()
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
        # The permission lookup is AUTHORITATIVE, and an unresolved lookup is
        # UNTRUSTED. Falling back to author_association on error failed open:
        # COLLABORATOR can mean read or triage, so a transient API, auth or
        # rate-limit failure would let an account without write access clear an
        # Ally-authored PR. Success is reserved for an authoritative
        # write/maintain/admin result; anything else leaves the gate pending,
        # which is the safe direction for a merge control.
        is_trusted = isinstance(login, str) and login in permission_trusted_logins
        if not (
            is_distinct
            and is_trusted
            and review.get("state") != "DISMISSED"
        ):
            continue

        body = str(review.get("body") or "")
        attested = attests_head(body, head_sha)
        matches_head = review.get("commit_id") == head_sha or attested
        if not matches_head:
            continue

        # commit_id is MUTABLE: observed on frr#29, an approval submitted
        # against one head later reported commit_id equal to a newer head it
        # had never covered (a revert made the trees identical). So the
        # POSITIVE path must not rest on commit_id alone -- it needs immutable
        # current-head evidence: the full head SHA attested in the review body
        # ("Reviewed head: <sha>"), or a 'review-gate-override: <sha>' comment
        # by the same trusted login. Blocking signals keep binding on
        # commit_id; a drifting commit_id may add red, never green.
        positively_bound = attested or login in head_authorized_logins

        at = str(review.get("submitted_at") or "")
        if review.get("state") == "APPROVED":
            if not positively_bound:
                continue
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


def comment_signal_time(comment):
    """Effective ordering key for a comment: the later of created_at/updated_at.

    Timestamps are ISO-8601 UTC ("2026-07-28T10:00:00Z") and therefore sort
    correctly as plain strings, which is what latest_signal() compares.
    """
    created = str(comment.get("created_at") or "")
    updated = str(comment.get("updated_at") or "")
    return max(created, updated)


def comment_signals_for_head(comments, head_sha, ally_logins, is_self_review):
    ally = set(ally_logins)
    short_head = short_sha(head_sha)
    signals = []

    for comment in comments:
        login = (comment.get("user") or {}).get("login")
        body = str(comment.get("body") or "")
        if not isinstance(login, str) or login not in ally:
            continue

        is_consolidated = is_consolidated_ally_comment_for_head(body, head_sha)
        is_issue_link = is_issue_link_ally_comment_for_head(body, head_sha)
        if not (is_consolidated or is_issue_link):
            continue

        # Order on the LATER of created_at/updated_at. GitHub keeps created_at
        # immutable across edits, so an older clean comment edited to add
        # blocking findings would otherwise keep losing latest_signal() to a
        # newer clean signal and leave the gate green on a review that now says
        # the opposite.
        at = comment_signal_time(comment)

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

        # An issue-link comment is informational -- it announces which
        # Paperclip issues a PR touches and carries NO review verdict. Treating
        # it as success let a bookkeeping comment clear the gate with no review
        # having happened. It is recognised (so a blocking count in one still
        # fails closed above) but contributes no positive signal.
        if is_issue_link and not is_consolidated:
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
            verdict is None and has_action_required_language(body)
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

        # Positive only on an affirmative verdict: an explicit pass, or
        # validated zero blocking counts. Silence is not consent -- a
        # consolidated body with neither is ambiguous and stays pending.
        has_zero_counts = (
            extract_issue_count(body, "Critical Issues") == 0
            and extract_issue_count(body, "Important Issues") == 0
        )
        if verdict != "pass" and not has_zero_counts:
            continue

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

    def order(entry):
        # Recency first; on an exact timestamp tie the blocking signal wins.
        # Without the tie-break, Python's stable sort hands the decision to
        # API list order -- red vs green decided by pagination. Ported from
        # hang-mmt-fec's same-second fail-closed rule.
        return (str(entry.get("at")), 1 if entry.get("status") == "failure" else 0)

    return sorted(signals, key=order)[-1]


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
        newer = current is None or str(signal["at"]) > str(current["at"])
        # Same-second tie between opposite states from one reviewer: fail
        # closed rather than let list order pick.
        tie_blocking = (
            current is not None
            and str(signal["at"]) == str(current["at"])
            and signal["status"] == "failure"
            and current["status"] != "failure"
        )
        if newer or tie_blocking:
            latest_by_author[signal["author"]] = signal

    current_states = list(latest_by_author.values())
    blocking = [s for s in current_states if s["status"] == "failure"]
    if blocking:
        return latest_signal(blocking)
    return latest_signal(current_states)


def override_attestation_logins(comments, head_sha):
    """Logins that authorized an override of THIS exact head.

    The label alone is PR-scoped and survives `synchronize`, so on its own it
    turns every future unreviewed head green -- which defeats the gate on
    precisely the push-then-review cycle it exists to protect. Pair it with a
    comment naming the full head SHA so the authorization dies with the commit
    it was granted for. Full SHA only, for the same reason attestations require
    one: a 7-char prefix is 28 bits and grindable.
    """
    logins = set()
    if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", head_sha or ""):
        return logins

    pattern = re.compile(
        r"^[ \t]*review-gate-override:[ \t]*%s[ \t]*$" % re.escape(head_sha),
        re.IGNORECASE | re.MULTILINE,
    )
    for comment in comments or []:
        login = (comment.get("user") or {}).get("login")
        if not isinstance(login, str):
            continue
        if pattern.search(str(comment.get("body") or "")):
            logins.add(login)
    return logins


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
            head_authorized_logins=override_attestation_logins(comments, head_sha),
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

    # Escape hatch: Ally does not reliably auto-review, so a "Waiting for Ally
    # review" pending can deadlock a PR forever. A maintainer can override --
    # but the override NEVER bypasses a review that flagged issues: a `failure`
    # on the current head stays red regardless. It only rescues the
    # reviewer-never-ran case.
    #
    # Two independent conditions, because the label alone is PR-scoped and
    # survives `synchronize`: it would silently clear every later unreviewed
    # head. The label carries the authorization (only maintainers can apply
    # one); a comment naming the full head SHA binds that authorization to a
    # specific revision, so pushing new code revokes it automatically.
    has_label = bool(override_label) and override_label in labels
    override_logins = override_attestation_logins(comments, head_sha)
    has_head_attestation = bool(override_logins & set(permission_trusted_logins))
    has_override = has_label and has_head_attestation

    if has_override and (signal is None or signal["status"] != "failure"):
        return (
            "success",
            "Ally review gate overridden for head %s (label '%s' + head-bound authorization)."
            % (short_sha(head_sha), override_label),
        )

    if signal is None:
        if has_label and not has_head_attestation:
            return (
                "pending",
                "Waiting for Ally review of head %s; label '%s' needs a "
                "'review-gate-override: <full head SHA>' comment."
                % (short_sha(head_sha), override_label),
            )
        return "pending", "Waiting for Ally review of head %s." % short_sha(head_sha)

    # A clean COMMENTED review (override didn't fire) is not a GitHub status
    # state. Not blocked by findings, but not an auto-pass either: stay
    # `pending` and tell the maintainer exactly what to do.
    if signal["status"] == CLEAN_COMMENTED_STATUS:
        return (
            "pending",
            "Ally reviewed head %s, no blocking findings; apply '%s' and comment "
            "'review-gate-override: <full head SHA>'."
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


STATUS_DESCRIPTION_LIMIT = 140


def clamp_description(description):
    """GitHub rejects status descriptions over 140 chars with a 422.

    That 422 lands on the FINAL status write, after the early `pending`
    claim -- so an over-length string doesn't just lose a message, it leaves
    the gate stuck at "Evaluating..." with a failed workflow. Every authored
    description is tested to fit (TestDescriptionLength); this clamp is the
    backstop for the untested inputs (operator-configured label names, an
    upstream change to the limit going unnoticed), where a truncated tail
    beats a stuck gate.
    """
    description = str(description or "")
    if len(description) <= STATUS_DESCRIPTION_LIMIT:
        return description
    return description[: STATUS_DESCRIPTION_LIMIT - 3] + "..."


def set_commit_status(api_base_url, owner, repo, sha, token, state, description, target_url):
    url = "%s/repos/%s/%s/statuses/%s" % (api_base_url.rstrip("/"), owner, repo, sha)
    _request(
        url,
        token,
        method="POST",
        payload={
            "context": STATUS_CONTEXT,
            "description": clamp_description(description),
            "state": state,
            "target_url": target_url,
        },
    )


def enrich_reviews_with_edit_times(api_base_url, owner, repo, pull_number, token, reviews):
    """Attach GraphQL `lastEditedAt` to each REST review as `last_edited_at`.

    The REST reviews payload exposes only the immutable submitted_at, so
    without this an older review edited to add blocking findings keeps losing
    to a newer clean signal (see review_signal_time()). GraphQL is the only
    place GitHub exposes a review-body edit timestamp.

    Fail-closed on error: this feeds signal ORDERING, and the failure
    direction of skipping it is a stale green -- the one direction a merge
    control must not fail. Raising here leaves the context at the
    already-posted "Evaluating..." pending, which any re-trigger clears.
    Matches the permission-lookup rule: an unresolved input is not a
    permissive default.
    """
    query = (
        "query($owner:String!,$repo:String!,$number:Int!,$cursor:String){"
        "repository(owner:$owner,name:$repo){pullRequest(number:$number){"
        "reviews(first:100,after:$cursor){pageInfo{hasNextPage endCursor}"
        "nodes{databaseId lastEditedAt}}}}}"
    )
    edited_at_by_id = {}
    cursor = None
    while True:
        data = _request(
            "%s/graphql" % api_base_url.rstrip("/"),
            token,
            method="POST",
            payload={
                "query": query,
                "variables": {
                    "owner": owner,
                    "repo": repo,
                    "number": pull_number,
                    "cursor": cursor,
                },
            },
        )
        if not isinstance(data, dict) or data.get("errors"):
            raise RuntimeError(
                "GraphQL lastEditedAt lookup failed: %s"
                % ((data or {}).get("errors") if isinstance(data, dict) else data)
            )
        connection = (
            ((data.get("data") or {}).get("repository") or {}).get("pullRequest") or {}
        ).get("reviews") or {}
        for node in connection.get("nodes") or []:
            if node.get("databaseId") is not None and node.get("lastEditedAt"):
                edited_at_by_id[node["databaseId"]] = node["lastEditedAt"]
        page = connection.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            break
        cursor = page.get("endCursor")

    for review in reviews:
        edited = edited_at_by_id.get(review.get("id"))
        if edited:
            review["last_edited_at"] = edited


def main():
    # Fresh coordinates per invocation: the module-level target otherwise
    # carries a previous in-process caller's repo/token/head into this run
    # (only matters for tests -- CI is one process per run -- but stale
    # coordinates in a crash write would point the error status at the wrong
    # head, so clear defensively rather than rely on caller hygiene).
    _STATUS_TARGET.clear()
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
    _STATUS_TARGET.update({"api": api_base_url, "owner": owner, "repo": repo, "token": token})

    # Resolve the PR NUMBER from whatever payload the event carries, then
    # refetch the PR itself for EVERY event. The embedded pull_request object
    # is a snapshot from event-emission time, and GitHub does not guarantee
    # event ordering: a delayed review/label event for head A can start after
    # `synchronize` moved the PR to head B (its cancel-in-progress run having
    # cancelled B's run), and evaluating the snapshot would post only for the
    # stale A -- leaving the CURRENT head with no status until some later
    # trigger. Refetching means every run, whatever woke it, evaluates and
    # posts for the head/labels/draft/author that exist NOW, so a stale-event
    # run is harmless rather than wrong.
    pull_number = (event.get("pull_request") or {}).get("number")
    if not pull_number:
        # issue_comment fires on PR comments too, but its payload carries an
        # `issue` (with a `pull_request` link) rather than the PR itself.
        issue = event.get("issue") or {}
        if issue.get("pull_request"):
            pull_number = issue.get("number")
    if not pull_number:
        print("No pull_request payload found; nothing to gate.")
        return

    # Claim the context on the PAYLOAD head before the authoritative refetch.
    # The refetch itself can raise (network, rate limit), and a run that dies
    # with no write leaves a previous same-head `success` standing -- the gate
    # failing open on exactly the kind of error it should hold for. A stale
    # payload head is harmless here for the same reason a stale-event run is:
    # the authoritative post-refetch write targets the real head, and a
    # pending on a superseded head gates nothing. Gated on the snapshot
    # claiming an open, non-draft PR so settled PRs are not stamped
    # (issue_comment payloads carry no head and are skipped), and best-effort
    # so a failed early write cannot itself kill the run before the
    # authoritative path gets its turn.
    payload_pr = event.get("pull_request") or {}
    payload_head = (payload_pr.get("head") or {}).get("sha")
    if not payload_head:
        # issue_comment payloads carry no pull_request.head.sha, so without
        # this probe the crash handler has no addressable commit: a refetch
        # crash would skip the `error` write and leave an earlier same-head
        # `success` standing -- fail-open on exactly the events that can
        # REMOVE the evidence behind a green gate (comment edits/deletes).
        # Resolve the head with a minimal fetch BEFORE any fallible
        # processing so this path gets the same fail-closed claim as
        # pull_request payloads. If even this probe fails, the raised error
        # fails the workflow run visibly -- there is no addressable commit
        # to stamp, and a silent return would hide the outage.
        probe = _request(
            "%s/repos/%s/%s/pulls/%d" % (api_base_url.rstrip("/"), owner, repo, pull_number),
            token,
        )
        if not probe:
            raise RuntimeError(
                "PR #%s head could not be resolved for the fail-closed claim" % pull_number
            )
        payload_pr = probe
        payload_head = (probe.get("head") or {}).get("sha")
    early_claim_active = False
    if payload_head:
        _STATUS_TARGET["sha"] = payload_head
        if not payload_pr.get("draft") and (payload_pr.get("state") or "open") == "open":
            try:
                set_commit_status(
                    api_base_url,
                    owner,
                    repo,
                    payload_head,
                    token,
                    "pending",
                    "Evaluating Ally review of head %s..." % short_sha(payload_head),
                    os.environ.get("STATUS_TARGET_URL"),
                )
                early_claim_active = True
            except Exception as error:  # noqa: BLE001 - the claim is best-effort
                print(
                    "early pending claim on payload head %s failed (continuing): %s"
                    % (short_sha(payload_head), error),
                    file=sys.stderr,
                )

    # Resolves an early claim that turned out to target a PR the refetch says
    # not to gate. The stale-HEAD case needs no cleanup (a pending on a
    # superseded head gates nothing), but when the payload head IS the current
    # head, a silent early return would strand the claim: on a merged/closed
    # PR nothing ever re-evaluates, leaving a required context yellow forever
    # on a commit that reached the base branch. Best-effort like the claim
    # itself.
    def resolve_early_claim(state, description):
        if not early_claim_active:
            return
        try:
            set_commit_status(
                api_base_url,
                owner,
                repo,
                payload_head,
                token,
                state,
                description,
                os.environ.get("STATUS_TARGET_URL"),
            )
        except Exception as error:  # noqa: BLE001 - cleanup is best-effort
            print(
                "resolving early claim on %s failed: %s" % (short_sha(payload_head), error),
                file=sys.stderr,
            )

    pull_request = _request(
        "%s/repos/%s/%s/pulls/%d" % (api_base_url.rstrip("/"), owner, repo, pull_number),
        token,
    )
    if not pull_request:
        print("PR #%s could not be fetched; nothing to gate." % pull_number)
        return

    if pull_request.get("state") and pull_request.get("state") != "open":
        # A delayed event can arrive after merge/close; there is no head left
        # to gate. The early claim (if any) must not be left stranded: a
        # settled PR gets no future evaluation, so a lingering `pending`
        # would sit yellow forever. `success` is safe here -- the PR cannot
        # merge again, so the context gates nothing.
        print("PR #%s is %s; nothing to gate." % (pull_number, pull_request["state"]))
        resolve_early_claim(
            "success", "PR is %s; nothing to gate." % pull_request["state"]
        )
        return

    if pull_request.get("draft"):
        # Keep the claim PENDING (fail-closed: a draft can return to ready at
        # this same head, and a `success` here would pre-clear it), but say
        # why -- the next ready_for_review event re-evaluates and overwrites.
        print("PR is a draft; nothing to gate.")
        resolve_early_claim(
            "pending", "PR is a draft; will re-evaluate when it becomes ready."
        )
        return

    head_sha = (pull_request.get("head") or {}).get("sha")
    if not head_sha:
        raise RuntimeError("pull_request.head.sha is required")
    _STATUS_TARGET["sha"] = head_sha

    pull_number = pull_request["number"]
    ally_logins = parse_list(os.environ.get("ALLY_REVIEWER_LOGINS"), DEFAULT_ALLY_LOGINS)
    pr_author_login = (pull_request.get("user") or {}).get("login")
    is_self_review = isinstance(pr_author_login, str) and pr_author_login in set(ally_logins)

    # Claim the context as `pending` BEFORE the fallible reads below. Everything
    # from here on can raise (network, rate limit, malformed payload), and a
    # re-evaluation that dies after an earlier same-head `success` would
    # otherwise leave the required context green while only the separately-named
    # workflow check goes red -- the merge control failing open on exactly the
    # kind of error it should hold for. Overwritten with the real verdict below.
    set_commit_status(
        api_base_url,
        owner,
        repo,
        head_sha,
        token,
        "pending",
        "Evaluating Ally review of head %s..." % short_sha(head_sha),
        os.environ.get("STATUS_TARGET_URL"),
    )

    reviews = fetch_paginated(api_base_url, "/repos/%s/%s/pulls/%d/reviews" % (owner, repo, pull_number), token)
    comments = fetch_paginated(api_base_url, "/repos/%s/%s/issues/%d/comments" % (owner, repo, pull_number), token)
    enrich_reviews_with_edit_times(api_base_url, owner, repo, pull_number, token, reviews)

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

    override_label = (os.environ.get("REVIEW_GATE_OVERRIDE_LABEL") or "review-gate-override").strip()
    raw_labels = pull_request.get("labels")
    labels = []
    if isinstance(raw_labels, list):
        for label in raw_labels:
            name = label if isinstance(label, str) else (label or {}).get("name")
            if name:
                labels.append(name)

    permission_trusted_logins = set()
    permission_resolved_logins = set()
    # Two independent reasons to resolve write permission: clearing a
    # self-authored PR via a distinct reviewer, and authorizing a head-bound
    # override. Resolve both candidate sets in one pass -- an override author
    # whose permission was never looked up is untrusted, so omitting them here
    # would make the escape hatch permanently inert.
    candidates = set()
    if is_self_review:
        candidates |= set(
            distinct_reviewer_candidate_logins(reviews, head_sha, ally_logins, pr_author_login)
        )
        # Head-bound authorization comments can positively bind a distinct
        # approval even without the override label, so their authors need
        # permission resolution whenever the distinct-reviewer path is live.
        candidates |= override_attestation_logins(comments, head_sha)
    if override_label and override_label in labels:
        candidates |= override_attestation_logins(comments, head_sha)
    if candidates:
        (
            permission_trusted_logins,
            permission_resolved_logins,
        ) = fetch_trusted_permission_logins(api_base_url, owner, repo, token, sorted(candidates))

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

    # Status descriptions fit GitHub's 140-char cap, so they name the override
    # command generically. The copy-pasteable form lives here in the log.
    print("Head-bound override command: review-gate-override: %s" % head_sha)

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


def run():
    try:
        main()
    except Exception as error:  # noqa: BLE001 - surface message, non-zero exit
        print(str(error), file=sys.stderr)
        # A crash must stay VISIBLE on the head, not just in the workflow log:
        # with no write, an earlier same-head `success` remains the status the
        # merge control reads, and the failed run is indistinguishable from no
        # run at all. Best-effort by construction -- the write needs whatever
        # coordinates main() managed to learn before dying, and a failure to
        # record the crash must not mask the original error's exit.
        target = dict(_STATUS_TARGET)
        if all(target.get(key) for key in ("api", "owner", "repo", "token", "sha")):
            try:
                set_commit_status(
                    target["api"],
                    target["owner"],
                    target["repo"],
                    target["sha"],
                    target["token"],
                    "error",
                    "review-gate crashed before posting a verdict: %s" % error,
                    os.environ.get("STATUS_TARGET_URL"),
                )
            except Exception as status_error:  # noqa: BLE001 - keep the original exit
                print(
                    "failed to record the crash as an error status: %s" % status_error,
                    file=sys.stderr,
                )
        sys.exit(1)


if __name__ == "__main__":
    run()
