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

import base64
import http.client
import json
import os
import re
import subprocess
import sys
import time
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
# blocking findings. Ally historically only COMMENTed -- never APPROVEd --
# so this is its "looks good". It is NOT a pass: since round 3 of the
# multicast vendoring review the ONLY green for this context is an exact-head
# App-seat APPROVED review, so a clean COMMENTED body holds `pending` until
# the App seat approves.
CLEAN_COMMENTED_STATUS = "clean-commented"
# Round 2 of the #47 review: an APPROVED whose body is coordinator-
# ambiguous is that seat's newest formal verdict but authorizes nothing
# and withdraws nothing -- it supersedes the seat's own earlier success
# while current_signals_per_login refuses to let it displace a standing
# blocker. decide() maps it to pending.
AMBIGUOUS_APPROVAL_STATUS = "ambiguous-approval"

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
# Coordinators are deliberately NOT in the breaker list above: English
# negation legitimately distributes across them ("no issues found or changes
# requested" is an all-clear), so breaking on them would false-fail compound
# negated prose. But a span that DID cross a coordinator is exactly where the
# mask can consume a real verdict ("no reviewer responded AND action
# required"). The STRICT variants below add the coordinators; the difference
# between the two mask outcomes is the machine-detectable ambiguity signal
# (see masked_blocking_ambiguity).
_NEGATION_SPAN_COORDINATORS = "and|or|nor|plus"
_STRICT_SPAN_BREAKERS = _NEGATION_SPAN_BREAKERS + "|" + _NEGATION_SPAN_COORDINATORS
NO_ACTION_REQUIRED_PATTERN = re.compile(
    r"\bno(?:[ \t]+(?!(?:" + _NEGATION_SPAN_BREAKERS + r")\b)\w+)*"
    r"[ \t]+(?:action|changes?)[ \t]+"
    r"(?:is[ \t]+|are[ \t]+|was[ \t]+|were[ \t]+)?(?:required|requested|needed)\b",
    re.IGNORECASE,
)
NO_ACTION_REQUIRED_STRICT_PATTERN = re.compile(
    r"\bno(?:[ \t]+(?!(?:" + _STRICT_SPAN_BREAKERS + r")\b)\w+)*"
    r"[ \t]+(?:action|changes?)[ \t]+"
    r"(?:is[ \t]+|are[ \t]+|was[ \t]+|were[ \t]+)?(?:required|requested|needed)\b",
    re.IGNORECASE,
)


# The "request changes" affirmative family (scanned above) has its own
# negated shapes the noun-phrase mask cannot reach: an infinitive after a
# negated noun phrase ("no need to request changes") and direct verb
# negation ("we do not request changes", "we won't request changes",
# "we need not request changes"). The modal list includes semi-modal
# "need" ("need not" / "needn't") -- the same negated-verb shape as the
# core modals. Adjacency keeps this safe: "not ONLY request changes"
# (which affirms) has an intervening word and never matches. Same clause
# bounds as the main mask; same fail-closed footing -- under the
# authorization inversion a mask error can only cause a false
# failure-or-pending, never a false green.
NO_REQUEST_CHANGES_PATTERN = re.compile(
    r"(?:\bno(?:[ \t]+(?!(?:" + _NEGATION_SPAN_BREAKERS + r")\b)\w+)*"
    r"[ \t]+to[ \t]+request[ \t]+changes?\b"
    r"|\b(?:do|does|did|would|will|shall|should|could|can|must|may|might|need|dare)"
    r"[ \t]+not[ \t]+request[ \t]+changes?\b"
    r"|\b(?:don't|doesn't|didn't|won't|wouldn't|shan't|shouldn't|couldn't|can't|cannot|mustn't|needn't)"
    r"[ \t]+request[ \t]+changes?\b)",
    re.IGNORECASE,
)
NO_REQUEST_CHANGES_STRICT_PATTERN = re.compile(
    r"(?:\bno(?:[ \t]+(?!(?:" + _STRICT_SPAN_BREAKERS + r")\b)\w+)*"
    r"[ \t]+to[ \t]+request[ \t]+changes?\b"
    r"|\b(?:do|does|did|would|will|shall|should|could|can|must|may|might|need|dare)"
    r"[ \t]+not[ \t]+request[ \t]+changes?\b"
    r"|\b(?:don't|doesn't|didn't|won't|wouldn't|shan't|shouldn't|couldn't|can't|cannot|mustn't|needn't)"
    r"[ \t]+request[ \t]+changes?\b)",
    re.IGNORECASE,
)


def has_action_required_language(body):
    masked = NO_ACTION_REQUIRED_PATTERN.sub(" ", body)
    masked = NO_REQUEST_CHANGES_PATTERN.sub(" ", masked)
    return ACTION_REQUIRED_COMMENT_PATTERN.search(masked) is not None


def masked_blocking_ambiguity(body):
    """True when ONLY a coordinator-crossing negation span stands between this
    body and a blocking verdict -- the machine-detectable signature of the
    mask consuming a real verdict (review rounds 7-8).

    Mechanics: the strict masks differ from the lenient ones in exactly one
    way -- their spans additionally break on coordinators (and/or/nor/plus).
    Strict spans are therefore a subset of lenient spans, so only three
    outcomes exist:
      - affirmative survives BOTH masks  -> real blocking; the failure paths
        own it (has_action_required_language is true) and this returns False;
      - affirmative survives NEITHER     -> a simple negated all-clear
        ("No action required", "no further changes requested") -- not
        ambiguous, may authorize;
      - affirmative survives STRICT only -> the lenient span crossed a
        coordinator. "No reviewer responded and action required: fix gate"
        (a pivot reading -- blocking) is indistinguishable by regex from
        "no issues found or changes requested" (a distributed negation --
        clean). Ambiguity resolves fail-closed: the body may not authorize
        green and may not be cleared by the override, no matter what pass
        verdict or zero-count sections accompany it (review round 8: a
        machine-readable all-clear must not launder a possibly-consumed
        blocking verdict). Cost: a genuine distributed-negation all-clear
        lands pending until re-worded -- a false HOLD, never a false green.
    """
    if has_action_required_language(body):
        return False
    strict_masked = NO_ACTION_REQUIRED_STRICT_PATTERN.sub(" ", body)
    strict_masked = NO_REQUEST_CHANGES_STRICT_PATTERN.sub(" ", strict_masked)
    return ACTION_REQUIRED_COMMENT_PATTERN.search(strict_masked) is not None


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


def self_review_signal(at, author, head_sha, seat):
    """A clean self-review (the PR was authored by an Ally identity, and Ally
    is reviewing its own PR) is not authoritative: neither Ally identity --
    the App seat, which structurally cannot approve its own PR, nor the
    shared `allyblockcast` User seat (BLO-24056: that account supplied 661
    App-authored approvals org-wide and is Ally's second hat, not an
    independent reviewer) -- may authorize this context. The positive path
    (BLO-25488) is a distinct, permission-trusted, non-Ally login's
    exact-head-attested APPROVED review, adopted in decide() from
    distinct_signals. Machine-readable blocking findings are classified
    before reaching here and still fail closed.
    """
    return {
        "at": str(at or ""),
        "author": author,
        "seat": seat,
        "description": (
            "Ally-authored PR: head %s cannot be App-self-approved; needs an "
            "approving review from a write-access human at this head."
            % short_sha(head_sha)
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
        user = review.get("user") or {}
        login = user.get("login")
        if not isinstance(login, str) or login not in ally:
            continue
        if review.get("state") == "DISMISSED":
            continue
        # POSITIVE Ally evidence must come from the App seat (REST
        # `user.type == "Bot"`), never the shared `allyblockcast` User seat
        # (review round 2 of the multicast vendoring): the org ruleset
        # already counts that User as the singleton Ally-team approval, so
        # accepting it here would let ONE User review satisfy BOTH controls
        # while the required App review is absent. Blocking evidence stays
        # identity-agnostic below -- dropping a User-seat CHANGES_REQUESTED
        # or blocking count would be fail-open. The User seat still
        # participates as a DISTINCT REVIEWER on App-authored PRs via the
        # permission-checked distinct_reviewer path, which is a separate
        # control.
        is_app_seat = user.get("type") == "Bot"
        # Round 2 of the #47 review: signals carry the SEAT alongside the
        # login. GitHub REST may normalize the App login to the same string
        # as the shared User login, and a login-only reduction key would then
        # merge two distinct actors -- letting a normalized App approval
        # erase the User seat's outstanding objection.
        seat = "app" if is_app_seat else "user"

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
        # Round 7 of the #47 review: STATE-WITHDRAWAL AUTHORITY orders by
        # submission time. review_signal_time() ranks a review at the later
        # of submitted_at/last_edited_at so a body edited to ADD blocking
        # findings ranks newest (fail closed) -- but that same edit-aware
        # clock let an OLD approval, body-edited after a newer
        # CHANGES_REQUESTED from the same identity, become the actor's
        # newest clean placeholder and withdraw an objection that was never
        # formally withdrawn. Positive and withdrawal signals (success,
        # clean-commented, the User-seat withdrawal placeholder, the
        # self-review placeholder) therefore bind to submitted_at; only
        # fail-closed body-derived evidence (blocking findings, coordinator
        # ambiguity) keeps the edit-aware time.
        submitted = str(review.get("submitted_at") or "")
        state = review.get("state")

        # Blocking body evidence is classified BEFORE the state branches
        # (round 4 of the multicast vendoring review): the APPROVED branch
        # used to return success without reading the body, so an exact-head
        # App approval whose body still carried `Critical Issues (1)` -- or
        # surviving (un-negated) action-required prose, or an explicit
        # changes-requested verdict -- greened the gate. Contradiction
        # resolves red for EVERY state, including a self-review, matching
        # the comment path's rule that machine-readable blocking findings
        # fail closed and stay un-overridable. The prose scan runs
        # independently of the verdict (review round 7); incidental
        # security/"blocking" mentions still do NOT match.
        verdict = explicit_verdict(body)
        if (
            has_blocking_count(body)
            or verdict == "changes-requested"
            or has_action_required_language(body)
        ):
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "seat": seat,
                    "description": "Ally review flagged blocking findings on head %s."
                    % short_sha(head_sha),
                    "kind": "formal-review",
                    "status": "failure",
                }
            )
            continue

        # Demote before reading the state so a bot review of its own PR can
        # neither hard-pass (APPROVED) nor hard-fail (CHANGES_REQUESTED); its
        # body-level blocking evidence has already failed closed above.
        if is_self_review:
            signals.append(self_review_signal(submitted, login, head_sha, seat))
            continue

        if state == "APPROVED":
            if not attested:
                # Unattested approvals bind nothing, in either direction.
                continue
            # The ambiguity check runs BEFORE either approval branch (round
            # 2 of the #47 review): the lenient mask may have consumed a
            # real blocking phrase, so an ambiguous approval may neither
            # authorize green nor stand as this seat's clean verdict. It is
            # emitted as the seat's current NON-success signal: it
            # supersedes the same seat's earlier success (the newest look is
            # no longer a clean approval), while current_signals_per_login
            # refuses to let it displace a standing blocker -- fail closed
            # in both directions. decide() maps it to pending.
            if masked_blocking_ambiguity(body):
                signals.append(
                    {
                        "at": at,
                        "author": login,
                        "seat": seat,
                        "description": "Ally approval of head %s is "
                        "coordinator-ambiguous; it neither authorizes nor "
                        "withdraws." % short_sha(head_sha),
                        "kind": "ambiguous-approval",
                        "status": AMBIGUOUS_APPROVAL_STATUS,
                    }
                )
                continue
            if not is_app_seat:
                # Round 4: an exact-head-attested User-seat approval carries
                # no positive authority, but it IS that identity's newest
                # formal verdict. Emit the clean-commented placeholder so the
                # per-seat reduction in decide() lets the User seat withdraw
                # ITS OWN earlier objection -- mirroring GitHub's rule that a
                # reviewer's new approval supersedes their prior
                # CHANGES_REQUESTED. decide() maps this status to pending, so
                # it can never become the green.
                signals.append(
                    {
                        "at": submitted,
                        "author": login,
                        "seat": seat,
                        "description": "Ally User-seat approval of head %s "
                        "(no positive authority)." % short_sha(head_sha),
                        "kind": "user-seat-approval",
                        "status": CLEAN_COMMENTED_STATUS,
                    }
                )
                continue
            signals.append(
                {
                    "at": submitted,
                    "author": login,
                    "seat": seat,
                    "description": "Ally approved head %s." % short_sha(head_sha),
                    "kind": "formal-review",
                    "status": "success",
                }
            )
            continue

        # The canonical distinct-reviewer negative verdict. Stays red
        # regardless of body prose or the override label. Round 8 of the
        # #47 review: this STATE signal binds to submitted_at like every
        # other formal-state signal -- editing an old objection's body must
        # not re-time it past the same seat's newer formal approval and
        # resurrect a formally withdrawn objection. An edit that ADDS
        # machine-readable blocking evidence still fails closed through the
        # edit-aware body-evidence branch above.
        if state == "CHANGES_REQUESTED":
            signals.append(
                {
                    "at": submitted,
                    "author": login,
                    "seat": seat,
                    "description": "Ally requested changes on head %s." % short_sha(head_sha),
                    "kind": "formal-review",
                    "status": "failure",
                }
            )
            continue

        if state == "COMMENTED":
            if not attested or not is_app_seat:
                continue
            # A coordinator-ambiguous body may not authorize green no matter
            # what pass verdict or zero counts accompany it (review round 8):
            # the mask may have consumed a real blocking phrase, and a
            # machine-readable all-clear must not launder that away. Round 6
            # of the #47 review: the ambiguous review is EMITTED rather than
            # discarded -- it is this App seat's newest formal look at the
            # head, so it supersedes the seat's older approval to pending
            # (while still never withdrawing a blocker, per the reduction).
            if masked_blocking_ambiguity(body):
                signals.append(
                    {
                        "at": at,
                        "author": login,
                        "seat": seat,
                        "description": "Ally review of head %s is "
                        "coordinator-ambiguous; it neither authorizes nor "
                        "withdraws." % short_sha(head_sha),
                        "kind": "ambiguous-commented-review",
                        "status": AMBIGUOUS_APPROVAL_STATUS,
                    }
                )
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
                    "at": submitted,
                    "author": login,
                    "seat": seat,
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

        seat = "app" if user.get("type") == "Bot" else "user"
        at = str(review.get("submitted_at") or "")
        if review.get("state") == "APPROVED":
            if not positively_bound:
                continue
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "seat": seat,
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
                    "seat": seat,
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
        user = comment.get("user") or {}
        login = user.get("login")
        body = str(comment.get("body") or "")
        if not isinstance(login, str) or login not in ally:
            continue
        # No positive seat gating here: since #45 the comment path carries
        # no positive branch, and its blocking evidence is deliberately
        # identity-agnostic (any Ally-login seat may fail the gate, no seat
        # may green it from a comment). The seat still labels the signal so
        # per-seat reduction in decide() keys distinct actors correctly even
        # when REST normalizes both seats to the same login string.
        seat = "app" if user.get("type") == "Bot" else "user"

        is_consolidated = is_consolidated_ally_comment_for_head(body, head_sha)
        is_issue_link = is_issue_link_ally_comment_for_head(body, head_sha)
        if not (is_consolidated or is_issue_link):
            continue

        # Order on the LATER of created_at/updated_at. GitHub keeps created_at
        # immutable across edits, so an older comment edited to add blocking
        # findings would otherwise carry a stale timestamp and lose
        # latest_signal() to an earlier formal approval, leaving the gate
        # green on a body that now says the opposite.
        at = comment_signal_time(comment)

        # Self-review cannot approve its own PR, but machine-readable blocking
        # findings must still fail closed and remain impossible to override.
        if has_blocking_count(body):
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "seat": seat,
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
            # Binds to created_at (the submission analog): an edited old
            # comment must not re-time this pending placeholder past the
            # actor's newer blocking evidence (round 7 of the #47 review).
            signals.append(
                self_review_signal(
                    str(comment.get("created_at") or ""), login, head_sha, seat
                )
            )
            continue

        verdict = explicit_verdict(body)
        # FAILURE on an actual changes-requested verdict OR surviving
        # (un-negated) action-required prose -- checked INDEPENDENTLY of the
        # verdict (review round 7): an explicit pass paired with "Action
        # required: fix X." is contradictory prose, and contradiction resolves
        # red. A positive review that merely *mentions* security / "blocking"
        # / "unsafe" / "finding" never fails here.
        if verdict == "changes-requested" or has_action_required_language(body):
            signals.append(
                {
                    "at": at,
                    "author": login,
                    "seat": seat,
                    "description": "Ally comment requested action on head %s." % short_head,
                    "kind": "consolidated-comment",
                    "status": "failure",
                }
            )
            continue

        # A coordinator-ambiguous body may not authorize green regardless of
        # verdict or counts (review round 8; see masked_blocking_ambiguity).
        # Round 2 of this PR's review removed the comment path's positive
        # branch entirely: a clean consolidated comment used to emit
        # `success`, which let an issue comment green `review/ally-complete`
        # with no formal review having happened, and let a later clean
        # comment out-rank an earlier formal blocking signal through
        # latest_signal(). Comments now contribute ONLY blocking evidence
        # (the failure appends above); the sole producer of `success` on
        # this context is the formal exact-head App-seat APPROVED branch in
        # review_signals_for_head. A clean comment is therefore inert here
        # -- it neither greens the gate nor withdraws a standing signal.

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


def canonical_actor_login(login, seat):
    """One grouping key per identity across REST login spellings (round 5 of
    the #47 review): the same GitHub App may surface as `x[bot]`, `app/x`,
    or a normalized bare `x` in different rows, and splitting those left a
    stale clean approval standing as a separate current `success` beside
    the App's newer ambiguous verdict under the other spelling. Only the
    App seat is normalized -- the shared User seat keeps its raw login, so
    the seat separation from round 2 (normalized App vs User with the same
    login string) is untouched: the seat component of the key still
    distinguishes them.
    """
    if seat != "app":
        return login
    name = login
    if name.startswith("app/"):
        name = name[len("app/"):]
    if name.endswith("[bot]"):
        name = name[: -len("[bot]")]
    return name


def current_signals_per_login(signals):
    """Each actor's CURRENT signal, independent of input order.

    Round 3 of the #47 review: the previous incremental fold depended on the
    order signals arrived -- decide() concatenates all reviews before all
    comments, so a seat's ambiguous approval could be installed first and
    that same seat's OLDER blocking comment then discarded as stale, erasing
    a blocker the ambiguity rule was supposed to preserve. Each (login,
    seat) group is now sorted before folding, so caller concatenation order
    cannot change the result.

    The key is (login, seat), not login alone (round 2 of the #47 review):
    GitHub REST may normalize the App login to the same string as the shared
    User login, and a login-only key would merge two distinct actors --
    letting a normalized App approval erase the User seat's outstanding
    objection.

    Ordering inside one actor is chronological with a fail-closed tie rank:
    on an equal timestamp, failure outranks ambiguity, and ambiguity
    outranks any non-blocking state (a clean approval and an ambiguous
    approval in the same second resolve to ambiguous -- pending, not
    success). Across timestamps the chronologically newest signal wins,
    EXCEPT that an AMBIGUOUS_APPROVAL_STATUS signal never displaces a
    standing failure: the blocker stays current until an UNAMBIGUOUS
    same-seat verdict supersedes it. Shared by the distinct-reviewer
    reduction and by decide()'s reduction of Ally's own dual-seat signals --
    the App seat and the shared User seat are distinct actors, so only the
    same identity may supersede its own objection.
    """

    def tie_rank(signal):
        # Higher rank folds LAST at an equal timestamp, so it wins the tie
        # unless a fold rule (ambiguity-vs-failure) says otherwise. Every
        # same-second pairing is deterministic (round 4 of the #47 review):
        # failure > ambiguity > clean/pending > success. Ranking success
        # LOWEST means an equal-second contradiction always resolves away
        # from green -- a clean COMMENTED beside a same-second approval
        # withdraws it to pending, never the reverse by REST list order.
        if signal["status"] == "failure":
            return 3
        if signal["status"] == AMBIGUOUS_APPROVAL_STATUS:
            return 2
        if signal["status"] == "success":
            return 0
        return 1

    grouped = {}
    for signal in signals:
        seat = signal.get("seat", "")
        actor = (canonical_actor_login(signal["author"], seat), seat)
        grouped.setdefault(actor, []).append(signal)

    current_states = []
    for group in grouped.values():
        # Round 6 of the #47 review: reduce each TIMESTAMP BUCKET to its
        # highest fail-closed precedence before applying it to prior state.
        # Folding individual signals let a clean approval withdraw a
        # standing blocker one step before the same-second ambiguous
        # approval was processed -- the bucket's contradictory verdicts must
        # collapse first (ambiguity beats the clean withdrawal), and an
        # ambiguous bucket still cannot withdraw the seat's earlier blocker.
        buckets = {}
        for signal in group:
            buckets.setdefault(str(signal["at"]), []).append(signal)
        current = None
        for at in sorted(buckets):
            representative = max(buckets[at], key=tie_rank)
            if (
                current is not None
                and current["status"] == "failure"
                and representative["status"] == AMBIGUOUS_APPROVAL_STATUS
            ):
                # An ambiguous verdict cannot withdraw this seat's blocker.
                continue
            current = representative
        if current is not None:
            current_states.append(current)

    return current_states


def reduce_distinct_reviewer_signals(signals):
    """Reduce to each reviewer's CURRENT state, then fail if any reviewer is
    currently requesting changes.

    Taking the single globally-latest signal is wrong with more than one
    reviewer: reviewer B approving after reviewer A requested changes would
    erase A's still-active objection and clear the gate. GitHub itself treats
    an outstanding CHANGES_REQUESTED as blocking regardless of who reviewed
    later, and so does this.
    """
    current_states = current_signals_per_login(signals)
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
    ally = set(ally_logins)
    is_self_review = isinstance(pr_author_login, str) and pr_author_login in ally

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

    # Round 4 of the multicast vendoring review: Ally's own signals reduce
    # PER LOGIN, exactly like distinct reviewers, because the App seat and
    # the shared User seat are distinct actors -- a later App approval must
    # not erase a User-seat CHANGES_REQUESTED that its own identity never
    # withdrew. After the reduction, selection is fail-closed by status:
    # any outstanding blocker wins; otherwise a standing App-seat approval
    # (only the formal App APPROVED branch can produce `success`, and only
    # that login's own newer signal can supersede it); otherwise the newest
    # clean/pending placeholder.
    ally_current = current_signals_per_login(ally_signals)
    ally_blocking = [s for s in ally_current if s["status"] == "failure"]
    ally_successes = [s for s in ally_current if s["status"] == "success"]
    if ally_blocking:
        signal = latest_signal(ally_blocking)
    elif ally_successes:
        signal = latest_signal(ally_successes)
    else:
        signal = latest_signal(ally_current)

    # Distinct-reviewer evidence contributes success as well as blocking
    # signals here (BLO-25488, fixing the round-3 regression where success
    # was dropped and no identity -- not even a trusted human -- could ever
    # green a self-review PR). This context's positive authority is now
    # EITHER Ally's own App-seat APPROVED (handled above via ally_successes)
    # OR a distinct, permission-trusted, NON-ALLY login's exact-head-attested
    # APPROVED. The Ally User seat structurally still qualifies as a
    # "distinct" participant here (case (b) of
    # distinct_reviewer_signals_for_head's is_distinct, needed so its own
    # CHANGES_REQUESTED keeps binding), but BLO-24056 found it supplying 661
    # App-authored approvals org-wide -- it is Ally's second hat, not an
    # independent reviewer, so it must never be the identity that turns this
    # green. Adopting `reduced` unconditionally on failure (as before) keeps
    # a trusted distinct reviewer's CHANGES_REQUESTED fail-closed regardless
    # of identity; adopting success only requires a SEPARATE reduction
    # restricted to non-Ally authors, so a chronologically-later Ally-seat
    # success cannot shadow an earlier, still-current non-Ally approval. A
    # reviewer's later approval still withdraws THEIR OWN earlier change
    # request inside the per-reviewer reduction. Ally's own OUTSTANDING
    # blocking findings outrank everything.
    if is_self_review and distinct_signals and not ally_blocking:
        reduced = reduce_distinct_reviewer_signals(distinct_signals)
        if reduced is not None and reduced["status"] == "failure":
            signal = reduced
        elif reduced is not None and reduced["status"] == "success":
            non_ally_signals = [s for s in distinct_signals if s["author"] not in ally]
            reduced_non_ally = reduce_distinct_reviewer_signals(non_ally_signals)
            if reduced_non_ally is not None and reduced_non_ally["status"] == "success":
                signal = reduced_non_ally

    # There is deliberately NO maintainer override on this context (round 3
    # of the multicast vendoring review): a head-bound label+comment override
    # was a second, unchecked-identity path to the same authority the
    # distinct-reviewer reduction above already grants under a permission AND
    # identity check. Deadlock relief for a reviewer that never ran is an
    # administrative action outside this context (branch-protection admin
    # bypass), not a state this script will ever report as success.

    if signal is None:
        return "pending", "Waiting for Ally review of head %s." % short_sha(head_sha)

    if signal["status"] == AMBIGUOUS_APPROVAL_STATUS:
        return (
            "pending",
            "Ally approval of head %s is ambiguous; awaiting an unambiguous "
            "App-seat APPROVED review." % short_sha(head_sha),
        )

    # A clean COMMENTED review is not a GitHub status state, and no label can
    # clear it any more: hold pending until the App seat APPROVES this head.
    if signal["status"] == CLEAN_COMMENTED_STATUS:
        return (
            "pending",
            "Ally reviewed head %s, no blocking findings; awaiting an "
            "App-seat APPROVED review." % short_sha(head_sha),
        )

    return signal["status"], signal["description"]


# BLO-19826: ported from Blockcast/onprem-k8s .github/scripts/require-ally-
# review.py @ c48c4489085ef50569c6f7c187d430362d398088 (2026-08-06). Every
# call below used to be single-shot, so one 502 aborted main() and the
# top-level handler turned it into a red job. Worst case was a 502 from the
# FINAL set_commit_status() -- after decide() had already computed a verdict
# (BLO-19194, run 30584001403): the real work was discarded, the context was
# left on the pre-claimed "Evaluating..." pending, and a maintainer had to
# hand-diagnose "infra noise or gate verdict?" and re-run. Retrying removes
# that ambiguity without touching the fail-closed posture: an exhausted retry
# still raises, so the context stays `pending` and the job still exits
# non-zero.
#
# Three independent bounds, so a retry storm can never stall the merge path:
#   * REQUEST_MAX_ATTEMPTS  -- total tries for one call (so at most 3 retries).
#   * REQUEST_TIMEOUT_SECONDS -- per attempt. urlopen() has NO default timeout,
#     so without this a single hung socket blocks forever and the wall-clock
#     bound below would be unenforceable.
#   * REQUEST_RETRY_BUDGET_SECONDS -- across all retries of one call. A retry
#     is only started if it can BEGIN inside the budget, so the worst case is
#     the budget plus one final attempt's timeout (~65s), not attempts x
#     timeout.
#
# Retrying the two POSTs here is safe because both are effectively idempotent:
# the GraphQL call is a pure read, and re-POSTing a commit status with the same
# context+state converges on the same effective status for that context.
#
# INTERACTION WITH THIS FILE'S OWN _PROBE_ATTEMPTS RETRY LAYER (below): this
# repo already has two hand-rolled outer retry wrappers -- _probe_pull_request
# (with a git-transport fallback the onprem-k8s design has no counterpart
# for) and set_commit_status -- that catch ANY exception from _request and
# retry up to _PROBE_ATTEMPTS=3 times on their own 1s/2s schedule via the
# _sleep test seam. Those are UNCHANGED by this port and still wrap the new,
# now-internally-retrying _request(). The composition is safe but not free:
# a permanent 5xx now takes up to _PROBE_ATTEMPTS outer attempts, each
# retrying up to REQUEST_MAX_ATTEMPTS times internally, before either wrapper
# gives up -- strictly more resilience, at the cost of a longer worst-case
# failure path (bounded: each layer bounds its own attempts and budget, nothing
# nests unboundedly). A permanent 4xx that _request() now fast-fails on the
# first attempt is still retried by the outer wrappers exactly as before this
# change, since they catch any exception unconditionally -- that pre-existing
# behavior is untouched here.
REQUEST_MAX_ATTEMPTS = 4
REQUEST_TIMEOUT_SECONDS = 20.0
REQUEST_RETRY_BUDGET_SECONDS = 45.0
REQUEST_BACKOFF_SECONDS = 1.0


def _retry_backoff_seconds(attempt):
    """Exponential backoff: 1s, 2s, 4s before attempts 2, 3, 4."""
    return REQUEST_BACKOFF_SECONDS * (2 ** (attempt - 1))


def _http_error_diagnostics(error):
    """Best-effort snapshot of a 4xx HTTPError: body + rate-limit headers.

    _request() used to raise straight off `error.code` with nothing else
    logged, so a rate-limited 403 and a genuine permission 403 were
    indistinguishable from the job log -- this class of failure was
    otherwise unreadable (BLO-20820). Kept permanently, not just for the
    retry decision below.
    """
    try:
        body = error.read()
        body_text = body.decode("utf-8", "replace")[:500] if body else ""
    except Exception:
        body_text = "<body unreadable>"
    headers = error.headers or {}
    return {
        "body": body_text,
        "retry_after": headers.get("Retry-After"),
        "rate_remaining": headers.get("X-RateLimit-Remaining"),
        "rate_reset": headers.get("X-RateLimit-Reset"),
    }


def _rate_limit_wait_seconds(diagnostics):
    """Seconds GitHub asked us to wait, from whichever header carries it."""
    retry_after = diagnostics["retry_after"]
    if retry_after:
        try:
            return max(0.0, float(retry_after))
        except (TypeError, ValueError):
            pass
    rate_reset = diagnostics["rate_reset"]
    if rate_reset:
        try:
            return max(0.0, float(rate_reset) - time.time())
        except (TypeError, ValueError):
            pass
    return None


def _request(url, token, method="GET", payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", "Bearer %s" % token)
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")

    deadline = time.monotonic() + REQUEST_RETRY_BUDGET_SECONDS
    for attempt in range(1, REQUEST_MAX_ATTEMPTS + 1):
        explicit_backoff = None
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            # HTTPError subclasses URLError, so this arm MUST precede the next.
            diagnostics = _http_error_diagnostics(error)
            print(
                "GitHub API %s %s -> HTTP %d: %s "
                "(retry-after=%s x-ratelimit-remaining=%s x-ratelimit-reset=%s)"
                % (
                    method,
                    url,
                    error.code,
                    diagnostics["body"] or "<empty body>",
                    diagnostics["retry_after"],
                    diagnostics["rate_remaining"],
                    diagnostics["rate_reset"],
                ),
                file=sys.stderr,
            )
            # A 429 is unambiguously rate-limited even when GitHub omits its
            # optional rate-limit headers. A 403 is ambiguous, so require an
            # explicit "not so fast" signal (Retry-After, or a zero primary
            # budget) before treating it as transient. This keeps genuine
            # permission failures fast while honoring all 429s with bounded
            # backoff (BLO-20820).
            # Any OTHER 4xx is a real ANSWER from GitHub -- auth, permission,
            # not-found -- retrying it would bury a genuine misconfiguration
            # under backoff, and callers branch on the code
            # (fetch_collaborator_permission treats 404 as "not a
            # collaborator"), so it must surface immediately and unchanged.
            rate_limited = error.code == 429 or (
                error.code == 403
                and (
                    diagnostics["retry_after"]
                    or diagnostics["rate_remaining"] == "0"
                )
            )
            if error.code < 500 and not rate_limited:
                raise
            transient = error
            # Only a CONFIRMED rate-limited 4xx gets the explicit GitHub-
            # provided wait time. An ordinary 5xx commonly carries the same
            # X-RateLimit-Reset header even though it was never rate-limited;
            # reading it here would let an unrelated hourly reset overrun the
            # retry budget and abort a plain transient 5xx that
            # _retry_backoff_seconds() would otherwise retry fine.
            explicit_backoff = (
                _rate_limit_wait_seconds(diagnostics) if rate_limited else None
            )
            # Retry-After: 0 is a rate-limit signal, but a zero-second sleep
            # would hot-loop. Use the ordinary bounded schedule when GitHub
            # supplies no positive wait.
            if explicit_backoff is not None and explicit_backoff <= 0:
                explicit_backoff = None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            # No HTTP response at all: DNS, refused connection, TLS failure,
            # reset peer, or a read that outran REQUEST_TIMEOUT_SECONDS.
            transient = error
        except http.client.HTTPException as error:
            # Protocol-level damage on an otherwise-open connection
            # (IncompleteRead, BadStatusLine on a half-closed keepalive).
            # Not an OSError, so it needs its own arm.
            transient = error

        if attempt == REQUEST_MAX_ATTEMPTS:
            raise transient
        backoff = (
            explicit_backoff if explicit_backoff is not None
            else _retry_backoff_seconds(attempt)
        )
        if time.monotonic() + backoff >= deadline:
            # Out of wall-clock budget. Fail closed rather than keep a
            # required check waiting. A rate-limit reset can be much further
            # out than this budget (e.g. an hourly repo cap) -- that is
            # intentional: a single job run should not block on it, and the
            # diagnostics above already state why it failed.
            raise transient
        print(
            "GitHub API %s %s failed transiently (%s); retry %d/%d in %.0fs"
            % (method, url, transient, attempt, REQUEST_MAX_ATTEMPTS - 1, backoff),
            file=sys.stderr,
        )
        time.sleep(backoff)

    raise AssertionError("unreachable: the retry loop must return or raise")


# The issue_comment head probe is the single point where a transient API
# failure used to leave a stale same-head `success` standing with no claim
# and no error write (review round 7). Two hardening layers close most of
# that window:
#   1. Retries with backoff -- a rate-limit blip or one 5xx no longer
#      forfeits the head.
#   2. A git-transport fallback (`git ls-remote refs/pull/N/head`) -- an
#      independent protocol path to the same immutable coordinate, so a
#      REST-plane outage alone cannot hide the head. Once EITHER source
#      yields the SHA it is claimed into _STATUS_TARGET, and any later
#      crash posts `error` to it.
# The residual window -- REST and git transport BOTH unreachable -- is
# physically irreducible: with no addressable commit there is nothing any
# code path could stamp, and posting the invalidating status itself
# requires the REST plane. That case exits non-zero with no status write.
_PROBE_ATTEMPTS = 3
_sleep = time.sleep  # test seam


def _probe_pull_request(url, token, attempts=_PROBE_ATTEMPTS):
    """GET the PR with retries; returns the payload or None (never raises)."""
    for attempt in range(attempts):
        try:
            payload = _request(url, token)
        except Exception as error:  # noqa: BLE001 - each attempt is fallible
            print(
                "head probe attempt %d/%d failed: %s" % (attempt + 1, attempts, error),
                file=sys.stderr,
            )
            payload = None
        if payload:
            return payload
        if attempt + 1 < attempts:
            _sleep(2 ** attempt)
    return None


def _parse_ls_remote_head(output):
    """First 40-hex OID column of `git ls-remote` output, or None."""
    for line in (output or "").splitlines():
        oid = line.split("\t")[0].split(" ")[0].strip().lower()
        if re.fullmatch(r"[0-9a-f]{40}", oid):
            return oid
    return None


def _git_pull_head_sha(owner, repo, pull_number, token):
    """Resolve refs/pull/N/head over git smart-HTTP -- a transport
    independent of the REST API plane. Returns the OID or None; never
    raises.

    The token travels via GIT_CONFIG_* environment variables, NEVER in
    argv: on a shared self-hosted runner /proc/<pid>/cmdline is readable
    by same-UID processes, and subprocess exceptions embed the full
    command (review round 8). The URL itself stays credential-free, and
    emitted error text is redacted as a second layer in case git echoes
    configuration back.
    """
    server = (os.environ.get("GITHUB_SERVER_URL") or "https://github.com").rstrip("/")
    url = "%s/%s/%s.git" % (server, owner, repo)
    basic = base64.b64encode(("x-access-token:%s" % token).encode()).decode()

    def redact(text):
        return (text or "").replace(token, "***").replace(basic, "***")

    try:
        result = subprocess.run(
            ["git", "ls-remote", url, "refs/pull/%d/head" % pull_number],
            capture_output=True,
            text=True,
            timeout=30,
            env={
                **os.environ,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.%s/.extraheader" % server,
                "GIT_CONFIG_VALUE_0": "Authorization: Basic %s" % basic,
            },
        )
    except Exception as error:  # noqa: BLE001 - fallback is best-effort
        print("git head fallback failed: %s" % redact(str(error)), file=sys.stderr)
        return None
    if result.returncode != 0:
        print(
            "git head fallback exited %d: %s"
            % (result.returncode, redact((result.stderr or "").strip())[:200]),
            file=sys.stderr,
        )
        return None
    return _parse_ls_remote_head(result.stdout)


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
    """POST the status with bounded retries. Status writes are the gate's
    entire output: a transient REST failure that drops one turns an
    evaluated verdict into silence, and silence in front of an earlier
    same-head `success` is fail-open (review round 8). Retries convert
    blip-length outages into eventual writes; a sustained outage still
    raises, which callers escalate (crash handler -> `error` status when
    possible, non-zero exit -> the required workflow check-run backstop
    otherwise).
    """
    url = "%s/repos/%s/%s/statuses/%s" % (api_base_url.rstrip("/"), owner, repo, sha)
    payload = {
        "context": STATUS_CONTEXT,
        "description": clamp_description(description),
        "state": state,
        "target_url": target_url,
    }
    last_error = None
    for attempt in range(_PROBE_ATTEMPTS):
        try:
            _request(url, token, method="POST", payload=payload)
            return
        except Exception as error:  # noqa: BLE001 - each attempt is fallible
            last_error = error
            print(
                "status write attempt %d/%d for %s failed: %s"
                % (attempt + 1, _PROBE_ATTEMPTS, short_sha(sha), error),
                file=sys.stderr,
            )
            if attempt + 1 < _PROBE_ATTEMPTS:
                _sleep(2 ** attempt)
    raise last_error


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
        # Resolve the head with a minimal retried fetch BEFORE any fallible
        # processing so this path gets the same fail-closed claim as
        # pull_request payloads. When the REST probe stays down, the git
        # smart-HTTP fallback supplies the same immutable coordinate over an
        # independent transport; the run then continues so the claim below
        # lands `pending` on the real head, and any later crash escalates it
        # to `error`. Only when BOTH transports fail is there no addressable
        # commit anywhere -- the raised error fails the workflow run visibly,
        # the documented irreducible residual (see _probe_pull_request).
        probe = _probe_pull_request(
            "%s/repos/%s/%s/pulls/%d" % (api_base_url.rstrip("/"), owner, repo, pull_number),
            token,
        )
        if probe:
            payload_pr = probe
            payload_head = (probe.get("head") or {}).get("sha")
        else:
            fallback_head = _git_pull_head_sha(owner, repo, pull_number, token)
            if not fallback_head:
                raise RuntimeError(
                    "PR #%s head could not be resolved for the fail-closed claim "
                    "(REST probe and git fallback both failed)" % pull_number
                )
            print(
                "REST head probe failed; git fallback resolved head %s"
                % short_sha(fallback_head)
            )
            # Draft/state unknown without the REST payload; an empty snapshot
            # falls through the claim gate below as open/non-draft, which is
            # the fail-closed direction (a stray pending blocks, never clears,
            # and resolve_early_claim cleans up if the refetch later says
            # settled).
            payload_pr = {}
            payload_head = fallback_head
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
        # An empty refetch is indistinguishable from an outage. Returning
        # zero here would leave whatever status history the head already has
        # as the visible truth -- fail-open when that history is a stale
        # `success` and the early claim happened to fail. Raise instead: the
        # crash handler escalates to `error` on the claimed head when the
        # REST plane allows, and the non-zero exit trips the required
        # workflow check-run backstop when it does not.
        raise RuntimeError("PR #%s could not be fetched; refusing to gate on absence" % pull_number)

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
