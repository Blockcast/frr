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
import datetime
import hashlib
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

# The App seat's spellings. The bare `allyblockcast` User seat is deliberately
# absent -- it is an author credential, not a reviewer; see
# DEFAULT_AUTHOR_ONLY_LOGINS.
#
# Ally EVIDENCE is still read across every spelling of these identities
# (login_matches_any), so the App's normalized bare login (`allyblockcast`,
# type Bot) is still the App, and the User seat's machine-readable blocking
# findings still fail closed on every PR. Positive evidence was already
# App-seat-only (type Bot). What the split removes is every TRUST grant: the
# seat can no longer be a distinct reviewer, bind an override, or author a
# deferral (BLO-18926/BLO-18965). One consequence is deliberate: on a PR the
# App authored, the seat's bare formal CHANGES_REQUESTED is a self-review
# signal like any other, so it no longer vetoes -- only its body findings do.
# (Production-neutral ON THIS REPO ONLY: the seat holds `read` on Blockcast/frr,
# so that veto never bound here. This file exists in divergent copies across
# the gate repos, and the premise is per-repo: as of 2026-09-26 the seat holds
# `write` on Blockcast/onprem-k8s, where its veto DOES bind and this change
# would remove a live merge control. Re-verify the seat's permission --
# `gh api repos/<owner>/<repo>/collaborators/allyblockcast/permission` --
# before porting this there or anywhere else.)
DEFAULT_ALLY_LOGINS = ["allyblockcast[bot]", "app/allyblockcast"]

# Identities that act on PRs but are never reviewers. This list, not the Ally
# list, is what demotes the seat: every Ally-membership test uses
# login_matches_any, under which the bare seat is a spelling of
# `allyblockcast[bot]`, so leaving it out of DEFAULT_ALLY_LOGINS is cosmetic.
# Naming it here is what strips its distinct-reviewer standing and its
# override and deferral trust. Matched with login_matches_any, never a raw
# compare: this list WITHHOLDS trust, and GitHub logins are case-insensitive.
DEFAULT_AUTHOR_ONLY_LOGINS = ["allyblockcast"]

# author_association on a review is computed relative to the *requesting
# token's* visibility of org membership, not the reviewer's actual repo
# access. The workflow's default GITHUB_TOKEN carries no `members:read` scope,
# so a genuine org MEMBER can be reported as the lower CONTRIBUTOR association
# even though the same reviewer shows MEMBER to a personal PAT. The
# collaborator-permission endpoint reflects the reviewer's actual repo-level
# grant directly and is not requester-view-dependent, so it is the ONLY trust
# signal. A lookup that errors leaves the login untrusted; there is no
# author_association fallback because COLLABORATOR can mean read or triage.
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
    """Parse a comma-separated operator list, falling back on an EMPTY RESULT.

    The fallback is applied to the PARSED list, not to the raw string. Testing
    the raw string left a fail-OPEN hole one step further in: `","` is
    non-empty, so it read as "supplied", and it parses to `[]`. That is not a
    contrived value -- a workflow composing this from two empty expressions
    (`${{ inputs.a }},${{ inputs.b }}`) yields exactly `,`, and `" , "` and
    `",,"` are the same shape.

    Why it is fail-open rather than merely wrong: every caller of this helper
    is a security-relevant trust list. An empty ally-login set makes every
    withholding check against it (login_matches_any in trusted_deferrals) return
    False, so the `allyblockcast` seat -- the credential agents hold to act on
    PRs, and the identity that RAISED the findings -- becomes eligible to author
    deferrals against its own findings. Ported from the .mjs lineage's parseList,
    which closed this after the same hole was found there (BLO-27578).
    """
    parsed = [item.strip() for item in str(value or "").split(",") if item.strip()]
    if parsed:
        return parsed
    return [item.strip() for item in fallback if str(item).strip()]


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


# --- Per-finding deferral (BLO-22676, ported under BLO-27578) ---------------
#
# The problem this closes: `review/ally-complete` had no terminating state for
# a finding the maintainers had READ, ACCEPTED, and booked to a follow-up
# issue. The finding stays in Ally's body at every subsequent head, so the
# count stays > 0, so the gate stays red forever. Observed cost on
# trafficcontrol PR #1278: one residual finding cycled seven times. The only
# escape was `review-gate-override`, a PR-scoped blanket that clears
# EVERYTHING -- so the coarse lever was the only lever, which is a worse
# security outcome than a narrow one.
#
# A deferral is an issue comment, from a trusted non-author-credential login,
# one of whose own lines reads:
#
#     review-gate-defer: content:<64-hex> issue:BLO-18949
#
# It is bound to the finding's CONTENT, not to a head and not to a slot: as
# long as Ally keeps re-flagging the same finding, one deferral keeps covering
# it; a DIFFERENT finding has different text, so it re-reds the check no
# matter which head or ordinal it lands at. Both acceptance criteria fall out
# of that one property instead of fighting each other.
#
# WHAT THIS IS PORTED FROM, AND WHAT WAS DELIBERATELY LEFT BEHIND.
# The reference is Blockcast/review-gate-action scripts/require-ally-review.mjs
# (PR #2, merge 741a18d, 2026-08-22) -- a SEPARATE LINEAGE from this file, not
# a copy of it, so this is a port of the mechanism rather than a sync. That
# implementation still carries POSITIONAL finding tokens
# (`origin:<head>:important:2`) for Ally's own carry-forward brackets, plus the
# as-of head resolver they require. None of that is here, because after its
# third hardening round a positional token can no longer AUTHORIZE a deferral
# there either (FINDING_TOKEN_SHAPE was collapsed onto the content shape): the
# slot is the defect -- `(head, severity, ordinal)` names a SLOT, not a
# finding, and a brand-new unrelated finding landing in the same slot at a head
# the author controls was covered by the old deferral every time. Porting the
# positional path would therefore have carried ~200 lines of grindable-short-SHA
# resolver machinery whose only remaining job is to feed ids that nothing can
# match -- and left a live footgun for whoever later widens the token shape
# back. Content ids are the whole mechanism; the rest was scaffolding.
#
# This port is also STRICTLY AHEAD of the reference in one place: the reference
# records a KNOWN RESIDUAL that its visibility anchor (below) holds only on the
# comment channel, because REST exposes no edit time for a review body and it
# does not read GraphQL. This file already does -- enrich_reviews_with_edit_times
# supplies `last_edited_at` -- so item_visible_at_ms closes that residual here.
DEFERRAL_TRUSTED_PERMISSIONS = {"admin"}

# A finding's CONTENT identity: sha256 over its own normalized bullet block,
# scoped by severity. The ONLY shape a deferral may name.
FINDING_CONTENT_TOKEN_SHAPE = r"content:[0-9a-f]{64}"
FINDING_CONTENT_TOKEN_PATTERN = re.compile(
    r"^%s$" % FINDING_CONTENT_TOKEN_SHAPE, re.IGNORECASE
)
# `issue:<ref>` must actually name an owning issue. An earlier revision of the
# reference accepted `\S+` here, which admitted opaque strings
# (`issue:not-a-real-ticket`, `issue:https://untracked.example`) and silently
# satisfied the "tied to one owning issue" acceptance criterion without ever
# resolving to a trackable ticket. Matched leniently (so a lowercase ref
# produces a LOUD refusal rather than a line that silently is not a deferral --
# see deferral_records_from_comments) and validated case-sensitively against
# ISSUE_REF_STRICT_PATTERN. Length is bounded because an unbounded ref is what
# made the can't-name-anything status path reachable at all. This gate has no
# tracker API, so even this only proves tracker-SHAPED: `BLO-99999999` passes,
# and nothing here claims more than that.
ISSUE_REF_LENIENT_SHAPE = r"[A-Za-z][A-Za-z0-9]{0,11}-\d{1,8}"
ISSUE_REF_STRICT_SHAPE = r"[A-Z][A-Z0-9]{0,11}-\d{1,8}"
ISSUE_REF_STRICT_PATTERN = re.compile(r"^%s$" % ISSUE_REF_STRICT_SHAPE)
DEFERRAL_LINE_PATTERN = re.compile(
    r"^[ \t]*review-gate-defer:[ \t]*(%s)[ \t]+issue:[ \t]*(%s)[ \t]*$"
    % (FINDING_CONTENT_TOKEN_SHAPE, ISSUE_REF_LENIENT_SHAPE),
    re.IGNORECASE | re.MULTILINE,
)


def finding_heading_pattern(label):
    """The `### {label} Issues (N)` heading, anchored to its own line.

    Deliberately stricter than extract_issue_count's bare `{label} Issues (N)`
    scan: enumeration must bind to a real section it can walk bullets under,
    while extract_issue_count reads the MAXIMUM across every occurrence
    including inline prose. When the two disagree the reconciliation in
    findings_for_section fails closed, which is the point -- see there.
    """
    return re.compile(
        r"^#{1,6}[ \t]*%s Issues \((\d+)\)[ \t]*$" % re.escape(label),
        re.IGNORECASE | re.MULTILINE,
    )


# Ally's own per-head metadata bracket (`- **[origin:35c24be important 1; ...]**
# Summary.`) and the bare carry-forward citation shape. Stripped BEFORE hashing:
# the head and the slot it names are per-head metadata, so hashing them would
# re-break the carry-forward property that makes one deferral cover a finding
# across heads -- which is the whole point of the mechanism.
#
# Anchored at the start only. A SHA appearing mid-prose is content, and in these
# repos two findings can legitimately differ by nothing but a SHA they quote, so
# a global strip would be a widening rather than a normalization.
#
# THE CLOSING `**` MUST FOLLOW THE `]` IMMEDIATELY. The reference lineage writes
# this as `^\*\*\[[^\]]*\].*?\*\*[ \t]*`, whose non-greedy `.*?` runs to the
# FIRST `**` after the bracket -- so on a bullet whose bold span closes after the
# TITLE rather than after the bracket, the strip eats the whole title as if it
# were metadata. That is a CONFIRMED content-id collision, demonstrated
# end-to-end against this gate (BLO-27578 adversarial pass): given
#
#     - **[HIGH] Unbounded read in the HTTP client** `client.go:88`
#     - **[HIGH] Missing authorization check on admin config writes** `client.go:12`
#
# both normalize to `` `client.go:#` `` and hash identically, so an admin's
# legitimate deferral of the first silently covered the second -- a brand-new,
# semantically unrelated finding -- and the gate went green. It violates both
# "a deferral covers only the finding it names" and "a later finding re-reds the
# check", and the admin cannot notice because they copy the digest the gate
# prints.
#
# Requiring `\]\*\*` fixes it in the fail-safe direction: on Ally's real renderer
# the bracket IS the whole bold run (verified against the live bodies on
# trafficcontrol PR #1278), so nothing legitimate stops being stripped; and if
# Ally ever does emit `**[x] title**`, the bracket is simply NOT stripped, the
# title stays in the digest, identity becomes MORE specific, and the failure mode
# is a deferral ceasing to apply -- never one applying where it should not.
FINDING_METADATA_BRACKET_PATTERN = re.compile(r"^\*\*\[[^\]]*\]\*\*[ \t]*")
FINDING_CARRY_FORWARD_TOKEN_PATTERN = re.compile(
    r"^(?:origin|prior)[: ]+[0-9a-f]{7,40}[ :]+(?:critical|important)[ :]+\d+[ \t]*",
    re.IGNORECASE,
)


def strip_finding_metadata_bracket(text):
    out = str(text or "")
    # Either order, and both, hence the loop: the bracket can be followed by a
    # bare token, and a bare token can precede a bracket.
    for _ in range(4):
        nxt = FINDING_CARRY_FORWARD_TOKEN_PATTERN.sub(
            "", FINDING_METADATA_BRACKET_PATTERN.sub("", out)
        )
        if nxt == out:
            break
        out = nxt
    return out


def normalize_finding_citations(text):
    """A backticked `file:line` citation is normalized to `file:#` before hashing.

    This is the one place identity is deliberately made LESS specific, so the
    trade-off is stated rather than implied. Line numbers drift on any push that
    edits the file ABOVE the finding -- which is exactly the push a carry-forward
    deferral has to survive -- so hashing them meant a legitimate deferral
    stopped applying whenever the author touched anything earlier in the file.
    That is fail-closed, but "fail-closed on every push" IS the never-green loop
    this mechanism exists to fix, and a maintainer whose per-finding deferral
    keeps evaporating reaches for the blanket override instead.

    The FILE PATH is kept, so two findings in different files still differ. What
    is given up is discriminating two findings in the SAME file whose entire
    block is byte-identical after normalization and which differ only by line
    number -- two findings that alike are the same finding restated at a new
    location, which is precisely the case carry-forward is for.

    Scoped to backticked spans, so a bare `:88` in prose is left alone.
    """
    return re.sub(
        r"`([^`\s]+?):\d+(?:-\d+)?`", lambda m: "`%s:#`" % m.group(1), str(text or "")
    )


def finding_content_id(block, label):
    """Identity over the finding's WHOLE block and its SEVERITY.

    Two collisions this closes, both confirmed against the real gate in the
    reference lineage:

      - Continuation lines. Ally writes multi-line findings; hashing only the
        `- ` line made `- **[x]** Input validation gap.` with a detail line
        reading `a.go:1 rejects empty strings` and one reading `b.go:99 allows
        unauthenticated admin writes` share an id. The maintainer read the
        detail line; the grant was bound only to the summary. Generic summaries
        ("Missing authorization check.") repeat across genuinely different
        findings, so this is not a corner case.

      - Severity. A deferral granted while Ally classed a finding Important
        silently silenced it once reclassified Critical. LLM severity is
        unstable run to run and an author can influence it by moving code onto
        a more sensitive path, so hashing the label makes reclassification
        re-red.

    Both only ever make identity MORE specific, so the failure mode is a
    deferral ceasing to apply (check goes red, a human re-rules) -- never one
    applying where it should not.
    """
    lines = list(block) if isinstance(block, (list, tuple)) else [block]
    first = strip_finding_metadata_bracket(
        re.sub(r"^[ \t]*-[ \t]+", "", str(lines[0] if lines else "") or "")
    )
    joined = " ".join([first] + [str(line or "") for line in lines[1:]])
    normalized = re.sub(r"\s+", " ", normalize_finding_citations(joined)).strip().lower()
    if normalized == "":
        return None
    scoped = "%s\n%s" % (str(label or "").strip().lower(), normalized)
    return "content:%s" % hashlib.sha256(scoped.encode("utf8")).hexdigest()


def canonical_deferral_token(raw_token):
    """Canonicalize the finding-id token of a `review-gate-defer:` line.

    Only the content shape is accepted. Unlike the reference's positional path
    this needs neither a head resolver nor an as-of timestamp: a content id
    means the same thing whenever it was written, so the whole class of
    as-of/live-set resolution bypasses that positional ids kept reopening has
    no surface here at all.
    """
    token = str(raw_token or "").strip()
    return token.lower() if FINDING_CONTENT_TOKEN_PATTERN.match(token) else None


def findings_for_section(body, label, expected_count, ambiguous_severities=None):
    """Enumerate the findings under a `### {label} Issues (N)` heading.

    Returns [] when the section declares no findings, and None -- "cannot
    verify" -- whenever the heading is missing, its declared count disagrees
    with `expected_count` (the same count has_blocking_count already trusts),
    the section's top-level bullet count does not exactly match, more than one
    occurrence of the heading actually enumerates bullets, or
    `ambiguous_severities` marks this label unresolvable.

    A deferral must never be able to widen coverage past what this script can
    positively enumerate, so EVERY parse mismatch falls back to the pre-existing
    raw-count blocking behaviour (see blocking_verdict_for_body) instead of
    guessing.

    The "exactly one bullet-bearing occurrence" rule is what keeps enumeration
    bound to the SAME section extract_issue_count scored. Ally bodies
    legitimately repeat these headings (a "Prior Findings Dispositioned" recap
    above the live section), and selecting the first occurrence while
    extract_issue_count takes the maximum let the two disagree: on a body whose
    recap enumerated its own bullets, a maintainer deferring what they read as
    the live findings would instead defer already-dispositioned ones and clear
    the section while a live finding stood. The real recap shape carries
    `{label} Issues (0)` with no bullets, so it is unaffected; a recap that does
    enumerate bullets is genuinely ambiguous and fails closed.
    """
    if expected_count is None or expected_count == 0:
        return []
    if ambiguous_severities and label.lower() in ambiguous_severities:
        return None

    enumerated = []
    for heading in finding_heading_pattern(label).finditer(body or ""):
        after = (body or "")[heading.end():]
        next_heading = re.search(r"^#{1,6}[ \t]", after, re.MULTILINE)
        section = after[: next_heading.start()] if next_heading else after
        # Each finding is its bullet line PLUS any indented continuation lines.
        # Bullet COUNTING is unchanged (one per `- ` line, so the declared count
        # still reconciles), but identity covers the whole block. Only indented
        # lines are absorbed -- the markdown continuation shape -- so unrelated
        # trailing prose in the section is not swallowed.
        blocks = []
        for raw_line in section.split("\n"):
            if re.match(r"^-[ \t]", raw_line):
                blocks.append([raw_line])
            elif blocks and re.match(r"^[ \t]+\S", raw_line):
                blocks[-1].append(raw_line)
        if blocks:
            enumerated.append((blocks, int(heading.group(1))))

    if len(enumerated) != 1:
        return None
    blocks, declared_count = enumerated[0]
    if declared_count != expected_count or len(blocks) != expected_count:
        return None

    lower_label = label.lower()
    findings = []
    for index, block in enumerate(blocks):
        findings.append(
            {
                "block": block,
                # None when the block normalizes to nothing -- such a finding
                # cannot be given a meaningful identity and so can never be
                # deferred, which is the fail-safe direction.
                "content_id": finding_content_id(block, lower_label),
                "label": lower_label,
                "line": block[0],
                "ordinal": index + 1,
            }
        )
    return findings


def finding_sets_equal(left, right):
    """Two parsed finding sets are the same report content -- not two competing
    numberings -- when every bullet line at every ordinal is byte-identical.
    """
    if len(left) != len(right):
        return False
    return all(a["line"] == b["line"] for a, b in zip(left, right))


def ambiguous_finding_severities(bodies):
    """Severities for which two same-head Ally artifacts disagree about what the
    findings even are.

    Two qualifying bodies that enumerate byte-identical bullets are the same
    report content (a duplicate delivery, a rerun with nothing changed) and are
    not a conflict. A genuine disagreement -- a rerun whose findings differ, a
    retry that reclassified something, concurrent workflow runs -- means this
    gate cannot say which report it is reasoning about, so the severity is
    unresolvable and falls back to raw-count blocking, same as any other
    unparseable section.

    Note this is weaker medicine than in the reference lineage, and
    deliberately kept anyway. There, ids were positional, so two disagreeing
    reports made `origin:<head>:important:1` genuinely AMBIGUOUS BETWEEN THEM
    and a deferral naming report A's finding silently matched report B's. With
    content ids that specific collision cannot happen -- different text, different
    id. What survives is the general conservatism: if the gate cannot tell which
    report is authoritative for a severity, it does not enumerate that severity
    at all.
    """
    ambiguous = set()
    for label in ("Critical", "Important"):
        reference = None
        for body in bodies:
            expected = extract_issue_count(body, "%s Issues" % label)
            if expected is None or expected == 0:
                continue
            findings = findings_for_section(body, label, expected)
            if findings is None:
                continue
            if reference is None:
                reference = findings
                continue
            if not finding_sets_equal(reference, findings):
                ambiguous.add(label.lower())
                break
    return ambiguous


# Every occurrence of the count token, not just headings and not just the first.
#
# Used solely to re-test the prose scans once deferral coverage has ALREADY
# fully accounted for those counts. ACTION_REQUIRED_COMMENT_PATTERN's own
# `critical issues? \([1-9]\d*\)` / `important issues? \([1-9]\d*\)`
# alternatives are a verbatim duplicate of the same text, so without stripping
# it a fully-deferred finding set would still trip the identical failure through
# that redundant path -- the count-derived blocking would survive the deferral
# under a different name.
#
# Strips the bare `{label} Issues (N)` token wherever it appears, matching what
# extract_issue_count reads rather than only the anchored heading, because an
# inline mention trips the prose scan exactly as well as a heading does. That is
# sound precisely because this is only ever reached AFTER findings_for_section
# reconciled the heading's declared count against extract_issue_count's maximum
# over all occurrences -- if an inline count disagreed with the heading, the
# enumeration already failed closed and no strip happens.
#
# This never touches the independent keyword alternatives (`changes requested`,
# `request changes`, `action required`), so a genuine blocking phrase elsewhere
# in the body still fails closed. That is the "neutralize only the count-derived
# blocking, never the prose-derived kind" requirement, enforced here rather than
# trusted to callers.
FINDING_COUNT_TOKEN_PATTERN = re.compile(
    r"(?:critical|important)[ \t]+issues?[ \t]*\(\d+\)", re.IGNORECASE
)


def strip_finding_count_headings(body):
    return FINDING_COUNT_TOKEN_PATTERN.sub(" ", str(body or ""))


def blocking_verdict_for_body(
    body,
    head_sha,
    deferred_finding_ids,
    eligible_for_deferral=False,
    ambiguous_severities=None,
):
    """Resolve whether a body's raw Critical/Important counts still block once
    trusted deferrals are applied.

    Returns (has_blocking_count, effective_body, deferral_applied).

    `effective_body` is only ever `body` itself (no deferrals applied, or
    coverage could not be verified) or `body` with just the count tokens blanked
    (full coverage confirmed) -- never anything a deferral could use to alter
    unrelated prose.

    `eligible_for_deferral` defaults False so an unattested caller cannot reach
    the deferral path by omission. It is the caller's attestation that this body
    genuinely reviewed `head_sha`: a review is SELECTED for a head on GitHub's
    mutable `commit_id` (Update branch can rewrite it after the fact), and
    clearing a body's findings on the strength of a live-head deferral when that
    body never reviewed that tree would let a deferral neutralize a stale,
    unrelated finding.
    """
    critical_count = extract_issue_count(body, "Critical Issues")
    important_count = extract_issue_count(body, "Important Issues")
    raw_blocking = (critical_count is not None and critical_count > 0) or (
        important_count is not None and important_count > 0
    )
    if not eligible_for_deferral or not raw_blocking or not deferred_finding_ids:
        return raw_blocking, body, False

    critical = findings_for_section(body, "Critical", critical_count, ambiguous_severities)
    important = findings_for_section(body, "Important", important_count, ambiguous_severities)
    if critical is None or important is None:
        return raw_blocking, body, False

    has_undeferred = any(
        finding["content_id"] is None or finding["content_id"] not in deferred_finding_ids
        for finding in list(critical) + list(important)
    )
    if has_undeferred:
        return True, body, False
    # Load-bearing: this body's raw counts WERE blocking and are not any more,
    # solely because trusted deferrals covered every finding.
    return False, strip_finding_count_headings(body), True


def item_visible_at_ms(item):
    """When the CURRENT body of a GitHub item came into existence.

    Reads the edit time in preference to the creation time: every parse here
    reads the body as it is NOW, so an in-place edit is a new body and must be
    timed as one. Returns None when nothing parses -- the caller treats that as
    unverifiable, which is the fail-safe direction.

    Reviews are where this file is ahead of the reference lineage. REST exposes
    only the immutable `submitted_at` for a review body, so the reference
    documents a KNOWN RESIDUAL: a review edited in place keeps its original
    anchor and an existing deferral still covers the rewritten finding. This
    file already fetches GraphQL `lastEditedAt` (enrich_reviews_with_edit_times)
    for signal ordering, so the same field closes the residual here.
    """
    candidates = [
        item.get("last_edited_at") if isinstance(item, dict) else None,
        item.get("updated_at") if isinstance(item, dict) else None,
        item.get("submitted_at") if isinstance(item, dict) else None,
        item.get("created_at") if isinstance(item, dict) else None,
    ]
    latest = None
    for raw in candidates:
        parsed = _parse_iso8601_ms(raw)
        if parsed is not None and (latest is None or parsed > latest):
            latest = parsed
    return latest


def _parse_iso8601_ms(raw):
    """Parse a GitHub ISO-8601 timestamp to epoch milliseconds, or None.

    Not a string comparison. review_signal_time/comment_signal_time compare
    these as plain strings, which is sound for ORDERING two values GitHub
    produced in the same format -- but the deferral visibility anchor is a
    security comparison between an Ally artifact's timestamp and a deferral
    comment's, and a `+00:00` spelling on one side would sort wrongly against a
    `Z` on the other. Parsing removes that dependency on format agreement.

    A timestamp with no offset is read as UTC rather than local: a naive
    `.timestamp()` would silently apply the runner's TZ to one side of the
    comparison. Unparseable returns None, which every caller treats as
    unverifiable -- the fail-safe direction.
    """
    text = str(raw or "").strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp() * 1000.0


def ally_finding_artifacts(reviews, comments, ally_logins):
    """Every Ally artifact that enumerates findings, at the head its OWN
    standalone attestation claims.

    Not filtered to the live head: a deferral legitimately anchors to the head
    where the finding was first raised and keeps covering it across every later
    head Ally carries it forward to.
    """
    artifacts = []
    for review in reviews or []:
        user = review.get("user") or {}
        login = user.get("login")
        body = str(review.get("body") or "")
        attested = parse_reviewed_head(body)
        if (
            isinstance(login, str)
            and login_matches_any(login, ally_logins)
            # An APPROVED artifact can still carry blocking findings; the
            # review signal path fails closed on those findings before it
            # considers the approval state. It must therefore mint the same
            # visibility anchor as a COMMENTED artifact.
            and review.get("state") in ("COMMENTED", "APPROVED")
            and attested is not None
        ):
            artifacts.append((body, attested, item_visible_at_ms(review)))
    for comment in comments or []:
        user = comment.get("user") or {}
        login = user.get("login")
        body = str(comment.get("body") or "")
        attested = parse_reviewed_head(body)
        if (
            isinstance(login, str)
            and login_matches_any(login, ally_logins)
            and attested is not None
            and (
                is_consolidated_ally_comment_for_head(body, attested)
                or is_issue_link_ally_comment_for_head(body, attested)
            )
        ):
            artifacts.append((body, attested, item_visible_at_ms(comment)))
    return artifacts


def finding_id_visibility(reviews, comments, ally_logins):
    """The earliest moment each content id was actually visible in an Ally artifact.

    This is the anti-PRE-CLEARING control, and it is what stops "authorization
    to defer" becoming "authorization to defer something that does not exist
    yet". Without it, a trusted login could post `review-gate-defer:` lines for
    content ids BEFORE Ally reviewed a head and pre-clear whatever Ally then
    found -- a blanket escape for future findings, which this feature's own
    acceptance criteria forbid, and one strictly weaker than the blanket
    override it exists to replace.

    Content ids make pre-clearing much harder than positional ones did (you
    would have to predict Ally's exact wording, not just a severity and an
    ordinal), but "harder" is not "impossible": a boilerplate finding whose text
    Ally reliably repeats is guessable. The anchor closes it outright.

    Requiring visibility BEFORE the deferral was written also closes in-place
    rewrites: if Ally edits its artifact so the finding now says something else,
    the content id changes and no anchor covers the new text, so it re-reds
    until deferred again against what it now says.

    Ambiguity is resolved PER ATTESTED HEAD, not against the live head: an
    artifact whose severity this gate has ruled unresolvable must not mint an
    anchor, or a report the gate itself refuses to trust becomes the thing
    authorizing a deferral.
    """
    visibility = {}
    artifacts = ally_finding_artifacts(reviews, comments, ally_logins)
    bodies_by_head = {}
    for body, head, _visible in artifacts:
        bodies_by_head.setdefault(head, []).append(body)
    ambiguous_by_head = {
        head: ambiguous_finding_severities(bodies) for head, bodies in bodies_by_head.items()
    }
    for body, head, visible_at in artifacts:
        if visible_at is None:
            continue
        for label in ("Critical", "Important"):
            findings = findings_for_section(
                body,
                label,
                extract_issue_count(body, "%s Issues" % label),
                ambiguous_by_head.get(head),
            )
            if findings is None:
                continue
            for finding in findings:
                content_id = finding["content_id"]
                if content_id is None:
                    continue
                earlier = visibility.get(content_id)
                if earlier is None or visible_at < earlier:
                    visibility[content_id] = visible_at
    return visibility


def deferral_comment_is_unedited(comment):
    """A deferral-bearing comment must be UNEDITED.

    A deferral line only authorizes anything if the login the API reports as the
    comment's author is the principal who actually wrote that line. For an
    EDITED comment it is not: GitHub's `write` role can edit anyone else's
    comments, and the REST comment object exposes only `user` (the ORIGINAL
    author) -- edit provenance lives solely in GraphQL `userContentEdits`. So a
    PR author holding write could append a `review-gate-defer:` line to an
    innocent maintainer's existing comment and the gate would attribute the
    ruling to them, walking straight around the self-deferral prohibition in
    trusted_deferrals, which is the single most important control here.

    Note the interaction that made this reachable: item_visible_at_ms
    deliberately reads the EDIT time, which is correct for freshness and is what
    makes such a forged line clear the visibility anchor (the edit timestamp
    always postdates Ally's artifact). The timestamp survives the edit; the
    authorship does not. Fixing one without the other is what opened the hole.

    The legitimate flow -- read the token the gate prints, post a NEW comment --
    has created_at == updated_at and is unaffected. An unparseable or absent
    timestamp on either side is REJECTED: "I could not read the edit timestamp"
    is precisely the state in which this must not vouch for a comment.
    """
    created = _parse_iso8601_ms((comment or {}).get("created_at"))
    updated = _parse_iso8601_ms((comment or {}).get("updated_at"))
    if created is None or updated is None:
        return False
    return updated <= created


def deferral_records_from_comments(comments):
    """Every well-formed `review-gate-defer:` line, UNFILTERED by trust."""
    records = []
    for comment in comments or []:
        body = str((comment or {}).get("body") or "")
        author = ((comment or {}).get("user") or {}).get("login")
        if not deferral_comment_is_unedited(comment):
            continue
        posted_at = item_visible_at_ms(comment)
        for match in DEFERRAL_LINE_PATTERN.finditer(body):
            finding_id = canonical_deferral_token(match.group(1))
            if finding_id is None:
                continue
            issue_ref = match.group(2)
            # Symmetric to the token check above, and LOUD where that one is
            # silent: a malformed finding id is almost always a copy-paste of
            # the wrong thing, but a malformed issue ref is a maintainer who
            # wrote a real ruling. Dropping that silently is what pushes them
            # to the blanket override this per-finding lever exists to avoid.
            if not ISSUE_REF_STRICT_PATTERN.match(issue_ref):
                print(
                    "review-gate-defer: REFUSED %s from %s -- issue:%s is not a "
                    "reference this gate will stand a green status on. Expected "
                    "%s (e.g. BLO-18949) -- UPPERCASE prefix, case-sensitive. "
                    "The finding stays outstanding."
                    % (finding_id, author or "(unknown author)", issue_ref, ISSUE_REF_STRICT_SHAPE)
                )
                continue
            records.append(
                {
                    "author": author,
                    "finding_id": finding_id,
                    "issue_ref": issue_ref,
                    "posted_at": posted_at,
                }
            )
    return records


def ally_login_variants(login):
    """Every REST spelling of one GitHub identity.

    A raw string compare is not sufficient anywhere trust is being WITHHELD: the
    App installation comments as `allyblockcast[bot]` (rendered
    `app/allyblockcast` in some payloads) while a configured entry may be the
    bare `allyblockcast`. Those are the same principal, and a bare compare says
    they are not -- which would let the App seat, the most privileged identity
    in this gate's threat model and the one that RAISED the findings, author its
    own deferrals.
    """
    canonical = str(login or "").strip().lower()
    without_bot = canonical[: -len("[bot]")] if canonical.endswith("[bot]") else canonical
    without_app = canonical[len("app/"):] if canonical.startswith("app/") else canonical
    return {
        canonical,
        without_bot,
        "%s[bot]" % without_bot,
        without_app,
        "app/%s" % without_app,
    }


def login_matches_any(login, logins):
    """True when `login` names the same identity as any entry in `logins`,
    comparing across the spelling variants of BOTH sides."""
    if not isinstance(login, str) or login == "":
        return False
    variants = ally_login_variants(login)
    for candidate in logins or []:
        if not isinstance(candidate, str):
            continue
        if ally_login_variants(candidate) & variants:
            return True
    return False


def trusted_deferrals(
    comments,
    ally_logins,
    collaborator_permissions,
    finding_visibility,
    pr_author_login=None,
    author_only_logins=DEFAULT_AUTHOR_ONLY_LOGINS,
):
    """Trust-filter the raw deferral records.

    Returns {content_id: issue_ref} -- a MAP, not a set. Callers that only gate
    on membership use it as one; the values exist so that a `success` written on
    the strength of a deferral can NAME the issue the risk was booked to.
    Keeping the ref out of this structure is what would force the status to
    choose between lying ("clean") and stalling ("pending") -- the audit trail
    would have nowhere to live but the job log.

    Four independent conditions, each of which drops the record:

      1. NO ALLY SEAT may author a deferral, across spelling variants. Checked
         BEFORE the permission tier so an Ally seat is refused for BEING an Ally
         seat -- the exclusion must not silently become a no-op if that seat is
         ever granted admin.
      2. THE PR'S OWN AUTHOR may never defer findings raised against their own
         PR, however much repo permission they hold. Deferral is the only lever
         in this gate that moves a red status toward green, so it is the one
         that most needs the separation of duties every other path here already
         enforces. Holding `admin` makes someone the accountable owner of the
         repo; it does not make them independent of their own change.
      3. `admin` collaborator permission -- one tier ABOVE the write/maintain/
         write that every other trust decision in this file accepts
         (TRUSTED_COLLABORATOR_PERMISSIONS). Deferral is the only lever that
         converts an outstanding finding into a green required status, so it
         carries the higher bar. Refusal is LOUD: a silently-dropped deferral is
         what pushes a maintainer to the blanket override, which is strictly
         worse than the per-finding lever they were reaching for.
      4. The named finding must have been VISIBLE in an Ally artifact before the
         deferral's current body was written (see finding_id_visibility). The
         comparison is `<=` rather than `<` because GitHub timestamps are
         second-granularity, so a deferral posted in the same second as the
         artifact is far more likely to be a prompt response than an attacker
         who guessed the exact second Ally would publish.

    Everything except the tier refusal drops silently: the finding it named
    simply stays undeferred, which is the fail-safe direction.
    """
    ids = {}
    for record in deferral_records_from_comments(comments):
        author = record["author"]
        if not isinstance(author, str) or author.strip() == "":
            continue
        if login_matches_any(author, ally_logins):
            continue
        # An author credential defers nothing, for the same reason no Ally
        # seat may: named separately so the refusal does not depend on the
        # credential happening to be a spelling of a configured Ally login.
        if login_matches_any(author, author_only_logins):
            continue
        if pr_author_login is not None and login_matches_any(author, [pr_author_login]):
            continue
        held = (collaborator_permissions or {}).get(author)
        if held is None:
            held = (collaborator_permissions or {}).get(author.strip().lower())
        if held not in DEFERRAL_TRUSTED_PERMISSIONS:
            print(
                "review-gate-defer: REFUSED %s from %s -- deferral requires %s "
                "collaborator permission, holds %s. The finding stays outstanding."
                % (
                    record["finding_id"],
                    author,
                    "/".join(sorted(DEFERRAL_TRUSTED_PERMISSIONS)),
                    held or "(not a collaborator)",
                )
            )
            continue
        visible_at = (finding_visibility or {}).get(record["finding_id"])
        if record["posted_at"] is None or visible_at is None or visible_at > record["posted_at"]:
            continue
        # First writer wins: if two trusted admins defer the same finding to
        # different issues, the status names the earlier ruling rather than
        # silently re-pointing the audit trail at whichever comment sorted last.
        if record["finding_id"] not in ids:
            ids[record["finding_id"]] = record["issue_ref"]
    return ids


def deferral_candidate_logins(comments):
    """Logins that authored a shape-valid deferral line, so main() knows whose
    collaborator permission to resolve. Shape only -- nothing here grants trust.
    """
    logins = set()
    for comment in comments or []:
        body = str((comment or {}).get("body") or "")
        if not DEFERRAL_LINE_PATTERN.search(body):
            continue
        login = ((comment or {}).get("user") or {}).get("login")
        if isinstance(login, str) and login.strip():
            logins.add(login)
    return logins


def qualifying_ally_bodies_for_head(reviews, comments, head_sha, ally_logins):
    """Ally bodies whose own attestation names THIS head."""
    normalized = str(head_sha or "").lower()
    bodies = []
    for review in reviews or []:
        user = review.get("user") or {}
        login = user.get("login")
        body = str(review.get("body") or "")
        if (
            isinstance(login, str)
            and login_matches_any(login, ally_logins)
            # Keep this in lockstep with ally_finding_artifacts(): a finding
            # on an APPROVED review is still blocking evidence and may be the
            # finding a load-bearing deferral needs to name in its audit trail.
            and review.get("state") in ("COMMENTED", "APPROVED")
            and parse_reviewed_head(body) == normalized
        ):
            bodies.append(body)
    for comment in comments or []:
        user = comment.get("user") or {}
        login = user.get("login")
        body = str(comment.get("body") or "")
        if (
            isinstance(login, str)
            and login_matches_any(login, ally_logins)
            and parse_reviewed_head(body) == normalized
            and (
                is_consolidated_ally_comment_for_head(body, head_sha)
                or is_issue_link_ally_comment_for_head(body, head_sha)
            )
        ):
            bodies.append(body)
    return bodies


def outstanding_finding_hints(
    reviews, comments, head_sha, ally_logins, deferred_finding_ids, ambiguous_severities=None
):
    """The copy-paste line a maintainer needs in order to defer each finding
    still blocking this head.

    The gate computes the content digest and prints it precisely so that nobody
    ever hand-computes one. A hand-computed digest would mean maintainers
    normalizing bullet text by eye, which is both error-prone and an invitation
    to "just tweak it until the gate goes green" -- the opposite of an auditable
    record. Findings already covered by a trusted deferral are omitted, so what
    is printed is exactly the outstanding set.
    """
    hints = []
    seen = set()
    for body in qualifying_ally_bodies_for_head(reviews, comments, head_sha, ally_logins):
        for label in ("Critical", "Important"):
            findings = findings_for_section(
                body,
                label,
                extract_issue_count(body, "%s Issues" % label),
                ambiguous_severities,
            )
            if findings is None:
                continue
            for finding in findings:
                content_id = finding["content_id"]
                if content_id is None or content_id in seen:
                    continue
                if deferred_finding_ids and content_id in deferred_finding_ids:
                    continue
                seen.add(content_id)
                hints.append(
                    {"content_id": content_id, "label": label, "ordinal": finding["ordinal"]}
                )
    return hints


def load_bearing_deferrals(
    reviews, comments, head_sha, ally_logins, deferrals, ambiguous_severities=None
):
    """The rulings a `success` write would be standing on: the deferrals actually
    suppressing a blocking finding at this head, with the issue each was booked to.

    Computed as a COUNTERFACTUAL -- re-run the outstanding-finding scan with an
    empty deferral map -- rather than threaded through the signal paths. The
    blocking verdict has many paths (formal review, comment, self-review
    demotion, explicit markers), and threading "which deferral suppressed which
    finding" through each of them is precisely the bookkeeping the reference
    lineage got wrong four times. With no deferrals in play the scan returns
    every blocking finding at this head; the ones ALSO in the deferral map are
    exactly the load-bearing set, and nothing had to know which path applied them.

    Order is the scan's own (Critical before Important, ordinal ascending), so
    the description is stable run to run instead of reordering with comment
    pagination.
    """
    issue_refs = []
    finding_count = 0
    if not deferrals:
        return finding_count, issue_refs
    for hint in outstanding_finding_hints(
        reviews, comments, head_sha, ally_logins, {}, ambiguous_severities
    ):
        issue_ref = deferrals.get(hint["content_id"])
        if issue_ref is None:
            continue
        finding_count += 1
        if issue_ref not in issue_refs:
            issue_refs.append(issue_ref)
    return finding_count, issue_refs


def _deferral_overflow_tail(hidden_issue_count):
    """The overflow count is over ISSUES, while the headline counts FINDINGS.

    Different axes whenever several findings are deferred to one issue: 12
    findings across 3 issues would otherwise render `12 deferred Ally findings
    ... BLO-1, BLO-2, +1 more`, and `+1` reads as a thirteenth finding. Naming
    the unit is the whole fix. Shared by the budget loop and the final render
    deliberately -- they have to agree to the character or the loop budgets
    against a tail the render does not emit, and the elision stops being honest.
    """
    if hidden_issue_count <= 0:
        return ""
    return ", +%d more %s" % (
        hidden_issue_count,
        "issue" if hidden_issue_count == 1 else "issues",
    )


def deferral_success_description(head_sha, finding_count, issue_refs):
    """A `success` written on the strength of a deferral must SAY so and must
    NAME the issues.

    The wording deliberately contains neither "clean" nor "approved": the 08-15
    bypass in the reference lineage wrote `success` with the text "Ally approved
    head 35c24be" over a live finding, and the danger there was never the state
    on its own -- it was a state paired with an attestation nobody had made.

    Budgeted to GitHub's 140-character limit BY CONSTRUCTION rather than leaning
    on clamp_description, because blind truncation would drop an issue
    reference, the one thing this description exists to carry. When the list
    genuinely does not fit, the overflow is COUNTED, so a reader can always tell
    how many rulings are in play even when it cannot name them all.

    Returns None when not one ruling can be named inside the budget. That is a
    REFUSAL, not a formatting detail: the caller turns it into `pending`,
    because on this path the description IS the audit trail, so a description
    naming nothing would be a green status attesting to a ruling it cannot
    identify.
    """
    noun = "finding" if finding_count == 1 else "findings"
    prefix = "%d deferred Ally %s on %s, not fixed: " % (
        finding_count,
        noun,
        short_sha(head_sha),
    )
    shown = []
    for issue_ref in issue_refs:
        tail = _deferral_overflow_tail(len(issue_refs) - len(shown) - 1)
        if len("%s%s%s" % (prefix, ", ".join(shown + [issue_ref]), tail)) > STATUS_DESCRIPTION_LIMIT:
            break
        shown.append(issue_ref)
    if not shown:
        return None
    return "%s%s%s" % (
        prefix,
        ", ".join(shown),
        _deferral_overflow_tail(len(issue_refs) - len(shown)),
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


def review_signals_for_head(
    reviews,
    head_sha,
    ally_logins,
    is_self_review,
    deferred_finding_ids=None,
    ambiguous_severities=None,
):
    signals = []

    for review in reviews:
        user = review.get("user") or {}
        login = user.get("login")
        if not isinstance(login, str) or not login_matches_any(login, ally_logins):
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
        # or blocking count would be fail-open. That is ALL the User seat
        # still does: since BLO-18965 it is an author credential, never a
        # distinct reviewer (see is_distinct_reviewer). On a self-review the
        # demotion below applies to the seat too, so there only its
        # machine-readable blocking findings bind, not a bare formal state.
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
        # A finding fully covered by a trusted `review-gate-defer` record is not
        # "blocking" here -- see blocking_verdict_for_body. ONLY the
        # count-derived blocking is neutralized:
        #
        #   * `verdict == "changes-requested"` is read from the UNMODIFIED body
        #     and is untouched. A deferral names FINDINGS, not Ally's overall
        #     verdict, so an explicit `Ally-Verdict: changes-requested` (or a
        #     `Recommended Action: request changes`) stays unconditionally
        #     blocking no matter how many findings are covered.
        #   * the prose scan runs against `effective_body`, which is `body`
        #     itself unless coverage was COMPLETE, in which case it is `body`
        #     with only the `{severity} Issues (N)` count tokens blanked. That
        #     strip exists because ACTION_REQUIRED_COMMENT_PATTERN carries those
        #     same count tokens as its own alternatives -- without it the
        #     count-derived blocking would survive the deferral through a
        #     redundant path. Every prose alternative (`changes requested`,
        #     `request changes`, `action required`) is left intact, so a genuine
        #     blocking phrase still fails closed on a fully-deferred body.
        #
        # Eligibility is the body's OWN `Reviewed head:` attestation, not the
        # `commit_id` this review was selected on: commit_id is GitHub-managed
        # and Update branch can rewrite it after the fact, so clearing findings
        # on the strength of a live-head deferral when the body never reviewed
        # that tree would let a deferral neutralize a stale, unrelated finding.
        eligible_for_deferral = parse_reviewed_head(body) == str(head_sha or "").lower()
        blocking_count, effective_body, _deferred = blocking_verdict_for_body(
            body,
            head_sha,
            deferred_finding_ids,
            eligible_for_deferral=eligible_for_deferral,
            ambiguous_severities=ambiguous_severities,
        )
        if (
            blocking_count
            or verdict == "changes-requested"
            or has_action_required_language(effective_body)
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
            # Evaluated against `effective_body` for the same reason the
            # prose scan above is: when deferral coverage is complete the only
            # remaining affirmative match may be the `{severity} Issues (N)`
            # count token, which this gate has already positively accounted
            # for. Monotone-safe -- masked_blocking_ambiguity can only fire on
            # an affirmative that SURVIVES the strict mask, and removing text
            # can never create one, so passing the stripped body can turn this
            # True->False but never False->True.
            if masked_blocking_ambiguity(effective_body):
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
            # Evaluated against `effective_body` for the same reason the
            # prose scan above is: when deferral coverage is complete the only
            # remaining affirmative match may be the `{severity} Issues (N)`
            # count token, which this gate has already positively accounted
            # for. Monotone-safe -- masked_blocking_ambiguity can only fire on
            # an affirmative that SURVIVES the strict mask, and removing text
            # can never create one, so passing the stripped body can turn this
            # True->False but never False->True.
            if masked_blocking_ambiguity(effective_body):
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
            #
            # DELIBERATELY READS THE RAW BODY, NOT `effective_body`. A fully
            # deferred finding set means "we read this and accepted the risk",
            # which is NOT the machine-readable all-clear this branch requires --
            # Ally still reported findings. Pointing this at the count-stripped
            # body would synthesise `Critical Issues (0) / Important Issues (0)`
            # that Ally never wrote, i.e. manufacture an authorization out of a
            # ruling, which is precisely the failure shape of the 08-15 bypass in
            # the reference lineage: a state paired with an attestation nobody
            # made. The deferral's job is to remove the FAILURE, never to
            # fabricate the PASS. A deferred body with no explicit pass verdict
            # therefore emits no positive signal at all and the gate holds at
            # pending -- see the test named for this invariant.
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


def is_self_review_author(pr_author_login, ally_logins, author_only_logins):
    """A PR authored by an Ally identity OR an author credential is a
    self-review. The author credential is the same actor as Ally, so its PRs
    must demand a distinct reviewer rather than being treated as third-party
    work needing only an Ally verdict."""
    return login_matches_any(pr_author_login, ally_logins) or login_matches_any(
        pr_author_login, author_only_logins
    )


def is_distinct_reviewer(user, ally_logins, pr_author_login, author_only_logins):
    """Whether a review's author is a genuinely separate actor from the PR
    author. Shared by the candidate and signal passes so the permission lookup
    and the verdict can never disagree about who qualifies.

    An author-only login is excluded FIRST and unconditionally. That ordering
    is the point: clause (a) below admits a login merely for being absent from
    the Ally set, so without this guard, demoting a seat out of that set would
    widen its trust rather than remove it (BLO-18926/BLO-18965).

    What remains qualifies in two cases:
      (a) a login outside the Ally set -- an ordinary trusted human; or
      (b) a real GitHub *User* seat inside the Ally set that is not an author
          credential. Bot/App Ally identities stay excluded (case (b) requires
          type == "User"), so the App can never self-clear the gate.
    Both Ally tests compare across spelling variants: the App's normalized
    bare login must not read as "outside the Ally set" and so qualify via (a).
    """
    login = (user or {}).get("login")
    return (
        isinstance(login, str)
        and not login_matches_any(login, author_only_logins)
        and login != pr_author_login
        and (not login_matches_any(login, ally_logins) or (user or {}).get("type") == "User")
    )


def distinct_reviewer_candidate_logins(
    reviews, head_sha, ally_logins, pr_author_login, author_only_logins=DEFAULT_AUTHOR_ONLY_LOGINS
):
    """Structural-only pass (no trust check): every login that would qualify as
    a distinct reviewer for this head if it turns out to be trusted. Scopes the
    collaborator-permission lookups to the logins that matter.
    """
    logins = set()
    for review in reviews:
        user = review.get("user") or {}
        login = user.get("login")
        is_distinct = is_distinct_reviewer(user, ally_logins, pr_author_login, author_only_logins)
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
    head_authorized_logins=None,
    author_only_logins=DEFAULT_AUTHOR_ONLY_LOGINS,
):
    head_authorized_logins = head_authorized_logins or set()
    signals = []

    for review in reviews:
        user = review.get("user") or {}
        login = user.get("login")

        # See is_distinct_reviewer: an author credential is never distinct,
        # so it can neither approve nor request changes on this path.
        is_distinct = is_distinct_reviewer(user, ally_logins, pr_author_login, author_only_logins)
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


def comment_signals_for_head(
    comments,
    head_sha,
    ally_logins,
    is_self_review,
    deferred_finding_ids=None,
    ambiguous_severities=None,
):
    short_head = short_sha(head_sha)
    signals = []

    for comment in comments:
        user = comment.get("user") or {}
        login = user.get("login")
        body = str(comment.get("body") or "")
        if not isinstance(login, str) or not login_matches_any(login, ally_logins):
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
        # findings must still fail closed and remain impossible to override. A
        # finding fully covered by a trusted `review-gate-defer` record is not
        # blocking here -- see blocking_verdict_for_body, and the review path's
        # note on why ONLY the count-derived blocking is neutralized.
        #
        # Eligibility: a consolidated comment is already selected by
        # is_consolidated_ally_comment_for_head, which requires attests_head, so
        # this is redundant-but-explicit there. It is load-bearing for the
        # issue-link shape, which is selected on contains_head_sha (a substring
        # scan) and carries no attestation line at all -- so an issue-link
        # comment can never reach the deferral path.
        eligible_for_deferral = parse_reviewed_head(body) == str(head_sha or "").lower()
        blocking_count, effective_body, _deferred = blocking_verdict_for_body(
            body,
            head_sha,
            deferred_finding_ids,
            eligible_for_deferral=eligible_for_deferral,
            ambiguous_severities=ambiguous_severities,
        )
        if blocking_count:
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
        if verdict == "changes-requested" or has_action_required_language(effective_body):
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


def override_attestation_logins(comments, head_sha, author_only_logins=DEFAULT_AUTHOR_ONLY_LOGINS):
    """Logins that authorized an override of THIS exact head.

    The label alone is PR-scoped and survives `synchronize`, so on its own it
    turns every future unreviewed head green -- which defeats the gate on
    precisely the push-then-review cycle it exists to protect. Pair it with a
    comment naming the full head SHA so the authorization dies with the commit
    it was granted for. Full SHA only, for the same reason attestations require
    one: a 7-char prefix is 28 bits and grindable.

    The comment must also be UNEDITED (same rule as deferral_comment_is_unedited):
    REST reports only the ORIGINAL author, so an edited comment cannot bind the
    override to the login it names. An override line found on an edited comment
    is dropped LOUDLY, naming the comment and the remedy, because the override is
    the last head-scoped lever before the blanket label and a silent drop would
    push a stuck maintainer straight to that label.
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
        # An author credential cannot authorize an override any more than it
        # can review.
        if not isinstance(login, str) or login_matches_any(login, author_only_logins):
            continue
        if not pattern.search(str(comment.get("body") or "")):
            continue
        # Same threat model as deferral_comment_is_unedited: GitHub's `write`
        # role can edit anyone else's comment and the REST object exposes only
        # the ORIGINAL author, so an edited comment cannot bind this override
        # (and, through head_authorized_logins, someone's drifting approval)
        # to the login it reports. Say so, in the same shape as the deferral
        # path's IGNORED line: the most likely reason anyone edits an override
        # comment is fixing a typo in the 40-hex SHA, and a silent drop would
        # be indistinguishable from "no override was ever posted".
        if not deferral_comment_is_unedited(comment):
            print(
                "review-gate-override: IGNORED an override line on comment %s by %s "
                "-- the comment was edited after posting (created %s, updated %s), "
                "and REST cannot attribute an edited line to its writer. Post a "
                "NEW comment instead."
                % (
                    comment.get("id", "unknown"),
                    login,
                    comment.get("created_at", "unknown"),
                    comment.get("updated_at", "unknown"),
                )
            )
            continue
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
    deferrals=None,
    author_only_logins=DEFAULT_AUTHOR_ONLY_LOGINS,
):
    """Pure decision core: returns (state, description).

    Split out from main() so the whole policy is testable without network.

    `deferrals` is {content_id: issue_ref}, already trust-filtered by
    trusted_deferrals(). Defaulting it to empty keeps every pre-deferral caller
    (and every existing test) on exactly the previous behaviour: with no
    deferrals in play blocking_verdict_for_body short-circuits to the raw count
    and the counterfactual below is skipped entirely.
    """
    permission_trusted_logins = permission_trusted_logins or set()
    deferrals = deferrals or {}
    is_self_review = is_self_review_author(pr_author_login, ally_logins, author_only_logins)

    # Severity-level ambiguity is resolved once, for the LIVE head, from the
    # Ally bodies that attest to it -- two same-head reports that disagree about
    # what the findings are make that severity unenumerable, so deferral
    # coverage cannot be claimed for it and it falls back to raw-count blocking.
    ambiguous_severities = (
        ambiguous_finding_severities(
            qualifying_ally_bodies_for_head(reviews, comments, head_sha, ally_logins)
        )
        if deferrals
        else None
    )

    def signals_with(deferred_ids):
        return review_signals_for_head(
            reviews,
            head_sha,
            ally_logins,
            is_self_review,
            deferred_finding_ids=deferred_ids,
            ambiguous_severities=ambiguous_severities,
        ) + comment_signals_for_head(
            comments,
            head_sha,
            ally_logins,
            is_self_review,
            deferred_finding_ids=deferred_ids,
            ambiguous_severities=ambiguous_severities,
        )

    ally_signals = signals_with(deferrals)

    distinct_signals = (
        distinct_reviewer_signals_for_head(
            reviews,
            head_sha,
            ally_logins,
            pr_author_login,
            permission_trusted_logins,
            head_authorized_logins=override_attestation_logins(
                comments, head_sha, author_only_logins
            ),
            author_only_logins=author_only_logins,
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
    #
    # Factored into a function of the signal list so the deferral
    # counterfactual below can re-run the IDENTICAL selection over the
    # undeferred signals. `distinct_signals` is deliberately outside it: the
    # distinct-reviewer path reads no Ally finding counts, so deferrals cannot
    # change it and it must not be recomputed per branch.
    def choose(signals):
        current = current_signals_per_login(signals)
        blocking = [s for s in current if s["status"] == "failure"]
        successes = [s for s in current if s["status"] == "success"]
        if blocking:
            chosen = latest_signal(blocking)
        elif successes:
            chosen = latest_signal(successes)
        else:
            chosen = latest_signal(current)

        # Distinct-reviewer evidence contributes success as well as blocking
        # signals here (BLO-25488, fixing the round-3 regression where success
        # was dropped and no identity -- not even a trusted human -- could ever
        # green a self-review PR). This context's positive authority is now
        # EITHER Ally's own App-seat APPROVED (handled above via successes)
        # OR a distinct, permission-trusted, NON-ALLY login's exact-head-attested
        # APPROVED. The shared `allyblockcast` User seat is an author
        # credential (BLO-24056 found it supplying 661 App-authored approvals
        # org-wide; BLO-18965 split it out of the Ally set), so
        # is_distinct_reviewer never admits it and it is filtered again here:
        # it must never be the identity that turns this green, whichever list
        # an operator happens to name it in. Adopting `reduced`
        # unconditionally on failure (as before) keeps a trusted distinct
        # reviewer's CHANGES_REQUESTED fail-closed regardless of identity;
        # adopting success only requires a SEPARATE reduction
        # restricted to non-Ally authors, so a chronologically-later Ally-seat
        # success cannot shadow an earlier, still-current non-Ally approval. A
        # reviewer's later approval still withdraws THEIR OWN earlier change
        # request inside the per-reviewer reduction. Ally's own OUTSTANDING
        # blocking findings outrank everything.
        if is_self_review and distinct_signals and not blocking:
            reduced = reduce_distinct_reviewer_signals(distinct_signals)
            if reduced is not None and reduced["status"] == "failure":
                chosen = reduced
            elif reduced is not None and reduced["status"] == "success":
                non_ally_signals = [
                    s
                    for s in distinct_signals
                    if not login_matches_any(s["author"], ally_logins)
                    and not login_matches_any(s["author"], author_only_logins)
                ]
                reduced_non_ally = reduce_distinct_reviewer_signals(non_ally_signals)
                if reduced_non_ally is not None and reduced_non_ally["status"] == "success":
                    chosen = reduced_non_ally
        return chosen

    signal = choose(ally_signals)

    # Was a deferral LOAD-BEARING -- i.e. would this head have been blocking
    # without it? Computed as a counterfactual re-run rather than threaded
    # through the signal paths, for the reason load_bearing_deferrals documents:
    # the blocking verdict has many paths and threading "which deferral
    # suppressed which finding" through each of them is exactly the bookkeeping
    # that went wrong repeatedly in the reference lineage.
    deferral_applied = False
    if deferrals:
        undeferred = choose(signals_with({}))
        deferral_applied = (
            undeferred is not None
            and undeferred["status"] == "failure"
            and (signal is None or signal["status"] != "failure")
        )

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
        # "no blocking findings" is a claim about the HEAD, and it is false when
        # the only reason nothing is blocking is that a finding was deferred.
        # This branch returns BEFORE the deferral capping below (which only
        # fires on `success`), so without this the ordinary comment-channel
        # deferral outcome would post "no blocking findings" with a real
        # outstanding finding on the head. It stays `pending` for a reason that
        # has nothing to do with the deferral -- a comment-shaped review is not
        # an approval, so an exact-head App-seat APPROVED is still missing --
        # but the description must not call a deferred head clean while it waits.
        if deferral_applied:
            return (
                "pending",
                "Ally findings on %s are deferred to their owning issues; "
                "awaiting an App-seat APPROVED review." % short_sha(head_sha),
            )
        return (
            "pending",
            "Ally reviewed head %s, no blocking findings; awaiting an "
            "App-seat APPROVED review." % short_sha(head_sha),
        )

    # A deferral may ATTEST TO A RULING, but it may never attest to the CODE.
    # Reaching `success` here says "Ally's review of this head has been brought
    # to a terminating state", NOT "this head is clean" -- and the description
    # says which, naming every issue the residual risk was booked to.
    #
    # Why `success` rather than a `pending` ceiling: on a REQUIRED status context
    # GitHub admits a merge only on `success`, so capping at `pending` blocks
    # exactly as hard as `failure`, just less legibly. A maintainer who books a
    # finding to an issue, watches red turn grey and still cannot merge reaches
    # for the blanket `review-gate-override` -- the coarse escape this
    # per-finding mechanism exists to make unnecessary. Capping would therefore
    # push traffic from the auditable lever to the blanket one, which is a worse
    # security outcome, not a safer one. It is also the canonical
    # never-terminating signal: `failure` at least tells a reader to act, while a
    # permanently-`pending` check tells every agent and monitor watching it to
    # keep waiting for a resolution that cannot come. BLO-22676 was filed about a
    # 7-cycle loop caused by a gate with no reachable terminal state; a stuck
    # `pending` is that same bug wearing a calmer colour.
    #
    # What made the 08-15 bypass in the reference lineage dangerous was never the
    # state on its own -- it was a state paired with an attestation nobody had
    # made. So the two are bound together here: if the owning issues cannot be
    # enumerated OR cannot be named inside GitHub's 140 characters, the audit
    # trail has nowhere to live and the status does NOT go green. `success` on
    # this path structurally implies a named issue.
    if deferral_applied and signal["status"] == "success":
        finding_count, issue_refs = load_bearing_deferrals(
            reviews, comments, head_sha, ally_logins, deferrals, ambiguous_severities
        )
        if not issue_refs:
            return (
                "pending",
                "Ally findings on %s are deferred but their owning issues "
                "could not be read; not green." % short_sha(head_sha),
            )
        described = deferral_success_description(head_sha, finding_count, issue_refs)
        if described is None:
            return (
                "pending",
                "Ally findings on %s are deferred but no owning issue fits "
                "this status; not green." % short_sha(head_sha),
            )
        return "success", described

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
    """Return the candidate logins whose repo permission is write/maintain/admin.

    The lookup is authoritative in both directions: a 404 "not a collaborator"
    is a real answer of "no permission", and a lookup that ERRORS leaves the
    login untrusted too. There is deliberately no author_association fallback --
    association is requester-view-dependent and COLLABORATOR can mean read or
    triage, so falling back on a transient API/auth/rate-limit failure would let
    an account without write access clear an Ally-authored PR. An unresolved
    lookup therefore leaves the gate pending, which is the safe direction.
    """
    trusted = set()
    for login in candidate_logins:
        try:
            permission = fetch_collaborator_permission(api_base_url, owner, repo, login, token)
            print("collaborator-permission: %s -> %s" % (login, permission or "(not a collaborator)"))
            if permission in TRUSTED_COLLABORATOR_PERMISSIONS:
                trusted.add(login)
        except Exception as error:  # noqa: BLE001 - non-fatal by design
            print(
                "collaborator-permission: lookup failed for %s; treating as untrusted: %s"
                % (login, error),
                file=sys.stderr,
            )
    return trusted


def fetch_collaborator_permission_map(api_base_url, owner, repo, token, candidate_logins):
    """Return {login: permission} for each candidate whose lookup COMPLETED.

    Distinct from fetch_trusted_permission_logins, which answers the boolean
    "is this login in TRUSTED_COLLABORATOR_PERMISSIONS". The deferral path needs
    the TIER itself because it accepts a narrower set
    (DEFERRAL_TRUSTED_PERMISSIONS = admin only) and refusing loudly means
    naming which tier the author actually holds.

    A login whose lookup ERRORED is absent from the map, which
    trusted_deferrals reads as "no permission" and refuses -- the same
    fail-closed rule as fetch_trusted_permission_logins. What is distinct here
    is only the shape: this returns the TIER, because deferral trust is
    admin-only and refusing loudly means naming the tier the author holds.
    This path can turn a red required status green, so an unresolved input
    must never become a permissive default.
    """
    permissions = {}
    for login in candidate_logins:
        try:
            permission = fetch_collaborator_permission(api_base_url, owner, repo, login, token)
        except Exception as error:  # noqa: BLE001 - non-fatal by design
            print(
                "deferral-permission: lookup failed for %s, treating as untrusted: %s"
                % (login, error),
                file=sys.stderr,
            )
            continue
        print(
            "deferral-permission: %s -> %s" % (login, permission or "(not a collaborator)")
        )
        if permission is not None:
            permissions[login] = permission
    return permissions


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
    # Author credentials, held out of every trust path. Configured separately
    # from ALLY_REVIEWER_LOGINS because removing a login from that list demotes
    # nothing -- it promotes the login to an ordinary distinct reviewer. Naming
    # it here is what strips its reviewer standing. parse_list's fallback keeps
    # an empty or `,` value from silently disabling the exclusion.
    author_only_logins = parse_list(
        os.environ.get("PR_AUTHOR_ONLY_LOGINS"), DEFAULT_AUTHOR_ONLY_LOGINS
    )
    pr_author_login = (pull_request.get("user") or {}).get("login")
    is_self_review = is_self_review_author(pr_author_login, ally_logins, author_only_logins)

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
    # Two independent reasons to resolve write permission: clearing a
    # self-authored PR via a distinct reviewer, and authorizing a head-bound
    # override. Resolve both candidate sets in one pass -- an override author
    # whose permission was never looked up is untrusted, so omitting them here
    # would make the escape hatch permanently inert.
    candidates = set()
    if is_self_review:
        candidates |= set(
            distinct_reviewer_candidate_logins(
                reviews, head_sha, ally_logins, pr_author_login, author_only_logins
            )
        )
        # Head-bound authorization comments can positively bind a distinct
        # approval even without the override label, so their authors need
        # permission resolution whenever the distinct-reviewer path is live.
        candidates |= override_attestation_logins(comments, head_sha, author_only_logins)
    if override_label and override_label in labels:
        candidates |= override_attestation_logins(comments, head_sha, author_only_logins)
    if candidates:
        permission_trusted_logins = fetch_trusted_permission_logins(
            api_base_url, owner, repo, token, sorted(candidates)
        )

    # --- Per-finding deferrals (BLO-22676 / BLO-27578) ---------------------
    #
    # Resolved separately from the sets above, and with a narrower trust tier:
    # a deferral is the only lever in this gate that converts an outstanding
    # finding into a green REQUIRED status, so it needs `admin` where the rest
    # of this file accepts write/maintain/admin, and it needs the tier itself
    # rather than a boolean so a refusal can name what the author holds.
    deferrals = {}
    deferral_candidates = deferral_candidate_logins(comments)
    if deferral_candidates:
        finding_visibility = finding_id_visibility(reviews, comments, ally_logins)
        deferrals = trusted_deferrals(
            comments,
            ally_logins=ally_logins,
            collaborator_permissions=fetch_collaborator_permission_map(
                api_base_url, owner, repo, token, sorted(deferral_candidates)
            ),
            finding_visibility=finding_visibility,
            pr_author_login=pr_author_login,
            author_only_logins=author_only_logins,
        )
    # ACCEPTED deferrals are logged unconditionally, not only when the gate is
    # red. The status description is budgeted to 140 chars and elides rulings
    # behind `+N more issues`, so this is the only place the FULL
    # content-id -> issue mapping survives; a deferral that was accepted but not
    # load-bearing is still a ruling someone made; and an audit trail that only
    # prints when the gate is red is not an audit trail.
    for content_id, issue_ref in sorted(deferrals.items()):
        print("review-gate-defer: ACCEPTED %s -> %s" % (content_id, issue_ref))

    state, description = decide(
        reviews=reviews,
        comments=comments,
        head_sha=head_sha,
        ally_logins=ally_logins,
        pr_author_login=pr_author_login,
        labels=labels,
        override_label=override_label,
        permission_trusted_logins=permission_trusted_logins,
        deferrals=deferrals,
        author_only_logins=author_only_logins,
    )

    # The copy-paste line a maintainer needs to defer a still-outstanding
    # finding. Printed only when the gate is not green, and computed by the gate
    # precisely so that nobody ever hand-computes a digest: hand-computing would
    # mean normalizing bullet text by eye, which is both error-prone and an
    # invitation to "tweak it until the gate goes green" -- the opposite of an
    # auditable record.
    if state != "success":
        hints = outstanding_finding_hints(
            reviews,
            comments,
            head_sha,
            ally_logins,
            deferrals,
            ambiguous_finding_severities(
                qualifying_ally_bodies_for_head(reviews, comments, head_sha, ally_logins)
            ),
        )
        for hint in hints:
            print(
                "review-gate-defer: to accept %s #%d on head %s, an admin "
                "collaborator who is NOT the PR author comments:\n"
                "    review-gate-defer: %s issue:BLO-XXXXX"
                % (hint["label"], hint["ordinal"], short_sha(head_sha), hint["content_id"])
            )
        for dropped in comments or []:
            body = str((dropped or {}).get("body") or "")
            if DEFERRAL_LINE_PATTERN.search(body) and not deferral_comment_is_unedited(dropped):
                print(
                    "review-gate-defer: IGNORED a deferral line on comment %s by %s "
                    "-- the comment was edited after posting (created %s, updated %s), "
                    "and REST cannot attribute an edited line to its writer. Post a "
                    "NEW comment instead."
                    % (
                        (dropped or {}).get("id", "unknown"),
                        ((dropped or {}).get("user") or {}).get("login", "unknown"),
                        (dropped or {}).get("created_at", "unknown"),
                        (dropped or {}).get("updated_at", "unknown"),
                    )
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
