#!/usr/bin/env python3
"""Fixtures pinning every load-bearing branch of require-ally-review.py.

This suite is the mitigation for hand-porting a security-relevant gate from
the original JavaScript: without it, a subtle translation slip would silently
weaken a merge control. Each test names the property it protects.

Stdlib only, no network -- decide() is a pure function.

Run: python3 -m unittest discover -s .github/scripts -p 'test_*.py'
"""

import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
import unittest.mock as mock

_SPEC = importlib.util.spec_from_file_location(
    "require_ally_review",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "require-ally-review.py"),
)
gate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gate)

HEAD = "79eb5909f56c8e55a14339a1662adaeea4ac863f"
OTHER = "5b91d5289c7cdb9c91016f101dc1581cbe7bd8a5"
ALLY = ["allyblockcast[bot]", "app/allyblockcast", "allyblockcast"]
HUMAN = "kkroo"
OVERRIDE = "review-gate-override"


def attest(head=HEAD, extra=""):
    """A consolidated Ally body carrying the standalone head attestation.

    Binding is on this line, not review.commit_id, so fixtures must state the
    revision the body claims to cover.
    """
    return "## Ally \u2014 Consolidated PR Review\n\nReviewed head: %s\n\n%s" % (head, extra)


def review(state, commit=HEAD, body=None, login="allyblockcast[bot]", at="2026-07-27T10:00:00Z",
           assoc="NONE", utype="Bot", edited=None):
    if body is None:
        body = attest(commit)
    row = {
        "state": state,
        "commit_id": commit,
        "body": body,
        "user": {"login": login, "type": utype},
        "submitted_at": at,
        "author_association": assoc,
    }
    if edited is not None:
        row["last_edited_at"] = edited
    return row


def comment(body, login="allyblockcast[bot]", at="2026-07-27T10:00:00Z", updated=None,
            utype="Bot"):
    """Defaults to the App seat (type Bot): positive Ally evidence requires
    it, and most fixtures exercise the authoritative path. Pass utype="User"
    to model the shared `allyblockcast` User seat."""
    row = {"body": body, "user": {"login": login, "type": utype}, "created_at": at}
    if updated is not None:
        row["updated_at"] = updated
    return row


def override_body(sha):
    """A maintainer's head-bound override authorization."""
    return "Reviewer never ran; overriding.\n\nreview-gate-override: %s\n" % sha


def decide(reviews=(), comments=(), head=HEAD, author=HUMAN, labels=(), trusted=None,
           resolved=None):
    return gate.decide(
        reviews=list(reviews),
        comments=list(comments),
        head_sha=head,
        ally_logins=ALLY,
        pr_author_login=author,
        labels=list(labels),
        override_label=OVERRIDE,
        permission_trusted_logins=trusted or set(),
        permission_resolved_logins=resolved or set(),
    )


CONSOLIDATED = attest(HEAD)
# An affirmative clean body: validated zero counts. Silence is no longer
# consent, so a consolidated body with neither a pass verdict nor explicit
# zero counts is ambiguous and stays pending.
CLEAN = attest(HEAD, "### Critical Issues (0)\n\n### Important Issues (0)\n")


class TestNoSignal(unittest.TestCase):
    """Branch 1 — the exact failure that went unnoticed for 21h on PR #30."""

    def test_no_reviews_at_all_is_pending(self):
        state, desc = decide()
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)
        self.assertIn(HEAD[:7], desc)

    def test_review_on_a_previous_head_does_not_count(self):
        # The PR #30 shape exactly: five reviews existed, none on this head.
        state, desc = decide(reviews=[review("COMMENTED", commit=OTHER, body=attest(OTHER))])
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_dismissed_review_on_head_does_not_count(self):
        state, _ = decide(reviews=[review("DISMISSED", body=CONSOLIDATED)])
        self.assertEqual(state, "pending")


class TestCleanCommented(unittest.TestCase):
    """Branch 3 — Ally only ever COMMENTs, so a clean comment must NOT auto-pass."""

    def test_clean_commented_holds_pending_and_names_the_label(self):
        # CLEAN (zero counts), not bare CONSOLIDATED prose: the inversion
        # requires a machine-readable all-clear for the review to count.
        state, desc = decide(reviews=[review("COMMENTED", body=CLEAN)])
        self.assertEqual(state, "pending")
        self.assertIn("no blocking findings", desc)
        self.assertIn("App-seat APPROVED", desc)

    def test_clean_commented_label_alone_does_not_clear(self):
        """The label is PR-scoped and survives `synchronize`. On its own it
        would clear every later unreviewed head, so it is necessary but not
        sufficient."""
        state, desc = decide(
            reviews=[review("COMMENTED", body=CONSOLIDATED)], labels=[OVERRIDE]
        )
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_former_override_combination_no_longer_clears(self):
        # Round 3 of the multicast vendoring review: the label+comment
        # override was a User-authorized success path on a context whose
        # sole positive authority is the App seat. It now clears nothing.
        state, desc = decide(
            reviews=[review("COMMENTED", body=CONSOLIDATED)],
            comments=[comment(override_body(HEAD), login=HUMAN)],
            labels=[OVERRIDE],
            trusted={HUMAN},
        )
        self.assertEqual(state, "pending")


class TestBlockingFindings(unittest.TestCase):
    """Branches 4, 5, 9 — real negatives stay red, label or not."""

    def test_important_issue_count_fails(self):
        body = CONSOLIDATED + "### Important Issues (1)\n\n- something real"
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "failure")

    def test_critical_issue_count_fails(self):
        body = CONSOLIDATED + "### Critical Issues (2)\n"
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "failure")

    def test_zero_counts_do_not_fail(self):
        body = CONSOLIDATED + "### Critical Issues (0)\n### Important Issues (0)\n"
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")  # clean-commented, needs label

    def test_override_never_bypasses_a_failure(self):
        body = CONSOLIDATED + "### Important Issues (1)\n"
        state, _ = decide(reviews=[review("COMMENTED", body=body)], labels=[OVERRIDE])
        self.assertEqual(state, "failure")

    def test_changes_requested_state_fails(self):
        state, _ = decide(reviews=[review("CHANGES_REQUESTED")])
        self.assertEqual(state, "failure")

    def test_changes_requested_beats_merge_verdict(self):
        # Fail-safe precedence when both markers somehow appear.
        body = CONSOLIDATED + "ally-verdict: changes-requested\nally-verdict: pass\n"
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "failure")


class TestPositiveProseIsNotAVerdict(unittest.TestCase):
    """Branch 6 — the trap the original guards with a long comment: a positive
    review that merely discusses security must not be read as negative."""

    def test_security_vocabulary_in_a_clean_review_does_not_fail(self):
        body = (
            CONSOLIDATED
            + "### Strengths\n\n- This blocks a real security gap and the unsafe "
            "RBAC finding is handled well.\n\n### Recommended Action\n\nMerge.\n"
        )
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertNotEqual(state, "failure")

    def test_explicit_merge_verdict_is_clean(self):
        body = CONSOLIDATED + "### Recommended Action\n\nMerge.\n"
        state, desc = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")
        self.assertIn("App-seat APPROVED", desc)


class TestSelfReview(unittest.TestCase):
    """Branch 7 — an Ally-authored PR cannot be cleared by Ally's own review."""

    def test_self_review_approval_is_demoted_to_pending(self):
        state, desc = decide(
            reviews=[review("APPROVED")], author="app/allyblockcast"
        )
        self.assertEqual(state, "pending")
        self.assertIn("independent author", desc)

    def test_self_review_blocking_findings_still_fail_closed(self):
        body = CONSOLIDATED + "### Critical Issues (1)\n"
        state, _ = decide(
            reviews=[review("COMMENTED", body=body)], author="app/allyblockcast"
        )
        self.assertEqual(state, "failure")

    def test_distinct_human_approval_clears_a_self_review_pr(self):
        """Branch 8 — trusted via author_association fallback."""
        state, desc = decide(
            reviews=[
                review("APPROVED", login="app/allyblockcast", at="2026-07-27T09:00:00Z"),
                review(
                    "APPROVED",
                    login=HUMAN,
                    utype="User",
                    assoc="MEMBER",
                    at="2026-07-27T11:00:00Z",
                ),
            ],
            author="app/allyblockcast",
            trusted={HUMAN},
        )
        # Round 3: App-authored PRs stay pending regardless of distinct
        # approvals; reopen the head under an independent author.
        self.assertEqual(state, "pending")
        self.assertIn("independent author", desc)

    def test_distinct_approval_trusted_via_collaborator_permission(self):
        """Branch 8 — association is CONTRIBUTOR (the visibility-gated false
        negative the original documents); permission lookup rescues it."""
        state, _ = decide(
            reviews=[
                review(
                    "APPROVED",
                    login=HUMAN,
                    utype="User",
                    assoc="CONTRIBUTOR",
                    at="2026-07-27T11:00:00Z",
                )
            ],
            author="app/allyblockcast",
            trusted={HUMAN},
        )
        # Round 3: pending — the permission lookup still resolves trust, but
        # a distinct approval can no longer green this context.
        self.assertEqual(state, "pending")

    def test_bot_ally_identity_cannot_be_its_own_distinct_reviewer(self):
        state, _ = decide(
            reviews=[review("APPROVED", login="allyblockcast[bot]", utype="Bot")],
            author="app/allyblockcast",
        )
        self.assertEqual(state, "pending")

    def test_distinct_approval_does_not_discard_ally_blocking_findings(self):
        body = CONSOLIDATED + "### Important Issues (1)\n"
        state, _ = decide(
            reviews=[
                review("COMMENTED", login="app/allyblockcast", body=body),
                review(
                    "APPROVED",
                    login=HUMAN,
                    utype="User",
                    assoc="MEMBER",
                    at="2026-07-27T12:00:00Z",
                ),
            ],
            author="app/allyblockcast",
        )
        self.assertEqual(state, "failure")


class TestCommentSignals(unittest.TestCase):
    """Consolidated / issue-link comments contribute BLOCKING signals only.

    Round 2 of this PR's review removed the comment path's positive branch:
    a clean consolidated comment used to return `success`, which let an
    issue comment green the gate with no formal review having happened."""

    def test_consolidated_clean_comment_is_inert(self):
        state, desc = decide(comments=[comment(CLEAN)])
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_consolidated_comment_without_a_verdict_stays_pending(self):
        """Silence is not consent: no pass verdict and no zero counts is
        ambiguous, so it must not clear the gate."""
        state, _ = decide(comments=[comment(CONSOLIDATED)])
        self.assertEqual(state, "pending")

    def test_consolidated_comment_for_other_head_is_ignored(self):
        body = "## Ally — Consolidated PR Review\n\nReviewed head: %s\n" % OTHER
        state, desc = decide(comments=[comment(body)])
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_issue_link_comment_does_not_clear_the_gate(self):
        """Informational bookkeeping, not a review verdict. Treating it as
        success let a link comment clear the gate with no review at all."""
        body = "Links Paperclip issues: BLO-18353 for head %s\n" % HEAD
        state, desc = decide(comments=[comment(body)])
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_issue_link_comment_with_blocking_count_still_fails(self):
        body = ("Links Paperclip issues: BLO-1 for head %s\n"
                "### Important Issues (1)\n" % HEAD)
        state, _ = decide(comments=[comment(body)])
        self.assertEqual(state, "failure")

    def test_unrelated_comment_is_not_a_signal(self):
        state, _ = decide(comments=[comment("looks good to me, head %s" % HEAD)])
        self.assertEqual(state, "pending")


class TestAttestationAsymmetry(unittest.TestCase):
    """Attestation gates CLEARING the gate, never blocking it. Applying it
    symmetrically downgraded an unattested CHANGES_REQUESTED to pending --
    weaker than the red it replaced. hang-mmt-fec's suite caught this."""

    def test_unattested_changes_requested_still_blocks(self):
        state, _ = decide(reviews=[review("CHANGES_REQUESTED", body="")])
        self.assertEqual(state, "failure")

    def test_unattested_blocking_counts_still_fail(self):
        body = "## Ally — Consolidated PR Review\n\n### Important Issues (1)\n"
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "failure")

    def test_unattested_approval_does_not_clear(self):
        state, _ = decide(reviews=[review("APPROVED", body="")])
        self.assertEqual(state, "pending")


class TestFullShaAttestation(unittest.TestCase):
    """A 7-char prefix is 28 bits — grindable. Only the full OID may bind a
    comment to a head."""

    def test_short_sha_only_comment_does_not_count(self):
        body = "## Ally — Consolidated PR Review\n\nReviewed head: %s\n" % HEAD[:7]
        state, desc = decide(comments=[comment(body)])
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_full_sha_comment_counts(self):
        # Positive comment evidence is inert since round 2 of this PR's
        # review, so full-SHA attestation recognition is pinned through the
        # blocking path: an unrecognized comment could not fail the gate.
        body = attest(HEAD, "### Critical Issues (2)\n")
        state, _ = decide(comments=[comment(body)])
        self.assertEqual(state, "failure")


class TestCommitIdIsNotProofOfCoverage(unittest.TestCase):
    """review.commit_id can name a head the reviewer never saw.

    Observed on Blockcast/frr#29 on 2026-07-28: an approval submitted against
    015670897f later reported commit_id a256a868a3, the then-current head. The
    intervening commit had been reverted, so the two trees were identical --
    but the review had still never been made against the commit it now named,
    and the PR read as freshly approved because of it.

    The body attestation is what actually binds a signal to a revision: Ally
    writes the SHA into text, and text does not move. These fixtures pin that
    the positive path trusts the attestation rather than commit_id alone, so a
    commit_id that drifts onto the current head cannot manufacture coverage.
    """

    def test_approval_on_head_attesting_another_head_does_not_clear(self):
        state, desc = decide(reviews=[review("APPROVED", commit=HEAD, body=attest(OTHER))])
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_clean_commented_on_head_attesting_another_head_does_not_clear(self):
        state, _ = decide(
            reviews=[review("COMMENTED", commit=HEAD, body=attest(OTHER))],
            comments=[comment(override_body(HEAD), login=HUMAN)],
            labels=[OVERRIDE],
            trusted={HUMAN},
        )
        # The override cannot rescue it either: with no signal for this head the
        # gate is still deciding about an unreviewed revision.
        self.assertNotEqual(state, "failure")

    def test_blocking_findings_still_fail_when_commit_id_drifts(self):
        # Fail-closed is unconditional: a drifting commit_id must never be a
        # way to shed a negative verdict.
        body = attest(OTHER) + "### Critical Issues (1)\n"
        state, _ = decide(reviews=[review("COMMENTED", commit=HEAD, body=body)])
        self.assertEqual(state, "failure")


class TestPermissionLookupIsAuthoritative(unittest.TestCase):
    """When the collaborator-permission lookup COMPLETES it is the answer;
    author_association is only a fallback for a lookup that errored."""

    def test_read_only_collaborator_cannot_clear_a_self_review_pr(self):
        # Association says COLLABORATOR, but the lookup resolved and did not
        # grant write/maintain/admin.
        state, _ = decide(
            reviews=[
                review("APPROVED", login=HUMAN, utype="User", assoc="COLLABORATOR",
                       at="2026-07-27T11:00:00Z")
            ],
            author="app/allyblockcast",
            trusted=set(),
            resolved={HUMAN},
        )
        self.assertEqual(state, "pending")

    def test_unresolved_lookup_fails_closed(self):
        """A lookup that errored is UNTRUSTED, not an invitation to fall back
        to author_association: COLLABORATOR can mean read or triage, so a
        transient API failure would otherwise let a read-only account clear an
        Ally-authored PR."""
        state, _ = decide(
            reviews=[
                review("APPROVED", login=HUMAN, utype="User", assoc="MEMBER",
                       at="2026-07-27T11:00:00Z")
            ],
            author="app/allyblockcast",
            trusted=set(),
            resolved=set(),
        )
        self.assertEqual(state, "pending")


class TestConflictingReviewers(unittest.TestCase):
    """One reviewer's later approval must not erase another's outstanding
    change request."""

    def test_later_approval_does_not_erase_earlier_changes_requested(self):
        state, _ = decide(
            reviews=[
                review("CHANGES_REQUESTED", login="reviewer-a", utype="User",
                       assoc="MEMBER", at="2026-07-27T10:00:00Z"),
                review("APPROVED", login="reviewer-b", utype="User",
                       assoc="MEMBER", at="2026-07-27T12:00:00Z"),
            ],
            author="app/allyblockcast",
            trusted={"reviewer-a", "reviewer-b"},
        )
        self.assertEqual(state, "failure")

    def test_same_reviewer_may_supersede_their_own_objection(self):
        state, _ = decide(
            reviews=[
                review("CHANGES_REQUESTED", login="reviewer-a", utype="User",
                       assoc="MEMBER", at="2026-07-27T10:00:00Z"),
                review("APPROVED", login="reviewer-a", utype="User",
                       assoc="MEMBER", at="2026-07-27T12:00:00Z"),
            ],
            author="app/allyblockcast",
            trusted={"reviewer-a"},
        )
        # The later approval withdraws reviewer-a's own objection, but a
        # surviving distinct approval maps to NO signal (round 3): pending,
        # never success.
        self.assertEqual(state, "pending")


class TestOverrideIsHeadBound(unittest.TestCase):
    """The override label is PR-scoped and survives `synchronize`. Left on its
    own it cleared every subsequent unreviewed head -- defeating the gate on
    exactly the push-then-review cycle it exists to protect. Authorization now
    needs the label AND a comment naming the full head SHA, so pushing new code
    revokes it."""

    def test_attestation_for_a_previous_head_does_not_carry_over(self):
        # The regression itself: override granted for OTHER, then a new push.
        state, desc = decide(
            comments=[comment(override_body(OTHER), login=HUMAN)],
            labels=[OVERRIDE],
            trusted={HUMAN},
        )
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_label_without_attestation_names_the_required_comment(self):
        state, desc = decide(labels=[OVERRIDE], trusted={HUMAN})
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_attestation_without_label_does_not_clear(self):
        state, _ = decide(
            comments=[comment(override_body(HEAD), login=HUMAN)], trusted={HUMAN}
        )
        self.assertEqual(state, "pending")

    def test_untrusted_author_cannot_authorize_an_override(self):
        state, _ = decide(
            comments=[comment(override_body(HEAD), login="drive-by")],
            labels=[OVERRIDE],
            trusted=set(),
        )
        self.assertEqual(state, "pending")

    def test_short_sha_attestation_is_rejected(self):
        # 7 chars is 28 bits: grindable, same reason review attestations
        # require the full OID.
        state, _ = decide(
            comments=[comment(override_body(HEAD[:7]), login=HUMAN)],
            labels=[OVERRIDE],
            trusted={HUMAN},
        )
        self.assertEqual(state, "pending")

    def test_override_still_never_bypasses_blocking_findings(self):
        body = CONSOLIDATED + "### Critical Issues (1)\n"
        state, _ = decide(
            reviews=[review("COMMENTED", body=body)],
            comments=[comment(override_body(HEAD), login=HUMAN)],
            labels=[OVERRIDE],
            trusted={HUMAN},
        )
        self.assertEqual(state, "failure")


class TestEditedCommentOrdering(unittest.TestCase):
    """created_at is immutable across edits, so ordering on it let an older
    comment edited to ADD findings lose to a newer clean signal."""

    def test_edited_older_comment_with_findings_beats_newer_clean_signal(self):
        edited = CONSOLIDATED + "### Important Issues (1)\n"
        state, _ = decide(
            comments=[
                # Created first, edited last -> its findings are the current word.
                comment(edited, at="2026-07-27T09:00:00Z", updated="2026-07-27T15:00:00Z"),
                comment(CLEAN, at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")

    def test_later_clean_comment_cannot_clear_blocking_comment(self):
        # Inverted in round 2 of this PR's review: a newer clean comment used
        # to supersede an older blocking one via latest_signal(). Clean
        # comments are inert now, so the blocking signal stands until a
        # formal App-seat APPROVED review of this head supersedes it.
        blocking = CONSOLIDATED + "### Important Issues (1)\n"
        state, _ = decide(
            comments=[
                comment(blocking, at="2026-07-27T09:00:00Z"),
                comment(CLEAN, at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")

    def test_missing_updated_at_falls_back_to_created_at(self):
        self.assertEqual(
            gate.comment_signal_time({"created_at": "2026-07-27T09:00:00Z"}),
            "2026-07-27T09:00:00Z",
        )


class TestEditedReviewOrdering(unittest.TestCase):
    """The formal-review twin of TestEditedCommentOrdering: submitted_at is
    immutable across body edits, so an older review edited to ADD findings
    must not lose to a newer clean signal. last_edited_at arrives via GraphQL
    enrichment in main(); fixtures inject it directly."""

    def test_edited_older_review_with_findings_beats_newer_clean_review(self):
        blocking = CONSOLIDATED + "### Important Issues (1)\n"
        state, _ = decide(
            reviews=[
                review("COMMENTED", body=blocking, at="2026-07-27T09:00:00Z",
                       edited="2026-07-27T15:00:00Z"),
                review("COMMENTED", body=CONSOLIDATED, at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")

    def test_unedited_review_ordering_is_unchanged(self):
        blocking = CONSOLIDATED + "### Important Issues (1)\n"
        state, _ = decide(
            reviews=[
                review("COMMENTED", body=blocking, at="2026-07-27T09:00:00Z"),
                review("COMMENTED", body=CLEAN, at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "pending")  # newest is clean-commented

    def test_missing_last_edited_at_falls_back_to_submitted_at(self):
        self.assertEqual(
            gate.review_signal_time({"submitted_at": "2026-07-27T09:00:00Z"}),
            "2026-07-27T09:00:00Z",
        )


class TestQualifiedMergeVerdicts(unittest.TestCase):
    """An explicit pass suppresses the fallback action-required scan, so the
    'Recommended Action: Merge' matcher must only accept a COMPLETE standalone
    Merge. A loose prefix match laundered 'Merge only after requested changes
    are addressed' into a clean signal that cleared the gate."""

    def _review_state(self, verdict_line):
        body = attest(HEAD, "### Recommended Action\n\n%s\n" % verdict_line)
        return decide(reviews=[review("COMMENTED", body=body)])

    def test_standalone_merge_is_a_pass(self):
        # Round 2 of this PR's review made the comment path positive-inert,
        # so the verdict matcher's discrimination shows on the review path:
        # a standalone Merge lands the clean-commented pending, a qualified
        # Merge contributes no clean signal at all.
        state, desc = self._review_state("Merge.")
        self.assertEqual(state, "pending")
        self.assertIn("no blocking findings", desc)

    def test_merge_only_after_changes_is_not_a_pass(self):
        state, desc = self._review_state(
            "Merge only after requested changes are addressed."
        )
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_merge_verdict_comment_is_inert(self):
        body = attest(HEAD, "### Recommended Action\n\nMerge.\n")
        state, desc = decide(comments=[comment(body)])
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_merge_after_fixes_is_not_a_pass(self):
        state, _ = self._review_state("Merge after fixes")
        self.assertEqual(state, "pending")

    def test_merge_must_be_blocked_is_not_a_pass(self):
        state, _ = self._review_state("Merge must be blocked")
        self.assertEqual(state, "pending")


class TestDescriptionLength(unittest.TestCase):
    """GitHub 422s status descriptions over 140 chars -- on the FINAL write,
    after the early pending claim, leaving the gate stuck at 'Evaluating...'.
    Every branch's authored description must fit; clamp_description is the
    backstop for unvetted inputs like operator-configured label names."""

    LIMIT = 140

    def assertFits(self, result):
        _, desc = result
        self.assertLessEqual(len(desc), self.LIMIT, "%d chars: %r" % (len(desc), desc))

    def test_every_decide_branch_fits(self):
        blocking = CONSOLIDATED + "### Critical Issues (1)\n"
        scenarios = [
            decide(),  # waiting
            decide(labels=[OVERRIDE], trusted={HUMAN}),  # label, no attestation
            decide(reviews=[review("COMMENTED", body=CONSOLIDATED)]),  # clean commented
            decide(  # override success
                reviews=[review("COMMENTED", body=CONSOLIDATED)],
                comments=[comment(override_body(HEAD), login=HUMAN)],
                labels=[OVERRIDE],
                trusted={HUMAN},
            ),
            decide(reviews=[review("COMMENTED", body=blocking)]),  # failure
            decide(  # override refused: mask-ambiguous body
                reviews=[review("COMMENTED", body=attest(
                    HEAD, "No reviewer responded and action required: fix gate."))],
                comments=[comment(override_body(HEAD), login=HUMAN)],
                labels=[OVERRIDE],
                trusted={HUMAN},
            ),
            decide(reviews=[review("CHANGES_REQUESTED")]),  # changes requested
            decide(reviews=[review("APPROVED")]),  # approved
            decide(reviews=[review("APPROVED")], author="app/allyblockcast"),  # self demoted
            decide(  # distinct reviewer success
                reviews=[review("APPROVED", login=HUMAN, utype="User", assoc="MEMBER",
                                at="2026-07-27T11:00:00Z")],
                author="app/allyblockcast",
                trusted={HUMAN},
            ),
            decide(comments=[comment(CLEAN)]),  # comment-clean success
        ]
        for result in scenarios:
            self.assertFits(result)

    def test_clamp_truncates_over_length_input(self):
        clamped = gate.clamp_description("x" * 300)
        self.assertEqual(len(clamped), self.LIMIT)
        self.assertTrue(clamped.endswith("..."))

    def test_clamp_passes_short_input_through(self):
        self.assertEqual(gate.clamp_description("short"), "short")


class TestContradictoryCounts(unittest.TestCase):
    """A body carrying duplicate count headings must fail closed on the max.
    First-match parsing read 'Critical Issues (0) ... Critical Issues (2)' as
    clean. Ported from hang-mmt-fec's gate."""

    def test_zero_then_nonzero_heading_fails(self):
        body = CLEAN + "\n### Critical Issues (2)\n"
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "failure")

    def test_contradictory_counts_with_explicit_pass_still_fail(self):
        """The load-bearing case: an explicit 'Merge.' verdict suppresses the
        keyword fallback, so first-match counts reading the (0) was the ONLY
        thing between this body and a clean signal."""
        body = attest(
            HEAD,
            "### Critical Issues (0)\n\n### Critical Issues (2)\n\n"
            "### Recommended Action\n\nMerge.\n",
        )
        state, _ = decide(comments=[comment(body)])
        self.assertEqual(state, "failure")

    def test_nonzero_then_zero_heading_still_fails(self):
        body = attest(HEAD, "### Important Issues (3)\n\n### Important Issues (0)\n")
        state, _ = decide(comments=[comment(body)])
        self.assertEqual(state, "failure")

    def test_duplicate_zero_headings_stay_clean(self):
        # Via the review path since round 2 of this PR's review: the
        # clean-commented description proves the duplicate zero headings
        # were read as clean, which a positive-inert comment cannot show.
        body = CLEAN + "\n### Critical Issues (0)\n"
        state, desc = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")
        self.assertIn("no blocking findings", desc)


class TestSameTimestampTies(unittest.TestCase):
    """Opposite signals at the same second must not let API list order pick
    between red and green. Ported from hang-mmt-fec's same-second rule."""

    def test_global_tie_prefers_blocking_regardless_of_list_order(self):
        blocking = CONSOLIDATED + "### Important Issues (1)\n"
        at = "2026-07-27T10:00:00Z"
        for ordering in (
            [comment(CLEAN, at=at), comment(blocking, at=at)],
            [comment(blocking, at=at), comment(CLEAN, at=at)],
        ):
            state, _ = decide(comments=ordering)
            self.assertEqual(state, "failure")

    def test_per_reviewer_tie_prefers_changes_requested(self):
        at = "2026-07-27T11:00:00Z"
        for first, second in (
            ("APPROVED", "CHANGES_REQUESTED"),
            ("CHANGES_REQUESTED", "APPROVED"),
        ):
            state, _ = decide(
                reviews=[
                    review(first, login=HUMAN, utype="User", assoc="MEMBER", at=at),
                    review(second, login=HUMAN, utype="User", assoc="MEMBER", at=at),
                ],
                author="app/allyblockcast",
                trusted={HUMAN},
            )
            self.assertEqual(state, "failure", "order %s,%s" % (first, second))


class TestDistinctReviewerHeadBinding(unittest.TestCase):
    """The distinct-reviewer POSITIVE path must not rest on mutable commit_id.

    Round 4 pinned this for the Ally path and left this one open -- the very
    path where the #29 drift actually happened (a trusted human approval's
    commit_id moved onto a head the reviewer never saw). Positives need
    immutable evidence: a body attestation or a head-bound authorization
    comment by the same trusted login. Blocking keeps binding on commit_id --
    drift may add red, never green.
    """

    def _approve(self, body, commit=HEAD):
        return review("APPROVED", commit=commit, body=body, login=HUMAN,
                      utype="User", assoc="MEMBER", at="2026-07-27T11:00:00Z")

    def test_drifted_commit_id_with_foreign_attestation_does_not_clear(self):
        # Ally's focused reproduction: commit_id says current head, body says
        # another head. The approval never covered this code.
        state, _ = decide(
            reviews=[self._approve(attest(OTHER))],
            author="app/allyblockcast",
            trusted={HUMAN},
        )
        self.assertEqual(state, "pending")

    def test_empty_body_approval_alone_does_not_clear(self):
        state, _ = decide(
            reviews=[self._approve("")],
            author="app/allyblockcast",
            trusted={HUMAN},
        )
        self.assertEqual(state, "pending")

    def test_attested_approval_clears_even_when_commit_id_drifts(self):
        # The inverse guarantee: immutable evidence wins over a stale
        # commit_id, so a legitimate approval survives GitHub's rewriting.
        state, _ = decide(
            reviews=[self._approve(attest(HEAD), commit=OTHER)],
            author="app/allyblockcast",
            trusted={HUMAN},
        )
        # Round 3: distinct approvals no longer produce success anywhere;
        # binding now only governs whether an approval may withdraw the SAME
        # reviewer's earlier change request.
        self.assertEqual(state, "pending")

    def test_authorization_comment_binds_an_empty_body_approval(self):
        state, _ = decide(
            reviews=[self._approve("")],
            comments=[comment(override_body(HEAD), login=HUMAN)],
            author="app/allyblockcast",
            trusted={HUMAN},
        )
        self.assertEqual(state, "pending")

    def test_authorization_by_a_different_login_does_not_bind(self):
        # The approver must bind their own approval; a third party's
        # authorization comment is not evidence of what THIS reviewer saw.
        state, _ = decide(
            reviews=[self._approve("")],
            comments=[comment(override_body(HEAD), login="someone-else")],
            author="app/allyblockcast",
            trusted={HUMAN, "someone-else"},
        )
        self.assertEqual(state, "pending")

    def test_changes_requested_still_binds_on_commit_id_alone(self):
        state, _ = decide(
            reviews=[review("CHANGES_REQUESTED", body="", login=HUMAN,
                            utype="User", assoc="MEMBER",
                            at="2026-07-27T11:00:00Z")],
            author="app/allyblockcast",
            trusted={HUMAN},
        )
        self.assertEqual(state, "failure")


class TestApprovalAndRecency(unittest.TestCase):
    def test_ally_approval_on_head_succeeds(self):
        state, _ = decide(reviews=[review("APPROVED")])
        self.assertEqual(state, "success")

    def test_explicit_pass_suppresses_the_prose_heuristic(self):
        # "no action required" contains the action-required keyword; an
        # explicit merge verdict must win over the heuristic.
        body = (
            CONSOLIDATED
            + "### Recommended Action\n\nMerge.\n\nNothing else: no action required.\n"
        )
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertNotEqual(state, "failure")

    def test_latest_signal_wins(self):
        # Under the authorization inversion the newest review only counts as
        # clean via machine-readable zero counts (CLEAN), not bare prose.
        clean = CLEAN
        blocking = CONSOLIDATED + "### Important Issues (1)\n"
        state, _ = decide(
            reviews=[
                review("COMMENTED", body=blocking, at="2026-07-27T09:00:00Z"),
                review("COMMENTED", body=clean, at="2026-07-27T12:00:00Z"),
            ]
        )
        # Newest is clean -> pending (not failure): recency governs.
        self.assertEqual(state, "pending")


class TestStalePayloadOrchestration(unittest.TestCase):
    """Runs serialize on a shared group and must be unconditionally willing to
    evaluate current state, whatever stale snapshot woke them. Round 7: a
    delayed event whose stale snapshot still said draft:true cancelled the
    then-cancellable in-flight ready-PR run and skipped the job on a
    workflow-level payload predicate -- the current head was left with no
    status. The predicate is gone; these fixtures prove the script layer makes
    that safe in BOTH stale directions by reading only the PR number (and a
    best-effort early-claim head) from the payload and taking draft state from
    the authoritative refetch."""

    STALE_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    def _run_main(self, payload_draft, refetched):
        event = {
            "pull_request": {
                "number": 7,
                "draft": payload_draft,
                "head": {"sha": self.STALE_HEAD},
            },
            "repository": {"full_name": "Blockcast/frr"},
        }
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False
        ) as handle:
            json.dump(event, handle)
            event_path = handle.name
        self.addCleanup(os.unlink, event_path)
        env = {
            "GITHUB_EVENT_PATH": event_path,
            "GITHUB_REPOSITORY": "Blockcast/frr",
            "GITHUB_TOKEN": "test-token",
        }
        statuses = []

        def record_status(api, owner, repo, sha, token, state, description,
                          target_url=None):
            statuses.append((sha, state))

        with mock.patch.dict(os.environ, env), \
                mock.patch.object(gate, "_request", return_value=refetched) as refetch, \
                mock.patch.object(gate, "set_commit_status", side_effect=record_status), \
                mock.patch.object(gate, "fetch_paginated", return_value=[]), \
                mock.patch.object(gate, "enrich_reviews_with_edit_times"):
            gate.main()
        return refetch, statuses

    def test_stale_draft_payload_still_gates_the_refetched_ready_head(self):
        # Payload says draft (stale); the PR is actually ready at a new head.
        # The run this event cancelled must be fully replaced: statuses go to
        # the refetched head, never the payload's.
        refetch, statuses = self._run_main(
            payload_draft=True,
            refetched={
                "number": 7,
                "state": "open",
                "draft": False,
                "head": {"sha": HEAD},
                "user": {"login": HUMAN},
                "labels": [],
            },
        )
        self.assertTrue(statuses)
        self.assertEqual({sha for sha, _ in statuses}, {HEAD})
        # Only the PR *number* crossed over from the stale payload.
        self.assertIn("/pulls/7", refetch.call_args[0][0])

    def test_stale_ready_payload_does_not_gate_a_draft_pr(self):
        # The inverse staleness: payload says ready, the PR has since gone
        # back to draft. The ready-claiming payload earns a best-effort early
        # pending on ITS OWN (stale) head -- harmless, a superseded head gates
        # nothing (the draft resolve keeps it pending with a note) -- but the
        # draft PR's current head must get no status.
        _, statuses = self._run_main(
            payload_draft=False,
            refetched={
                "number": 7,
                "state": "open",
                "draft": True,
                "head": {"sha": HEAD},
                "user": {"login": HUMAN},
                "labels": [],
            },
        )
        self.assertEqual({sha for sha, _ in statuses}, {self.STALE_HEAD})
        self.assertEqual({state for _, state in statuses}, {"pending"})
        self.assertNotIn(HEAD, {sha for sha, _ in statuses})

    def test_settled_pr_resolves_the_early_claim(self):
        # Round 2: a delayed event whose payload still said open earns the
        # early claim, then the refetch says merged/closed AT THE SAME HEAD.
        # A silent return would strand a required context yellow forever on a
        # commit that reached the base branch -- nothing re-evaluates a
        # settled PR. The claim must resolve to success (the PR cannot merge
        # again, so the context gates nothing).
        _, statuses = self._run_main(
            payload_draft=False,
            refetched={
                "number": 7,
                "state": "closed",
                "draft": False,
                "head": {"sha": self.STALE_HEAD},
                "user": {"login": HUMAN},
                "labels": [],
            },
        )
        self.assertEqual(
            statuses,
            [(self.STALE_HEAD, "pending"), (self.STALE_HEAD, "success")],
        )

    def test_draft_pr_same_head_keeps_the_claim_failclosed(self):
        # Same-head draft: the PR can return to ready at this exact head, so
        # resolving to success would pre-clear the gate (fail-open). The
        # claim stays pending -- self-healing via the next ready_for_review.
        _, statuses = self._run_main(
            payload_draft=False,
            refetched={
                "number": 7,
                "state": "open",
                "draft": True,
                "head": {"sha": self.STALE_HEAD},
                "user": {"login": HUMAN},
                "labels": [],
            },
        )
        self.assertEqual(
            statuses,
            [(self.STALE_HEAD, "pending"), (self.STALE_HEAD, "pending")],
        )


class TestNegatedActionRequired(unittest.TestCase):
    """"No action required" contains "action required" as a substring, so the
    raw affirmative scan read Ally's all-clear as a changes-requested verdict.
    Negated forms are masked before the scan; a separate un-negated
    affirmative in the same body must still fail."""

    def test_no_action_required_comment_is_not_a_failure(self):
        # The mask's only job is preventing a false FAILURE from negated
        # prose. On the (positive-inert) comment path that shows as pending
        # rather than failure; on the review path the clean-commented
        # description additionally proves the body was read as clean.
        body = attest(
            HEAD,
            "No action required.\n\n### Critical Issues (0)\n\n### Important Issues (0)\n",
        )
        state, description = decide(comments=[comment(body)])
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", description)
        state, description = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")
        self.assertIn("no blocking findings", description)

    def test_no_further_action_required_variant(self):
        body = attest(
            HEAD,
            "No further action is required.\n\n### Critical Issues (0)\n\n### Important Issues (0)\n",
        )
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")

    def test_no_changes_requested_is_not_a_failure(self):
        # Review round 2: the mask covered only the "action required" phrase
        # family; "No changes requested." hit the sibling `changes requested`
        # alternation and produced the same false failure.
        body = attest(
            HEAD,
            "No changes requested.\n\n### Critical Issues (0)\n\n### Important Issues (0)\n",
        )
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")

    def test_adverb_does_not_defeat_the_mask(self):
        body = attest(
            HEAD,
            "No immediate action required.\n\n### Critical Issues (0)\n\n### Important Issues (0)\n",
        )
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")

    def test_no_changes_needed_variant(self):
        body = attest(
            HEAD,
            "No changes are needed.\n\n### Critical Issues (0)\n\n### Important Issues (0)\n",
        )
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")

    def test_multi_modifier_negations_do_not_defeat_the_mask(self):
        # Review rounds 3-4: the mask first allowed exactly zero or one
        # modifier word, then an arbitrary cap of three -- each left some
        # ordinary multi-modifier all-clear prose ("no ADDITIONAL
        # APPLICATION SOURCE CODE changes requested") with the affirmative
        # substring behind, blocking a clean review. The span is now
        # clause-bounded instead of counted.
        for text in (
            "No additional code changes requested.",
            "No immediate further action required.",
            "No additional application source code changes requested.",
        ):
            body = attest(
                HEAD,
                text + "\n\n### Critical Issues (0)\n\n### Important Issues (0)\n",
            )
            state, _ = decide(reviews=[review("COMMENTED", body=body)])
            self.assertEqual(state, "pending", text)

    def test_mask_window_does_not_cross_punctuation(self):
        # The clause-bounded window must not let a standalone "No." swallow
        # a separate affirmative sentence: modifiers admit only word
        # characters, so punctuation ends the span.
        body = attest(HEAD, "No. Changes requested: fix the overflow before merge.")
        state, _ = decide(comments=[comment(body)])
        self.assertEqual(state, "failure")

    def test_mask_span_stops_at_pivots_and_verbs(self):
        # Review round 5 CRITICAL: the unbounded modifier run accepted every
        # word, so a same-line pivot let the mask consume a genuine verdict
        # ("No reviewer has responded but action required:" masked to
        # ": ..."), flipping the gate fail-open. Modifiers now exclude
        # adversative/discourse pivots and auxiliary verbs -- both fixtures
        # die at "has" before even reaching the conjunction.
        for text in (
            "No reviewer has responded but action required: fix the gate.",
            "No reviewer requested this but changes requested: fix the gate.",
        ):
            body = attest(HEAD, text)
            state, _ = decide(comments=[comment(body)])
            self.assertEqual(state, "failure", repr(text))

    def test_mask_window_does_not_cross_line_boundaries(self):
        # Review round 4 CRITICAL: with "\s+" separators the mask crossed a
        # paragraph boundary -- a bare "No" ending one paragraph erased a
        # real blocking verdict opening the next ("No\n\nAction required:"
        # became ": ..."), flipping the gate fail-open. Separators admit
        # only horizontal whitespace, so a line boundary ends the span and
        # the blocking verdict survives the mask.
        for text in (
            "No\n\nAction required: fix the gate.",
            "No\n\nChanges requested: fix the gate.",
        ):
            body = attest(HEAD, text)
            state, _ = decide(comments=[comment(body)])
            self.assertEqual(state, "failure", repr(text))

    def test_affirmative_changes_requested_still_fails(self):
        body = attest(HEAD, "Changes requested: the overflow must be fixed first.")
        state, _ = decide(comments=[comment(body)])
        self.assertEqual(state, "failure")

    def test_no_action_required_review_is_not_a_failure(self):
        body = attest(
            HEAD,
            "No action required.\n\n### Critical Issues (0)\n\n### Important Issues (0)\n",
        )
        state, description = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")
        self.assertIn("no blocking findings", description)

    def test_affirmative_action_required_still_fails(self):
        body = attest(HEAD, "Action required: fix the overflow before merge.")
        state, _ = decide(comments=[comment(body)])
        self.assertEqual(state, "failure")

    def test_negation_does_not_mask_a_separate_affirmative(self):
        body = attest(
            HEAD,
            "No action required for the docs change. Action required: fix the gate.",
        )
        state, _ = decide(comments=[comment(body)])
        self.assertEqual(state, "failure")


class TestCrashVisibility(unittest.TestCase):
    """A run that dies must not exit silently. With no write, an earlier
    same-head `success` remains the visible truth (fail-open), and a crash
    before the refetch previously left no record at all. run() turns any
    crash into an `error` status on the best-known head, and main() claims a
    best-effort `pending` on the payload head BEFORE the fallible refetch."""

    STALE_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    def setUp(self):
        gate._STATUS_TARGET.clear()
        self.addCleanup(gate._STATUS_TARGET.clear)

    def _run(self, payload_draft=False, request=None, paginated=None):
        event = {
            "pull_request": {
                "number": 7,
                "draft": payload_draft,
                "head": {"sha": self.STALE_HEAD},
            },
            "repository": {"full_name": "Blockcast/frr"},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(event, handle)
            event_path = handle.name
        self.addCleanup(os.unlink, event_path)
        env = {
            "GITHUB_EVENT_PATH": event_path,
            "GITHUB_REPOSITORY": "Blockcast/frr",
            "GITHUB_TOKEN": "test-token",
        }
        calls = []

        def record_status(api, owner, repo, sha, token, state, description,
                          target_url=None):
            calls.append(("status", sha, state))

        def record_request(url, token, method="GET", payload=None):
            calls.append(("request", url))
            if isinstance(request, Exception):
                raise request
            return request

        def record_paginated(api, path, token):
            if isinstance(paginated, Exception):
                raise paginated
            return []

        with mock.patch.dict(os.environ, env), \
                mock.patch.object(gate, "_request", side_effect=record_request), \
                mock.patch.object(gate, "set_commit_status", side_effect=record_status), \
                mock.patch.object(gate, "fetch_paginated", side_effect=record_paginated), \
                mock.patch.object(gate, "enrich_reviews_with_edit_times"):
            with self.assertRaises(SystemExit) as caught:
                gate.run()
        self.assertEqual(caught.exception.code, 1)
        statuses = [(c[1], c[2]) for c in calls if c[0] == "status"]
        return statuses, calls

    def test_refetch_crash_posts_error_to_payload_head(self):
        statuses, _ = self._run(request=RuntimeError("refetch boom"))
        self.assertEqual(
            statuses,
            [(self.STALE_HEAD, "pending"), (self.STALE_HEAD, "error")],
        )

    def test_crash_after_refetch_posts_error_to_current_head(self):
        refetched = {
            "number": 7,
            "state": "open",
            "draft": False,
            "head": {"sha": HEAD},
            "user": {"login": HUMAN},
            "labels": [],
        }
        statuses, _ = self._run(request=refetched, paginated=RuntimeError("reviews boom"))
        # Early claim on the payload head, authoritative claim on the real
        # head, then the crash recorded against the real head -- never the
        # stale one.
        self.assertEqual(statuses[-1], (HEAD, "error"))
        self.assertIn((HEAD, "pending"), statuses)

    def test_early_claim_lands_before_the_refetch(self):
        refetched = {
            "number": 7,
            "state": "open",
            "draft": False,
            "head": {"sha": HEAD},
            "user": {"login": HUMAN},
            "labels": [],
        }
        _, calls = self._run(request=refetched, paginated=RuntimeError("boom"))
        kinds = [c[0] for c in calls]
        self.assertEqual(kinds[0], "status", "the payload-head claim must precede the refetch")
        self.assertEqual(kinds[1], "request")

    def test_draft_payload_makes_no_early_claim_but_crash_stays_visible(self):
        statuses, _ = self._run(payload_draft=True, request=RuntimeError("boom"))
        self.assertEqual(statuses, [(self.STALE_HEAD, "error")])

    def test_status_write_failure_does_not_mask_the_exit(self):
        event = {
            "pull_request": {"number": 7, "draft": False, "head": {"sha": self.STALE_HEAD}},
            "repository": {"full_name": "Blockcast/frr"},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(event, handle)
            event_path = handle.name
        self.addCleanup(os.unlink, event_path)
        env = {
            "GITHUB_EVENT_PATH": event_path,
            "GITHUB_REPOSITORY": "Blockcast/frr",
            "GITHUB_TOKEN": "test-token",
        }
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(gate, "_request", side_effect=RuntimeError("api down")), \
                mock.patch.object(gate, "set_commit_status", side_effect=RuntimeError("statuses down")):
            with self.assertRaises(SystemExit) as caught:
                gate.run()
        self.assertEqual(caught.exception.code, 1)


class TestWorkflowContracts(unittest.TestCase):
    """Regex checks over the two workflow files, pinning the properties the
    vendoring overlay must preserve. Stdlib-only on purpose: the selftest
    environment guarantees no third-party YAML parser."""

    WORKFLOWS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "workflows")

    def _read(self, name):
        with open(os.path.join(self.WORKFLOWS, name), encoding="utf8") as handle:
            return handle.read()

    def test_gate_workflow_never_cancels_in_flight_runs(self):
        # Cancellation is not atomic: a cancelled run can land an in-flight
        # final status POST after the superseding run wrote its verdict for
        # the same SHA. Every run recomputes full state, so serialization
        # loses nothing and closes that write race.
        gate_yml = self._read("review-gate.yml")
        self.assertRegex(gate_yml, r"(?m)^\s*cancel-in-progress:\s*false\s*$")
        self.assertNotIn("cancel-in-progress: ${{", gate_yml)

    def test_gate_job_name_is_the_required_backstop_check(self):
        # Branch protection requires the check-run named after the gate job
        # ("Ally review gate") ALONGSIDE the review/ally-complete commit
        # status (review round 8): a run that cannot reach the REST plane
        # cannot write any status, but its non-zero exit still reports
        # through the Actions plane and turns this check red on
        # pull_request_target heads -- the fail-closed backstop for
        # REST-outage runs. Renaming the job or adding continue-on-error
        # silently detaches it from the protection rule.
        gate_yml = self._read("review-gate.yml")
        self.assertRegex(gate_yml, r"(?m)^\s*name:\s*Ally review gate\s*$")
        self.assertNotIn("continue-on-error", gate_yml)

    def test_selftest_push_covers_both_fleet_default_branches(self):
        # frr's default branch is master; vendored repos default to main. A
        # master-only push trigger silently never runs the post-merge
        # self-test on those repos. Anchored on the trigger-level `push:` key
        # (2-space indent at line start), not a positional split -- the token
        # can legitimately appear earlier in a comment or a new trigger, and
        # a positional split would silently retarget this assertion.
        selftest_yml = self._read("review-gate-selftest.yml")
        trigger = re.search(r"(?m)^\s{2}push:\s*$", selftest_yml)
        self.assertIsNotNone(trigger, "selftest must keep a push trigger")
        push_block = selftest_yml[trigger.end():]
        branches = re.findall(r"(?m)^\s*-\s*([\w./-]+)\s*$", push_block.split("paths:", 1)[0])
        self.assertLessEqual({"master", "main"}, set(branches))

    def test_workflows_share_one_self_hosted_runner_label(self):
        # The vendoring overlay's single allowed diff is the runner label,
        # applied uniformly. Asserting consistency (not a hardcoded name)
        # keeps this test itself byte-identical across the fleet. Each file
        # must contribute at least one scalar match: an overlay rewriting one
        # workflow to a list/expression form (`runs-on: [self-hosted, gpu]`)
        # would otherwise contribute zero labels and the consistency check
        # would pass on exactly the divergence it exists to catch.
        labels = set()
        for name in ("review-gate.yml", "review-gate-selftest.yml"):
            matches = re.findall(r"(?m)^\s*runs-on:\s*(\S+)\s*$", self._read(name))
            self.assertTrue(
                matches,
                "%s has no scalar runs-on -- overlay must keep the scalar form" % name,
            )
            labels.update(matches)
        self.assertEqual(len(labels), 1, "gate and selftest must run on the same label: %s" % labels)
        label = next(iter(labels))
        self.assertNotRegex(
            label, r"(?i)\b(?:ubuntu|macos|windows)-", "hosted runner labels are forbidden"
        )


class TestUserSeatCannotProvidePositiveEvidence(unittest.TestCase):
    """Multicast-vendoring review round 2 CRITICAL: the org ruleset counts the
    shared `allyblockcast` User as the singleton Ally-team approval, so if the
    gate also accepted that User's reviews as positive Ally evidence, ONE User
    review would satisfy BOTH controls while the required App review is
    absent. Positive evidence therefore requires `user.type == "Bot"` (the
    App seat); blocking evidence stays identity-agnostic (dropping a User-seat
    CHANGES_REQUESTED would be fail-open); and the User seat keeps its
    separate, permission-checked DISTINCT-REVIEWER role on App-authored PRs.
    """

    def _user_review(self, state, body=None, **kw):
        return review(state, body=body, login="allyblockcast", utype="User", **kw)

    def test_user_seat_attested_approval_alone_stays_pending(self):
        # Round 4: the exact-head-attested User-seat approval now emits the
        # clean-commented placeholder (so it can withdraw its own earlier
        # objection under per-login reduction), but it still cannot green --
        # the gate pends awaiting the formal App-seat approval.
        state, desc = decide(reviews=[self._user_review("APPROVED", body=attest(HEAD))])
        self.assertEqual(state, "pending")
        self.assertIn("awaiting an App-seat APPROVED", desc)

    def test_user_seat_zero_count_commented_review_stays_pending(self):
        state, desc = decide(reviews=[self._user_review("COMMENTED", body=CLEAN)])
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_user_seat_clean_consolidated_comment_stays_pending(self):
        state, _ = decide(comments=[comment(CLEAN, login="allyblockcast", utype="User")])
        self.assertEqual(state, "pending")

    def test_user_seat_pass_verdict_comment_stays_pending(self):
        body = attest(HEAD, "### Recommended Action\n\nMerge.\n")
        state, _ = decide(comments=[comment(body, login="allyblockcast", utype="User")])
        self.assertEqual(state, "pending")

    def test_user_seat_changes_requested_still_fails(self):
        state, _ = decide(reviews=[self._user_review("CHANGES_REQUESTED")])
        self.assertEqual(state, "failure")

    def test_user_seat_blocking_count_still_fails(self):
        blocking = attest(HEAD, "### Critical Issues (2)\n")
        state, _ = decide(reviews=[self._user_review("COMMENTED", body=blocking)])
        self.assertEqual(state, "failure")
        state, _ = decide(
            comments=[comment(blocking, login="allyblockcast", utype="User")]
        )
        self.assertEqual(state, "failure")

    def test_user_seat_positive_does_not_shadow_bot_blocking(self):
        # A newer User-seat all-clear contributes NO signal, so it cannot
        # out-recency an older App-seat blocking review.
        blocking = attest(HEAD, "### Important Issues (1)\n")
        state, _ = decide(
            reviews=[
                review("COMMENTED", body=blocking, at="2026-07-27T09:00:00Z"),
                self._user_review("APPROVED", body=attest(HEAD),
                                  at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")

    def test_app_seat_approval_still_succeeds(self):
        state, _ = decide(reviews=[review("APPROVED")])
        self.assertEqual(state, "success")

    def test_user_seat_distinct_approval_cannot_green_app_authored_pr(self):
        # Inverted per round 3 of the multicast vendoring review: the
        # merge-token User seat (or ANY trusted distinct approval) can no
        # longer substitute for the App signal on an App-authored PR. Such
        # heads stay pending until reopened under an independent author.
        state, _ = decide(
            reviews=[review("APPROVED", login="allyblockcast", utype="User",
                            at="2026-07-27T11:00:00Z")],
            author="app/allyblockcast",
            trusted={"allyblockcast"},
        )
        self.assertEqual(state, "pending")



class TestIssueCommentCrashClaim(unittest.TestCase):
    """Review round 5 CRITICAL 2 / round 7 CRITICAL 2: issue_comment payloads
    carry no pull_request.head.sha, so a refetch crash previously skipped the
    `error` write and left an earlier same-head `success` standing -- fail-open
    on exactly the events (comment edit/delete) that can REMOVE the evidence
    behind a green gate. main() now probes the head FIRST (with retries), falls
    back to git transport when the REST plane is down, and claims whichever
    source yields the SHA -- so the crash handler always has an addressable
    commit. Only when BOTH transports fail does the run exit non-zero with no
    write: with no addressable commit there is nothing any code path could
    stamp, and posting the invalidating status itself requires the REST plane
    -- the physically irreducible residual."""

    def setUp(self):
        gate._STATUS_TARGET.clear()
        self.addCleanup(gate._STATUS_TARGET.clear)

    def _run(self, request_effects, git_fallback=None, expect_exit=True,
             status_error=None):
        event = {
            "issue": {"number": 7, "pull_request": {"url": "x"}},
            "repository": {"full_name": "Blockcast/frr"},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(event, handle)
            event_path = handle.name
        self.addCleanup(os.unlink, event_path)
        env = {
            "GITHUB_EVENT_PATH": event_path,
            "GITHUB_REPOSITORY": "Blockcast/frr",
            "GITHUB_TOKEN": "test-token",
        }
        calls = []
        effects = list(request_effects)

        def record_status(api, owner, repo, sha, token, state, description,
                          target_url=None):
            calls.append(("status", sha, state))
            if status_error is not None:
                raise status_error

        def record_request(url, token, method="GET", payload=None):
            calls.append(("request", url))
            effect = effects.pop(0) if effects else None
            if isinstance(effect, Exception):
                raise effect
            return effect

        with mock.patch.dict(os.environ, env), \
                mock.patch.object(gate, "_request", side_effect=record_request), \
                mock.patch.object(gate, "set_commit_status", side_effect=record_status), \
                mock.patch.object(gate, "_sleep", lambda seconds: None), \
                mock.patch.object(gate, "_git_pull_head_sha",
                                  return_value=git_fallback), \
                mock.patch.object(gate, "fetch_paginated", return_value=[]), \
                mock.patch.object(gate, "enrich_reviews_with_edit_times"):
            if expect_exit:
                with self.assertRaises(SystemExit) as caught:
                    gate.run()
                self.assertEqual(caught.exception.code, 1)
            else:
                gate.run()
        return [(c[1], c[2]) for c in calls if c[0] == "status"]

    def test_refetch_crash_after_probe_posts_error_to_probed_head(self):
        probe = {
            "number": 7,
            "state": "open",
            "draft": False,
            "head": {"sha": HEAD},
        }
        statuses = self._run([probe, RuntimeError("refetch boom")])
        self.assertEqual(statuses, [(HEAD, "pending"), (HEAD, "error")])

    def test_probe_retry_recovers_from_a_transient_failure(self):
        # One 5xx/rate-limit blip must no longer forfeit the head: attempt 2
        # succeeds, the claim lands, and the later refetch crash escalates it.
        probe = {
            "number": 7,
            "state": "open",
            "draft": False,
            "head": {"sha": HEAD},
        }
        statuses = self._run(
            [RuntimeError("transient 502"), probe, RuntimeError("refetch boom")]
        )
        self.assertEqual(statuses, [(HEAD, "pending"), (HEAD, "error")])

    def test_git_fallback_claims_the_head_when_rest_probe_is_down(self):
        # Review round 7 CRITICAL 2: the head comes from an independent
        # transport when every REST probe attempt fails, so the claim (and any
        # later crash escalation) still reaches the exact head whose comment
        # evidence changed -- stale green cannot survive a REST-plane blip.
        statuses = self._run(
            [
                RuntimeError("rest down"),
                RuntimeError("rest down"),
                RuntimeError("rest down"),
                RuntimeError("refetch boom"),
            ],
            git_fallback=HEAD,
        )
        self.assertEqual(statuses, [(HEAD, "pending"), (HEAD, "error")])

    def test_both_transports_failing_fails_the_run(self):
        # The irreducible residual: REST and git transport both unreachable
        # means no addressable commit exists anywhere -- and the invalidating
        # status write itself needs the REST plane. Non-zero exit is the only
        # remaining signal.
        statuses = self._run(
            [RuntimeError("rest down")] * 3,
            git_fallback=None,
        )
        self.assertEqual(statuses, [])

    def test_status_write_failure_after_git_fallback_still_exits_nonzero(self):
        # Review round 8 CRITICAL 2: git resolves the head but the REST plane
        # stays down, so the pending claim AND the crash-handler error write
        # both fail. Nothing addressed to the head can land -- the run must
        # exit non-zero so the required workflow check-run (the Actions-plane
        # backstop that needs no REST write from us) turns red. Both writes
        # must still have been ATTEMPTED against the exact fallback head.
        statuses = self._run(
            [RuntimeError("rest down")] * 4,
            git_fallback=HEAD,
            status_error=RuntimeError("statuses down"),
        )
        self.assertEqual(statuses, [(HEAD, "pending"), (HEAD, "error")])


class TestGitHeadFallbackParsing(unittest.TestCase):
    def test_parses_the_oid_column(self):
        self.assertEqual(
            gate._parse_ls_remote_head("%s\trefs/pull/7/head\n" % HEAD), HEAD
        )

    def test_rejects_non_oid_output(self):
        for output in ("", "not-a-sha\trefs/pull/7/head\n", "fatal: auth failed\n"):
            self.assertIsNone(gate._parse_ls_remote_head(output), repr(output))


class TestGitFallbackTokenHygiene(unittest.TestCase):
    """Review round 8 Important: /proc/<pid>/cmdline is readable by same-UID
    processes on the shared self-hosted runner, and subprocess exceptions
    embed argv -- so the token must never appear on the git command line. It
    travels via GIT_CONFIG_* environment variables, and any emitted error
    text is redacted as a second layer."""

    TOKEN = "sekret-token-value"

    def test_token_absent_from_argv_and_present_in_env_config(self):
        captured = {}

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["env"] = kwargs.get("env") or {}
            return subprocess.CompletedProcess(
                argv, 0, stdout="%s\trefs/pull/7/head\n" % HEAD, stderr=""
            )

        with mock.patch.object(gate.subprocess, "run", side_effect=fake_run):
            sha = gate._git_pull_head_sha("Blockcast", "frr", 7, self.TOKEN)
        self.assertEqual(sha, HEAD)
        joined = " ".join(captured["argv"])
        self.assertNotIn(self.TOKEN, joined)
        self.assertNotIn("x-access-token", joined)
        header_values = [
            value
            for key, value in captured["env"].items()
            if key.startswith("GIT_CONFIG_VALUE")
        ]
        expected = gate.base64.b64encode(
            ("x-access-token:%s" % self.TOKEN).encode()
        ).decode()
        self.assertTrue(
            any(expected in value for value in header_values),
            "credential must travel via GIT_CONFIG_* env: %s" % header_values,
        )

    def test_error_text_is_redacted(self):
        def fake_run(argv, **kwargs):
            raise RuntimeError("boom %s boom" % self.TOKEN)

        stderr = io.StringIO()
        with mock.patch.object(gate.subprocess, "run", side_effect=fake_run), \
                contextlib.redirect_stderr(stderr):
            self.assertIsNone(
                gate._git_pull_head_sha("Blockcast", "frr", 7, self.TOKEN)
            )
        output = stderr.getvalue()
        self.assertIn("git head fallback failed", output)
        self.assertNotIn(self.TOKEN, output)


class TestAuthorizationInversion(unittest.TestCase):
    """Review round 5 CRITICAL 1: prose must never authorize green. The
    conjunction probes below defeat the negation mask by construction (an
    unlisted pivot can always exist) -- under the inversion that mask error
    can no longer authorize anything, because a review without an explicit
    pass verdict or machine-readable zero counts contributes no clean
    signal. NOT-success is the fail-closed contract here; the negation mask
    only prevents false failures."""

    def test_conjunction_probes_cannot_authorize_green(self):
        for text in (
            "No reviewer responded and action required: fix the gate.",
            "No reviewer replied or changes requested: fix the gate.",
        ):
            body = attest(HEAD, text)
            state, _ = decide(reviews=[review("COMMENTED", body=body)])
            self.assertNotEqual(state, "success", repr(text))
            state, _ = decide(comments=[comment(body)])
            self.assertNotEqual(state, "success", repr(text))

    def test_bare_prose_review_no_longer_authorizes(self):
        # The pre-inversion behavior: an attested body whose only signal is
        # the ABSENCE of blocking prose. Silence is not authorization.
        body = attest(HEAD, "Looks good overall.")
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")

    def test_negated_request_changes_family_masks(self):
        # Review round 5 Important + round 7 Important: the "request changes"
        # affirmative family was scanned but had no negated forms in the mask,
        # so clean prose blocked. Round 7 adds the semi-modal "need not" /
        # "needn't" shapes. With CLEAN counts present these must authorize.
        for text in (
            "No need to request changes.",
            "We do not request changes.",
            "We need not request changes.",
            "We needn't request changes.",
        ):
            self.assertFalse(
                gate.has_action_required_language(text), repr(text)
            )
            body = attest(
                HEAD,
                text + "\n\n### Critical Issues (0)\n\n### Important Issues (0)\n",
            )
            state, _ = decide(reviews=[review("COMMENTED", body=body)])
            self.assertEqual(state, "pending", repr(text))

    def test_affirmative_need_to_request_changes_still_fails(self):
        # Adjacency control for the widened modal list: "need TO request
        # changes" and "not ONLY request changes" are affirmative -- an
        # intervening word breaks the negated-verb shape, so neither may mask.
        for text in (
            "We need to request changes here.",
            "You must not only request changes but also fix the docs.",
        ):
            self.assertTrue(gate.has_action_required_language(text), repr(text))


class TestPassBlockingContradiction(unittest.TestCase):
    """Review round 7 CRITICAL 3: an explicit pass verdict must not suppress
    surviving (un-negated) blocking prose in the same body. Contradiction
    resolves red, exactly as contradictory issue counts do."""

    CONTRADICTORY = (
        "### Recommended Action\n\nMerge.\n\nAction required: fix the gate.\n"
    )

    def test_pass_plus_blocking_prose_fails_in_a_review(self):
        body = attest(HEAD, self.CONTRADICTORY)
        state, _ = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "failure")

    def test_pass_plus_blocking_prose_fails_in_a_comment(self):
        body = attest(HEAD, self.CONTRADICTORY)
        state, _ = decide(comments=[comment(body)])
        self.assertEqual(state, "failure")

    def test_pass_plus_negated_prose_stays_clean(self):
        # The mask still protects genuinely negated prose alongside a pass:
        # only SURVIVING affirmative phrases contradict. The comment path is
        # positive-inert (pending, not failure); the review path lands the
        # clean-commented pending.
        body = attest(
            HEAD, "### Recommended Action\n\nMerge.\n\nNo action required.\n"
        )
        state, desc = decide(comments=[comment(body)])
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)
        state, desc = decide(reviews=[review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")
        self.assertIn("no blocking findings", desc)


class TestOverrideMaskAmbiguity(unittest.TestCase):
    """Review round 7 CRITICAL 1: the negation mask can consume a REAL
    blocking phrase behind an unlisted pivot ("No reviewer responded AND
    action required"). Under the inversion that body authorizes nothing --
    but the maintainer override then cleared the head, laundering the mask
    error into green. Bodies whose only escape from a blocking verdict is
    the mask (no pass verdict, no zero counts) are ambiguous, and the
    override refuses them."""

    AMBIGUOUS = "No reviewer responded and action required: fix gate."

    def _with_override(self, reviews):
        return decide(
            reviews=reviews,
            comments=[comment(override_body(HEAD), login=HUMAN)],
            labels=[OVERRIDE],
            trusted={HUMAN},
        )

    def test_mask_ambiguous_review_stays_pending_despite_override_combo(self):
        # Ally's round-7 probe: attested review whose blocking phrase the
        # mask erased, plus the full FORMER override combination. With the
        # override removed (round 3), nothing can clear it.
        body = attest(HEAD, self.AMBIGUOUS)
        state, _ = self._with_override([review("COMMENTED", body=body)])
        self.assertEqual(state, "pending")

    def test_mask_ambiguous_comment_stays_pending_despite_override_combo(self):
        state, desc = decide(
            comments=[
                comment(attest(HEAD, self.AMBIGUOUS)),
                comment(override_body(HEAD), login=HUMAN),
            ],
            labels=[OVERRIDE],
            trusted={HUMAN},
        )
        self.assertEqual(state, "pending")

    def test_zero_count_body_with_negated_prose_holds_clean_commented(self):
        # The normal clean-commented -> override flow must survive: zero
        # counts are Ally's machine-readable summary and outrank prose
        # scanning, so "No action required" alongside them is not ambiguous.
        body = attest(
            HEAD,
            "### Critical Issues (0)\n\n### Important Issues (0)\n\n"
            "No action required.\n",
        )
        state, desc = self._with_override([review("COMMENTED", body=body)])
        # Round 3: only an App-seat APPROVED review clears; the clean-
        # commented state holds pending even with the former override.
        self.assertEqual(state, "pending")
        self.assertIn("App-seat APPROVED", desc)

    def test_reviewer_never_ran_stays_pending_despite_override_combo(self):
        state, desc = self._with_override([])
        self.assertEqual(state, "pending")
        self.assertIn("Waiting for Ally review", desc)

    def test_ambiguity_is_not_laundered_by_machine_readable_all_clears(self):
        # Review round 8 CRITICAL 1: adding `ally-verdict: pass` or both
        # zero-count headings to a mask-erased blocking body must not make it
        # authorize. Both combinations, both signal paths.
        for all_clear in (
            "\n\nally-verdict: pass\n",
            "\n\n### Critical Issues (0)\n\n### Important Issues (0)\n",
        ):
            body = attest(HEAD, self.AMBIGUOUS + all_clear)
            state, _ = decide(comments=[comment(body)])
            self.assertEqual(state, "pending", repr(all_clear))
            state, _ = decide(reviews=[review("COMMENTED", body=body)])
            self.assertEqual(state, "pending", repr(all_clear))
            # ...and the former override combination clears nothing either.
            state, _ = self._with_override([review("COMMENTED", body=body)])
            self.assertEqual(state, "pending", repr(all_clear))

    def test_masked_blocking_ambiguity_unit_matrix(self):
        cases = [
            # Coordinator-crossing span: the pivot reading may be blocking.
            (self.AMBIGUOUS, True),
            # All-clears do not launder ambiguity (round 8).
            (self.AMBIGUOUS + "\nally-verdict: pass", True),
            (
                self.AMBIGUOUS
                + "\n### Critical Issues (0)\n### Important Issues (0)\n",
                True,
            ),
            # Distributed negation across a coordinator is regex-
            # indistinguishable from the pivot reading: a false HOLD by
            # design, never a false green.
            ("No issues found or changes requested.", True),
            # Surviving blocking phrase: the failure paths own it.
            ("Action required: fix the gate.", False),
            # Simple negated all-clears mask under BOTH variants.
            ("No action required.", False),
            ("No further changes requested.", False),
            # Per-conjunct negation re-states "no", so strict spans never
            # need to cross the coordinator.
            ("No critical issues and no changes requested.", False),
            # No affirmative vocabulary at all.
            ("Looks good overall.", False),
        ]
        for text, expected in cases:
            self.assertEqual(
                gate.masked_blocking_ambiguity(text), expected, repr(text)
            )


class TestSuccessExclusivity(unittest.TestCase):
    """Round 2 of this PR's review: `success` has exactly ONE producer -- the
    formal exact-head App-seat APPROVED review. Every other positive-looking
    shape of Ally evidence lands pending, and positive comment evidence is
    inert entirely. This is the machine-checkable form of the sole-authority
    invariant this change claims."""

    def test_only_a_formal_app_seat_approval_returns_success(self):
        cases = [
            ("formal-app-seat-approved",
             dict(reviews=[review("APPROVED")]), "success"),
            ("clean-commented-review",
             dict(reviews=[review("COMMENTED", body=CLEAN)]), "pending"),
            ("clean-consolidated-comment",
             dict(comments=[comment(CLEAN)]), "pending"),
            ("pass-verdict-comment",
             dict(comments=[comment(
                 attest(HEAD, "### Recommended Action\n\nMerge.\n"))]),
             "pending"),
            ("user-seat-approval",
             dict(reviews=[review("APPROVED", login="allyblockcast",
                                  utype="User")]), "pending"),
            ("unattested-app-approval",
             dict(reviews=[review("APPROVED", body=attest(OTHER))]), "pending"),
            ("app-self-approval",
             dict(reviews=[review("APPROVED")], author="app/allyblockcast"),
             "pending"),
            ("trusted-distinct-approval-on-app-authored-pr",
             dict(reviews=[review("APPROVED", login=HUMAN, utype="User")],
                  author="app/allyblockcast", trusted={HUMAN}), "pending"),
        ]
        for name, kwargs, expected in cases:
            state, _ = decide(**kwargs)
            self.assertEqual(state, expected, name)

    def test_later_clean_comment_cannot_outrank_a_formal_blocking_review(self):
        # The round-2 Critical's second half: latest_signal() must never let
        # a clean comment supersede formal blocking evidence. Inert positive
        # comments cannot -- the blocking review stays the newest signal.
        state, _ = decide(
            reviews=[review("CHANGES_REQUESTED", at="2026-07-27T09:00:00Z")],
            comments=[comment(CLEAN, at="2026-07-27T12:00:00Z")],
        )
        self.assertEqual(state, "failure")

    def test_later_clean_comment_does_not_withdraw_a_formal_approval(self):
        state, _ = decide(
            reviews=[review("APPROVED", at="2026-07-27T09:00:00Z")],
            comments=[comment(CLEAN, at="2026-07-27T12:00:00Z")],
        )
        self.assertEqual(state, "success")

    def test_later_blocking_comment_still_fails_over_a_formal_approval(self):
        state, _ = decide(
            reviews=[review("APPROVED", at="2026-07-27T09:00:00Z")],
            comments=[comment(attest(HEAD, "### Critical Issues (1)\n"),
                              at="2026-07-27T12:00:00Z")],
        )
        self.assertEqual(state, "failure")


class TestApprovedBodyContradiction(unittest.TestCase):
    """Round 4 CRITICAL 1: blocking body evidence is classified before the
    state branches, so an exact-head App APPROVED whose body still carries
    machine-readable blocking findings (or surviving action-required prose)
    is a contradiction and resolves red -- it must never green the gate."""

    def test_approved_with_nonzero_counts_fails(self):
        body = attest(HEAD, "### Critical Issues (1)\n")
        state, desc = decide(reviews=[review("APPROVED", body=body)])
        self.assertEqual(state, "failure")
        self.assertIn("blocking findings", desc)

    def test_approved_with_action_required_prose_fails(self):
        body = attest(HEAD, "Action required: fix the decode bounds.\n")
        state, _ = decide(reviews=[review("APPROVED", body=body)])
        self.assertEqual(state, "failure")

    def test_approved_with_changes_requested_verdict_fails(self):
        body = attest(
            HEAD, "### Recommended Action\n\nRequest changes before merge.\n"
        )
        state, _ = decide(reviews=[review("APPROVED", body=body)])
        self.assertEqual(state, "failure")

    def test_approved_with_negated_prose_still_greens(self):
        # The negation mask keeps protecting genuine all-clear prose in an
        # approval body -- only SURVIVING affirmatives contradict.
        body = attest(
            HEAD,
            "No action required.\n\n### Critical Issues (0)\n\n"
            "### Important Issues (0)\n",
        )
        state, _ = decide(reviews=[review("APPROVED", body=body)])
        self.assertEqual(state, "success")

    def test_approved_with_masked_ambiguous_body_stays_pending(self):
        # Round-8 invariant extended to the APPROVED branch: a body whose
        # only escape from a blocking phrase is the lenient mask may not
        # authorize green even with the formal state. Fail-closed = pending.
        body = attest(
            HEAD, "No reviewer responded and action required: fix the gate.\n"
        )
        state, _ = decide(reviews=[review("APPROVED", body=body)])
        self.assertEqual(state, "pending")

    def test_self_review_with_blocking_counts_fails(self):
        # Body-level blocking evidence now fails closed BEFORE the
        # self-review demotion, matching the comment path's rule.
        body = attest(HEAD, "### Important Issues (2)\n")
        state, _ = decide(
            reviews=[review("APPROVED", body=body)], author="app/allyblockcast"
        )
        self.assertEqual(state, "failure")


class TestPerLoginSeatReduction(unittest.TestCase):
    """Round 4 CRITICAL 2: Ally's App and User seats are distinct actors.
    A later App approval must not erase a User-seat CHANGES_REQUESTED the
    User identity never withdrew; only the same identity supersedes its own
    objection."""

    def _user_review(self, state, body=None, **kw):
        return review(state, body=body, login="allyblockcast", utype="User", **kw)

    def test_app_approval_does_not_erase_user_seat_changes_requested(self):
        state, desc = decide(
            reviews=[
                self._user_review("CHANGES_REQUESTED", at="2026-07-27T09:00:00Z"),
                review("APPROVED", at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")
        self.assertIn("requested changes", desc)

    def test_user_seat_withdraws_its_own_objection_via_attested_approval(self):
        state, _ = decide(
            reviews=[
                self._user_review("CHANGES_REQUESTED", at="2026-07-27T09:00:00Z"),
                self._user_review(
                    "APPROVED", body=attest(HEAD), at="2026-07-27T10:00:00Z"
                ),
                review("APPROVED", at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "success")

    def test_unattested_user_approval_does_not_withdraw(self):
        # An approval that neither matches the head nor attests it binds
        # nothing in either direction; the User objection stands.
        state, _ = decide(
            reviews=[
                self._user_review("CHANGES_REQUESTED", at="2026-07-27T09:00:00Z"),
                self._user_review(
                    "APPROVED",
                    body=attest(OTHER),
                    commit=OTHER,
                    at="2026-07-27T10:00:00Z",
                ),
                review("APPROVED", at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")

    def test_user_withdrawal_newest_does_not_unseat_app_approval(self):
        # Selection is by status priority after per-login reduction: with no
        # outstanding blocker, the App seat's standing approval greens even
        # when a User-seat placeholder is globally newest.
        state, _ = decide(
            reviews=[
                review("APPROVED", at="2026-07-27T12:00:00Z"),
                self._user_review(
                    "APPROVED", body=attest(HEAD), at="2026-07-27T13:00:00Z"
                ),
            ]
        )
        self.assertEqual(state, "success")

    def test_apps_own_newer_clean_review_still_supersedes_its_approval(self):
        # Same-login supersession is preserved: the App seat's newest signal
        # is its current state, so its own later clean COMMENTED review
        # returns the gate to pending-awaiting-approval.
        state, desc = decide(
            reviews=[
                review("APPROVED", at="2026-07-27T12:00:00Z"),
                review("COMMENTED", body=CLEAN, at="2026-07-27T13:00:00Z"),
            ]
        )
        self.assertEqual(state, "pending")
        self.assertIn("awaiting an App-seat APPROVED", desc)


class TestSeatAwareReduction(unittest.TestCase):
    """Round 2 of the #47 review: reduction keys are (login, seat), and
    ambiguous approvals fail closed against prior state in both directions.
    """

    AMBIGUOUS = "No reviewer responded and action required: fix the gate.\n"

    def test_normalized_app_login_does_not_merge_seats(self):
        # GitHub REST may normalize the App login to the same string as the
        # shared User login. The seats are still distinct actors: a
        # normalized App approval must not erase the User seat's objection.
        state, desc = decide(
            reviews=[
                review("CHANGES_REQUESTED", login="allyblockcast", utype="User",
                       at="2026-07-27T09:00:00Z"),
                review("APPROVED", login="allyblockcast", utype="Bot",
                       at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")
        self.assertIn("requested changes", desc)

    def test_same_seat_same_login_still_supersedes(self):
        # The seat-aware key must not break same-actor withdrawal: the same
        # (login, seat) pair's newer approval supersedes its own objection.
        state, _ = decide(
            reviews=[
                review("CHANGES_REQUESTED", login="allyblockcast", utype="Bot",
                       at="2026-07-27T09:00:00Z"),
                review("APPROVED", login="allyblockcast", utype="Bot",
                       at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "success")

    def test_apps_own_ambiguous_approval_supersedes_its_success(self):
        # An ambiguous approval is the seat's newest formal verdict: the
        # earlier clean success is no longer current, and the gate pends.
        state, desc = decide(
            reviews=[
                review("APPROVED", at="2026-07-27T10:00:00Z"),
                review("APPROVED", body=attest(HEAD, self.AMBIGUOUS),
                       at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "pending")
        self.assertIn("ambiguous", desc)

    def test_ambiguous_user_approval_does_not_withdraw_blocker(self):
        # Fail closed in the other direction: an ambiguous User-seat
        # approval must not act as that seat's withdrawal, so the objection
        # survives a standing App approval.
        state, _ = decide(
            reviews=[
                review("CHANGES_REQUESTED", login="allyblockcast", utype="User",
                       at="2026-07-27T09:00:00Z"),
                review("APPROVED", login="allyblockcast", utype="User",
                       body=attest(HEAD, self.AMBIGUOUS),
                       at="2026-07-27T10:00:00Z"),
                review("APPROVED", at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")

    def test_unambiguous_user_approval_still_withdraws_after_ambiguous(self):
        # The seat's own UNAMBIGUOUS approval remains the withdrawal path
        # even after an ambiguous attempt.
        state, _ = decide(
            reviews=[
                review("CHANGES_REQUESTED", login="allyblockcast", utype="User",
                       at="2026-07-27T09:00:00Z"),
                review("APPROVED", login="allyblockcast", utype="User",
                       body=attest(HEAD, self.AMBIGUOUS),
                       at="2026-07-27T10:00:00Z"),
                review("APPROVED", login="allyblockcast", utype="User",
                       body=attest(HEAD), at="2026-07-27T11:00:00Z"),
                review("APPROVED", at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "success")

    def test_reduction_is_input_order_independent_across_sources(self):
        # Round 3 of the #47 review: decide() concatenates all reviews
        # before all comments, so the User seat's ambiguous approval (10:00)
        # used to install first and that seat's OLDER blocking comment
        # (09:00) was discarded as stale -- erasing the blocker by input
        # order. The per-actor fold now sorts chronologically first: the
        # blocker installs, the ambiguous approval cannot withdraw it, and
        # the separate App approval must not green the head.
        state, _ = decide(
            reviews=[
                review("APPROVED", login="allyblockcast", utype="User",
                       body=attest(HEAD, self.AMBIGUOUS),
                       at="2026-07-27T10:00:00Z"),
                review("APPROVED", at="2026-07-27T12:00:00Z"),
            ],
            comments=[
                comment(attest(HEAD, "### Critical Issues (1)\n"),
                        login="allyblockcast", utype="User",
                        at="2026-07-27T09:00:00Z"),
            ],
        )
        self.assertEqual(state, "failure")

    def test_same_second_clean_and_ambiguous_approvals_resolve_ambiguous(self):
        # Round 3 of the #47 review: at an equal timestamp ambiguity
        # outranks a non-blocking success, in either input order, so a
        # clean and an ambiguous App approval in the same second land
        # pending rather than letting list order pick success.
        clean = review("APPROVED", at="2026-07-27T12:00:00Z")
        ambiguous = review("APPROVED", body=attest(HEAD, self.AMBIGUOUS),
                           at="2026-07-27T12:00:00Z")
        for ordering in ([clean, ambiguous], [ambiguous, clean]):
            state, desc = decide(reviews=list(ordering))
            self.assertEqual(state, "pending")
            self.assertIn("ambiguous", desc)

    def test_same_second_failure_still_outranks_ambiguity(self):
        # Tie precedence is failure > ambiguity > non-blocking.
        state, _ = decide(
            reviews=[
                review("APPROVED", login="allyblockcast", utype="User",
                       body=attest(HEAD, self.AMBIGUOUS),
                       at="2026-07-27T12:00:00Z"),
                review("CHANGES_REQUESTED", login="allyblockcast", utype="User",
                       at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")

    def test_same_second_success_and_clean_review_resolve_pending(self):
        # Round 4 of the #47 review: success and clean-commented both ranked
        # 0, so REST list order decided a same-second approval-vs-clean-
        # review tie. The full precedence (failure > ambiguity >
        # clean/pending > success) now resolves an equal-second
        # contradiction away from green in either input order.
        approved = review("APPROVED", at="2026-07-27T12:00:00Z")
        clean = review("COMMENTED", body=CLEAN, at="2026-07-27T12:00:00Z")
        for ordering in ([approved, clean], [clean, approved]):
            state, desc = decide(reviews=list(ordering))
            self.assertEqual(state, "pending")
            self.assertIn("awaiting an App-seat APPROVED", desc)

    def test_app_login_aliases_group_as_one_actor(self):
        # Round 5 of the #47 review: REST may expose the same App seat as
        # `allyblockcast[bot]` in one row and normalized `allyblockcast` in
        # another. Splitting them left an older clean approval standing as a
        # separate current success beside the App's newer ambiguous verdict.
        # Both alias directions must reduce to one actor: the ambiguous
        # approval is that actor's newest signal, and the gate pends.
        for old_login, new_login in (
            ("allyblockcast[bot]", "allyblockcast"),
            ("allyblockcast", "allyblockcast[bot]"),
        ):
            state, desc = decide(
                reviews=[
                    review("APPROVED", login=old_login,
                           at="2026-07-27T10:00:00Z"),
                    review("APPROVED", login=new_login,
                           body=attest(HEAD, self.AMBIGUOUS),
                           at="2026-07-27T12:00:00Z"),
                ]
            )
            self.assertEqual(state, "pending", (old_login, new_login))
            self.assertIn("ambiguous", desc)

    def test_alias_canonicalization_keeps_seats_apart(self):
        # The round-2 property survives round 5: a normalized App approval
        # and a User-seat objection under the SAME login string stay
        # distinct actors (the seat component of the key separates them).
        state, _ = decide(
            reviews=[
                review("CHANGES_REQUESTED", login="allyblockcast", utype="User",
                       at="2026-07-27T09:00:00Z"),
                review("APPROVED", login="allyblockcast[bot]", utype="Bot",
                       at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")

    def test_same_second_clean_and_ambiguous_bucket_cannot_clear_blocker(self):
        # Round 6 of the #47 review: folding individual signals let the
        # clean approval withdraw the 09:00 blocker one step before the
        # same-second ambiguous approval was processed, and a separate App
        # approval then greened. Each timestamp bucket now collapses to its
        # highest fail-closed precedence first: the 10:00 bucket is
        # ambiguous, ambiguity cannot withdraw the blocker, and the head
        # stays failure -- in either bucket input order.
        blocker = review("CHANGES_REQUESTED", login="allyblockcast",
                         utype="User", at="2026-07-27T09:00:00Z")
        clean = review("APPROVED", login="allyblockcast", utype="User",
                       body=attest(HEAD), at="2026-07-27T10:00:00Z")
        ambiguous = review("APPROVED", login="allyblockcast", utype="User",
                           body=attest(HEAD, self.AMBIGUOUS),
                           at="2026-07-27T10:00:00Z")
        app = review("APPROVED", at="2026-07-27T12:00:00Z")
        for ordering in ([blocker, clean, ambiguous, app],
                         [blocker, ambiguous, clean, app]):
            state, _ = decide(reviews=list(ordering))
            self.assertEqual(state, "failure")

    def test_newer_ambiguous_commented_review_supersedes_approval(self):
        # Round 6 of the #47 review: an attested App-seat ambiguous
        # COMMENTED review was discarded, so an older App approval stayed
        # green. It is now the seat's current non-success signal: the gate
        # returns to pending.
        state, desc = decide(
            reviews=[
                review("APPROVED", at="2026-07-27T09:00:00Z"),
                review("COMMENTED", body=attest(HEAD, self.AMBIGUOUS),
                       at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "pending")
        self.assertIn("ambiguous", desc)

    def test_ambiguous_commented_review_still_cannot_withdraw_blocker(self):
        # The emitted ambiguous review obeys the same reduction rule as
        # ambiguous approvals: it never withdraws its own seat's blocker.
        # Both signals are App-seat here -- a User-seat ambiguous COMMENTED
        # emits nothing at all (the branch is App-gated before ambiguity).
        state, _ = decide(
            reviews=[
                review("CHANGES_REQUESTED", at="2026-07-27T09:00:00Z"),
                review("COMMENTED", body=attest(HEAD, self.AMBIGUOUS),
                       at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")

    def test_edited_old_approval_cannot_withdraw_newer_objection(self):
        # Round 7 of the #47 review: withdrawal authority binds to
        # submitted_at. The edit-aware clock let an old User approval,
        # body-edited AFTER the same identity's newer CHANGES_REQUESTED,
        # become the actor's newest clean placeholder -- withdrawing an
        # objection no new formal review ever withdrew, and letting a
        # separate App approval green the head.
        state, _ = decide(
            reviews=[
                review("APPROVED", login="allyblockcast", utype="User",
                       body=attest(HEAD), at="2026-07-27T09:00:00Z",
                       edited="2026-07-27T13:00:00Z"),
                review("CHANGES_REQUESTED", login="allyblockcast", utype="User",
                       at="2026-07-27T12:00:00Z"),
                review("APPROVED", at="2026-07-27T14:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")

    def test_edited_old_app_approval_cannot_outrank_newer_clean_review(self):
        # The same submitted_at rule for the success signal: editing an old
        # App approval's body must not rank it past the seat's newer clean
        # COMMENTED look, which holds the gate pending awaiting a NEW formal
        # approval.
        state, desc = decide(
            reviews=[
                review("APPROVED", at="2026-07-27T09:00:00Z",
                       edited="2026-07-27T13:00:00Z"),
                review("COMMENTED", body=CLEAN, at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "pending")
        self.assertIn("awaiting an App-seat APPROVED", desc)

    def test_review_edited_to_add_blocking_still_ranks_newest(self):
        # The fail-closed half of the round-7 rule is unchanged: blocking
        # evidence keeps the edit-aware clock, so an old clean review edited
        # to ADD findings outranks the seat's newer approval.
        state, _ = decide(
            reviews=[
                review("COMMENTED",
                       body=attest(HEAD, "### Critical Issues (1)\n"),
                       at="2026-07-27T09:00:00Z",
                       edited="2026-07-27T13:00:00Z"),
                review("APPROVED", at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")

    def test_edited_old_objection_cannot_resurrect_past_withdrawal(self):
        # Round 8 of the #47 review: the CHANGES_REQUESTED state signal
        # binds to submitted_at too. Editing an old objection's plain body
        # (no blocking counts or prose) must not re-time the STATE past the
        # same seat's newer formal approval -- the 12:00 approval remains
        # the User seat's current verdict and the App approval greens.
        state, _ = decide(
            reviews=[
                review("CHANGES_REQUESTED", login="allyblockcast", utype="User",
                       at="2026-07-27T09:00:00Z",
                       edited="2026-07-27T13:00:00Z"),
                review("APPROVED", login="allyblockcast", utype="User",
                       body=attest(HEAD), at="2026-07-27T12:00:00Z"),
                review("APPROVED", at="2026-07-27T14:00:00Z"),
            ]
        )
        self.assertEqual(state, "success")

    def test_objection_edited_to_add_blocking_counts_stays_red(self):
        # The symmetric fail-closed pin: when the edit ADDS machine-readable
        # blocking evidence, the edit-aware body-evidence branch (not the
        # state branch) emits the failure at edit time, outranking the
        # seat's 12:00 withdrawal.
        state, _ = decide(
            reviews=[
                review("CHANGES_REQUESTED", login="allyblockcast", utype="User",
                       body=attest(HEAD, "### Critical Issues (1)\n"),
                       at="2026-07-27T09:00:00Z",
                       edited="2026-07-27T13:00:00Z"),
                review("APPROVED", login="allyblockcast", utype="User",
                       body=attest(HEAD), at="2026-07-27T12:00:00Z"),
                review("APPROVED", at="2026-07-27T14:00:00Z"),
            ]
        )
        self.assertEqual(state, "failure")


if __name__ == "__main__":
    unittest.main()
