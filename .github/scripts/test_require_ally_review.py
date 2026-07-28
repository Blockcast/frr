#!/usr/bin/env python3
"""Fixtures pinning every load-bearing branch of require-ally-review.py.

This suite is the mitigation for hand-porting a security-relevant gate from
the original JavaScript: without it, a subtle translation slip would silently
weaken a merge control. Each test names the property it protects.

Stdlib only, no network -- decide() is a pure function.

Run: python3 -m unittest discover -s .github/scripts -p 'test_*.py'
"""

import importlib.util
import os
import unittest

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
           assoc="NONE", utype="Bot"):
    if body is None:
        body = attest(commit)
    return {
        "state": state,
        "commit_id": commit,
        "body": body,
        "user": {"login": login, "type": utype},
        "submitted_at": at,
        "author_association": assoc,
    }


def comment(body, login="allyblockcast[bot]", at="2026-07-27T10:00:00Z"):
    return {"body": body, "user": {"login": login}, "created_at": at}


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
        state, desc = decide(reviews=[review("COMMENTED", body=CONSOLIDATED)])
        self.assertEqual(state, "pending")
        self.assertIn("no blocking findings", desc)
        self.assertIn(OVERRIDE, desc)

    def test_clean_commented_clears_with_override_label(self):
        state, desc = decide(
            reviews=[review("COMMENTED", body=CONSOLIDATED)], labels=[OVERRIDE]
        )
        self.assertEqual(state, "success")
        self.assertIn("overridden", desc)


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
        self.assertIn(OVERRIDE, desc)


class TestSelfReview(unittest.TestCase):
    """Branch 7 — an Ally-authored PR cannot be cleared by Ally's own review."""

    def test_self_review_approval_is_demoted_to_pending(self):
        state, desc = decide(
            reviews=[review("APPROVED")], author="app/allyblockcast"
        )
        self.assertEqual(state, "pending")
        self.assertIn("not authoritative", desc)

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
        self.assertEqual(state, "success")
        self.assertIn("distinct reviewer", desc)

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
        self.assertEqual(state, "success")

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
    """Consolidated / issue-link comments count as signals for the head."""

    def test_consolidated_comment_with_zero_counts_is_clean(self):
        state, _ = decide(comments=[comment(CLEAN)])
        self.assertEqual(state, "success")

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
        state, _ = decide(comments=[comment(CLEAN)])
        self.assertEqual(state, "success")


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
        self.assertEqual(state, "success")


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
        clean = CONSOLIDATED
        blocking = CONSOLIDATED + "### Important Issues (1)\n"
        state, _ = decide(
            reviews=[
                review("COMMENTED", body=blocking, at="2026-07-27T09:00:00Z"),
                review("COMMENTED", body=clean, at="2026-07-27T12:00:00Z"),
            ]
        )
        # Newest is clean -> pending (not failure): recency governs.
        self.assertEqual(state, "pending")


if __name__ == "__main__":
    unittest.main()
