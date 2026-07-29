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


def comment(body, login="allyblockcast[bot]", at="2026-07-27T10:00:00Z", updated=None):
    row = {"body": body, "user": {"login": login}, "created_at": at}
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
        state, desc = decide(reviews=[review("COMMENTED", body=CONSOLIDATED)])
        self.assertEqual(state, "pending")
        self.assertIn("no blocking findings", desc)
        self.assertIn(OVERRIDE, desc)

    def test_clean_commented_label_alone_does_not_clear(self):
        """The label is PR-scoped and survives `synchronize`. On its own it
        would clear every later unreviewed head, so it is necessary but not
        sufficient."""
        state, desc = decide(
            reviews=[review("COMMENTED", body=CONSOLIDATED)], labels=[OVERRIDE]
        )
        self.assertEqual(state, "pending")
        self.assertIn("review-gate-override: <full head SHA>", desc)

    def test_clean_commented_clears_with_label_and_head_attestation(self):
        state, desc = decide(
            reviews=[review("COMMENTED", body=CONSOLIDATED)],
            comments=[comment(override_body(HEAD), login=HUMAN)],
            labels=[OVERRIDE],
            trusted={HUMAN},
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
        self.assertEqual(state, "success")


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
        self.assertIn("review-gate-override: <full head SHA>", desc)

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

    def test_unedited_ordering_is_unchanged(self):
        blocking = CONSOLIDATED + "### Important Issues (1)\n"
        state, _ = decide(
            comments=[
                comment(blocking, at="2026-07-27T09:00:00Z"),
                comment(CLEAN, at="2026-07-27T12:00:00Z"),
            ]
        )
        self.assertEqual(state, "success")

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
                review("COMMENTED", body=CONSOLIDATED, at="2026-07-27T12:00:00Z"),
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

    def _comment_state(self, verdict_line):
        body = attest(HEAD, "### Recommended Action\n\n%s\n" % verdict_line)
        state, _ = decide(comments=[comment(body)])
        return state

    def test_standalone_merge_is_a_pass(self):
        self.assertEqual(self._comment_state("Merge."), "success")

    def test_merge_only_after_changes_is_not_a_pass(self):
        self.assertEqual(
            self._comment_state("Merge only after requested changes are addressed."),
            "pending",
        )

    def test_merge_after_fixes_is_not_a_pass(self):
        self.assertEqual(self._comment_state("Merge after fixes"), "pending")

    def test_merge_must_be_blocked_is_not_a_pass(self):
        self.assertEqual(self._comment_state("Merge must be blocked"), "pending")


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
        body = CLEAN + "\n### Critical Issues (0)\n"
        state, _ = decide(comments=[comment(body)])
        self.assertEqual(state, "success")


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
        self.assertEqual(state, "success")

    def test_authorization_comment_binds_an_empty_body_approval(self):
        state, _ = decide(
            reviews=[self._approve("")],
            comments=[comment(override_body(HEAD), login=HUMAN)],
            author="app/allyblockcast",
            trusted={HUMAN},
        )
        self.assertEqual(state, "success")

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
