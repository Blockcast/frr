#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class TestDimtLifecycleWiring(unittest.TestCase):
    def test_kernel_requests_require_positive_ack(self):
        encoder = (ROOT / "zebra" / "if_netlink.c").read_text()
        batch = (ROOT / "zebra" / "kernel_netlink.c").read_text()

        for flag in ("NLM_F_CREATE", "NLM_F_EXCL", "NLM_F_ACK"):
            self.assertIn(flag, encoder)
        self.assertIn("RTM_NEWADDR", encoder)
        self.assertIn("RTM_DELLINK", encoder)
        self.assertIn("err == 1", batch)
        self.assertIn("DIMT_TUNNEL_DEL\n\t\t\t     ? ZEBRA_DPLANE_REQUEST_FAILURE", batch)

    def test_owner_results_are_correlated_by_tunnel_id(self):
        zclient = (ROOT / "lib" / "zclient.c").read_text()
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()

        self.assertIn("stream_putl(s, notify->tunnel_id)", zclient)
        self.assertIn("zserv_find_client_session", dimt)
        for result in (
            "ZAPI_DIMT_TUNNEL_INSTALLED",
            "ZAPI_DIMT_TUNNEL_FAIL_INSTALL",
            "ZAPI_DIMT_TUNNEL_REMOVED",
            "ZAPI_DIMT_TUNNEL_REMOVE_FAIL",
        ):
            self.assertIn(result, dimt)

    def test_outer_resolution_rejects_dimt_nexthops(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()

        self.assertIn("rib_match(afi, SAFI_UNICAST", dimt)
        self.assertIn("ALL_NEXTHOPS_PTR", dimt)
        self.assertIn("zebra_dimt_if_lifecycle_owned", dimt)
        self.assertIn("ZAPI_DIMT_TUNNEL_FAIL_INSTALL", dimt)

    def test_delete_revalidates_interface_and_cleanup_retries(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()

        self.assertIn("zebra_dimt_tunnel_resolve_ifindex(entry)", dimt)
        self.assertIn("hook_register_prio(if_del, 0, zebra_dimt_if_del)", dimt)
        cleanup_branch = dimt.split("if (entry->state == ZEBRA_DIMT_CLEANUP)", 1)[1]
        self.assertIn("zebra_dimt_tunnel_cleanup_link(entry)", cleanup_branch)

    def test_new_dataplane_api_version_and_vrf_scope_are_explicit(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        dplane = (ROOT / "zebra" / "zebra_dplane.c").read_text()
        l2 = (ROOT / "zebra" / "zebra_l2.h").read_text()

        self.assertIn("zvrf_id(zvrf) != VRF_DEFAULT", dimt)
        self.assertIn("MAKE_FRRVERSION(4, 1, 0)", dplane)
        self.assertLess(l2.index("link_nsid"), l2.index("encap_type"))

    def test_address_encoder_revalidates_dimt_link_identity(self):
        encoder = (ROOT / "zebra" / "if_netlink.c").read_text()
        address_branch = encoder.split(
            "if (dimt->phase == ZEBRA_DIMT_TUNNEL_ADDRESS)", 1
        )[1].split("RTM_NEWADDR", 1)[0]

        self.assertIn("netlink_dimt_if_matches(ctx, dimt)", address_branch)

    def test_delete_worker_revalidates_dimt_link_identity(self):
        encoder = (ROOT / "zebra" / "if_netlink.c").read_text()
        delete_put = encoder.split("netlink_put_dimt_tunnel_msg", 1)[1]

        self.assertIn("netlink_dimt_if_matches(ctx, dimt)", delete_put)
        self.assertIn("ZEBRA_DPLANE_REQUEST_SUCCESS", delete_put)

    def test_delete_encoder_revalidates_and_binds_to_ifindex(self):
        encoder = (ROOT / "zebra" / "if_netlink.c").read_text()
        delete_branch = encoder.split(
            "dplane_ctx_get_op(ctx) == DPLANE_OP_DIMT_TUNNEL_DEL) {", 1
        )[1].split("RTM_NEWLINK", 1)[0]

        # Identity is revalidated at encode time, and the RTM_DELLINK binds
        # to the validated ifindex -- the identity Linux never reuses until
        # wrap -- NOT the trivially reusable dimt-%08x name, so a same-name
        # replacement created after encoding cannot be deleted.
        self.assertIn("netlink_dimt_if_matches(ctx, dimt)", delete_branch)
        self.assertIn("RTM_DELLINK", delete_branch)
        self.assertIn("req->ifi.ifi_index = dimt->delete_ifindex", delete_branch)
        self.assertNotIn("IFLA_IFNAME", delete_branch)

    def test_worker_matcher_checks_full_identity_including_mtu(self):
        encoder = (ROOT / "zebra" / "if_netlink.c").read_text()
        matcher = encoder.split("static bool netlink_dimt_if_matches", 1)[1]
        matcher = matcher.split("static ssize_t", 1)[0]

        for check in (
            "ZAPI_DIMT_TUNNEL_KEY_PRESENT",
            "ZAPI_DIMT_TUNNEL_MTU_PRESENT",
            "encap_dport",
        ):
            self.assertIn(check, matcher)

    def test_add_during_delete_rejects_instead_of_rebinding_owner(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        identical_add = dimt.split("if (add) {", 1)[1]

        deleting_reject = identical_add.index(
            "entry->state == ZEBRA_DIMT_DELETING"
        )
        rebind = identical_add.index(
            "entry->ctx.owner_session = ctx.owner_session"
        )
        self.assertLess(deleting_reject, rebind)

    def test_uncertain_create_result_keeps_ownership_for_reconcile(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        batch = (ROOT / "zebra" / "kernel_netlink.c").read_text()
        dplane = (ROOT / "zebra" / "zebra_dplane.h").read_text()

        self.assertIn("result_authoritative", dplane)
        # Explicit kernel verdicts and provably-unsent requests are marked
        # authoritative; everything else is an uncertain outcome.
        self.assertIn("dplane_ctx_dimt_tunnel_set_authoritative", batch)
        uncertain = dimt.split("!ctx->result_authoritative", 1)[1]
        self.assertIn(
            "ZEBRA_DIMT_CLEANUP", uncertain.split("return;", 1)[0]
        )
        # The interface-update hook adopts a link that survived an
        # uncertain create and tears it down.
        if_update = dimt.split("void zebra_dimt_tunnel_if_update", 1)[1]
        self.assertIn(
            "ZEBRA_DIMT_CLEANUP", if_update.split("ZEBRA_DIMT_ADDING", 1)[0]
        )

    def test_uncertain_delete_reconciles_before_restoring_installed(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()

        # Both CREATE and DELETE distinguish lost verdicts from explicit
        # kernel verdicts.
        self.assertEqual(dimt.count("!ctx->result_authoritative"), 2)
        # The uncertain-DELETE branch re-resolves the interface before
        # deciding between REMOVE_FAIL and REMOVED, instead of restoring
        # INSTALLED blindly.
        uncertain_del = dimt.rsplit("!ctx->result_authoritative", 1)[1]
        head = uncertain_del.split("ZAPI_DIMT_TUNNEL_REMOVED", 1)[0]
        self.assertIn("zebra_dimt_tunnel_resolve_ifindex(entry)", head)
        self.assertIn("ZAPI_DIMT_TUNNEL_REMOVE_FAIL", head)

    def test_no_message_results_skip_ack_correlation(self):
        batch = (ROOT / "zebra" / "kernel_netlink.c").read_text()
        update_multi = batch.split("void kernel_update_multi", 1)[1]

        # A synthetic FRR_NETLINK_SUCCESS (no message encoded) goes straight
        # to the handled queue, never into the batch's ack correlation where
        # the end-of-responses drain could overwrite its verdict -- and the
        # pending batch is flushed FIRST so it cannot overtake earlier
        # requests' results.
        self.assertIn(
            "dplane_ctx_enqueue_tail(&handled_list, ctx)", update_multi
        )
        success_branch = update_multi.split("res == FRR_NETLINK_SUCCESS", 1)[1]
        self.assertLess(
            success_branch.index("nl_batch_send(&batch)"),
            success_branch.index(
                "dplane_ctx_enqueue_tail(&handled_list, ctx)"
            ),
        )
        self.assertLess(
            update_multi.index("res == FRR_NETLINK_SUCCESS"),
            update_multi.index(
                "dplane_ctx_enqueue_tail(&(batch.ctx_list), ctx)"
            ),
        )

    def test_stale_responses_are_dropped_before_dequeue(self):
        batch = (ROOT / "zebra" / "kernel_netlink.c").read_text()
        read_resp = batch.split("static int nl_batch_read_resp", 1)[1]

        # A response older than the current head is discarded WITHOUT
        # dequeueing: consuming the head would fail it as unanswered and
        # orphan its real ack right behind the stale message.
        walk = read_resp.split("Find the corresponding context object", 1)[1]
        stale = walk.index("dropping stale response")
        dequeue = walk.index("ctx = dplane_ctx_dequeue(&(bth->ctx_list))")
        self.assertLess(stale, dequeue)

    def test_seq_ordering_is_wrap_aware(self):
        # The sequence counter is 32-bit and wraps; ordering must be
        # serial-number arithmetic. A plain relational compare reads a
        # delayed pre-wrap response as newer than a post-wrap head and
        # drains the batch (behavioral coverage: test_netlink_seq.c).
        batch = (ROOT / "zebra" / "kernel_netlink.c").read_text()
        walk = batch.split("static int nl_batch_read_resp", 1)[1].split(
            "Find the corresponding context object", 1
        )[1].split("if (ignore_msg)", 1)[0]
        self.assertIn("nl_seq_lt(seq,", walk)
        self.assertNotIn("->seq > seq", walk)
        self.assertNotIn("->seq < seq", walk)

        # Update partners span the wrap too: the successor is computed
        # modulo the 32-bit space, never as a signed `seq + 1`.
        self.assertIn("nl_seq_next((uint32_t)dplane_ctx_get_ns(ctx)->seq)",
                      walk)

        helpers = (ROOT / "zebra" / "netlink_seq.h").read_text()
        self.assertIn("(int32_t)(a - b) < 0", helpers)

    def test_restart_adopts_exact_kernel_tunnel(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        request = dimt.split("void zebra_dimt_tunnel_request", 1)[1]

        self.assertIn("zebra_dimt_if_matches(entry, ifp)", request)
        self.assertIn("zebra_dimt_if_address_matches(entry, ifp)", request)


if __name__ == "__main__":
    unittest.main()
