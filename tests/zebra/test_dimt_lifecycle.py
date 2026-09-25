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

        # The address phase completes a link into a tunnel, so it demands the
        # fixed outer TTL as well as identity.
        self.assertIn("netlink_dimt_if_matches(ctx, dimt, true)", address_branch)

    def test_delete_worker_revalidates_dimt_link_identity(self):
        encoder = (ROOT / "zebra" / "if_netlink.c").read_text()
        delete_put = encoder.split("netlink_put_dimt_tunnel_msg", 1)[1]

        self.assertIn("netlink_dimt_if_matches(ctx, dimt, false)", delete_put)
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
        self.assertIn("netlink_dimt_if_matches(ctx, dimt, false)", delete_branch)
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
            "check_ttl && gre->ttl != ZEBRA_DIMT_TUNNEL_TTL",
        ):
            self.assertIn(check, matcher)

    def test_create_encodes_a_fixed_outer_ttl(self):
        # Without IFLA_GRE_TTL both gre and ip6gre inherit the inner TTL,
        # which is 1 for every link-local PIM/IGMP packet: control traffic
        # dies at the first transit router of a multi-hop underlay.
        encoder = (ROOT / "zebra" / "if_netlink.c").read_text()
        dplane = (ROOT / "zebra" / "zebra_dplane.h").read_text()
        create = encoder.split(
            "static ssize_t netlink_dimt_tunnel_msg_encoder", 1
        )[1].split("req->n.nlmsg_type = RTM_NEWLINK;", 1)[1]
        create = create.split("nl_attr_nest_end(&req->n, rta_data)", 1)[0]

        self.assertIn("#define ZEBRA_DIMT_TUNNEL_TTL 64", dplane)
        self.assertIn(
            "nl_attr_put8(&req->n, buflen, IFLA_GRE_TTL, ZEBRA_DIMT_TUNNEL_TTL)",
            create,
        )
        # One encoding for both kinds: the TTL must not sit inside the
        # v4-only branch.
        v4_branch = create.split("if (IS_IPADDR_V4(&tunnel->outer_local)) {", 1)[
            1
        ].split("} else if", 1)[0]
        self.assertNotIn("IFLA_GRE_TTL", v4_branch)

    def test_gre_ttl_is_parsed_and_kept_current(self):
        netlink = (ROOT / "zebra" / "if_netlink.c").read_text()
        l2 = (ROOT / "zebra" / "zebra_l2.c").read_text()
        l2h = (ROOT / "zebra" / "zebra_l2.h").read_text()

        gre = l2h.split("struct zebra_l2info_gre {", 1)[1].split("};", 1)[0]
        self.assertIn("uint8_t ttl;", gre)
        extract = netlink.split("static int netlink_extract_gre_info", 1)[1]
        extract = extract.split("static int netlink_extract_vxlan_info", 1)[0]
        self.assertIn("attr[IFLA_GRE_TTL]", extract)
        # An in-place `ip link set ... ttl` arrives as an UPDATE, which only
        # refreshed vtep_ip before; the TTL must be refreshed there too.
        update = l2.split("void zebra_l2_greif_add_update", 1)[1].split(
            "old_vtep_ip = zif->l2info.gre.vtep_ip;", 1
        )[0]
        self.assertIn("zif->l2info.gre.ttl = gre_info->ttl;", update)

    def test_wrong_ttl_link_is_replaced_not_adopted(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        request = dimt.split("void zebra_dimt_tunnel_request", 1)[1]
        request = request.split("void zebra_dimt_tunnel_dplane_result", 1)[0]
        result = dimt.split("void zebra_dimt_tunnel_dplane_result", 1)[1]

        # Adoption is the strict (TTL-checking) match; a same-identity link
        # with the wrong TTL is deleted and re-created, never adopted and
        # never merely refused.
        self.assertLess(
            request.index("zebra_dimt_if_stale_ttl(entry, ifp)"),
            request.index("zebra_dimt_if_matches(entry, ifp)"),
        )
        replace = request.split("zebra_dimt_if_stale_ttl(entry, ifp)", 1)[1]
        replace = replace.split("zebra_dimt_if_matches(entry, ifp)", 1)[0]
        self.assertIn("zebra_dimt_tunnel_replace(entry, ifp)", replace)
        helper = dimt.split("zebra_dimt_tunnel_replace(struct zebra_dimt_tunnel", 1)[1]
        helper = helper.split("\n}\n", 1)[0]
        self.assertIn("ZEBRA_DIMT_REPLACING", helper)
        self.assertIn("dplane_dimt_tunnel_del", helper)
        # The replacement's create rides the delete's result.
        replacing = result.split("entry->state == ZEBRA_DIMT_REPLACING", 1)[1]
        replacing = replacing.split("cleanup = entry", 1)[0]
        self.assertIn("ZEBRA_DIMT_TUNNEL_CREATE", replacing)
        self.assertIn("dplane_dimt_tunnel_add", replacing)
        # Delete and cleanup paths use identity only, so a wrong-TTL link of
        # ours can always be removed.
        resolve = dimt.split("static bool zebra_dimt_tunnel_resolve_ifindex", 1)[1]
        resolve = resolve.split("static void", 1)[0]
        self.assertIn("zebra_dimt_if_identity_matches(entry, ifp)", resolve)

    def test_installed_link_that_loses_its_ttl_is_replaced(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        iface = (ROOT / "zebra" / "interface.c").read_text()

        # The UPDATE path (an existing link changed in place) must look at
        # the refreshed TTL, not only the first sighting of the link.
        update = iface.split("interface_update_l2info(ctx, ifp, zif_type, 0,", 1)[1]
        update = update.split("zebra_l2if_update_bond", 1)[0]
        self.assertIn("zebra_dimt_tunnel_if_change(ifp);", update)
        change = dimt.split("void zebra_dimt_tunnel_if_change(struct interface *ifp)", 1)[1]
        change = change.split("\n}\n", 1)[0]
        self.assertIn("ZEBRA_DIMT_INSTALLED", change)
        self.assertIn("zebra_dimt_if_stale_ttl(entry, ifp)", change)
        self.assertIn("zebra_dimt_tunnel_replace(entry, ifp)", change)

    def test_failed_replacement_delete_keeps_a_cleanup_tombstone(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        result = dimt.split("void zebra_dimt_tunnel_dplane_result", 1)[1]
        replacing = result.split("entry->state == ZEBRA_DIMT_REPLACING", 1)[1]
        failed = replacing.split("if (!success) {", 1)[1].split("\n\t\t}\n", 1)[0]
        # Never forget an entry whose stale link may survive the failed
        # delete: that strands a blackholing netdev nothing tracks.
        self.assertIn("zebra_dimt_tunnel_replace_failed(", failed)
        self.assertNotIn("zebra_dimt_tunnel_forget", failed)
        helper = dimt.split("zebra_dimt_tunnel_replace_failed(struct zebra_dimt_tunnel", 1)[1]
        helper = helper.split("\n}\n", 1)[0]
        self.assertIn("ZEBRA_DIMT_CLEANUP", helper)
        # Forget only once the link is provably gone.
        self.assertLess(
            helper.index("zebra_dimt_tunnel_resolve_ifindex(entry)"),
            helper.index("zebra_dimt_tunnel_forget(entry)"),
        )

    def test_delete_during_replacement_cancels_the_create(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        request = dimt.split("void zebra_dimt_tunnel_request", 1)[1]
        request = request.split("void zebra_dimt_tunnel_dplane_result", 1)[0]
        delete = request.split("entry->state == ZEBRA_DIMT_REPLACING", 1)[1]
        delete = delete.split("return;", 1)[0]
        self.assertIn("entry->replace_cancelled = true;", delete)
        result = dimt.split("void zebra_dimt_tunnel_dplane_result", 1)[1]
        replacing = result.split("entry->state == ZEBRA_DIMT_REPLACING", 1)[1]
        cancelled = replacing.split("if (entry->replace_cancelled) {", 1)[1]
        cancelled = cancelled.split("}", 1)[0]
        self.assertIn("ZAPI_DIMT_TUNNEL_REMOVED", cancelled)

    def test_pimd_teardown_prunes_only_when_a_delete_can_follow(self):
        pim = (ROOT / "pimd" / "pim_dimt.c").read_text()
        reconcile = pim.split("void pim_dimt_reconcile(struct pim_instance *pim)", 1)[1]
        reconcile = reconcile.split("\nvoid ", 1)[0]
        # Every prune ahead of a DEL is preceded by the zclient check, so a
        # zebra outage does not turn each reconcile pass into prune+join.
        chunks = reconcile.split("pim_dimt_tunnel_prune_riders(pim, tun);")[:-1]
        self.assertEqual(len(chunks), 2)
        for chunk in chunks:
            self.assertIn("pim_dimt_zclient_usable()", chunk[-400:])

    def test_pimd_tunnel_ifp_checks_the_name_behind_the_ifindex(self):
        pim = (ROOT / "pimd" / "pim_dimt.c").read_text()
        ifp = pim.split("pim_dimt_tunnel_ifp(struct pim_instance *pim,", 1)[1]
        ifp = ifp.split("\n}\n", 1)[0]
        self.assertIn("strncmp(ifp->name, tun->ifname", ifp)

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
        self.assertIn("nl_seq_next(dplane_ctx_get_ns(ctx)->seq)", walk)

        # The PRODUCER must be modulo-safe as well: the batch encoder
        # tags an update's second message with nl_seq_next on an
        # unsigned local, and the sequence fields feeding it are
        # unsigned end-to-end (a signed `seq++` is UB at INT_MAX).
        producer = batch.split("enum netlink_msg_status netlink_batch_add_msg",
                               1)[1].split("static enum netlink_msg_status", 1)[0]
        self.assertIn("uint32_t seq;", producer)
        self.assertIn("seq = nl_seq_next(seq)", producer)
        self.assertNotIn("seq++", producer)

        ns_h = (ROOT / "zebra" / "zebra_ns.h").read_text()
        nlsock = ns_h.split("struct nlsock {", 1)[1].split("};", 1)[0]
        self.assertIn("uint32_t seq;", nlsock)
        self.assertNotIn("int seq;", nlsock)

        dplane_h = (ROOT / "zebra" / "zebra_dplane.h").read_text()
        info = dplane_h.split("struct zebra_dplane_info {", 1)[1].split(
            "};", 1
        )[0]
        self.assertIn("uint32_t seq;", info)
        self.assertNotIn("int seq;", info)

        helpers = (ROOT / "zebra" / "netlink_seq.h").read_text()
        self.assertIn("(int32_t)(a - b) < 0", helpers)

    def test_restart_adopts_exact_kernel_tunnel(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        request = dimt.split("void zebra_dimt_tunnel_request", 1)[1]

        self.assertIn("zebra_dimt_if_matches(entry, ifp)", request)
        self.assertIn("zebra_dimt_if_address_matches(entry, ifp)", request)


if __name__ == "__main__":
    unittest.main()
