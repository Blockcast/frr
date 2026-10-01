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
        cleanup_branch = dimt.split("if (entry->state == ZEBRA_DIMT_CLEANUP)", 1)[1]
        self.assertIn("zebra_dimt_tunnel_cleanup_link(entry)", cleanup_branch)

    def test_link_deletion_reaches_dimt_before_the_ifindex_reset(self):
        """BLO-38034: an if_del hook fires after if_delete_update() has reset
        the ifindex and wiped l2info, and never for a configured ifp, so it
        could not match.  The call must sit after the delete is distributed
        and before the reset, and a rename (whose netdev survives) opts out.
        """
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        iface = (ROOT / "zebra" / "interface.c").read_text()

        self.assertNotIn("hook_register_prio(if_del", dimt)
        update = iface.split("static void zebra_if_delete_update(", 1)[1]
        update = update.split("\n}\n", 1)[0]
        call = update.index("zebra_dimt_tunnel_if_delete(ifp)")
        self.assertLess(update.index("zebra_interface_delete_update(ifp)"), call)
        self.assertLess(call, update.index("if_set_index(ifp, IFINDEX_INTERNAL)"))
        self.assertLess(call, update.index("memset(&zif->l2info"))
        self.assertIn("if (link_gone)", update[:call])
        rename = iface.split("static void set_ifindex(", 1)[1]
        rename = rename.split("\n}\n", 1)[0]
        self.assertIn("zebra_if_delete_update(&oifp, false)", rename)

    def test_deleted_tombstone_needs_a_kernel_ack_and_replays_deferred(self):
        """A tombstone waits for an RTM_DELLINK only a real kernel ACK
        promises, and its parked ADD is replayed from an event, never from
        the deletion itself, while the dying ifp is still listed by name."""
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()

        deleted = dimt.split("static void zebra_dimt_tunnel_deleted(", 1)[1]
        deleted = deleted.split("\n}\n", 1)[0]
        self.assertIn("ctx->result_authoritative", deleted)
        self.assertIn("ZEBRA_DIMT_DELETED", deleted)
        if_delete = dimt.split("void zebra_dimt_tunnel_if_delete(", 1)[1]
        if_delete = if_delete.split("\n}\n", 1)[0]
        self.assertIn("event_add_event(", if_delete)
        self.assertNotIn("zebra_dimt_tunnel_add(", if_delete)
        self.assertIn("event_cancel(&zebra_dimt_replay_ev)", dimt)
        # The replay forgets the tombstone before it serves the parked ADD,
        # so zebra_dimt_tunnel_add() never sees an owner to check: the park
        # itself checks it, for an ADD and a DEL alike, before parking or
        # answering REMOVED.
        park = dimt.split("static void zebra_dimt_tunnel_park(", 1)[1]
        park = park.split("\n}\n", 1)[0]
        owner = park.index("zebra_dimt_owner_matches(entry, ctx)")
        self.assertLess(owner, park.index("entry->parked = *ctx;"))
        self.assertLess(owner, park.index("ZAPI_DIMT_TUNNEL_REMOVED"))
        replay = dimt.split(
            "static void zebra_dimt_tunnel_replay(struct event *event)\n{", 1
        )[1]
        replay = replay.split("\n}\n", 1)[0]
        self.assertLess(
            replay.index("zebra_dimt_tunnel_forget("),
            replay.index("zebra_dimt_tunnel_add("),
        )

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
        # Anchor on the definition, not the first mention: the encoder's own
        # comment names netlink_put_dimt_tunnel_msg() first, and a slice from
        # there took in the encoder's recheck, so it passed with the put-time
        # skip neutered.  Stop at the batch add so only the skip is in view.
        delete_put = encoder.split(
            "\nnetlink_put_dimt_tunnel_msg(struct nl_batch *bth,", 1
        )[1].split("netlink_batch_add_msg(", 1)[0]
        # Collapse whitespace so the whole condition is matched as one
        # string: an extra "&& 0" (or any other term) anywhere in it fails.
        delete_put = " ".join(delete_put.split())

        self.assertIn(
            "if (dplane_ctx_get_op(ctx) == DPLANE_OP_DIMT_TUNNEL_DEL && "
            "!netlink_dimt_if_matches(ctx, dimt, false)) { "
            "dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS); "
            "return FRR_NETLINK_SUCCESS; }",
            delete_put,
        )
        # A skip is a synthetic verdict, never an authoritative one.
        self.assertNotIn("set_authoritative", delete_put)

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
            "check_outer_hdr &&",
            "gre->ttl != ZEBRA_DIMT_TUNNEL_TTL",
            "!(gre->flags & ZEBRA_DIMT_TUNNEL_IP6_FLAGS)",
        ):
            self.assertIn(check, matcher)
        # Mask, never compare: see test_outer_header_drift_covers_ttl_and_ip6_
        # encap_limit() for the kernel behaviour that makes the equality form
        # reject every link.
        self.assertNotIn("gre->flags != ZEBRA_DIMT_TUNNEL_IP6_FLAGS", matcher)

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
        request = dimt.split("static void zebra_dimt_tunnel_add(", 2)[2]
        request = request.split("\n}\n", 1)[0]
        result = dimt.split("void zebra_dimt_tunnel_dplane_result", 1)[1]

        # Adoption is the strict (outer-header-checking) match; a
        # same-identity link with the wrong outer TTL, or an ip6gre without
        # "encaplimit none", is deleted and re-created, never adopted and
        # never merely refused.
        self.assertLess(
            request.index("zebra_dimt_if_stale_outer_hdr(entry, ifp)"),
            request.index("zebra_dimt_if_matches(entry, ifp)"),
        )
        replace = request.split("zebra_dimt_if_stale_outer_hdr(entry, ifp)", 1)[1]
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
        # Delete and cleanup paths use identity only, so a link of ours with
        # the wrong outer header can always be removed.
        resolve = dimt.split("static bool zebra_dimt_tunnel_resolve_ifindex", 1)[1]
        resolve = resolve.split("static void", 1)[0]
        self.assertIn("zebra_dimt_if_identity_matches(entry, ifp)", resolve)

    def test_installed_link_that_loses_its_ttl_is_replaced(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        iface = (ROOT / "zebra" / "interface.c").read_text()

        # The UPDATE path (an existing link changed in place) must look at
        # the refreshed outer header, not only the first sighting of the link.
        update = iface.split("interface_update_l2info(ctx, ifp, zif_type, 0,", 1)[1]
        update = update.split("zebra_l2if_update_bond", 1)[0]
        self.assertIn("zebra_dimt_tunnel_if_change(ifp);", update)
        change = dimt.split("void zebra_dimt_tunnel_if_change(struct interface *ifp)", 1)[1]
        change = change.split("\n}\n", 1)[0]
        self.assertIn("ZEBRA_DIMT_INSTALLED", change)
        self.assertIn("zebra_dimt_if_stale_outer_hdr(entry, ifp)", change)
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
        identical_add = dimt.split("static void zebra_dimt_tunnel_add(", 2)[2]

        deleting_reject = identical_add.index(
            "entry->state == ZEBRA_DIMT_DELETING"
        )
        rebind = identical_add.index(
            "entry->ctx.owner_session = ctx->owner_session"
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

        # A CREATE distinguishes a lost verdict from an explicit one.  A
        # failed DELETE no longer needs to: lost or explicit (ENODEV after an
        # out-of-band delete, BLO-38034), it re-resolves the interface before
        # deciding between REMOVE_FAIL and REMOVED, instead of restoring
        # INSTALLED blindly.  The only other reader is the cleanup branch,
        # where a non-authoritative success is a delete the dplane skipped
        # after the link's RTM_DELLINK was processed, and only once that
        # RTM_DELLINK was seen (link_deleted).
        self.assertEqual(dimt.count("!ctx->result_authoritative"), 2)
        self.assertEqual(
            dimt.count("(entry->link_deleted && !ctx->result_authoritative)"),
            1,
        )
        if_delete = dimt.split("void zebra_dimt_tunnel_if_delete(", 1)[1]
        pending = if_delete.split("if (entry->cleanup_pending) {", 1)[1]
        self.assertIn(
            "entry->link_deleted = true;", pending.split("break;", 1)[0]
        )
        result = dimt.split("void zebra_dimt_tunnel_dplane_result", 1)[1]
        failed_del = result.split(
            "if (!add && !success && entry && !cleanup) {", 1
        )[1]
        head = failed_del.split("ZAPI_DIMT_TUNNEL_REMOVED", 1)[0]
        self.assertIn("zebra_dimt_tunnel_resolve_ifindex(entry)", head)
        self.assertIn("ZAPI_DIMT_TUNNEL_REMOVE_FAIL", head)
        self.assertNotIn(
            "if (!add && entry && !success && !cleanup)\n\t\tentry->state = "
            "ZEBRA_DIMT_INSTALLED;",
            result,
        )

    def test_no_message_results_skip_ack_correlation(self):
        batch = (ROOT / "zebra" / "kernel_netlink.c").read_text()
        update_multi = batch.split("void kernel_update_multi", 1)[1]

        # A synthetic FRR_NETLINK_SUCCESS (no message encoded) goes straight
        # to the handled queue, never into the batch's ack correlation where
        # the end-of-responses drain could overwrite its verdict -- and the
        # pending batch is flushed FIRST so it cannot overtake earlier
        # requests' results.
        # This only pins the shape of the source; the behaviour itself is
        # driven through the real kernel_update_multi() against a fake kernel
        # by tests/zebra/test_dimt_netlink.c, cases G (drain) and I (read
        # failure).
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
        request = dimt.split("static void zebra_dimt_tunnel_add(", 2)[2]

        self.assertIn("zebra_dimt_if_matches(entry, ifp)", request)
        self.assertIn("zebra_dimt_if_address_matches(entry, ifp)", request)

    def test_ip6gre_netdevs_are_created_with_encaplimit_none(self):
        """The create must send IFLA_GRE_FLAGS, and only for ip6gre.

        Omitting IFLA_GRE_ENCAP_LIMIT does not mean "no encap limit":
        ip6gre_newlink() memsets its parms, so the kernel prepends a Tunnel
        Encapsulation Limit destination option carrying *0*, which RFC 2473
        s5.1 makes an instruction to discard any packet a transit router would
        have to encapsulate again.  Plain gre has no such attribute, so both
        puts sit behind the IS_IPADDR_V6 guard.
        """
        encoder = (ROOT / "zebra" / "if_netlink.c").read_text()
        create = encoder.split("netlink_dimt_tunnel_msg_encoder", 1)[1].split(
            "IFLA_GRE_TTL", 1
        )[1].split("IFLA_GRE_IKEY", 1)[0]

        self.assertIn("IS_IPADDR_V6(&tunnel->outer_local)", create)
        self.assertIn("IFLA_GRE_ENCAP_LIMIT, 0", create)
        self.assertIn("IFLA_GRE_FLAGS,", create)
        self.assertIn("ZEBRA_DIMT_TUNNEL_IP6_FLAGS", create)

        dplane_h = (ROOT / "zebra" / "zebra_dplane.h").read_text()
        self.assertIn("#define ZEBRA_DIMT_TUNNEL_IP6_FLAGS 0x1", dplane_h)

    def test_gre_flags_are_read_back_from_the_kernel(self):
        """Without the extractor the drift check reads a constant 0.

        zebra compares the cached l2info against ZEBRA_DIMT_TUNNEL_IP6_FLAGS,
        so an unparsed IFLA_GRE_FLAGS would make every ip6gre look stale
        forever: each ADD would delete and recreate a link that was already
        correct, and the create would never be adopted.
        """
        encoder = (ROOT / "zebra" / "if_netlink.c").read_text()
        extract = encoder.split("static int netlink_extract_gre_info", 1)[1].split(
            "\n}", 1
        )[0]

        self.assertIn("attr[IFLA_GRE_FLAGS]", extract)
        self.assertIn("gre_info->flags", extract)

        l2 = (ROOT / "zebra" / "zebra_l2.h").read_text()
        gre_info = l2.split("struct zebra_l2info_gre {", 1)[1].split("};", 1)[0]
        self.assertIn("uint32_t flags;", gre_info)

        # The IN-PLACE update path copies field by field, not by memcpy, so a
        # flag left out here is invisible to zebra_dimt_tunnel_if_change():
        # `ip link set dimt-... type ip6gre encaplimit 4` on an installed
        # tunnel would silently keep reporting INSTALLED.
        l2c = (ROOT / "zebra" / "zebra_l2.c").read_text()
        update = l2c.split("void zebra_l2_greif_add_update", 1)[1].split(
            "if (add) {", 1
        )[1].split("\n}", 1)[0]
        self.assertIn("zif->l2info.gre.flags = gre_info->flags;", update)

    def test_outer_header_drift_covers_ttl_and_ip6_encap_limit(self):
        """Both halves of the fixed outer header gate adoption.

        Split by family on purpose: ipgre_fill_info() never emits
        IFLA_GRE_FLAGS, so a gre link's cached `flags` is the memset 0 and an
        unconditional comparison would reject every IPv4-outer tunnel.

        Both readers MASK for the bit.  IFLA_GRE_FLAGS reads back as a
        superset of what was sent -- ip6_tnl_link_config() recomputes the
        link's IP6_TNL_F_CAP_* bits into the same word on every config -- so
        `flags == ZEBRA_DIMT_TUNNEL_IP6_FLAGS` is false even for a netdev
        zebra has just created with exactly that value.  That equality form
        shipped in f2c0d7f9 and hung every IPv6-outer ADD: adoption is what
        answers the client, so a link that can never be adopted produces no
        reply at all, and the caller times out rather than seeing a failure.
        Assert the absence of the equality form too -- checking only that the
        constant is *mentioned* passes on both spellings, which is why the
        original of this test was green against the bug.
        """
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        outer = dimt.split("static bool zebra_dimt_if_outer_hdr_matches", 1)[
            1
        ].split("\n}", 1)[0]

        self.assertIn("ZEBRA_DIMT_TUNNEL_TTL", outer)
        self.assertIn("ZEBRA_IF_IP6GRE", outer)
        self.assertIn(
            "(zif->l2info.gre.flags & ZEBRA_DIMT_TUNNEL_IP6_FLAGS)", outer
        )
        self.assertNotIn(
            "zif->l2info.gre.flags == ZEBRA_DIMT_TUNNEL_IP6_FLAGS", outer
        )

        # Replacement, not refusal: a pre-fix netdev must be rebuilt, and
        # rebuilt one tunnel at a time off its own demand edge -- zebra never
        # sweeps DIMT links.
        self.assertIn("zebra_dimt_if_stale_outer_hdr(entry, ifp)", dimt)
        self.assertIn("zebra_dimt_if_outer_hdr_matches(ifp)", dimt)

        # The dplane-side identity check gates on the same pair.
        encoder = (ROOT / "zebra" / "if_netlink.c").read_text()
        matches = encoder.split("static bool netlink_dimt_if_matches", 1)[1].split(
            "\n}", 1
        )[0]
        self.assertIn("check_outer_hdr", matches)
        self.assertIn("ZEBRA_DIMT_TUNNEL_IP6_FLAGS", matches)

    def test_missing_mtu_is_warned_on_the_accepted_add(self):
        """zebra cannot invent an MTU, so the warning is the whole remedy.

        Placed where a new entry is allocated, so it fires once per tunnel
        rather than on every idempotent re-ADD from a reconnecting pimd.
        """
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        request = dimt.split("static void zebra_dimt_tunnel_add(", 2)[2]
        warn = request.split("ZAPI_DIMT_TUNNEL_MTU_PRESENT", 1)[1]

        self.assertIn("zlog_warn", warn)
        self.assertLess(
            request.index("zlog_warn"),
            request.index("XCALLOC(MTYPE_DIMT_TUNNEL"),
        )
        self.assertIn('#include "lib/log.h"', dimt)


if __name__ == "__main__":
    unittest.main()
