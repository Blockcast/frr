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

    def test_restart_adopts_exact_kernel_tunnel(self):
        dimt = (ROOT / "zebra" / "zebra_dimt.c").read_text()
        request = dimt.split("void zebra_dimt_tunnel_request", 1)[1]

        self.assertIn("zebra_dimt_if_matches(entry, ifp)", request)
        self.assertIn("zebra_dimt_if_address_matches(entry, ifp)", request)


if __name__ == "__main__":
    unittest.main()
