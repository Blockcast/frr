// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Blockcast, Inc. */

/* bgp_dimt_peer_is_trusted() is a pure function of the path and its peer, so
 * it can be pinned directly with synthetic structs -- no session, no topology.
 *
 * The topotest alongside this (tests/topotests/bgp_dimt_umh_trust) covers the
 * neighbour arms end-to-end through a real eBGP session.  What it cannot
 * reach cheaply is the locally-originated arm, which needs a VPNv4 session and
 * a VRF leak to exercise, so that arm is pinned here instead.  BLO-36553.
 */

#include <zebra.h>

#include "privs.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_dimt.h"

struct zebra_privs_t bgpd_privs = {};

static struct bgp test_bgp;
static struct peer self_peer;

/* A path as the loc-RIB would hold it: `peer` is who bgpd believes put it
 * there, `sub_type` is how it got there.  For a leaked VPN route those two
 * disagree -- leak_update() sets peer to the TARGET instance's peer_self while
 * sub_type records BGP_ROUTE_IMPORTED -- and that disagreement is the whole
 * point of this test.
 */
static struct bgp_path_info path(struct peer *peer, uint8_t sub_type)
{
	struct bgp_path_info pi = {};

	pi.peer = peer;
	pi.sub_type = sub_type;
	return pi;
}

static void check(const char *name, struct bgp_path_info *pi, bool want)
{
	const char *why = NULL;
	bool got = bgp_dimt_peer_is_trusted(pi, &why);

	if (got != want) {
		fprintf(stderr, "FAIL %s: expected %s, got %s (why=%s)\n", name,
			want ? "trusted" : "refused", got ? "trusted" : "refused",
			why ? why : "(none)");
		exit(1);
	}

	/* The contract in bgp_dimt.h: on a refusal with a nameable peer, *why
	 * is set, because the caller logs it and charges a counter against
	 * that peer.  A silent refusal is an unactionable one. */
	if (!got && pi->peer && !why) {
		fprintf(stderr, "FAIL %s: refused without a reason\n", name);
		exit(1);
	}
}

int main(void)
{
	struct bgp_path_info pi;
	struct peer neighbor = {};

	test_bgp.peer_self = &self_peer;
	self_peer.bgp = &test_bgp;

	neighbor.bgp = &test_bgp;
	neighbor.as = 65001;

	/* Locally originated: our own route-map attached the UMH. */
	pi = path(&self_peer, BGP_ROUTE_STATIC);
	check("network statement", &pi, true);
	pi = path(&self_peer, BGP_ROUTE_REDISTRIBUTE);
	check("redistribute", &pi, true);
	pi = path(&self_peer, BGP_ROUTE_NORMAL);
	check("locally originated, normal sub-type", &pi, true);

	/* NOT locally originated, despite carrying peer_self.  A VPN leak
	 * re-homes the path onto the target instance's peer_self and discards
	 * the sending neighbour, while ecommunity_strip_rts() removes only
	 * route targets -- so an untrusted VPNv4 neighbour's 0x80 UMH survives
	 * into a unicast table wearing a local identity.  Trusting the peer
	 * pointer here would honour it. */
	pi = path(&self_peer, BGP_ROUTE_IMPORTED);
	check("leaked from another instance", &pi, false);

	/* Negative control: the neighbour arms still behave, so a regression
	 * that refused everything could not pass this file. */
	neighbor.sort = BGP_PEER_EBGP;
	pi = path(&neighbor, BGP_ROUTE_NORMAL);
	check("unmarked eBGP neighbour", &pi, false);

	neighbor.sort = BGP_PEER_IBGP;
	SET_FLAG(neighbor.flags, PEER_FLAG_DIMT_TRUSTED);
	pi = path(&neighbor, BGP_ROUTE_NORMAL);
	check("dimt-trusted iBGP neighbour", &pi, true);

	/* An iBGP neighbour is trusted on the strength of the knob, not of the
	 * peer pointer, so the import rule must not leak across to it: a
	 * genuinely relayed route reaches us as BGP_ROUTE_NORMAL from a real
	 * peer and is unaffected by the check above. */
	pi = path(&neighbor, BGP_ROUTE_IMPORTED);
	check("dimt-trusted iBGP neighbour, imported path", &pi, true);

	/* No peer to name: refused, and *why stays NULL by contract. */
	pi = path(NULL, BGP_ROUTE_NORMAL);
	check("path with no peer", &pi, false);

	puts("DIMT UMH trust-gate tests passed");
	return 0;
}
