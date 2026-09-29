// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Blockcast, Inc. */

/* bgp_dimt_peer_is_trusted() is a pure function of the path and its peer, so
 * it can be pinned directly with synthetic structs -- no session, no topology.
 *
 * The topotest alongside this (tests/topotests/bgp_dimt_umh_trust) covers the
 * neighbour arms end-to-end through a real eBGP session.  What it cannot
 * reach cheaply is the locally-originated arm, which needs a VPNv4 session and
 * a VRF leak to exercise, so that arm is pinned here instead.  BLO-36553.
 *
 * check_refusal_charged_once() is the one part that goes through the loc-RIB
 * update hook, because what it pins -- one refusal per attribute set, however
 * often the path is re-processed -- lives in the hook, not in the gate.
 */

#include <zebra.h>

#include "privs.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_network.h"
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

/* An interned attribute set carrying one IPv4 UMH (192.0.2.<octet>, type
 * PIM), or none when octet is 0. */
static struct attr *umh_attr(uint8_t octet)
{
	uint8_t umh[ECOMMUNITY_SIZE] = {
		ECOMMUNITY_ENCODE_IP,
		ECOMMUNITY_UMH,
		192,
		0,
		2,
		octet,
		0,
		ECOMMUNITY_UMH_LA(0, ZAPI_UMH_TYPE_PIM),
	};
	struct attr attr = {};

	if (octet)
		bgp_attr_set_ecommunity(&attr, ecommunity_parse(umh, sizeof(umh), false));
	return bgp_attr_intern(&attr);
}

/* One loc-RIB pass over pi as its unchanged best path, which is what
 * bgp_process_main_one() does on a re-process with add-path transmit on.
 *
 * hook_call() for this hook is static to bgp_route.c, so walk the entries
 * bgp_dimt_init() registered instead -- the same function bgpd calls, reached
 * the same way. Only argless entries exist here. */
static void reprocess(struct bgp_path_info *pi)
{
	/* Same union lib/hook.h lands he->hookfn through: ISO C defines no
	 * conversion between void * and a function pointer, so assigning one
	 * to the other directly is a constraint violation a pedantic build
	 * rejects. */
	union {
		void *voidptr;
		int (*fptr)(struct bgp *bgp, afi_t afi, safi_t safi,
			    struct bgp_dest *bn,
			    struct bgp_path_info *old_route,
			    struct bgp_path_info *new_route);
	} hookp;
	struct hookent *he;

	for (he = _hook_bgp_route_update.entries; he; he = he->next) {
		hookp.voidptr = he->hookfn;
		hookp.fptr(&test_bgp, AFI_IP, SAFI_UNICAST, NULL, pi, pi);
	}
}

static void check_count(const char *name, const struct peer *peer, uint64_t want)
{
	if (peer->stat_dimt_umh_rejected != want) {
		fprintf(stderr, "FAIL %s: refusal counter is %" PRIu64 ", expected %" PRIu64 "\n",
			name, peer->stat_dimt_umh_rejected, want);
		exit(1);
	}
}

/* The refusal counter tracks what the neighbour sent, so re-reading a path
 * whose attributes have not moved must not charge it again -- and a path whose
 * attributes HAVE moved must, even though it is the same bgp_path_info. */
static void check_refusal_charged_once(void)
{
	struct attr *umh_a, *umh_b, *no_umh, *cur, *next;
	struct peer untrusted = {};
	struct bgp_path_info pi;

	/* bgp_attr_unintern() reaches bgp_get_default(), so bm must exist. */
	qobj_init();
	bgp_master_init(event_master_create(NULL), BGP_SOCKET_SNDBUF_SIZE, list_new());
	bgp_attr_init();
	umh_a = umh_attr(1);
	umh_b = umh_attr(2);
	no_umh = umh_attr(0);

	untrusted.bgp = &test_bgp;
	untrusted.as = 65002;
	untrusted.sort = BGP_PEER_EBGP;
	pi = path(&untrusted, BGP_ROUTE_NORMAL);

	/* Not the default instance, so the hook stops after the audit and never
	 * reaches the pin path, which needs a real dest and a zclient. */
	test_bgp.inst_type = BGP_INSTANCE_TYPE_VRF;
	bgp_dimt_init();

	pi.attr = umh_a;
	reprocess(&pi);
	check_count("first arrival", &untrusted, 1);
	reprocess(&pi);
	reprocess(&pi);
	check_count("re-processed with unchanged attributes", &untrusted, 1);

	pi.attr = umh_b;
	reprocess(&pi);
	check_count("same path re-announced with different attributes", &untrusted, 2);

	/* Losing the UMH releases the record, so the charged set coming back is
	 * a new arrival rather than a re-read. */
	pi.attr = no_umh;
	reprocess(&pi);
	pi.attr = umh_b;
	reprocess(&pi);
	check_count("UMH dropped then re-announced", &untrusted, 3);

	/* Two UPDATEs landing before best-path runs, with bgp_update()'s order:
	 * intern the new attr, then unintern the old. Here the path is the only
	 * other holder, so the record's own reference is all that keeps the
	 * charged set alive -- without it that set is freed at the first swap
	 * and the next same-sized allocation hands its address straight back. */
	cur = umh_attr(3);
	pi.attr = cur;
	reprocess(&pi);
	check_count("sole-owner path, first arrival", &untrusted, 4);
	next = umh_attr(4);
	bgp_attr_unintern(&cur);
	pi.attr = cur = next;
	next = umh_attr(5);
	bgp_attr_unintern(&cur);
	pi.attr = cur = next;
	reprocess(&pi);
	check_count("two re-announcements coalesced before best-path", &untrusted, 5);

	bgp_dimt_terminate();
	if (pi.dimt_umh_refused)
		bgp_attr_unintern(&pi.dimt_umh_refused);
	bgp_attr_unintern(&cur);
	bgp_attr_unintern(&umh_a);
	bgp_attr_unintern(&umh_b);
	bgp_attr_unintern(&no_umh);
}

/* The wrong-family hint's throttle, pinned directly: check_refusal_charged_once()
 * runs a VRF instance, so the hook returns before the wrong-family block and
 * never reaches it. */
static void check_xfam_throttle(void)
{
	struct peer peer = {};
	struct {
		const char *name;
		struct peer *peer;
		time_t now;
		bool want;
	} steps[] = {
		{ "no peer is never throttled", NULL, 0, true },
		{ "no peer, again", NULL, 0, true },
		/* 0 is a real monotime during the first second of uptime, so the
		 * first call must log even at 0. */
		{ "first call at t=0", &peer, 0, true },
		{ "inside the 60s window", &peer, 30, false },
		/* Had the suppressed call at 30 stamped the state, 60 would
		 * still be inside the window. */
		{ "exactly 60s after the last emit", &peer, 60, true },
		{ "inside the next window", &peer, 119, false },
		{ "exactly 60s after that emit", &peer, 120, true },
	};
	size_t i;

	for (i = 0; i < array_size(steps); i++) {
		bool got = bgp_dimt_umh_xfam_should_log(steps[i].peer, steps[i].now);

		if (got != steps[i].want) {
			fprintf(stderr, "FAIL %s: got %d, expected %d\n", steps[i].name, got,
				steps[i].want);
			exit(1);
		}
	}
}

int main(void)
{
	struct bgp_path_info pi;
	struct peer neighbor = {};
	unsigned int st;

	test_bgp.peer_self = &self_peer;
	self_peer.bgp = &test_bgp;

	neighbor.bgp = &test_bgp;
	neighbor.as = 65001;

	/* Every sub_type against peer_self, not a hand-picked handful.
	 *
	 * The gate allow-lists the locally-originating sub-types, so the space
	 * above the named ones is the fail-closed arm and is asserted as such
	 * over the whole uint8_t range that `bgp_path_info.sub_type` can hold.
	 * A sub-type added to bgp_route.h therefore arrives here already pinned
	 * to REFUSED, and wiring it trusted without adding a row below fails
	 * this test rather than silently inheriting a verdict -- which is the
	 * regression that cost two review rounds (BGP_ROUTE_IMPORTED, then
	 * BGP_ROUTE_AGGREGATE, each found only after the deny-list shipped).
	 *
	 * ADDING A SUB-TYPE: add a row here with an explicit verdict, and say
	 * in bgp_dimt.c which producer originates it. Do not delete the default
	 * arm to make a new one pass.
	 *
	 * BGP_ROUTE_RFP is only defined under ENABLE_BGP_VNC; it is covered by
	 * the default arm either way, so it needs no #ifdef here.
	 */
	for (st = 0; st <= UINT8_MAX; st++) {
		char name[64];
		bool want;

		switch (st) {
		case BGP_ROUTE_STATIC:       /* `network`                  */
		case BGP_ROUTE_REDISTRIBUTE: /* redistribution + route-map */
			want = true;
			break;
		default:
			/* NORMAL (0, so also an unset sub_type), IMPORTED (VPN
			 * leak), AGGREGATE (as-set merges a component's
			 * ecommunity), RFP, and anything later. */
			want = false;
			break;
		}

		snprintf(name, sizeof(name), "peer_self sub_type %u", st);
		pi = path(&self_peer, (uint8_t)st);
		check(name, &pi, want);
	}

	/* The two laundering sub-types called out by name, so a reader of this
	 * file sees the security claim rather than only the loop's arithmetic.
	 * A VPN leak re-homes the path onto the target instance's peer_self and
	 * discards the sending neighbour, while ecommunity_strip_rts() removes
	 * only route targets -- so an untrusted VPNv4 neighbour's 0x80 UMH
	 * survives into a unicast table wearing a local identity. An as-set
	 * aggregate merges each component's whole ecommunity, so a UMH already
	 * refused on the component re-enters on the aggregate. */
	pi = path(&self_peer, BGP_ROUTE_IMPORTED);
	check("leaked from another instance", &pi, false);
	pi = path(&self_peer, BGP_ROUTE_AGGREGATE);
	check("as-set aggregate of a neighbour's route", &pi, false);

	/* BGP_ROUTE_NORMAL is 0, so this is also the verdict for a path whose
	 * sub_type was never set -- a zero-initialised or partially-constructed
	 * bgp_path_info must land on the REFUSED side, not the trusted one.
	 * Its only peer_self producer (bgp_unreach.c:922) originates into
	 * SAFI_UNREACH, which no consumer of this gate reads. */
	pi = path(&self_peer, BGP_ROUTE_NORMAL);
	check("peer_self with an unset/default sub_type", &pi, false);

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
	 * peer pointer, so the peer_self sub_type rules must not leak across to
	 * it: a genuinely relayed route reaches us from a real peer and its
	 * sub_type says nothing about who authored the UMH. */
	pi = path(&neighbor, BGP_ROUTE_IMPORTED);
	check("dimt-trusted iBGP neighbour, imported path", &pi, true);
	pi = path(&neighbor, BGP_ROUTE_AGGREGATE);
	check("dimt-trusted iBGP neighbour, aggregate path", &pi, true);

	/* eBGP, so the iBGP/CONFED short-circuit does not apply and the origin
	 * test runs.  path() leaves pi.attr NULL, so aspath_origin_as() reports
	 * path_is_empty with no ambiguity and the empty-AS_PATH arm refuses.
	 * That arm is documented as unreachable over a real session -- RFC 7606
	 * treats a malformed AS_PATH as a withdraw at parse -- which is exactly
	 * why the topotest cannot pin its direction and this row has to.
	 */
	neighbor.sort = BGP_PEER_EBGP;
	pi = path(&neighbor, BGP_ROUTE_NORMAL);
	check("dimt-trusted eBGP neighbour, empty AS_PATH", &pi, false);

	/* No peer to name: refused, and *why stays NULL by contract. */
	pi = path(NULL, BGP_ROUTE_NORMAL);
	check("path with no peer", &pi, false);

	check_refusal_charged_once();
	check_xfam_throttle();

	puts("DIMT UMH trust-gate tests passed");
	return 0;
}
