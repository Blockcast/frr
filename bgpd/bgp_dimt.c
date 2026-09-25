// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DIMT (draft-zzhang-mboned-dynamic-internet-mcast-tunnel) UMH origination.
 *
 * A multicast source's unicast route may carry an Upstream Multicast Hop
 * extended community (ECOMMUNITY_UMH): "to reach this source's multicast,
 * send your PIM (Light) join toward <UMH address>". bgpd's role is pure
 * extraction: on every loc-RIB update in the IPv4 or IPv6 unicast table,
 * mirror the best path's UMH EC to pimd through zebra's stateless UMH relay
 * (ZEBRA_UMH_ADD/DEL). pimd/pim6d own the resulting table and steer (S,G)
 * RPF onto the PIM Light tunnel facing the UMH.
 *
 * The IPv4 UMH is an 8-byte IPv4-address-specific EC on attr->ecommunity; the
 * IPv6 UMH is a 20-byte IPv6-address-specific EC on attr->ipv6_ecommunity. The
 * zapi relay carries a family-tagged struct ipaddr, so only the per-family EC
 * extraction below differs.
 *
 * Withdraw semantics matter: a prefix re-announced WITHOUT the EC must act
 * as a DEL (attribute loss, not route loss, is the classic hook bug). The
 * hook's old_route cannot answer this: on an UPDATE bgpd reuses the
 * path_info and swaps its attr before best-path runs, so old_route already
 * shows the new attr. A local shadow table of announced prefixes supplies
 * the real "did we send an ADD for this" answer.
 */

#include <zebra.h>

#include "lib/zclient.h"
#include "lib/stream.h"
#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/monotime.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_dimt.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_DIMT_UMH, "BGP DIMT UMH shadow entry");

/* Prefixes we have announced a UMH for (info = the sent zapi_umh), one table
 * per AFI. A single FRR route_table's radix descent is family-blind and would
 * return the same node for a v4 X/32 and a v6 /32 whose leading 32 bits equal
 * X (longer v6 prefixes instead corrupt the tree through cross-family glue
 * nodes), so v4 and v6 shadows must live in separate tables. Only [AFI_IP]
 * and [AFI_IP6] are ever used. */
static struct route_table *dimt_sent[AFI_MAX];

/*
 * May this path's UMH extended community steer where we join?
 *
 * The UMH EC says "send your PIM join toward <address>", so whoever can put
 * one on a route we accept decides where a stream is pulled from. Before this
 * gate existed the answer was "anybody on the path": a transit AS or an IX
 * route server could attach a 0x80 to a prefix it merely carried and redirect
 * our join. Two conditions now have to hold, and the default is DENY.
 *
 * 1. The neighbour is marked `neighbor <nbr> dimt-trusted`. Unmarked
 *    neighbours -- which is every neighbour until an operator says otherwise
 *    -- have their UMH ECs ignored. A locally originated route (peer_self) is
 *    trusted: its EC came from our own route-map.
 *
 * 2. Origin-AS parity with the UMH large community's trust rule in
 *    bgp_mvpn_resolve_from_lcommunity(): the claimant must be the route's
 *    origin, and that origin must be knowable at all. The two lanes share
 *    aspath_origin_as() so an AS_SET, an AS 0, or a confederation-member
 *    origin refuses a UMH identically in both.
 *
 *    The LC lane compares the origin against the tuple's Global
 *    Administrator. The EC has no AS field -- its Global Administrator is the
 *    UMH address itself -- so the comparand here is the NEIGHBOUR's AS:
 *
 *      eBGP: origin_as must equal peer->as. A trusted external neighbour may
 *            claim a UMH for prefixes it originates, and not for a third
 *            party's prefix it merely transits. This is the half of the fix
 *            that bounds a trusted-but-over-reaching peer, where condition 1
 *            bounds an untrusted one.
 *
 *      iBGP: accepted. Marking an INTERNAL neighbour dimt-trusted is a
 *            statement that our own AS vets UMHs at its border -- a route
 *            reflector legitimately relays an eBGP-learned route together
 *            with the UMH its ingress speaker already accepted under this
 *            same gate, and re-deriving origin == peer->as at the RR client
 *            would refuse every such route. An empty AS_PATH (locally
 *            originated inside our AS) is the same trust domain by
 *            definition.
 *
 * *why is filled with a short reason on refusal, for the caller's log.
 */
bool bgp_dimt_peer_is_trusted(const struct bgp_path_info *pi, const char **why)
{
	const char *ambiguous_reason = NULL;
	struct peer *peer;
	unsigned int origin_as;
	bool path_is_empty;

	*why = NULL;

	if (!pi || !pi->peer || !pi->peer->bgp)
		return false;

	peer = pi->peer;

	/* Our own route-map put the EC there. */
	if (peer == peer->bgp->peer_self)
		return true;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_DIMT_TRUSTED)) {
		*why = "neighbor is not dimt-trusted";
		return false;
	}

	origin_as = aspath_origin_as(pi->attr ? pi->attr->aspath : NULL,
				     &ambiguous_reason, &path_is_empty);
	if (ambiguous_reason) {
		*why = ambiguous_reason;
		return false;
	}

	/* Inside our own AS the border already applied this gate; see (2). */
	if (peer->sort == BGP_PEER_IBGP || peer->sort == BGP_PEER_CONFED)
		return true;

	/* eBGP. An empty AS_PATH names no origin and cannot authorise a claim;
	 * it is malformed over eBGP anyway (RFC 7606 treat-as-withdraw at
	 * parse), so this arm should be unreachable rather than restrictive. */
	if (path_is_empty || origin_as != peer->as) {
		*why = "route origin AS is not the trusted neighbor's AS";
		return false;
	}

	return true;
}

/* Rate-limited refusal log, once a minute per peer, plus an always-accurate
 * counter. The log is throttled because a crafted feed could otherwise spam
 * it; the counter is what a probe is actually detected on, so it is never
 * throttled. Per-peer rather than per-instance so "who is probing us" is
 * answerable from `show bgp neighbor` without grepping logs. */
static void bgp_dimt_umh_refuse(struct peer *peer, const char *why)
{
	time_t now = monotime(NULL);

	peer->stat_dimt_umh_rejected++;

	/* "Have we ever logged" is its own flag rather than a zero timestamp:
	 * monotime() counts from boot, so 0 is a real time during the first
	 * second of uptime. */
	if (peer->dimt_umh_log_seen && now - peer->dimt_umh_log_last < 60)
		return;

	peer->dimt_umh_log_seen = true;
	peer->dimt_umh_log_last = now;
	zlog_notice("DIMT: UMH extended community from %s refused: %s",
		    peer->host ? peer->host : "(unknown peer)", why);
}

/* Pull the best UMH EC (highest preference wins) out of a path's extended
 * communities. The IPv4 UMH rides the 8-byte ecommunity list (type 0x01,
 * Local Admin at byte 7); the IPv6 UMH rides the 20-byte ipv6_ecommunity list
 * (type 0x00, Local Admin at byte 19). Returns true and fills a family-tagged
 * umh/umh_type/preference on match.
 *
 * Refuses everything from a peer that fails bgp_dimt_peer_is_trusted(). That
 * gate lives HERE, not at the call sites, so every consumer of a 0x80 EC --
 * the pin path below and bgp_mvpn.c's settlement attestation lane alike --
 * inherits it. An attested settlement origin forged by a route server is as
 * damaging as a redirected join.
 *
 * Trust is evaluated AFTER decoding rather than as an early return, so the
 * counter moves only when a path actually carried a UMH we would otherwise
 * have honoured. An untrusted neighbour sending ordinary routes must not
 * inflate it.
 *
 * Exported (see bgp_dimt.h): bgp_mvpn.c's settlement-event attestation lane
 * decodes 0x80 through this function rather than duplicating the layout.
 */
bool bgp_dimt_umh_from_path(const struct bgp_path_info *pi, afi_t afi,
			    struct ipaddr *umh, uint8_t *umh_type,
			    uint8_t *preference)
{
	const struct ecommunity *ecom;
	const char *why = NULL;
	bool is_v6 = (afi == AFI_IP6);
	uint8_t want_type = is_v6 ? ECOMMUNITY_ENCODE_AS : ECOMMUNITY_ENCODE_IP;
	uint8_t unit = is_v6 ? IPV6_ECOMMUNITY_SIZE : ECOMMUNITY_SIZE;
	uint8_t la_off = is_v6 ? 19 : 7;
	uint32_t i;
	bool found = false;

	if (!pi || !pi->attr)
		return false;

	ecom = is_v6 ? bgp_attr_get_ipv6_ecommunity(pi->attr)
		     : bgp_attr_get_ecommunity(pi->attr);
	if (!ecom || !ecom->val || ecom->unit_size != unit)
		return false;

	for (i = 0; i < ecom->size; i++) {
		const uint8_t *pnt = ecom->val + (i * unit);
		uint8_t la_type = ECOMMUNITY_UMH_LA_TYPE(pnt[la_off]);
		uint8_t la_pref = ECOMMUNITY_UMH_LA_PREF(pnt[la_off]);

		if (pnt[0] != want_type || pnt[1] != ECOMMUNITY_UMH)
			continue;

		/* Unknown UMH types are ignored, reserved bits are not
		 * checked -- forward compatibility. */
		if (la_type != ZAPI_UMH_TYPE_PIM &&
		    la_type != ZAPI_UMH_TYPE_AMT_RELAY)
			continue;

		if (found && la_pref <= *preference)
			continue;

		if (is_v6) {
			SET_IPADDR_V6(umh);
			memcpy(&umh->ipaddr_v6, pnt + 2,
			       sizeof(umh->ipaddr_v6));
		} else {
			SET_IPADDR_V4(umh);
			memcpy(&umh->ipaddr_v4, pnt + 2,
			       sizeof(umh->ipaddr_v4));
		}
		*umh_type = la_type;
		*preference = la_pref;
		found = true;
	}

	/* pi is const, but the peer it points at is not -- the refusal is a
	 * property of the peer, not of the path. */
	if (found && !bgp_dimt_peer_is_trusted(pi, &why)) {
		bgp_dimt_umh_refuse(pi->peer, why);
		return false;
	}

	return found;
}

static void bgp_dimt_umh_send(const struct prefix *p,
			      const struct ipaddr *umh, uint8_t umh_type,
			      uint8_t preference, bool add)
{
	struct zapi_umh zumh = {};

	if (!bgp_zclient || bgp_zclient->sock < 0) {
		/* The caller still updates the shadow table on this failure,
		 * which is correct: replay serves from the shadow, so it stays
		 * the authoritative "what pimd should hold" set and the next
		 * pimd replay recovers exactly the mappings we dropped here. */
		zlog_warn("DIMT: UMH %s for %pFX not sent: zebra session down; pimd will resync on its next replay",
			  add ? "add" : "del", p);
		return;
	}

	prefix_copy(&zumh.prefix, p);
	zumh.umh = *umh; /* already family-tagged by bgp_dimt_umh_from_path() */
	zumh.umh_type = umh_type;
	zumh.preference = preference;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("DIMT: %s UMH %pIA (type %u pref %u) for %pFX",
			   add ? "add" : "del", umh, umh_type, preference,
			   p);

	zapi_umh_encode(bgp_zclient->obuf,
			add ? ZEBRA_UMH_ADD : ZEBRA_UMH_DEL, VRF_DEFAULT,
			&zumh);
	if (zclient_send_message(bgp_zclient) == ZCLIENT_SEND_FAILURE)
		zlog_warn("DIMT: UMH %s for %pFX not sent: zclient send failed; pimd will resync on its next replay",
			  add ? "add" : "del", p);
}

static int bgp_dimt_route_update(struct bgp *bgp, afi_t afi, safi_t safi,
				 struct bgp_dest *dest,
				 struct bgp_path_info *old_route,
				 struct bgp_path_info *new_route)
{
	const struct prefix *p;
	struct ipaddr new_umh = {};
	uint8_t new_type = 0;
	uint8_t new_pref = 0;
	bool new_has;

	/* IPv4/IPv6 unicast in the default instance only. Extraction is
	 * same-family by choice: a v4 UMH EC is read from v4 routes and a v6
	 * UMH EC from v6 routes; a cross-family UMH EC is deliberately ignored
	 * (BGP itself does not forbid one -- see the warn below). */
	if ((afi != AFI_IP && afi != AFI_IP6) || safi != SAFI_UNICAST ||
	    bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return 0;

	p = bgp_dest_get_prefix(dest);

	new_has = bgp_dimt_umh_from_path(new_route, afi, &new_umh, &new_type,
					 &new_pref);

	if (new_has) {
		struct route_node *rn = route_node_get(dimt_sent[afi], p);
		struct zapi_umh *st = rn->info;

		if (!st) {
			st = XCALLOC(MTYPE_BGP_DIMT_UMH, sizeof(*st));
			rn->info = st; /* keep the get-ref as the tree ref */
		} else
			route_unlock_node(rn);

		prefix_copy(&st->prefix, p);
		st->umh = new_umh; /* family already tagged by from_path() */
		st->umh_type = new_type;
		st->preference = new_pref;

		/* ADD is an upsert on the pimd side; resending an unchanged
		 * mapping is harmless (the hook can fire with
		 * old_select == new_select). */
		bgp_dimt_umh_send(p, &new_umh, new_type, new_pref, true);
	} else {
		struct route_node *rn;
		struct ipaddr xf_umh = {};
		uint8_t xf_type = 0;
		uint8_t xf_pref = 0;

		/* A wrong-family UMH EC still attaches and displays in
		 * `show bgp`, so without a hint the operator sees a
		 * "configured" UMH that never maps and multicast that never
		 * starts. Say why nothing happened. */
		if (bgp_dimt_umh_from_path(new_route,
					   afi == AFI_IP ? AFI_IP6 : AFI_IP,
					   &xf_umh, &xf_type, &xf_pref))
			zlog_warn("DIMT: %pFX carries a UMH extended community of the wrong address family; ignored (the UMH family must match the route family)",
				  p);

		/* Route withdrawn, or re-announced without the EC: DEL iff
		 * we ever announced it. */
		rn = route_node_lookup(dimt_sent[afi], p);
		if (!rn)
			return 0;
		if (rn->info) {
			struct zapi_umh *st = rn->info;

			bgp_dimt_umh_send(p, &st->umh, st->umh_type,
					  st->preference, false);
			XFREE(MTYPE_BGP_DIMT_UMH, st);
			rn->info = NULL;
			route_unlock_node(rn); /* tree ref */
		}
		route_unlock_node(rn); /* lookup ref */
	}

	return 0;
}

/* pimd (re-)subscribed through zebra: re-dump the shadow table. The shadow
 * is updated on every loc-RIB change regardless of send success, so it --
 * not the RIB -- is the single source of truth for "what pimd should
 * hold". */
int bgp_dimt_umh_replay(ZAPI_CALLBACK_ARGS)
{
	afi_t afi;

	if (!dimt_sent[AFI_IP] && !dimt_sent[AFI_IP6])
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("DIMT: pimd requested UMH replay");

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		struct route_node *rn;

		if (!dimt_sent[afi])
			continue;

		for (rn = route_top(dimt_sent[afi]); rn; rn = route_next(rn)) {
			struct zapi_umh *st = rn->info;

			if (!st)
				continue;

			bgp_dimt_umh_send(&st->prefix, &st->umh, st->umh_type,
					  st->preference, true);
		}
	}

	return 0;
}

/* `no router bgp` tears the loc-RIB down via bgp_table_finish() without
 * firing per-prefix bgp_route_update hooks, so without this pimd would keep
 * every announced mapping forever. Send a DEL per shadow entry and flush the
 * table's contents (the table itself stays allocated for a re-created
 * instance). */
static int bgp_dimt_instance_delete(struct bgp *bgp)
{
	afi_t afi;

	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return 0;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		struct route_node *rn;

		if (!dimt_sent[afi])
			continue;

		for (rn = route_top(dimt_sent[afi]); rn; rn = route_next(rn)) {
			struct zapi_umh *st = rn->info;

			if (!st)
				continue;

			bgp_dimt_umh_send(&st->prefix, &st->umh, st->umh_type,
					  st->preference, false);
			XFREE(MTYPE_BGP_DIMT_UMH, rn->info);
			rn->info = NULL;
			route_unlock_node(rn); /* tree ref */
		}
	}

	return 0;
}

void bgp_dimt_init(void)
{
	dimt_sent[AFI_IP] = route_table_init();
	dimt_sent[AFI_IP6] = route_table_init();
	hook_register(bgp_route_update, bgp_dimt_route_update);
	hook_register(bgp_inst_delete, bgp_dimt_instance_delete);
}

void bgp_dimt_terminate(void)
{
	afi_t afi;

	/* Post-terminate hook fires must not deref the freed table. */
	hook_unregister(bgp_route_update, bgp_dimt_route_update);
	hook_unregister(bgp_inst_delete, bgp_dimt_instance_delete);

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		struct route_node *rn;

		if (!dimt_sent[afi])
			continue;

		for (rn = route_top(dimt_sent[afi]); rn; rn = route_next(rn)) {
			if (!rn->info)
				continue;
			XFREE(MTYPE_BGP_DIMT_UMH, rn->info);
			rn->info = NULL;
			route_unlock_node(rn);
		}
		route_table_finish(dimt_sent[afi]);
		dimt_sent[afi] = NULL;
	}
}
