// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DIMT (draft-zzhang-mboned-dynamic-internet-mcast-tunnel) UMH origination.
 *
 * A multicast source's unicast route may carry an Upstream Multicast Hop
 * extended community (ECOMMUNITY_UMH): "to reach this source's multicast,
 * send your PIM (Light) join toward <UMH address>". bgpd's role is pure
 * extraction: on every loc-RIB update in the IPv4 unicast table, mirror the
 * best path's UMH EC to pimd through zebra's stateless UMH relay
 * (ZEBRA_UMH_ADD/DEL). pimd owns the resulting table and steers (S,G) RPF
 * onto the PIM Light tunnel facing the UMH.
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

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_dimt.h"

/* Prefixes we have announced a UMH for (info = the sent zapi_umh). */
static struct route_table *dimt_sent;

/* Pull the best UMH EC (highest preference wins) out of a path's extended
 * communities. Returns true and fills umh/umh_type/preference on match. */
static bool bgp_dimt_umh_from_path(const struct bgp_path_info *pi,
				   struct in_addr *umh, uint8_t *umh_type,
				   uint8_t *preference)
{
	const struct ecommunity *ecom;
	uint32_t i;
	bool found = false;

	if (!pi || !pi->attr)
		return false;

	ecom = bgp_attr_get_ecommunity(pi->attr);
	if (!ecom || !ecom->val || ecom->unit_size != ECOMMUNITY_SIZE)
		return false;

	for (i = 0; i < ecom->size; i++) {
		const uint8_t *pnt = ecom->val + (i * ECOMMUNITY_SIZE);
		uint8_t la_type = pnt[7] & 0x0f;
		uint8_t la_pref = pnt[7] >> 4;

		if (pnt[0] != ECOMMUNITY_ENCODE_IP ||
		    pnt[1] != ECOMMUNITY_UMH)
			continue;

		/* Unknown UMH types are ignored, reserved bits (pnt[6])
		 * are not checked -- forward compatibility. */
		if (la_type != ZAPI_UMH_TYPE_PIM &&
		    la_type != ZAPI_UMH_TYPE_AMT_RELAY)
			continue;

		if (found && la_pref <= *preference)
			continue;

		memcpy(&umh->s_addr, pnt + 2, sizeof(umh->s_addr));
		*umh_type = la_type;
		*preference = la_pref;
		found = true;
	}

	return found;
}

static void bgp_dimt_umh_send(const struct prefix *p, struct in_addr umh,
			      uint8_t umh_type, uint8_t preference, bool add)
{
	struct zapi_umh zumh = {};

	if (!bgp_zclient || bgp_zclient->sock < 0)
		return;

	prefix_copy(&zumh.prefix, p);
	SET_IPADDR_V4(&zumh.umh);
	zumh.umh.ipaddr_v4 = umh;
	zumh.umh_type = umh_type;
	zumh.preference = preference;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("DIMT: %s UMH %pI4 (type %u pref %u) for %pFX",
			   add ? "add" : "del", &umh, umh_type, preference,
			   p);

	zapi_umh_encode(bgp_zclient->obuf,
			add ? ZEBRA_UMH_ADD : ZEBRA_UMH_DEL, VRF_DEFAULT,
			&zumh);
	zclient_send_message(bgp_zclient);
}

static int bgp_dimt_route_update(struct bgp *bgp, afi_t afi, safi_t safi,
				 struct bgp_dest *dest,
				 struct bgp_path_info *old_route,
				 struct bgp_path_info *new_route)
{
	const struct prefix *p;
	struct in_addr new_umh;
	uint8_t new_type = 0;
	uint8_t new_pref = 0;
	bool new_has;

	/* v4 unicast in the default instance only; v6 is out of scope for
	 * now (the UMH EC carries a v4 address either way). */
	if (afi != AFI_IP || safi != SAFI_UNICAST ||
	    bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return 0;

	p = bgp_dest_get_prefix(dest);

	new_has = bgp_dimt_umh_from_path(new_route, &new_umh, &new_type,
					 &new_pref);

	if (new_has) {
		struct route_node *rn = route_node_get(dimt_sent, p);
		struct zapi_umh *st = rn->info;

		if (!st) {
			st = XCALLOC(MTYPE_TMP, sizeof(*st));
			rn->info = st; /* keep the get-ref as the tree ref */
		} else
			route_unlock_node(rn);

		prefix_copy(&st->prefix, p);
		SET_IPADDR_V4(&st->umh);
		st->umh.ipaddr_v4 = new_umh;
		st->umh_type = new_type;
		st->preference = new_pref;

		/* ADD is an upsert on the pimd side; resending an unchanged
		 * mapping is harmless (the hook can fire with
		 * old_select == new_select). */
		bgp_dimt_umh_send(p, new_umh, new_type, new_pref, true);
	} else {
		/* Route withdrawn, or re-announced without the EC: DEL iff
		 * we ever announced it. */
		struct route_node *rn = route_node_lookup(dimt_sent, p);

		if (!rn)
			return 0;
		if (rn->info) {
			struct zapi_umh *st = rn->info;

			bgp_dimt_umh_send(p, st->umh.ipaddr_v4, st->umh_type,
					  st->preference, false);
			XFREE(MTYPE_TMP, st);
			rn->info = NULL;
			route_unlock_node(rn); /* tree ref */
		}
		route_unlock_node(rn); /* lookup ref */
	}

	return 0;
}

/* pimd (re-)subscribed through zebra: re-dump every selected v4 unicast
 * path that carries a UMH EC. */
int bgp_dimt_umh_replay(ZAPI_CALLBACK_ARGS)
{
	struct bgp *bgp = bgp_get_default();
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	if (!bgp)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("DIMT: pimd requested UMH replay");

	for (dest = bgp_table_top(bgp->rib[AFI_IP][SAFI_UNICAST]); dest;
	     dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi;
		     pi = pi->next) {
			struct in_addr umh;
			uint8_t umh_type, pref;

			if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
				continue;
			if (bgp_dimt_umh_from_path(pi, &umh, &umh_type,
						   &pref))
				bgp_dimt_umh_send(bgp_dest_get_prefix(dest),
						  umh, umh_type, pref, true);
			break;
		}
	}

	return 0;
}

void bgp_dimt_init(void)
{
	dimt_sent = route_table_init();
	hook_register(bgp_route_update, bgp_dimt_route_update);
}

void bgp_dimt_terminate(void)
{
	struct route_node *rn;

	if (!dimt_sent)
		return;

	for (rn = route_top(dimt_sent); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;
		XFREE(MTYPE_TMP, rn->info);
		rn->info = NULL;
		route_unlock_node(rn);
	}
	route_table_finish(dimt_sent);
	dimt_sent = NULL;
}
