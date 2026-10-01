// SPDX-License-Identifier: GPL-2.0-or-later
#include <zebra.h>

#define _LINUX_IN6_H
#define _LINUX_IF_H
#define _LINUX_IP_H
#include <linux/if_tunnel.h>

#include "lib/frrevent.h"
#include "lib/if.h"
#include "lib/linklist.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/nexthop.h"
#include "lib/stream.h"
#include "lib/zclient.h"
#include "zebra/rib.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_dimt.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zserv.h"

DEFINE_MTYPE_STATIC(ZEBRA, DIMT_TUNNEL, "Zebra DIMT tunnel");

struct zebra_dimt_tunnel {
	struct zebra_dimt_tunnel_ctx ctx;
	vrf_id_t vrf_id;
	ifindex_t ifindex;
	bool create_acked;
	bool cleanup_pending;
	bool cleanup_notify_owner;
	/* A DEL arrived while REPLACING: finish the delete, skip the create. */
	bool replace_cancelled;
	/* ADDING/ADDRESSING only: zebra processed the RTM_DELLINK of the link
	 * this entry was building while the create or address op was still in
	 * flight.  Nothing of zebra's deletes a link in those states, so the
	 * delete was out of band and the link provably existed; see
	 * zebra_dimt_tunnel_fail_install(). */
	bool link_deleted;
	enum {
		ZEBRA_DIMT_ADDING,
		ZEBRA_DIMT_ADDRESSING,
		ZEBRA_DIMT_INSTALLED,
		ZEBRA_DIMT_DELETING,
		ZEBRA_DIMT_CLEANUP,
		/* Deleting a link of ours whose outer header is not the
		 * fixed one (see zebra_dimt_if_outer_hdr_matches); the
		 * create follows the delete. */
		ZEBRA_DIMT_REPLACING,
		/* Our delete (an owner DEL, a cancelled replace, or zebra's
		 * own cleanup) succeeded, but zebra still lists the deleted
		 * link until its RTM_DELLINK is processed.  The owner has been
		 * answered REMOVED -- or, for a silent cleanup, only the
		 * FAIL_INSTALL that preceded it.  See
		 * zebra_dimt_tunnel_deleted(). */
		ZEBRA_DIMT_DELETED,
	} state;
	/* DELETED only: the latest ADD that arrived for the tunnel while the
	 * deleted link was still listed, replayed by
	 * zebra_dimt_tunnel_replay() once it is gone. */
	bool parked_add;
	struct zebra_dimt_tunnel_ctx parked;
};

/* Replays the ADDs parked on DELETED entries whose link is gone. */
static struct event *zebra_dimt_replay_ev;

static void zebra_dimt_notify(const struct zebra_dimt_tunnel_ctx *ctx,
			      vrf_id_t vrf_id, ifindex_t ifindex,
			      enum zapi_dimt_tunnel_notify_owner result);
static void zebra_dimt_tunnel_replay(struct event *event);

static void zebra_dimt_tunnel_free(void *arg)
{
	XFREE(MTYPE_DIMT_TUNNEL, arg);
}

static struct zebra_dimt_tunnel *
zebra_dimt_tunnel_lookup(vrf_id_t vrf_id, uint32_t tunnel_id)
{
	struct listnode *node;
	struct zebra_dimt_tunnel *entry;

	if (!zrouter.dimt_tunnels)
		return NULL;
	for (ALL_LIST_ELEMENTS_RO(zrouter.dimt_tunnels, node, entry))
		if (entry->vrf_id == vrf_id &&
		    entry->ctx.tunnel.tunnel_id == tunnel_id)
			return entry;
	return NULL;
}

static bool zebra_dimt_owner_matches(const struct zebra_dimt_tunnel *entry,
				     const struct zebra_dimt_tunnel_ctx *ctx)
{
	return entry->ctx.owner_proto == ctx->owner_proto &&
	       entry->ctx.owner_instance == ctx->owner_instance;
}

/*
 * Is `ifp` this tunnel's link, by name-independent identity: kind, outer
 * endpoints, key, MTU and encapsulation?  Deliberately NOT the fixed outer
 * header -- see zebra_dimt_if_matches() for the stricter test and why the two
 * differ.
 */
static bool zebra_dimt_if_identity_matches(const struct zebra_dimt_tunnel *entry,
					   const struct interface *ifp)
{
	const struct zapi_dimt_tunnel *tunnel = &entry->ctx.tunnel;
	const struct zebra_if *zif = ifp->info;
	const struct zebra_l2info_gre *gre;
	uint32_t key = 0;
	uint16_t encap_type = TUNNEL_ENCAP_NONE;

	if (!zif || (IS_IPADDR_V4(&tunnel->outer_local)
			     ? zif->zif_type != ZEBRA_IF_GRE
			     : zif->zif_type != ZEBRA_IF_IP6GRE))
		return false;
	gre = &zif->l2info.gre;
	if (!ipaddr_is_same(&gre->vtep_ip, &tunnel->outer_local) ||
	    !ipaddr_is_same(&gre->vtep_ip_remote, &tunnel->outer_remote))
		return false;
	if (tunnel->options & ZAPI_DIMT_TUNNEL_KEY_PRESENT)
		key = htonl(tunnel->key);
	if (gre->ikey != key || gre->okey != key)
		return false;
	if ((tunnel->options & ZAPI_DIMT_TUNNEL_MTU_PRESENT) &&
	    ifp->mtu != tunnel->mtu)
		return false;
	if (tunnel->encap == ZAPI_DIMT_TUNNEL_ENCAP_GRE_IN_FOU)
		encap_type = TUNNEL_ENCAP_FOU;
	return gre->encap_type == encap_type &&
	       (encap_type != TUNNEL_ENCAP_FOU ||
		gre->encap_dport == htons(tunnel->dport));
}

/*
 * The fixed outer header every DIMT netdev must carry: the outer TTL / hop
 * limit, plus "encaplimit none" on ip6gre.  See ZEBRA_DIMT_TUNNEL_TTL and
 * ZEBRA_DIMT_TUNNEL_IP6_FLAGS for why each is load-bearing; both are the
 * same class of blackhole, invisible to a one-hop lab.
 *
 * gre never reports IFLA_GRE_FLAGS, so the flag half is ip6gre-only -- on a
 * v4 link `flags` is the memset 0 and comparing it would reject every tunnel.
 *
 * Test the bit, never the whole word: IFLA_GRE_FLAGS reads back as a superset
 * of what was requested, because ip6_tnl_link_config() ORs the link's current
 * IP6_TNL_F_CAP_* capability bits into the same field.  An equality test
 * therefore rejects zebra's own freshly created netdev, and since the create
 * path answers the client only once it adopts the link, the request gets no
 * reply at all rather than a failure.
 */
static bool zebra_dimt_if_outer_hdr_matches(const struct interface *ifp)
{
	const struct zebra_if *zif = ifp->info;

	if (!zif || zif->l2info.gre.ttl != ZEBRA_DIMT_TUNNEL_TTL)
		return false;
	return zif->zif_type != ZEBRA_IF_IP6GRE ||
	       (zif->l2info.gre.flags & ZEBRA_DIMT_TUNNEL_IP6_FLAGS);
}

/*
 * Identity AND the fixed outer header: the test for a link that may be
 * adopted or completed as this tunnel.
 *
 * The outer header is split out because the two questions zebra asks of a
 * link have different answers for a DIMT netdev built with the wrong one --
 * in practice one an older build created with "inherit", or an ip6gre one
 * created before "encaplimit none", either of which survives the upgrade
 * because zebra never sweeps DIMT links:
 *
 *  - "may it carry this tunnel?"  No.  An inheriting tunnel sends every
 *    link-local PIM/IGMP packet with outer TTL 1, and an ip6gre without
 *    IP6_TNL_F_IGN_ENCAP_LIMIT prepends a zero Tunnel Encapsulation Limit
 *    option that forbids any further encapsulation in the underlay -- both
 *    precisely the blackholes ZEBRA_DIMT_TUNNEL_TTL and
 *    ZEBRA_DIMT_TUNNEL_IP6_FLAGS exist to remove.  Adopting one would
 *    re-notify INSTALLED for a netdev that cannot signal past one hop.
 *  - "is it ours to delete?"  Yes.  Name and endpoints say it is, and a
 *    delete that also demanded the right outer header could never remove it.
 *
 * So adoption uses this function and every delete/cleanup path uses the
 * identity-only one, and zebra_dimt_tunnel_request() REPLACES a link that
 * passes identity but fails the outer header (delete, then create) rather
 * than refusing it: refusing would answer FAIL_INSTALL, and pimd
 * deliberately never retries a failed tunnel on a timer, so the upgraded
 * router would sit without the tunnel until some unrelated demand edge
 * happened along.  That replace is also the staged rollout: an operator
 * upgrades a PoP, and each existing netdev is replaced only when its own
 * tunnel is next requested or changes, one at a time, never as a sweep.  An
 * in-place RTM_NEWLINK change was rejected as well: zebra caches GRE
 * parameters from the notification stream, so the address phase would race
 * the change's own notification, and rtnl changelink for gre re-derives every
 * parameter from the request -- a second full encoding of the tunnel with
 * none of the create path's EXCL protection.
 */
static bool zebra_dimt_if_matches(const struct zebra_dimt_tunnel *entry,
				  const struct interface *ifp)
{
	return zebra_dimt_if_identity_matches(entry, ifp) &&
	       zebra_dimt_if_outer_hdr_matches(ifp);
}

/* A link that is ours but still carries the wrong outer header: never adopt
 * it as the result of a create -- it is the stale link a REPLACING entry just
 * deleted, seen before its RTM_DELLINK has reached zebra. */
static bool zebra_dimt_if_stale_outer_hdr(const struct zebra_dimt_tunnel *entry,
					  const struct interface *ifp)
{
	return zebra_dimt_if_identity_matches(entry, ifp) &&
	       !zebra_dimt_if_outer_hdr_matches(ifp);
}

static bool zebra_dimt_prefix_matches_ipaddr(const struct prefix *prefix,
					     const struct ipaddr *addr)
{
	if (IS_IPADDR_V4(addr))
		return prefix->family == AF_INET &&
		       IPV4_ADDR_SAME(&prefix->u.prefix4, &addr->ipaddr_v4);
	if (IS_IPADDR_V6(addr))
		return prefix->family == AF_INET6 &&
		       IPV6_ADDR_SAME(&prefix->u.prefix6, &addr->ipaddr_v6);
	return false;
}

static bool zebra_dimt_if_address_matches(const struct zebra_dimt_tunnel *entry,
					  const struct interface *ifp)
{
	const struct zapi_dimt_tunnel *tunnel = &entry->ctx.tunnel;
	struct connected *connected;

	frr_each (if_connected, ifp->connected, connected) {
		if (!CHECK_FLAG(connected->conf, ZEBRA_IFC_QUEUED) ||
		    !CONNECTED_PEER(connected) || !connected->address ||
		    !connected->destination)
			continue;
		if (zebra_dimt_prefix_matches_ipaddr(connected->address,
						       &tunnel->inner_local) &&
		    zebra_dimt_prefix_matches_ipaddr(connected->destination,
						       &tunnel->inner_peer))
			return true;
	}
	return false;
}

static bool zebra_dimt_tunnel_resolve_ifindex(struct zebra_dimt_tunnel *entry)
{
	struct interface *ifp;

	if (!entry->ifindex)
		return false;
	ifp = if_lookup_by_index(entry->ifindex, entry->vrf_id);
	if (!ifp || strcmp(entry->ctx.ifname, ifp->name) != 0 ||
	    !zebra_dimt_if_identity_matches(entry, ifp)) {
		entry->ifindex = 0;
		return false;
	}

	return true;
}

static void zebra_dimt_tunnel_forget(struct zebra_dimt_tunnel *entry)
{
	listnode_delete(zrouter.dimt_tunnels, entry);
	zebra_dimt_tunnel_free(entry);
}

static enum zebra_dplane_result
zebra_dimt_tunnel_address(struct zebra_dimt_tunnel *entry)
{
	entry->ctx.phase = ZEBRA_DIMT_TUNNEL_ADDRESS;
	entry->ctx.delete_ifindex = entry->ifindex;
	entry->state = ZEBRA_DIMT_ADDRESSING;
	return dplane_dimt_tunnel_add(entry->vrf_id, &entry->ctx);
}

static enum zebra_dplane_result
zebra_dimt_tunnel_cleanup_link(struct zebra_dimt_tunnel *entry)
{
	enum zebra_dplane_result result;

	if (entry->cleanup_pending)
		return ZEBRA_DPLANE_REQUEST_QUEUED;
	if (!zebra_dimt_tunnel_resolve_ifindex(entry))
		return ZEBRA_DPLANE_REQUEST_SUCCESS;
	entry->ctx.phase = ZEBRA_DIMT_TUNNEL_DELETE;
	entry->ctx.delete_ifindex = entry->ifindex;
	entry->state = ZEBRA_DIMT_CLEANUP;
	result = dplane_dimt_tunnel_del(entry->vrf_id, &entry->ctx);
	entry->cleanup_pending = result == ZEBRA_DPLANE_REQUEST_QUEUED;
	return result;
}

/* The owner learns a link it was building vanished: REMOVED after the
 * FAIL_INSTALL already sent, then the entry is forgotten.  FAIL_INSTALL alone
 * parks pimd's tunnel in FAILED, which re-requests only on a demand edge, so a
 * demanded tunnel would stay dark; REMOVED is the only result that proves
 * absence, and pimd re-ADDs on it.
 *
 * Only for entry->link_deleted, i.e. once an out-of-band RTM_DELLINK for the
 * link was processed.  Never for a create that failed without producing a
 * link, nor for one whose link merely fails resolve_ifindex() on a name or
 * identity mismatch: pimd would re-ADD into the same failure forever. */
static void zebra_dimt_tunnel_forget_vanished(struct zebra_dimt_tunnel *entry)
{
	if (entry->link_deleted)
		zebra_dimt_notify(&entry->ctx, entry->vrf_id, 0,
				  ZAPI_DIMT_TUNNEL_REMOVED);
	zebra_dimt_tunnel_forget(entry);
}

static void zebra_dimt_tunnel_fail_install(struct zebra_dimt_tunnel *entry)
{
	enum zebra_dplane_result result;

	zebra_dimt_notify(&entry->ctx, entry->vrf_id, entry->ifindex,
			  ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
	/* Keep lifecycle ownership even if cleanup cannot be queued. A later
	 * identical request retries cleanup instead of colliding with the link. */
	result = zebra_dimt_tunnel_cleanup_link(entry);
	if (result == ZEBRA_DPLANE_REQUEST_SUCCESS)
		zebra_dimt_tunnel_forget_vanished(entry);
}

/* Replace a link of ours built with the wrong outer header (see
 * zebra_dimt_if_matches()): delete it here, and the create follows in
 * zebra_dimt_tunnel_dplane_result().  The delete is bound to the stale
 * link's ifindex like any other; entry->ifindex stays 0 so neither its
 * deletion (zebra_dimt_tunnel_if_delete()) nor a late notification for it
 * is mistaken for the new link. */
static enum zebra_dplane_result
zebra_dimt_tunnel_replace(struct zebra_dimt_tunnel *entry,
			  const struct interface *stale)
{
	entry->ifindex = 0;
	entry->create_acked = false;
	entry->link_deleted = false;
	entry->ctx.phase = ZEBRA_DIMT_TUNNEL_DELETE;
	entry->ctx.delete_ifindex = stale->ifindex;
	entry->state = ZEBRA_DIMT_REPLACING;
	return dplane_dimt_tunnel_del(entry->vrf_id, &entry->ctx);
}

/* The delete of a stale-TTL link was refused, or its verdict was lost, so
 * the link may still be in the kernel.  Report the failure (FAIL_INSTALL,
 * or REMOVE_FAIL when the owner had cancelled the replacement) but keep the
 * entry as a cleanup tombstone bound to that link, exactly as
 * zebra_dimt_tunnel_fail_install() does: the next identical ADD retries the
 * delete against a tracked entry instead of leaving a blackholing netdev
 * that nothing owns.  Only a link that is provably gone lets us forget. */
static void
zebra_dimt_tunnel_replace_failed(struct zebra_dimt_tunnel *entry,
				 ifindex_t stale_ifindex,
				 enum zapi_dimt_tunnel_notify_owner result)
{
	zebra_dimt_notify(&entry->ctx, entry->vrf_id, 0, result);
	entry->ifindex = stale_ifindex;
	entry->ctx.delete_ifindex = 0;
	entry->state = ZEBRA_DIMT_CLEANUP;
	if (!zebra_dimt_tunnel_resolve_ifindex(entry))
		zebra_dimt_tunnel_forget(entry);
}

/* An existing link changed in place.  The one change DIMT acts on is an
 * installed tunnel losing its fixed outer header (`ip link set dimt-...
 * type gre ttl 1`, or back to inherit, or an ip6gre regaining a non-zero
 * encap limit): that is the blackhole ZEBRA_DIMT_TUNNEL_TTL and
 * ZEBRA_DIMT_TUNNEL_IP6_FLAGS remove, so replace the link rather than keep
 * reporting it INSTALLED.  pimd follows the replacement through the
 * interface events it already handles (the old netdev's delete unpins its
 * riders, the new one is adopted by name) and the INSTALLED that completes
 * the new link's address phase. */
void zebra_dimt_tunnel_if_change(struct interface *ifp)
{
	struct listnode *node;
	struct zebra_dimt_tunnel *entry;

	if (!zrouter.dimt_tunnels)
		return;
	for (ALL_LIST_ELEMENTS_RO(zrouter.dimt_tunnels, node, entry)) {
		if (entry->vrf_id != ifp->vrf->vrf_id ||
		    entry->ifindex != ifp->ifindex)
			continue;
		if (entry->state == ZEBRA_DIMT_INSTALLED &&
		    zebra_dimt_if_stale_outer_hdr(entry, ifp) &&
		    zebra_dimt_tunnel_replace(entry, ifp) !=
			    ZEBRA_DPLANE_REQUEST_QUEUED)
			zebra_dimt_tunnel_replace_failed(
				entry, ifp->ifindex,
				ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
		break;
	}
}

void zebra_dimt_tunnel_if_update(struct interface *ifp)
{
	struct listnode *node;
	struct zebra_dimt_tunnel *entry;

	if (!zrouter.dimt_tunnels)
		return;
	for (ALL_LIST_ELEMENTS_RO(zrouter.dimt_tunnels, node, entry)) {
		if (entry->vrf_id != ifp->vrf->vrf_id ||
		    strcmp(entry->ctx.ifname, ifp->name) != 0)
			continue;
		if (entry->state == ZEBRA_DIMT_CLEANUP && !entry->ifindex &&
		    zebra_dimt_if_identity_matches(entry, ifp)) {
			/* An uncertain create left this entry as a cleanup
			 * tombstone and the link did survive in the kernel.
			 * Adopt it and tear it down. */
			entry->ifindex = ifp->ifindex;
			zebra_dimt_tunnel_cleanup_link(entry);
			break;
		}
		if (entry->state != ZEBRA_DIMT_ADDING)
			break;
		if (zebra_dimt_if_stale_outer_hdr(entry, ifp))
			break;
		entry->ifindex = ifp->ifindex;
		/* A link bound earlier and deleted out of band is replaced by
		 * this one. */
		entry->link_deleted = false;
		if (entry->create_acked &&
		    zebra_dimt_tunnel_address(entry) !=
			    ZEBRA_DPLANE_REQUEST_QUEUED)
			zebra_dimt_tunnel_fail_install(entry);
		break;
	}
}

static struct zebra_dimt_tunnel *
zebra_dimt_tunnel_lookup_ifindex(vrf_id_t vrf_id, ifindex_t ifindex)
{
	struct listnode *node;
	struct zebra_dimt_tunnel *entry;

	for (ALL_LIST_ELEMENTS_RO(zrouter.dimt_tunnels, node, entry))
		if (entry->vrf_id == vrf_id && entry->ifindex == ifindex)
			return entry;
	return NULL;
}

/*
 * The netdev behind `ifp` is gone: its RTM_DELLINK was processed, or its
 * netns went away.  Called from if_delete_update() after the interface
 * delete has been distributed and while `ifp` still carries the ifindex and
 * l2info it had -- never for a rename, whose netdev survives under its new
 * name.
 *
 * This replaces an if_del hook that could never match (BLO-38034):
 * if_delete_update() resets the ifindex to IFINDEX_INTERNAL and wipes
 * zif->l2info before if_delete() fires the hook, and a configured ifp never
 * reaches if_delete() at all.  An out-of-band delete (`ip link del`, a netns
 * teardown) therefore left the entry INSTALLED on a dead ifindex and the
 * owner was never told -- the tunnel stayed "up" in pimd with no netdev.
 *
 * Entries legitimately at ifindex 0 (REPLACING, ADDING before the
 * RTM_NEWLINK, a CLEANUP tombstone for a link never seen) cannot match: the
 * caller's ifindex is a real one.
 *
 * An entry is forgotten here only when no dplane op for it is in flight.
 * Results are matched to entries by tunnel_id alone, so a result orphaned by
 * forgetting its entry would land on the next entry created for the same
 * tunnel.  A state with an op in flight is left for that op's result to
 * decide: ADDRESSING, DELETING and a CLEANUP tombstone with cleanup_pending
 * set drop the ifindex; ADDING keeps the dead ifindex so the create ack's
 * address phase fails against it; REPLACING is already at ifindex 0.
 * ADDRESSING and ADDING also set link_deleted, so their failed install is
 * followed by REMOVED (zebra_dimt_tunnel_fail_install()).  DELETED drops the
 * ifindex and defers the parked-ADD replay.
 */
void zebra_dimt_tunnel_if_delete(struct interface *ifp)
{
	struct zebra_dimt_tunnel *entry;

	if (!zrouter.dimt_tunnels || ifp->ifindex == IFINDEX_INTERNAL)
		return;
	entry = zebra_dimt_tunnel_lookup_ifindex(ifp->vrf->vrf_id,
						 ifp->ifindex);
	if (!entry)
		return;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("DIMT tunnel %s: link %s(%d) deleted (state %d)",
			   entry->ctx.ifname, ifp->name, ifp->ifindex,
			   entry->state);

	switch (entry->state) {
	case ZEBRA_DIMT_CLEANUP:
		if (entry->cleanup_pending) {
			entry->ifindex = 0;
			break;
		}
		/* A tombstone bound to this link with nothing in flight.  The
		 * owner was told FAIL_INSTALL or REMOVE_FAIL when it was made,
		 * and REMOVED is the only result that proves absence to pimd,
		 * so say it now that the link is provably gone. */
		fallthrough;
	case ZEBRA_DIMT_INSTALLED:
		/* No dplane op is ever in flight for an INSTALLED entry. */
		zebra_dimt_notify(&entry->ctx, entry->vrf_id, 0,
				  ZAPI_DIMT_TUNNEL_REMOVED);
		zebra_dimt_tunnel_forget(entry);
		break;
	case ZEBRA_DIMT_ADDRESSING:
		/* The in-flight address result now fails the ifindex check and
		 * goes through zebra_dimt_tunnel_fail_install(), which follows
		 * its FAIL_INSTALL with REMOVED for the vanished link. */
		entry->link_deleted = true;
		entry->ifindex = 0;
		break;
	case ZEBRA_DIMT_DELETING:
		/* The in-flight delete answers the owner; see the failed-delete
		 * block in zebra_dimt_tunnel_dplane_result(). */
		entry->ifindex = 0;
		break;
	case ZEBRA_DIMT_DELETED:
		/* Replay any parked ADD -- but not from here: `ifp` is still
		 * listed by name with its l2info intact, and a fresh create
		 * run now would adopt the very link being deleted. */
		entry->ifindex = 0;
		event_add_event(zrouter.master, zebra_dimt_tunnel_replay, NULL,
				0, &zebra_dimt_replay_ev);
		break;
	case ZEBRA_DIMT_ADDING:
		/* zebra_dimt_tunnel_if_update() bound the link while the
		 * create is still in flight.  Keep the dead index: the create
		 * ack then runs the address phase against it, which fails, and
		 * the owner gets FAIL_INSTALL and then REMOVED.  Clearing it
		 * would leave the ack waiting for an RTM_NEWLINK that never
		 * comes. */
		entry->link_deleted = true;
		break;
	case ZEBRA_DIMT_REPLACING:
		break;
	}
}

static bool zebra_dimt_if_lifecycle_owned(ifindex_t ifindex, vrf_id_t vrf_id)
{
	struct listnode *node;
	struct zebra_dimt_tunnel *entry;
	struct interface *ifp;

	if (!zrouter.dimt_tunnels)
		return false;
	ifp = if_lookup_by_index(ifindex, vrf_id);
	for (ALL_LIST_ELEMENTS_RO(zrouter.dimt_tunnels, node, entry)) {
		if (entry->vrf_id != vrf_id)
			continue;
		if (entry->ifindex && entry->ifindex == ifindex)
			return true;
		if (ifp && strcmp(entry->ctx.ifname, ifp->name) == 0)
			return true;
	}
	return false;
}

static bool zebra_dimt_outer_remote_valid(
	vrf_id_t vrf_id, const struct zapi_dimt_tunnel *tunnel)
{
	union g_addr addr = {};
	struct route_entry *re;
	struct nexthop_group *nhg;
	struct nexthop *nexthop;
	afi_t afi;
	bool resolved = false;

	if (IS_IPADDR_V4(&tunnel->outer_remote)) {
		afi = AFI_IP;
		addr.ipv4 = tunnel->outer_remote.ipaddr_v4;
	} else if (IS_IPADDR_V6(&tunnel->outer_remote)) {
		afi = AFI_IP6;
		addr.ipv6 = tunnel->outer_remote.ipaddr_v6;
	} else
		return false;

	re = rib_match(afi, SAFI_UNICAST, vrf_id, &addr, NULL);
	if (!re)
		return false;
	nhg = rib_get_fib_nhg(re);
	if (!nhg)
		return false;

	for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE) ||
		    !CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE) ||
		    CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE))
			continue;
		resolved = true;
		if (zebra_dimt_if_lifecycle_owned(nexthop->ifindex,
						    nexthop->vrf_id))
			return false;
	}
	return resolved;
}

static void zebra_dimt_notify(const struct zebra_dimt_tunnel_ctx *ctx,
			      vrf_id_t vrf_id, ifindex_t ifindex,
			      enum zapi_dimt_tunnel_notify_owner result)
{
	struct zapi_dimt_tunnel_notify notify = {
		.tunnel_id = ctx->tunnel.tunnel_id,
		.ifindex = ifindex,
		.result = result,
	};
	struct zserv *client;
	struct stream *s;

	client = zserv_find_client_session(ctx->owner_proto, ctx->owner_instance,
					   ctx->owner_session);
	if (!client)
		return;
	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);
	zapi_dimt_tunnel_notify_encode(s, vrf_id, &notify);
	zserv_send_message(client, s);
}

/*
 * Our delete of the link at ctx->delete_ifindex succeeded and the owner has
 * been answered: REMOVED, or nothing further after the FAIL_INSTALL that
 * preceded a silent cleanup.  Forget the entry -- unless zebra still lists
 * that link.  A silent cleanup keeps the tombstone too: forgetting it would
 * let an ADD landing before the RTM_DELLINK adopt the dying link.
 *
 * The kernel ACKs the RTM_DELLINK on the dplane's command socket, but zebra
 * learns the link is gone only when the dplane pthread later reads the
 * RTM_DELLINK broadcast from netlink_dplane_in.  An ADD landing in that gap
 * would take the fresh-create path and adopt the dying link (see
 * zebra_dimt_tunnel_park()).  So while the link is still listed keep the
 * entry as a DELETED tombstone bound to it; zebra_dimt_tunnel_if_delete()
 * releases it when the link goes.
 *
 * Only a real kernel ACK proves an RTM_DELLINK is on its way.  The skip path
 * in netlink_put_dimt_tunnel_msg() answers success without touching the
 * kernel -- the link no longer matched what zebra lists -- and leaves
 * result_authoritative unset; a tombstone there could wait forever.
 */
static void zebra_dimt_tunnel_deleted(struct zebra_dimt_tunnel *entry,
				      const struct zebra_dimt_tunnel_ctx *ctx)
{
	struct interface *ifp = NULL;

	if (ctx->result_authoritative && ctx->delete_ifindex)
		ifp = if_lookup_by_index(ctx->delete_ifindex, entry->vrf_id);
	if (!ifp || !CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) ||
	    strcmp(ifp->name, ctx->ifname) != 0 ||
	    !zebra_dimt_if_identity_matches(entry, ifp)) {
		zebra_dimt_tunnel_forget(entry);
		return;
	}
	entry->state = ZEBRA_DIMT_DELETED;
	entry->ifindex = ctx->delete_ifindex;
	entry->cleanup_pending = false;
	entry->cleanup_notify_owner = false;
	entry->replace_cancelled = false;
	entry->create_acked = false;
	entry->link_deleted = false;
	entry->parked_add = false;
}

static void zebra_dimt_tunnel_add(const struct zebra_dimt_tunnel_ctx *ctx,
				  vrf_id_t vrf_id);

static struct zebra_dimt_tunnel *zebra_dimt_tunnel_lookup_released(void)
{
	struct listnode *node;
	struct zebra_dimt_tunnel *entry;

	for (ALL_LIST_ELEMENTS_RO(zrouter.dimt_tunnels, node, entry))
		if (entry->state == ZEBRA_DIMT_DELETED && !entry->ifindex)
			return entry;
	return NULL;
}

/* Forget every DELETED tombstone whose link is now gone and run the ADD
 * parked on it as if it had just arrived.  One entry per pass, with the
 * lookup restarted each time: the add path appends to the list (never in
 * DELETED state, so this terminates). */
static void zebra_dimt_tunnel_replay(struct event *event)
{
	struct zebra_dimt_tunnel *entry;
	struct zebra_dimt_tunnel_ctx parked;
	vrf_id_t vrf_id;
	bool replay;

	if (!zrouter.dimt_tunnels)
		return;
	while ((entry = zebra_dimt_tunnel_lookup_released())) {
		replay = entry->parked_add;
		parked = entry->parked;
		vrf_id = entry->vrf_id;
		zebra_dimt_tunnel_forget(entry);
		if (!replay)
			continue;
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("DIMT tunnel %s: replaying parked ADD",
				   parked.ifname);
		zebra_dimt_tunnel_add(&parked, vrf_id);
	}
}

/* An ADD, after decoding and validation: from a client, or replayed by
 * zebra_dimt_tunnel_replay() once the link a DELETED entry was waiting on is
 * gone. */
static void zebra_dimt_tunnel_add(const struct zebra_dimt_tunnel_ctx *ctx,
				  vrf_id_t vrf_id)
{
	struct zebra_dimt_tunnel *entry;
	struct interface *ifp;
	enum zebra_dplane_result result;

	entry = zebra_dimt_tunnel_lookup(vrf_id, ctx->tunnel.tunnel_id);
	if (entry) {
		if (zebra_dimt_owner_matches(entry, ctx) &&
		    memcmp(&entry->ctx.tunnel, &ctx->tunnel,
			   sizeof(ctx->tunnel)) == 0) {
			if (entry->state == ZEBRA_DIMT_CLEANUP) {
				zebra_dimt_notify(
					ctx, entry->vrf_id, entry->ifindex,
					ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
				result = zebra_dimt_tunnel_cleanup_link(entry);
				if (result == ZEBRA_DPLANE_REQUEST_SUCCESS)
					zebra_dimt_tunnel_forget(entry);
				return;
			}
			if (entry->state == ZEBRA_DIMT_DELETING) {
				/* A delete is in flight and its completion
				 * belongs to the delete requester. Reject the
				 * add instead of rebinding ownership; the owner
				 * retries once REMOVED arrives. */
				zebra_dimt_notify(
					ctx, entry->vrf_id, entry->ifindex,
					ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
				return;
			}
			entry->ctx.owner_session = ctx->owner_session;
			if (entry->state == ZEBRA_DIMT_INSTALLED) {
				if (!zebra_dimt_tunnel_resolve_ifindex(entry)) {
					zebra_dimt_notify(
						ctx, entry->vrf_id, 0,
						ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
					zebra_dimt_tunnel_forget(entry);
					return;
				}
				zebra_dimt_notify(&entry->ctx, entry->vrf_id,
						  entry->ifindex,
						  ZAPI_DIMT_TUNNEL_INSTALLED);
			}
			return;
		}
		zebra_dimt_notify(ctx, vrf_id, entry->ifindex,
				  ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
		return;
	}
	if (!zebra_dimt_outer_remote_valid(vrf_id, &ctx->tunnel)) {
		zebra_dimt_notify(ctx, vrf_id, 0,
				  ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
		return;
	}
	if (!zrouter.dimt_tunnels) {
		zrouter.dimt_tunnels = list_new();
		zrouter.dimt_tunnels->del = zebra_dimt_tunnel_free;
	}
	if (!(ctx->tunnel.options & ZAPI_DIMT_TUNNEL_MTU_PRESENT))
		zlog_warn("DIMT tunnel %s: no MTU in the request; the netdev inherits the kernel default, which does not account for the %s outer header and fragments or drops full-size payloads",
			  ctx->ifname,
			  IS_IPADDR_V6(&ctx->tunnel.outer_local)
				  ? "IPv6 + GRE"
				  : "IPv4 + GRE");
	entry = XCALLOC(MTYPE_DIMT_TUNNEL, sizeof(*entry));
	entry->ctx = *ctx;
	entry->ctx.phase = ZEBRA_DIMT_TUNNEL_CREATE;
	entry->vrf_id = vrf_id;
	entry->state = ZEBRA_DIMT_ADDING;
	listnode_add(zrouter.dimt_tunnels, entry);
	ifp = if_lookup_by_name(ctx->ifname, entry->vrf_id);
	if (ifp && zebra_dimt_if_stale_outer_hdr(entry, ifp)) {
		/* Ours, but built with the wrong outer header. */
		if (zebra_dimt_tunnel_replace(entry, ifp) !=
		    ZEBRA_DPLANE_REQUEST_QUEUED)
			zebra_dimt_tunnel_replace_failed(
				entry, ifp->ifindex,
				ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
		return;
	}
	if (ifp && zebra_dimt_if_matches(entry, ifp)) {
		entry->ifindex = ifp->ifindex;
		if (zebra_dimt_if_address_matches(entry, ifp)) {
			entry->state = ZEBRA_DIMT_INSTALLED;
			zebra_dimt_notify(&entry->ctx, entry->vrf_id,
					  entry->ifindex,
					  ZAPI_DIMT_TUNNEL_INSTALLED);
			return;
		}
		if (zebra_dimt_tunnel_address(entry) ==
		    ZEBRA_DPLANE_REQUEST_QUEUED)
			return;
		zebra_dimt_tunnel_fail_install(entry);
		return;
	}
	result = dplane_dimt_tunnel_add(entry->vrf_id, &entry->ctx);
	if (result != ZEBRA_DPLANE_REQUEST_QUEUED) {
		zebra_dimt_notify(ctx, entry->vrf_id, 0,
				  ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
		listnode_delete(zrouter.dimt_tunnels, entry);
		zebra_dimt_tunnel_free(entry);
	}
}

/*
 * A request for a tunnel whose link we just deleted, while zebra still lists
 * that link (see zebra_dimt_tunnel_deleted()).
 *
 * An ADD cannot be served yet: the fresh-create path would find the dying
 * link by name, zebra_dimt_if_matches() would pass on its intact l2info, its
 * address would still be flagged ZEBRA_IFC_QUEUED, and the ADD would be
 * answered INSTALLED on a dead ifindex (BLO-38034).  pimd re-ADDs the moment
 * REMOVED lands, so this is an ordinary sequence, not a corner case.  Park
 * it, whatever its owner or bytes -- pimd's endpoint-change re-ADD differs
 * from the request just deleted -- and answer it when the link is gone.
 * Only the latest ADD is kept: it is the one its owner is waiting on.
 *
 * A DEL finds nothing left to remove, and cancels a parked ADD of its own.
 */
static void zebra_dimt_tunnel_park(struct zebra_dimt_tunnel *entry,
				   const struct zebra_dimt_tunnel_ctx *ctx,
				   bool add)
{
	if (add) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("DIMT tunnel %s: ADD parked until deleted link %d is gone",
				   ctx->ifname, entry->ifindex);
		entry->parked = *ctx;
		entry->parked_add = true;
		return;
	}
	zebra_dimt_notify(ctx, entry->vrf_id, 0, ZAPI_DIMT_TUNNEL_REMOVED);
	if (entry->parked_add &&
	    entry->parked.owner_proto == ctx->owner_proto &&
	    entry->parked.owner_instance == ctx->owner_instance)
		entry->parked_add = false;
}

void zebra_dimt_tunnel_request(struct zserv *client, struct zmsghdr *hdr,
			       struct stream *msg, struct zebra_vrf *zvrf)
{
	struct zebra_dimt_tunnel_ctx ctx = {};
	struct zebra_dimt_tunnel *entry;
	enum zebra_dplane_result result;
	bool add = hdr->command == ZEBRA_DIMT_TUNNEL_ADD;

	ctx.owner_proto = client->proto;
	ctx.owner_instance = client->instance;
	ctx.owner_session = client->session_id;
	if (zapi_dimt_tunnel_decode(msg, hdr->command, &ctx.tunnel) < 0 ||
	    client->proto != ZEBRA_ROUTE_PIM || zvrf_id(zvrf) != VRF_DEFAULT) {
		zebra_dimt_notify(&ctx, zvrf_id(zvrf), 0,
				  add ? ZAPI_DIMT_TUNNEL_FAIL_INSTALL
				      : ZAPI_DIMT_TUNNEL_REMOVE_FAIL);
		return;
	}
	snprintf(ctx.ifname, sizeof(ctx.ifname), "dimt-%08x",
		 ctx.tunnel.tunnel_id);
	entry = zebra_dimt_tunnel_lookup(zvrf_id(zvrf),
					 ctx.tunnel.tunnel_id);

	if (entry && entry->state == ZEBRA_DIMT_DELETED) {
		zebra_dimt_tunnel_park(entry, &ctx, add);
		return;
	}
	if (add) {
		zebra_dimt_tunnel_add(&ctx, zvrf_id(zvrf));
		return;
	}

	if (!entry) {
		zebra_dimt_notify(&ctx, zvrf_id(zvrf), 0,
				  ZAPI_DIMT_TUNNEL_REMOVED);
		return;
	}
	if (!zebra_dimt_owner_matches(entry, &ctx)) {
		zebra_dimt_notify(&ctx, zvrf_id(zvrf), entry->ifindex,
				  ZAPI_DIMT_TUNNEL_REMOVE_FAIL);
		return;
	}
	entry->ctx.owner_session = ctx.owner_session;
	if (entry->state == ZEBRA_DIMT_DELETING)
		return;
	if (entry->state == ZEBRA_DIMT_REPLACING) {
		/* The stale link's delete is already in flight; let it finish
		 * the job and answer REMOVED instead of building the
		 * replacement.  A REMOVE_FAIL here would leave the owner
		 * believing the tunnel is up once the replacement lands. */
		entry->ctx.owner_proto = ctx.owner_proto;
		entry->ctx.owner_instance = ctx.owner_instance;
		entry->replace_cancelled = true;
		return;
	}
	if (entry->state == ZEBRA_DIMT_CLEANUP) {
		entry->cleanup_notify_owner = true;
		result = zebra_dimt_tunnel_cleanup_link(entry);
		if (result == ZEBRA_DPLANE_REQUEST_SUCCESS) {
			zebra_dimt_notify(&entry->ctx, entry->vrf_id, 0,
					  ZAPI_DIMT_TUNNEL_REMOVED);
			zebra_dimt_tunnel_forget(entry);
		} else if (result != ZEBRA_DPLANE_REQUEST_QUEUED)
			zebra_dimt_notify(&entry->ctx, entry->vrf_id,
					  entry->ifindex,
					  ZAPI_DIMT_TUNNEL_REMOVE_FAIL);
		return;
	}
	if (entry->state != ZEBRA_DIMT_INSTALLED) {
		zebra_dimt_notify(&ctx, zvrf_id(zvrf), entry->ifindex,
				  ZAPI_DIMT_TUNNEL_REMOVE_FAIL);
		return;
	}
	entry->ctx.owner_proto = ctx.owner_proto;
	entry->ctx.owner_instance = ctx.owner_instance;
	if (!zebra_dimt_tunnel_resolve_ifindex(entry)) {
		zebra_dimt_notify(&entry->ctx, entry->vrf_id, 0,
				  ZAPI_DIMT_TUNNEL_REMOVED);
		zebra_dimt_tunnel_forget(entry);
		return;
	}
	entry->ctx.delete_ifindex = entry->ifindex;
	entry->ctx.phase = ZEBRA_DIMT_TUNNEL_DELETE;
	entry->state = ZEBRA_DIMT_DELETING;
	result = dplane_dimt_tunnel_del(entry->vrf_id, &entry->ctx);
	if (result != ZEBRA_DPLANE_REQUEST_QUEUED) {
		entry->state = ZEBRA_DIMT_INSTALLED;
		zebra_dimt_notify(&entry->ctx, entry->vrf_id, entry->ifindex,
				  ZAPI_DIMT_TUNNEL_REMOVE_FAIL);
	}
}

void zebra_dimt_tunnel_dplane_result(struct zebra_dplane_ctx *dplane_ctx)
{
	const struct zebra_dimt_tunnel_ctx *ctx =
		dplane_ctx_get_dimt_tunnel(dplane_ctx);
	struct zebra_dimt_tunnel *entry;
	bool success = dplane_ctx_get_status(dplane_ctx) ==
		       ZEBRA_DPLANE_REQUEST_SUCCESS;
	bool add = dplane_ctx_get_op(dplane_ctx) == DPLANE_OP_DIMT_TUNNEL_ADD;
	ifindex_t ifindex = ctx->delete_ifindex;
	vrf_id_t vrf_id = dplane_ctx_get_vrf(dplane_ctx);
	bool cleanup;

	entry = zebra_dimt_tunnel_lookup(vrf_id, ctx->tunnel.tunnel_id);

	if (!add && entry && entry->state == ZEBRA_DIMT_REPLACING) {
		/* The stale-TTL link is gone (or was already gone: the
		 * worker answers a delete for a vanished link with success).
		 * Build the replacement through the ordinary create path --
		 * unless the owner asked for the tunnel to go away while the
		 * delete was in flight, in which case the delete was the
		 * whole job.
		 *
		 * A failed delete -- explicit or unconfirmed -- may leave the
		 * old link in place, so an EXCL create could only collide
		 * with it: keep the entry as a cleanup tombstone. */
		if (!success) {
			bool cancelled = entry->replace_cancelled;

			entry->replace_cancelled = false;
			zebra_dimt_tunnel_replace_failed(
				entry, ifindex,
				cancelled ? ZAPI_DIMT_TUNNEL_REMOVE_FAIL
					  : ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
			return;
		}
		if (entry->replace_cancelled) {
			zebra_dimt_notify(&entry->ctx, vrf_id, 0,
					  ZAPI_DIMT_TUNNEL_REMOVED);
			zebra_dimt_tunnel_deleted(entry, ctx);
			return;
		}
		entry->ifindex = 0;
		entry->ctx.delete_ifindex = 0;
		entry->ctx.phase = ZEBRA_DIMT_TUNNEL_CREATE;
		entry->state = ZEBRA_DIMT_ADDING;
		if (dplane_dimt_tunnel_add(entry->vrf_id, &entry->ctx) ==
		    ZEBRA_DPLANE_REQUEST_QUEUED)
			return;
		/* The old link is gone and no new one was queued: nothing
		 * is left in the kernel to track. */
		zebra_dimt_notify(&entry->ctx, vrf_id, 0,
				  ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
		zebra_dimt_tunnel_forget(entry);
		return;
	}

	cleanup = entry && entry->state == ZEBRA_DIMT_CLEANUP;
	if (!add && cleanup)
		entry->cleanup_pending = false;

	if (add && entry && ctx->phase == ZEBRA_DIMT_TUNNEL_CREATE &&
	    success) {
		struct interface *ifp;

		entry->create_acked = true;
		ifp = if_lookup_by_name(ctx->ifname, vrf_id);
		/* Adopt only a live link.  The name may resolve to a dead
		 * one in two ways:
		 *
		 *  - After a replacement, to the deleted stale-TTL link until
		 *    its RTM_DELLINK is processed.  entry->ifindex is still 0,
		 *    the new link's RTM_NEWLINK follows in kernel order, and
		 *    zebra_dimt_tunnel_if_update() adopts it then.
		 *  - To a configured interface, which outlives its deleted
		 *    link at IFINDEX_INTERNAL with ACTIVE cleared.  For a fresh
		 *    entry (ifindex still 0) the new link's RTM_NEWLINK
		 *    follows, as above.  But if if_update() already bound the
		 *    new link and an out-of-band delete then removed it,
		 *    entry->ifindex holds the dead index (see the ADDING case
		 *    of zebra_dimt_tunnel_if_delete()) and no RTM_NEWLINK will
		 *    come: overwriting it with 0 would wedge the entry in
		 *    ADDING.  Keeping it lets the address phase fail, which
		 *    answers FAIL_INSTALL and then REMOVED.
		 *
		 * Identity is left to the address phase (resolve_ifindex()),
		 * which fails the install on a mismatch: an already-listed
		 * link gets no second RTM_NEWLINK, so refusing it here would
		 * wedge the entry instead. */
		if (ifp && ifp->ifindex != IFINDEX_INTERNAL &&
		    CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) &&
		    !zebra_dimt_if_stale_outer_hdr(entry, ifp)) {
			entry->ifindex = ifp->ifindex;
			entry->link_deleted = false;
		}
		if (!entry->ifindex ||
		    zebra_dimt_tunnel_address(entry) ==
			    ZEBRA_DPLANE_REQUEST_QUEUED)
			return;
		zebra_dimt_tunnel_fail_install(entry);
		return;
	}
	if (add && !success && entry &&
	    ctx->phase == ZEBRA_DIMT_TUNNEL_CREATE &&
	    !ctx->result_authoritative) {
		struct interface *ifp;

		/* No kernel verdict arrived: the RTM_NEWLINK may have been
		 * applied even though the request is reported as failed.
		 * Report the failure but keep lifecycle ownership so a
		 * surviving link is adopted and torn down instead of being
		 * left unmanaged to collide with a later ADD. */
		zebra_dimt_notify(&entry->ctx, vrf_id, 0,
				  ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
		entry->state = ZEBRA_DIMT_CLEANUP;
		ifp = if_lookup_by_name(ctx->ifname, vrf_id);
		if (ifp && ifp->ifindex != IFINDEX_INTERNAL &&
		    zebra_dimt_if_identity_matches(entry, ifp)) {
			entry->ifindex = ifp->ifindex;
			entry->link_deleted = false;
		}
		/* Keep the entry even when nothing can be cleaned yet;
		 * zebra_dimt_tunnel_if_update() reconciles a link that only
		 * becomes visible later -- unless the create's link was
		 * already seen and deleted out of band, so none can come. */
		if (zebra_dimt_tunnel_cleanup_link(entry) ==
			    ZEBRA_DPLANE_REQUEST_SUCCESS &&
		    entry->link_deleted)
			zebra_dimt_tunnel_forget_vanished(entry);
		return;
	}
	if (add && success && entry &&
	    ctx->phase == ZEBRA_DIMT_TUNNEL_ADDRESS) {
		ifindex = ctx->delete_ifindex;
		if (entry->ifindex != ifindex ||
		    !zebra_dimt_tunnel_resolve_ifindex(entry)) {
			zebra_dimt_tunnel_fail_install(entry);
			return;
		}
		entry->state = ZEBRA_DIMT_INSTALLED;
	}
	if (add && !success && entry &&
	    ctx->phase == ZEBRA_DIMT_TUNNEL_ADDRESS) {
		zebra_dimt_tunnel_fail_install(entry);
		return;
	}
	if (!add && !success && cleanup &&
	    !zebra_dimt_tunnel_resolve_ifindex(entry)) {
		/* A cleanup delete failed and the link is gone: the explicit
		 * failure is ENODEV after an out-of-band delete (see below),
		 * and zebra_dimt_tunnel_if_delete() cleared the ifindex when
		 * that delete's RTM_DELLINK came first.  Answer REMOVED and
		 * forget, exactly as if_delete() does for a tombstone whose
		 * link goes while nothing is in flight, so both orders of the
		 * RTM_DELLINK and this result converge.  entry->ctx is the
		 * DEL requester when cleanup_notify_owner is set and the owner
		 * otherwise.  A tombstone whose link is still listed stays. */
		zebra_dimt_notify(&entry->ctx, vrf_id, 0,
				  ZAPI_DIMT_TUNNEL_REMOVED);
		zebra_dimt_tunnel_forget(entry);
		return;
	}
	if (!add && !success && entry && !cleanup) {
		/* The delete failed, or its verdict was lost.  Either way the
		 * reconciled interface state decides, never the failure
		 * alone: a lost verdict may hide a delete the kernel applied,
		 * and an explicit one is ENODEV when an out-of-band delete
		 * already removed the link (netlink_parse_error() forgives
		 * ENODEV only for DELROUTE) -- in which case
		 * zebra_dimt_tunnel_if_delete() may have cleared the ifindex
		 * too.  Restoring INSTALLED there would keep an entry nothing
		 * can match again and answer an identical ADD INSTALLED for a
		 * link that no longer exists. */
		if (zebra_dimt_tunnel_resolve_ifindex(entry)) {
			entry->state = ZEBRA_DIMT_INSTALLED;
			zebra_dimt_notify(&entry->ctx, vrf_id, entry->ifindex,
					  ZAPI_DIMT_TUNNEL_REMOVE_FAIL);
			return;
		}
		zebra_dimt_notify(&entry->ctx, vrf_id, 0,
				  ZAPI_DIMT_TUNNEL_REMOVED);
		zebra_dimt_tunnel_forget(entry);
		return;
	}
	if (!cleanup || entry->cleanup_notify_owner)
		zebra_dimt_notify(
			entry ? &entry->ctx : ctx, vrf_id, ifindex,
			add ? (success ? ZAPI_DIMT_TUNNEL_INSTALLED
				       : ZAPI_DIMT_TUNNEL_FAIL_INSTALL)
			    : (success ? ZAPI_DIMT_TUNNEL_REMOVED
				       : ZAPI_DIMT_TUNNEL_REMOVE_FAIL));
	if (cleanup && entry)
		entry->cleanup_notify_owner = false;

	if (entry && !add && success)
		zebra_dimt_tunnel_deleted(entry, ctx);
	else if (entry && add && !success &&
		 ctx->phase == ZEBRA_DIMT_TUNNEL_CREATE)
		zebra_dimt_tunnel_forget(entry);
}

void zebra_dimt_tunnel_init(void)
{
	/* Link deletion reaches DIMT through zebra_dimt_tunnel_if_delete(),
	 * called from if_delete_update(), not through a hook. */
}

void zebra_dimt_tunnel_cleanup(void)
{
	event_cancel(&zebra_dimt_replay_ev);
	if (zrouter.dimt_tunnels)
		list_delete(&zrouter.dimt_tunnels);
}
