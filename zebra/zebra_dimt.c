// SPDX-License-Identifier: GPL-2.0-or-later
#include <zebra.h>

#define _LINUX_IN6_H
#define _LINUX_IF_H
#define _LINUX_IP_H
#include <linux/if_tunnel.h>

#include "lib/if.h"
#include "lib/hook.h"
#include "lib/linklist.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/nexthop.h"
#include "lib/stream.h"
#include "lib/zclient.h"
#include "zebra/rib.h"
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
	} state;
};

static void zebra_dimt_notify(const struct zebra_dimt_tunnel_ctx *ctx,
			      vrf_id_t vrf_id, ifindex_t ifindex,
			      enum zapi_dimt_tunnel_notify_owner result);

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
 */
static bool zebra_dimt_if_outer_hdr_matches(const struct interface *ifp)
{
	const struct zebra_if *zif = ifp->info;

	if (!zif || zif->l2info.gre.ttl != ZEBRA_DIMT_TUNNEL_TTL)
		return false;
	return zif->zif_type != ZEBRA_IF_IP6GRE ||
	       zif->l2info.gre.flags == ZEBRA_DIMT_TUNNEL_IP6_FLAGS;
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

static void zebra_dimt_tunnel_fail_install(struct zebra_dimt_tunnel *entry)
{
	enum zebra_dplane_result result;

	zebra_dimt_notify(&entry->ctx, entry->vrf_id, entry->ifindex,
			  ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
	/* Keep lifecycle ownership even if cleanup cannot be queued. A later
	 * identical request retries cleanup instead of colliding with the link. */
	result = zebra_dimt_tunnel_cleanup_link(entry);
	if (result == ZEBRA_DPLANE_REQUEST_SUCCESS)
		zebra_dimt_tunnel_forget(entry);
}

/* Replace a link of ours built with the wrong outer header (see
 * zebra_dimt_if_matches()): delete it here, and the create follows in
 * zebra_dimt_tunnel_dplane_result().  The delete is bound to the stale
 * link's ifindex like any other; entry->ifindex stays 0 so neither its
 * if_del nor a late notification for it is mistaken for the new link. */
static enum zebra_dplane_result
zebra_dimt_tunnel_replace(struct zebra_dimt_tunnel *entry,
			  const struct interface *stale)
{
	entry->ifindex = 0;
	entry->create_acked = false;
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
		if (entry->create_acked &&
		    zebra_dimt_tunnel_address(entry) !=
			    ZEBRA_DPLANE_REQUEST_QUEUED)
			zebra_dimt_tunnel_fail_install(entry);
		break;
	}
}

static int zebra_dimt_if_del(struct interface *ifp)
{
	struct listnode *node;
	struct zebra_dimt_tunnel *entry;

	if (!zrouter.dimt_tunnels)
		return 0;
	for (ALL_LIST_ELEMENTS_RO(zrouter.dimt_tunnels, node, entry)) {
		if (entry->vrf_id == ifp->vrf->vrf_id &&
		    entry->ifindex == ifp->ifindex) {
			entry->ifindex = 0;
			if (entry->state == ZEBRA_DIMT_INSTALLED)
				entry->state = ZEBRA_DIMT_CLEANUP;
			break;
		}
	}
	return 0;
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

void zebra_dimt_tunnel_request(struct zserv *client, struct zmsghdr *hdr,
			       struct stream *msg, struct zebra_vrf *zvrf)
{
	struct zebra_dimt_tunnel_ctx ctx = {};
	struct zebra_dimt_tunnel *entry;
	struct interface *ifp;
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

	if (add) {
		if (entry) {
			if (zebra_dimt_owner_matches(entry, &ctx) &&
			    memcmp(&entry->ctx.tunnel, &ctx.tunnel,
				   sizeof(ctx.tunnel)) == 0) {
				if (entry->state == ZEBRA_DIMT_CLEANUP) {
					zebra_dimt_notify(
						&ctx, entry->vrf_id,
						entry->ifindex,
						ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
					result = zebra_dimt_tunnel_cleanup_link(entry);
					if (result == ZEBRA_DPLANE_REQUEST_SUCCESS)
						zebra_dimt_tunnel_forget(entry);
					return;
				}
				if (entry->state == ZEBRA_DIMT_DELETING) {
					/* A delete is in flight and its
					 * completion belongs to the delete
					 * requester. Reject the add instead
					 * of rebinding ownership; the owner
					 * retries once REMOVED arrives. */
					zebra_dimt_notify(
						&ctx, entry->vrf_id,
						entry->ifindex,
						ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
					return;
				}
				entry->ctx.owner_session = ctx.owner_session;
				if (entry->state == ZEBRA_DIMT_INSTALLED) {
					if (!zebra_dimt_tunnel_resolve_ifindex(entry)) {
						zebra_dimt_notify(
							&ctx, entry->vrf_id, 0,
							ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
						zebra_dimt_tunnel_forget(entry);
						return;
					}
					zebra_dimt_notify(
						&entry->ctx, entry->vrf_id,
						entry->ifindex,
						ZAPI_DIMT_TUNNEL_INSTALLED);
				}
				return;
			}
			zebra_dimt_notify(&ctx, zvrf_id(zvrf), entry->ifindex,
					  ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
			return;
		}
		if (!zebra_dimt_outer_remote_valid(zvrf_id(zvrf), &ctx.tunnel)) {
			zebra_dimt_notify(&ctx, zvrf_id(zvrf), 0,
					  ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
			return;
		}
		if (!zrouter.dimt_tunnels) {
			zrouter.dimt_tunnels = list_new();
			zrouter.dimt_tunnels->del = zebra_dimt_tunnel_free;
		}
		if (!(ctx.tunnel.options & ZAPI_DIMT_TUNNEL_MTU_PRESENT))
			zlog_warn("DIMT tunnel %s: no MTU in the request; the netdev inherits the kernel default, which does not account for the %s outer header and fragments or drops full-size payloads",
				  ctx.ifname,
				  IS_IPADDR_V6(&ctx.tunnel.outer_local)
					  ? "IPv6 + GRE"
					  : "IPv4 + GRE");
		entry = XCALLOC(MTYPE_DIMT_TUNNEL, sizeof(*entry));
		entry->ctx = ctx;
		entry->ctx.phase = ZEBRA_DIMT_TUNNEL_CREATE;
		entry->vrf_id = zvrf_id(zvrf);
		entry->state = ZEBRA_DIMT_ADDING;
		listnode_add(zrouter.dimt_tunnels, entry);
		ifp = if_lookup_by_name(ctx.ifname, entry->vrf_id);
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
			zebra_dimt_notify(&ctx, entry->vrf_id, 0,
					  ZAPI_DIMT_TUNNEL_FAIL_INSTALL);
			listnode_delete(zrouter.dimt_tunnels, entry);
			zebra_dimt_tunnel_free(entry);
		}
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
			zebra_dimt_tunnel_forget(entry);
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
		/* After a replacement the name may still resolve to the
		 * deleted stale-TTL link until its RTM_DELLINK is processed;
		 * the new link's RTM_NEWLINK follows it in kernel order and
		 * zebra_dimt_tunnel_if_update() adopts it then. */
		if (ifp && !zebra_dimt_if_stale_outer_hdr(entry, ifp))
			entry->ifindex = ifp->ifindex;
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
		if (ifp && zebra_dimt_if_identity_matches(entry, ifp))
			entry->ifindex = ifp->ifindex;
		/* Keep the entry even when nothing can be cleaned yet;
		 * zebra_dimt_tunnel_if_update() reconciles a link that only
		 * becomes visible later. */
		zebra_dimt_tunnel_cleanup_link(entry);
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
	if (!add && !success && entry && !cleanup &&
	    !ctx->result_authoritative) {
		/* The delete's verdict was lost: the kernel may have removed
		 * the link, and zebra_dimt_if_del() may already have cleared
		 * the ifindex. Trust the reconciled interface state instead
		 * of resurrecting INSTALLED blindly -- an identical ADD must
		 * never report INSTALLED for a link that no longer exists. */
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

	if (!add && entry && !success && !cleanup)
		entry->state = ZEBRA_DIMT_INSTALLED;

	if (entry && ((add && !success &&
		      ctx->phase == ZEBRA_DIMT_TUNNEL_CREATE) ||
		     (!add && success))) {
		zebra_dimt_tunnel_forget(entry);
	}
}

void zebra_dimt_tunnel_init(void)
{
	hook_register_prio(if_del, 0, zebra_dimt_if_del);
}

void zebra_dimt_tunnel_cleanup(void)
{
	if (zrouter.dimt_tunnels)
		list_delete(&zrouter.dimt_tunnels);
}
