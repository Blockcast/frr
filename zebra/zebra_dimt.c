// SPDX-License-Identifier: GPL-2.0-or-later
#include <zebra.h>

#include "lib/if.h"
#include "lib/hook.h"
#include "lib/linklist.h"
#include "lib/memory.h"
#include "lib/nexthop.h"
#include "lib/stream.h"
#include "lib/zclient.h"
#include "zebra/rib.h"
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
	enum {
		ZEBRA_DIMT_ADDING,
		ZEBRA_DIMT_ADDRESSING,
		ZEBRA_DIMT_INSTALLED,
		ZEBRA_DIMT_DELETING,
		ZEBRA_DIMT_CLEANUP,
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

static bool zebra_dimt_tunnel_resolve_ifindex(struct zebra_dimt_tunnel *entry)
{
	struct interface *ifp =
		if_lookup_by_name(entry->ctx.ifname, entry->vrf_id);

	entry->ifindex = ifp ? ifp->ifindex : 0;
	return entry->ifindex != 0;
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

static int zebra_dimt_if_real(struct interface *ifp)
{
	struct listnode *node;
	struct zebra_dimt_tunnel *entry;

	if (!zrouter.dimt_tunnels)
		return 0;
	for (ALL_LIST_ELEMENTS_RO(zrouter.dimt_tunnels, node, entry)) {
		if (entry->vrf_id != ifp->vrf->vrf_id ||
		    strcmp(entry->ctx.ifname, ifp->name) != 0)
			continue;
		entry->ifindex = ifp->ifindex;
		if (entry->state == ZEBRA_DIMT_ADDING && entry->create_acked &&
		    zebra_dimt_tunnel_address(entry) !=
			    ZEBRA_DPLANE_REQUEST_QUEUED)
			zebra_dimt_tunnel_fail_install(entry);
		break;
	}
	return 0;
}

static int zebra_dimt_if_del(struct interface *ifp)
{
	struct listnode *node;
	struct zebra_dimt_tunnel *entry;

	if (!zrouter.dimt_tunnels)
		return 0;
	for (ALL_LIST_ELEMENTS_RO(zrouter.dimt_tunnels, node, entry)) {
		if (entry->vrf_id == ifp->vrf->vrf_id &&
		    strcmp(entry->ctx.ifname, ifp->name) == 0) {
			entry->ifindex = 0;
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
				entry->ctx.owner_session = ctx.owner_session;
				if (entry->state == ZEBRA_DIMT_INSTALLED) {
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
		entry = XCALLOC(MTYPE_DIMT_TUNNEL, sizeof(*entry));
		entry->ctx = ctx;
		entry->ctx.phase = ZEBRA_DIMT_TUNNEL_CREATE;
		entry->vrf_id = zvrf_id(zvrf);
		entry->state = ZEBRA_DIMT_ADDING;
		listnode_add(zrouter.dimt_tunnels, entry);
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
	cleanup = entry && entry->state == ZEBRA_DIMT_CLEANUP;
	if (!add && cleanup)
		entry->cleanup_pending = false;

	if (add && entry && ctx->phase == ZEBRA_DIMT_TUNNEL_CREATE &&
	    success) {
		struct interface *ifp;

		entry->create_acked = true;
		ifp = if_lookup_by_name(ctx->ifname, vrf_id);
		if (ifp)
			entry->ifindex = ifp->ifindex;
		if (!entry->ifindex ||
		    zebra_dimt_tunnel_address(entry) ==
			    ZEBRA_DPLANE_REQUEST_QUEUED)
			return;
		zebra_dimt_tunnel_fail_install(entry);
		return;
	}
	if (add && success && entry &&
	    ctx->phase == ZEBRA_DIMT_TUNNEL_ADDRESS) {
		ifindex = ctx->delete_ifindex;
		entry->ifindex = ifindex;
		entry->state = ZEBRA_DIMT_INSTALLED;
	}
	if (add && !success && entry &&
	    ctx->phase == ZEBRA_DIMT_TUNNEL_ADDRESS) {
		zebra_dimt_tunnel_fail_install(entry);
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
	hook_register_prio(if_real, 0, zebra_dimt_if_real);
}

void zebra_dimt_tunnel_cleanup(void)
{
	if (zrouter.dimt_tunnels)
		list_delete(&zrouter.dimt_tunnels);
}
