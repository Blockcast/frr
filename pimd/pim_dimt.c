// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DIMT (draft-zzhang-mboned-dynamic-internet-mcast-tunnel) UMH consumer.
 *
 * bgpd extracts the Upstream Multicast Hop extended community from unicast
 * source routes and relays (prefix -> UMH) mappings here through zebra's
 * stateless UMH relay. For every (S,G) upstream whose source is covered by
 * a mapping, RPF is pinned to the PIM Light interface whose connected
 * subnet contains the UMH, with rpf_addr = UMH -- the pim_vxlan
 * "orig mroute" STATIC_IIF pattern.
 *
 * This is the sole receiver-driven RPF override. tools/dimt-reconcile-v3.sh
 * is retired in the same commit, and that ordering is a correctness fix
 * rather than cleanup: v3 drove staticd `ip mroute` from BGP UMH state
 * scraped out of `show bgp` *text* output, so until it was removed two
 * independent overrides answered to the same UMH with nothing coordinating
 * them. Leaving both live races the pin against a text-scraping poll loop.
 */

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "prefix.h"
#include "vty.h"
#include "json.h"
#include "zclient.h"
#include "stream.h"
#include "jhash.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_iface.h"
#include "pim_memory.h"
#include "pim_rpf.h"
#include "pim_upstream.h"
#include "pim_oil.h"
#include "pim_mroute.h"
#include "pim_str.h"
#include "pim_zebra.h"
#include "pim_dimt.h"

extern struct zclient *pim_zclient;

DEFINE_MTYPE_STATIC(PIMD, PIM_DIMT_UMH, "PIM DIMT UMH mapping");
DEFINE_MTYPE_STATIC(PIMD, PIM_DIMT_ENDPOINT, "PIM DIMT tunnel endpoint");
DEFINE_MTYPE_STATIC(PIMD, PIM_DIMT_TUNNEL, "PIM DIMT tunnel state");

static void pim_dimt_umh_free(void *arg)
{
	XFREE(MTYPE_PIM_DIMT_UMH, arg);
}

static void pim_dimt_endpoint_free(void *arg)
{
	XFREE(MTYPE_PIM_DIMT_ENDPOINT, arg);
}

static void pim_dimt_tunnel_free(void *arg)
{
	XFREE(MTYPE_PIM_DIMT_TUNNEL, arg);
}

void pim_dimt_init(struct pim_instance *pim)
{
	pim->dimt_umh_list = list_new();
	pim->dimt_umh_list->del = pim_dimt_umh_free;
	pim->dimt_endpoint_list = list_new();
	pim->dimt_endpoint_list->del = pim_dimt_endpoint_free;
	pim->dimt_tunnel_list = list_new();
	pim->dimt_tunnel_list->del = pim_dimt_tunnel_free;
}

void pim_dimt_terminate(struct pim_instance *pim)
{
	if (pim->dimt_umh_list)
		list_delete(&pim->dimt_umh_list);
	if (pim->dimt_endpoint_list)
		list_delete(&pim->dimt_endpoint_list);
	if (pim->dimt_tunnel_list)
		list_delete(&pim->dimt_tunnel_list);
}

static struct pim_dimt_umh *pim_dimt_umh_find(struct pim_instance *pim,
					      const struct prefix *prefix)
{
	struct listnode *node;
	struct pim_dimt_umh *umh;

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_umh_list, node, umh))
		if (prefix_same(&umh->prefix, prefix))
			return umh;

	return NULL;
}

/* Longest-prefix match a source address against the UMH table. */
static struct pim_dimt_umh *pim_dimt_umh_lookup(struct pim_instance *pim,
						pim_addr src)
{
	struct listnode *node;
	struct pim_dimt_umh *umh, *best = NULL;
	struct prefix psrc;

	pim_addr_to_prefix(&psrc, src);

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_umh_list, node, umh)) {
		if (!prefix_match(&umh->prefix, &psrc))
			continue;
		if (!best || umh->prefix.prefixlen > best->prefix.prefixlen)
			best = umh;
	}

	return best;
}

/* The light interface facing a UMH: pim and pim-light enabled and a
 * connected (or ptp peer) subnet containing the UMH address.  Requiring
 * pim_enable filters out interfaces that cannot send joins and interfaces
 * mid-teardown by `no ip pim`. */
static struct interface *pim_dimt_light_iface(struct pim_instance *pim,
					      pim_addr umh_addr)
{
	struct interface *ifp;
	struct prefix pumh;

	pim_addr_to_prefix(&pumh, umh_addr);

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;
		struct connected *c;

		if (!pim_ifp || !pim_ifp->pim_enable ||
		    !pim_ifp->pim_light_enable || !if_is_operative(ifp))
			continue;

		frr_each (if_connected, ifp->connected, c) {
			if (c->address->family != PIM_AF)
				continue;
			if (c->destination &&
			    prefix_match(c->destination, &pumh))
				return ifp;
			if (prefix_match(c->address, &pumh))
				return ifp;
		}
	}

	return NULL;
}

/* Pin an upstream's RPF onto the light interface facing its UMH.
 * Mirrors pim_vxlan's orig-mroute handling: fill_static_iif() resets
 * rpf_addr, so the UMH must be written after it; the STATIC_IIF flag
 * makes pim_rpf_update() a no-op from then on. */
static void pim_dimt_upstream_pin(struct pim_instance *pim,
				  struct pim_upstream *up,
				  struct pim_dimt_umh *umh,
				  struct interface *ifp)
{
	if (PIM_UPSTREAM_FLAG_TEST_STATIC_IIF(up->flags) &&
	    up->rpf.source_nexthop.interface == ifp &&
	    !pim_addr_cmp(up->rpf.rpf_addr, umh->umh)) {
		/* The pin is unchanged, but the vif index backing it may not
		 * be.  pim_if_add_vif() refuses an interface whose primary
		 * address is still unset (pim_iface.c, -4), and a DIMT netdev
		 * is adopted on the INSTALLED notify -- which zebra emits off
		 * the dplane ack, before the inner address it just programmed
		 * has come back round to pimd as a connected route.  So the
		 * first pin here routinely runs with mroute_vif_index == -1
		 * and programs a bogus iif.  pim_if_addr_add() later retries
		 * pim_if_add_vif() and the vif becomes real, but it reaches
		 * this pin through pim_dimt_iface_up() -- which lands exactly
		 * on this early return, so nothing would ever re-program the
		 * MFC and readiness could never see the DIMT vif admitted.
		 * Refresh it here: the helper recomputes the iif from the
		 * interface and no-ops when it is genuinely unchanged. */
		if (up->channel_oil)
			pim_upstream_mroute_iif_update(up->channel_oil,
						       __func__);
		return;
	}

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: pinning %s RPF to %s via UMH %pPAs",
			   up->sg_str, ifp->name, &umh->umh);

	PIM_UPSTREAM_FLAG_SET_SRC_DIMT(up->flags);
	PIM_UPSTREAM_FLAG_SET_STATIC_IIF(up->flags);
	pim_upstream_fill_static_iif(up, ifp);
	up->rpf.source_nexthop.mrib_nexthop_addr = umh->umh;
	up->rpf.rpf_addr = umh->umh;

	pim_upstream_update_use_rpt(up, false /*update_mroute*/);
	if (up->channel_oil)
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);
	pim_upstream_update_join_desired(pim, up);
}

/* Undo a pin (mapping removed): return the upstream to normal RPF
 * resolution.  Only touches upstreams DIMT itself pinned -- STATIC_IIF
 * owned by another user (pim_vxlan) is left alone. */
static void pim_dimt_upstream_unpin(struct pim_instance *pim,
				    struct pim_upstream *up)
{
	if (!PIM_UPSTREAM_FLAG_TEST_SRC_DIMT(up->flags))
		return;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: unpinning %s RPF", up->sg_str);

	PIM_UPSTREAM_FLAG_UNSET_SRC_DIMT(up->flags);
	PIM_UPSTREAM_FLAG_UNSET_STATIC_IIF(up->flags);
	up->rpf.rpf_addr = PIMADDR_ANY;

	(void)pim_rpf_update(pim, up, NULL, NULL, __func__);
	pim_upstream_update_use_rpt(up, false /*update_mroute*/);
	if (up->channel_oil)
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);
	pim_upstream_update_join_desired(pim, up);
}

/* Is this upstream DIMT-steered *by intent* -- does a usable pim-type
 * mapping claim its source?  Deliberately distinct from
 * PIM_UPSTREAM_FLAG_SRC_DIMT, which records the achieved state: that flag is
 * set only inside pim_dimt_upstream_pin(), so it means "the RPF is pinned
 * onto a DIMT netdev", not "this path is ours".
 *
 * Readiness reporting needs intent, not achievement.  When a tunnel fails to
 * create there is no netdev to pin, so the flag is never set -- and keying
 * the report off it makes FWD_FAILED structurally unreachable: the path
 * disappears from `show ... dimt forwarding` entirely instead of reporting
 * the failure D3 requires.  Reporting nothing is strictly worse than the
 * "sits in requested forever" failure the contract set out to kill.
 *
 * The claiming mapping is returned via *umhp so callers need not look it up
 * twice; it is non-NULL exactly when this returns true.
 */
static bool pim_dimt_upstream_steered(struct pim_instance *pim,
				      struct pim_upstream *up,
				      struct pim_dimt_umh **umhp)
{
	struct pim_dimt_umh *umh;

	*umhp = NULL;

	if (pim_addr_is_any(up->sg.src))
		return false;
	/* STATIC_IIF set by another owner (e.g. pim_vxlan): keep theirs.
	 * Only upstreams DIMT pinned itself, or unpinned ones, are
	 * eligible -- and DIMT has nothing to report about a path it does
	 * not own. */
	if (PIM_UPSTREAM_FLAG_TEST_STATIC_IIF(up->flags) &&
	    !PIM_UPSTREAM_FLAG_TEST_SRC_DIMT(up->flags))
		return false;

	umh = pim_dimt_umh_lookup(pim, up->sg.src);

	/* Only pim-type mappings drive joins (amt-relay is stored and
	 * displayed only).  A local UMH means we ARE the UMH (source-side
	 * PE: our own origination echoes back through the loc-RIB hook) --
	 * normal RPF toward the local source applies, never a pin toward
	 * ourselves. */
	if (!umh || umh->umh_type != ZAPI_UMH_TYPE_PIM)
		return false;
	if (if_lookup_address_local(&umh->umh, PIM_AF, pim->vrf->vrf_id))
		return false;

	*umhp = umh;
	return true;
}

/* Authoritative pin resolution for one upstream: pin it when a usable
 * pim-type mapping covers the source, otherwise drop any pin DIMT owns. */
void pim_dimt_upstream_apply(struct pim_instance *pim,
			     struct pim_upstream *up)
{
	struct pim_dimt_umh *umh;
	struct interface *ifp = NULL;

	if (pim_dimt_upstream_steered(pim, up, &umh)) {
		ifp = pim_dimt_light_iface(pim, umh->umh);
		if (!ifp && PIM_DEBUG_PIM_TRACE)
			zlog_debug("DIMT: UMH %pPAs covers %s but no light interface resolves; not pinning",
				   &umh->umh, up->sg_str);
	}

	if (!ifp) {
		/* The source is not (or no longer) pinnable: drop any
		 * stale DIMT pin so the mapping table and the actual
		 * pinned RPF agree. */
		pim_dimt_upstream_unpin(pim, up);
		return;
	}

	pim_dimt_upstream_pin(pim, up, umh, ifp);
}

/* A light interface became usable (up / addressed / light-enabled):
 * mappings that could not resolve an interface before can pin now --
 * the reconciler recreating a tunnel netdev is exactly this. */
void pim_dimt_iface_up(struct pim_instance *pim, struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_upstream *up;

	if (!pim_ifp || !pim_ifp->pim_light_enable)
		return;
	if (!pim->dimt_umh_list || !listcount(pim->dimt_umh_list))
		return;

	frr_each (rb_pim_upstream, &pim->upstream_head, up)
		pim_dimt_upstream_apply(pim, up);

	/* This is the path on which readiness normally becomes true, so the
	 * edge has to be relayed from here.  A DIMT netdev is adopted on the
	 * INSTALLED notify, before the inner address it just programmed has
	 * come back round as a connected route -- so at notify time the vif
	 * does not exist yet and conjunct (3) is false.  pim_if_addr_add()
	 * reaches us once the address lands, the pin above re-programs the MFC,
	 * and only then do all three conjuncts hold.  Without this the
	 * PENDING -> READY transition is computed correctly but never announced
	 * to bgpd until some later, unrelated event happens to call it.
	 *
	 * Edge-triggered downstream (pim_gtm_forwarding_update() returns
	 * immediately when the state is unchanged), so this is cheap and safe
	 * to call on every interface-up. */
	pim_dimt_readiness_update(pim);
}

/* The pinned light interface went down or away.  STATIC_IIF exists to make
 * pim_rpf_update() a no-op, so none of the normal ifdown paths clear the
 * upstream's interface pointer -- the join timer would fire into a freed
 * pim_interface.  Unpin everything pinned here and re-resolve (another
 * light interface may cover the same UMH). */
void pim_dimt_iface_down(struct pim_instance *pim, struct interface *ifp)
{
	struct pim_upstream *up;

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (!PIM_UPSTREAM_FLAG_TEST_SRC_DIMT(up->flags))
			continue;
		if (up->rpf.source_nexthop.interface != ifp)
			continue;

		pim_dimt_upstream_unpin(pim, up);
		pim_dimt_upstream_apply(pim, up);
	}

	/* The mirror of the iface_up case: losing the pin drops readiness out
	 * of READY, and that edge is just as much bgpd's business as the one
	 * that established it. */
	pim_dimt_readiness_update(pim);
}

void pim_dimt_umh_update(struct pim_instance *pim,
			 const struct zapi_umh *zumh, bool add)
{
	struct pim_dimt_umh *umh;
	struct pim_upstream *up;

	if (zumh->prefix.family != PIM_AF)
		return;

	umh = pim_dimt_umh_find(pim, &zumh->prefix);

	if (add) {
		if (!umh) {
			umh = XCALLOC(MTYPE_PIM_DIMT_UMH, sizeof(*umh));
			prefix_copy(&umh->prefix, &zumh->prefix);
			listnode_add(pim->dimt_umh_list, umh);
		}
#if PIM_IPV == 4
		umh->umh = zumh->umh.ipaddr_v4;
#else
		umh->umh = zumh->umh.ipaddr_v6;
#endif
		umh->umh_type = zumh->umh_type;
		umh->preference = zumh->preference;

		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("DIMT: UMH add %pFX -> %pPAs (type %u pref %u)",
				   &umh->prefix, &umh->umh, umh->umh_type,
				   umh->preference);
	} else {
		if (!umh)
			return;

		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("DIMT: UMH del %pFX", &zumh->prefix);

		listnode_delete(pim->dimt_umh_list, umh);
		pim_dimt_umh_free(umh);
	}

	/* apply() is authoritative: it pins newly covered upstreams and
	 * unpins ones no longer covered. */
	frr_each (rb_pim_upstream, &pim->upstream_head, up)
		pim_dimt_upstream_apply(pim, up);

	/* A mapping change is a demand edge: it can create the first demand
	 * for a UMH or drop the last one. */
	pim_dimt_reconcile(pim);
	pim_dimt_readiness_update(pim);
}

void pim_dimt_umh_flush(struct pim_instance *pim)
{
	struct pim_upstream *up;

	if (!pim->dimt_umh_list)
		return;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: flushing %u UMH mappings",
			   listcount(pim->dimt_umh_list));

	list_delete_all_node(pim->dimt_umh_list);

	frr_each (rb_pim_upstream, &pim->upstream_head, up)
		pim_dimt_upstream_apply(pim, up);

	pim_dimt_reconcile(pim);
	pim_dimt_readiness_update(pim);
}

void pim_dimt_show_umh(struct pim_instance *pim, struct vty *vty, bool json)
{
	struct listnode *node;
	struct pim_dimt_umh *umh;
	json_object *jobj = NULL;

	if (json)
		jobj = json_object_new_object();
	else
		vty_out(vty, "%-22s %-16s %-10s %-4s %s\n", "Prefix", "UMH",
			"Type", "Pref", "Interface");

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_umh_list, node, umh)) {
		struct interface *ifp = pim_dimt_light_iface(pim, umh->umh);
		const char *type = umh->umh_type == ZAPI_UMH_TYPE_PIM
					   ? "pim"
					   : (umh->umh_type ==
						      ZAPI_UMH_TYPE_AMT_RELAY
						      ? "amt-relay"
						      : "unknown");

		if (jobj) {
			json_object *jumh = json_object_new_object();
			char umh_str[PIM_ADDRSTRLEN];
			char pfx_str[PREFIX_STRLEN];

			snprintfrr(umh_str, sizeof(umh_str), "%pPAs",
				   &umh->umh);
			snprintfrr(pfx_str, sizeof(pfx_str), "%pFX",
				   &umh->prefix);
			json_object_string_add(jumh, "umh", umh_str);
			json_object_string_add(jumh, "type", type);
			json_object_int_add(jumh, "preference",
					    umh->preference);
			json_object_string_add(jumh, "interface",
					       ifp ? ifp->name : "none");
			json_object_object_add(jobj, pfx_str, jumh);
		} else {
			vty_out(vty, "%-22pFX %-16pPAs %-10s %-4u %s\n",
				&umh->prefix, &umh->umh, type,
				umh->preference, ifp ? ifp->name : "none");
		}
	}

	if (jobj)
		vty_json(vty, jobj);
}

/* ------------------------------------------------------------------------
 * Explicit tunnel endpoint configuration (contract D2)
 *
 * Every value is stated by an operator or signalled; nothing is derived.
 * The Phase-A `10.99.X.Y <-> 100.64.X.Y` arithmetic is refused outright by
 * D2, so there is no default row, no wildcard row and no computed fallback:
 * a UMH with no matching row simply never gets a tunnel.
 * ------------------------------------------------------------------------
 */

static struct pim_dimt_endpoint *pim_dimt_endpoint_find(struct pim_instance *pim,
							pim_addr umh)
{
	struct listnode *node;
	struct pim_dimt_endpoint *ep;

	if (!pim->dimt_endpoint_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_endpoint_list, node, ep))
		if (!pim_addr_cmp(ep->umh, umh))
			return ep;

	return NULL;
}

static void pim_dimt_endpoint_apply_change(struct pim_instance *pim,
					   const struct pim_dimt_endpoint *ep);

bool pim_dimt_endpoint_set(struct pim_instance *pim,
			   const struct pim_dimt_endpoint *in)
{
	struct pim_dimt_endpoint *ep;

	/* The outer pair must agree on family -- an IPv4 local with an IPv6
	 * remote is not a tunnel, it is a typo.  The inner/outer families are
	 * deliberately NOT required to match: carrying v6 multicast over a v4
	 * underlay is the whole point of an explicit outer. */
	if (in->outer_local.ipa_type != in->outer_remote.ipa_type)
		return false;
	/* gre-in-fou is a UDP encapsulation; without a destination port there
	 * is nothing to encapsulate into. */
	if (in->encap == ZAPI_DIMT_TUNNEL_ENCAP_GRE_IN_FOU && !in->dport)
		return false;
	if (in->encap != ZAPI_DIMT_TUNNEL_ENCAP_GRE &&
	    in->encap != ZAPI_DIMT_TUNNEL_ENCAP_GRE_IN_FOU)
		return false;

	ep = pim_dimt_endpoint_find(pim, in->umh);
	if (!ep) {
		ep = XCALLOC(MTYPE_PIM_DIMT_ENDPOINT, sizeof(*ep));
		listnode_add(pim->dimt_endpoint_list, ep);
	}
	*ep = *in;

	/* Re-point any tunnel already built from the previous row.  reconcile()
	 * alone cannot do this: it builds the request only when it creates the
	 * tunnel, so an edited row would otherwise never reach the netdev. */
	pim_dimt_endpoint_apply_change(pim, ep);

	pim_dimt_reconcile(pim);
	return true;
}

void pim_dimt_endpoint_unset(struct pim_instance *pim, pim_addr umh)
{
	struct pim_dimt_endpoint *ep = pim_dimt_endpoint_find(pim, umh);

	if (!ep)
		return;

	listnode_delete(pim->dimt_endpoint_list, ep);
	pim_dimt_endpoint_free(ep);

	/* Demand for this UMH is now unsatisfiable: reconcile tears the
	 * tunnel down rather than leaving an orphan netdev behind. */
	pim_dimt_reconcile(pim);
}

int pim_dimt_endpoint_config_write(struct pim_instance *pim, struct vty *vty)
{
	struct listnode *node;
	struct pim_dimt_endpoint *ep;
	int written = 0;

	if (!pim->dimt_endpoint_list)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_endpoint_list, node, ep)) {
		vty_out(vty, " dimt tunnel-endpoint %pPA inner-local %pIA outer-local %pIA outer %pIA encap %s",
			&ep->umh, &ep->inner_local, &ep->outer_local,
			&ep->outer_remote,
			ep->encap == ZAPI_DIMT_TUNNEL_ENCAP_GRE_IN_FOU
				? "gre-in-fou"
				: "gre");
		if (ep->encap == ZAPI_DIMT_TUNNEL_ENCAP_GRE_IN_FOU)
			vty_out(vty, " dport %u", ep->dport);
		if (ep->key_set)
			vty_out(vty, " key %u", ep->key);
		if (ep->mtu_set)
			vty_out(vty, " mtu %u", ep->mtu);
		vty_out(vty, "\n");
		written++;
	}

	return written;
}

/* ------------------------------------------------------------------------
 * Tunnel request/ack state machine (contract D3)
 *
 * Edge-triggered throughout: every transition below is driven by a zapi
 * notify, a UMH mapping change, an interface event or a zebra reconnect.
 * There is no timer, no polling loop and no hold-down anywhere in this
 * file -- that absence is the requirement Phase A structurally could not
 * meet, so it is load-bearing rather than stylistic.
 * ------------------------------------------------------------------------
 */

/* Allocate the pimd-owned tunnel_id cookie for a UMH.
 *
 * Deterministic in the UMH rather than monotonic, and that is load-bearing
 * for D4 restart re-derivation.  The ifname zebra derives is `dimt-%08x` of
 * this id, so a restarted pimd (or a reconnected zebra) that re-derives the
 * SAME id re-issues a byte-identical ADD, which zebra answers by re-adopting
 * the surviving netdev and re-notifying INSTALLED.  A monotonic counter
 * would instead mint a fresh id for the same UMH, build a second netdev
 * beside the first, and strand the original -- zebra deliberately does not
 * sweep netdevs, so nothing would ever clean it up.
 *
 * 0 is reserved as "no tunnel".  A collision against a different UMH already
 * holding the id is resolved by probing upward; with a 2^32 space and a
 * per-router UMH count in the tens this is vanishingly rare, and the probe
 * is deterministic over the replayed set.
 */
static uint32_t pim_dimt_tunnel_id_alloc(struct pim_instance *pim, pim_addr umh)
{
	uint32_t id = jhash(&umh, sizeof(umh), 0x11d17);
	struct listnode *node;
	struct pim_dimt_tunnel *tun;
	bool taken;

	do {
		if (!id)
			id = 1;
		taken = false;
		for (ALL_LIST_ELEMENTS_RO(pim->dimt_tunnel_list, node, tun))
			if (tun->tunnel_id == id && pim_addr_cmp(tun->umh, umh)) {
				taken = true;
				break;
			}
		if (taken)
			id++;
	} while (taken);

	return id;
}

static struct pim_dimt_tunnel *pim_dimt_tunnel_find(struct pim_instance *pim,
						    pim_addr umh)
{
	struct listnode *node;
	struct pim_dimt_tunnel *tun;

	if (!pim->dimt_tunnel_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_tunnel_list, node, tun))
		if (!pim_addr_cmp(tun->umh, umh))
			return tun;

	return NULL;
}

static struct pim_dimt_tunnel *
pim_dimt_tunnel_find_by_id(struct pim_instance *pim, uint32_t tunnel_id)
{
	struct listnode *node;
	struct pim_dimt_tunnel *tun;

	if (!pim->dimt_tunnel_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_tunnel_list, node, tun))
		if (tun->tunnel_id == tunnel_id)
			return tun;

	return NULL;
}

/* Send one ADD or DEL for `tun`.  The request bytes are built once at
 * allocation time and never recomputed, because zebra treats a
 * byte-identical re-ADD as idempotent (it memcmp()s the stored request) --
 * that is exactly what makes reconnect replay safe, and it only holds if
 * we resend the identical struct. */
static bool pim_dimt_tunnel_send(struct pim_dimt_tunnel *tun, bool add)
{
	struct stream *s;

	if (!pim_zclient || pim_zclient->sock < 0)
		return false;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: tunnel %s id=%u umh=%pPAs", add ? "ADD" : "DEL",
			   tun->tunnel_id, &tun->umh);

	s = pim_zclient->obuf;
	zapi_dimt_tunnel_encode(s, add ? ZEBRA_DIMT_TUNNEL_ADD
				       : ZEBRA_DIMT_TUNNEL_DEL,
				VRF_DEFAULT, &tun->req);

	return zclient_send_message(pim_zclient) != ZCLIENT_SEND_FAILURE;
}

/* Build the immutable request for a UMH from its configured endpoint row. */
static void pim_dimt_tunnel_build_req(struct pim_instance *pim,
				      struct pim_dimt_tunnel *tun,
				      const struct pim_dimt_endpoint *ep)
{
	struct zapi_dimt_tunnel *req = &tun->req;

	memset(req, 0, sizeof(*req));
	req->tunnel_id = tun->tunnel_id;
	req->inner_local = ep->inner_local;
	/* The inner peer IS the UMH -- the settlement identity, never a
	 * derived address (D2). */
#if PIM_IPV == 4
	req->inner_peer.ipa_type = IPADDR_V4;
	req->inner_peer.ipaddr_v4 = tun->umh;
#else
	req->inner_peer.ipa_type = IPADDR_V6;
	req->inner_peer.ipaddr_v6 = tun->umh;
#endif
	req->outer_local = ep->outer_local;
	req->outer_remote = ep->outer_remote;
	req->encap = ep->encap;
	req->dport = ep->dport;
	if (ep->key_set) {
		req->options |= ZAPI_DIMT_TUNNEL_KEY_PRESENT;
		req->key = ep->key;
	}
	if (ep->mtu_set) {
		req->options |= ZAPI_DIMT_TUNNEL_MTU_PRESENT;
		req->mtu = ep->mtu;
	}

	snprintf(tun->ifname, sizeof(tun->ifname), "dimt-%08x", tun->tunnel_id);
}

/* An endpoint row was edited.  Re-point any tunnel already built from the
 * previous version of it.
 *
 * pim_dimt_reconcile() cannot do this on its own: it calls
 * pim_dimt_tunnel_build_req() only on the path that CREATES a tunnel, so for a
 * UMH that already has one the edited row was previously accepted into the
 * config, echoed back by `show running-config`, and never reached the netdev.
 * The tunnel kept encapsulating to the old outer endpoint, and because none of
 * the three readiness conjuncts inspects the outer address it still reported
 * READY -- config and kernel silently disagreeing, which is exactly the failure
 * mode this contract exists to eliminate.
 *
 * A re-ADD cannot express the change: zebra memcmp()s the stored request and
 * answers a differing one with FAIL_INSTALL rather than mutating the netdev in
 * place, so the only path is DEL then ADD.  That is what readd_pending already
 * means, so this reuses it rather than inventing a second mechanism.
 *
 * The request is rebuilt unconditionally at the end, and the comparison is made
 * against the rebuilt bytes rather than against the endpoint struct: those
 * bytes are what zebra actually compares, so this cannot drift from zebra's own
 * notion of "identical".  Rebuilding before the DEL is safe -- zebra's delete
 * path matches on tunnel_id and owner only, never on the tunnel parameters.
 */
static void pim_dimt_endpoint_apply_change(struct pim_instance *pim,
					   const struct pim_dimt_endpoint *ep)
{
	struct pim_dimt_tunnel *tun = pim_dimt_tunnel_find(pim, ep->umh);
	struct zapi_dimt_tunnel prev;

	if (!tun)
		return;

	prev = tun->req;
	pim_dimt_tunnel_build_req(pim, tun, ep);

	/* build_req() memset()s the request first, so padding is deterministic
	 * and this memcmp is well-defined.  It is also the same comparison
	 * zebra makes. */
	if (!memcmp(&prev, &tun->req, sizeof(prev)))
		return;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: endpoint for UMH %pPAs changed; rebuilding tunnel %s (state %d)",
			   &ep->umh, tun->ifname, tun->state);

	switch (tun->state) {
	case PIM_DIMT_TUNNEL_INSTALLED:
	case PIM_DIMT_TUNNEL_REQUESTED:
		/* A netdev exists (or is being built) with the old parameters.
		 * Tear it down; the ADD is re-issued from the rebuilt request
		 * when REMOVED lands. */
		if (pim_dimt_tunnel_send(tun, false)) {
			tun->state = PIM_DIMT_TUNNEL_REMOVING;
			tun->readd_pending = true;
		}
		break;
	case PIM_DIMT_TUNNEL_REMOVING:
		/* Already tearing down; the re-ADD picks up the new request. */
		tun->readd_pending = true;
		break;
	case PIM_DIMT_TUNNEL_IDLE:
	case PIM_DIMT_TUNNEL_FAILED:
		/* No netdev to replace.  reconcile() re-ADDs from the rebuilt
		 * request on the demand edge that follows, and FAILED
		 * re-requesting here is correct: an edited endpoint is exactly
		 * the operator action that can fix a failed outer. */
		break;
	}
}

/* Does this upstream demand a native DIMT tunnel, and toward which UMH?
 * Returns NULL when the upstream is not DIMT-steered at all.
 *
 * Demand and readiness-reporting are the SAME predicate, deliberately
 * sharing one implementation: a tunnel exists because some upstream
 * demanded it, so every tunnel must have at least one upstream reporting
 * on it.  These were two hand-copied bodies until the copies drifted --
 * readiness kept its own SRC_DIMT test, which is the achieved-pin flag, so
 * a tunnel whose create failed raised demand but reported nothing at all. */
static struct pim_dimt_umh *pim_dimt_upstream_demand(struct pim_instance *pim,
						     struct pim_upstream *up)
{
	struct pim_dimt_umh *umh;

	return pim_dimt_upstream_steered(pim, up, &umh) ? umh : NULL;
}

/* Recompute tunnel demand across every upstream and drive the resulting
 * ADD/DEL edges.  Idempotent by construction: it is safe (and expected) to
 * call this from any event that can change the answer. */
void pim_dimt_reconcile(struct pim_instance *pim)
{
	struct listnode *node, *nnode;
	struct pim_dimt_tunnel *tun;
	struct pim_upstream *up;
	struct pim_dimt_umh *umh;
	struct pim_dimt_endpoint *ep;

	if (!pim->dimt_tunnel_list || !pim->dimt_endpoint_list)
		return;

	/* Both lists are allocated unconditionally by pim_dimt_init(), so the
	 * NULL check above never fires on a live instance.  This one does:
	 * with no endpoint rows no tunnel can be created (the walk below needs
	 * an ep), and with no tunnels there is nothing to tear down -- so the
	 * answer cannot change and the upstream walk is pure cost.  That keeps
	 * the pim_upstream_new()/pim_upstream_del() hooks free for every
	 * deployment not using DIMT, which is the overwhelming majority. */
	if (!listcount(pim->dimt_endpoint_list) &&
	    !listcount(pim->dimt_tunnel_list))
		return;

	/* Recount demand from scratch rather than incrementing on events:
	 * a missed decrement would strand a tunnel forever. */
	for (ALL_LIST_ELEMENTS_RO(pim->dimt_tunnel_list, node, tun))
		tun->refcount = 0;

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		umh = pim_dimt_upstream_demand(pim, up);
		if (!umh)
			continue;

		ep = pim_dimt_endpoint_find(pim, umh->umh);
		if (!ep) {
			/* No explicit row: deliberately no tunnel.  Log it
			 * once per pass -- a silently missing mapping is the
			 * failure mode the derivation used to paper over. */
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug("DIMT: %s demands UMH %pPAs but no tunnel-endpoint row is configured; no tunnel",
					   up->sg_str, &umh->umh);
			continue;
		}

		tun = pim_dimt_tunnel_find(pim, umh->umh);
		if (!tun) {
			tun = XCALLOC(MTYPE_PIM_DIMT_TUNNEL, sizeof(*tun));
			tun->umh = umh->umh;
			tun->tunnel_id = pim_dimt_tunnel_id_alloc(pim, umh->umh);
			tun->state = PIM_DIMT_TUNNEL_IDLE;
			pim_dimt_tunnel_build_req(pim, tun, ep);
			listnode_add(pim->dimt_tunnel_list, tun);
		}
		tun->refcount++;
	}

	for (ALL_LIST_ELEMENTS(pim->dimt_tunnel_list, node, nnode, tun)) {
		if (tun->refcount) {
			switch (tun->state) {
			case PIM_DIMT_TUNNEL_IDLE:
			case PIM_DIMT_TUNNEL_FAILED:
				/* FAILED re-requests only on a real edge
				 * (new demand, endpoint change, reconnect) --
				 * never on a timer, so a persistently broken
				 * outer cannot become a retry loop. */
				if (pim_dimt_tunnel_send(tun, true))
					tun->state = PIM_DIMT_TUNNEL_REQUESTED;
				break;
			case PIM_DIMT_TUNNEL_REMOVING:
				/* Demand returned mid-teardown.  Re-ADD only
				 * after REMOVED lands, otherwise zebra
				 * rejects the add against the in-flight
				 * delete. */
				tun->readd_pending = true;
				break;
			case PIM_DIMT_TUNNEL_REQUESTED:
			case PIM_DIMT_TUNNEL_INSTALLED:
				break;
			}
			continue;
		}

		switch (tun->state) {
		case PIM_DIMT_TUNNEL_INSTALLED:
		case PIM_DIMT_TUNNEL_REQUESTED:
			tun->readd_pending = false;
			if (pim_dimt_tunnel_send(tun, false))
				tun->state = PIM_DIMT_TUNNEL_REMOVING;
			break;
		case PIM_DIMT_TUNNEL_IDLE:
		case PIM_DIMT_TUNNEL_FAILED:
			listnode_delete(pim->dimt_tunnel_list, tun);
			pim_dimt_tunnel_free(tun);
			break;
		case PIM_DIMT_TUNNEL_REMOVING:
			tun->readd_pending = false;
			break;
		}
	}
}

/* An interface pimd asked zebra to create just appeared (or was addressed).
 * Adopt it as a PIM Light interface so it can carry the RPF pin and become a
 * multicast vif.  No-op for interfaces we did not request. */
void pim_dimt_ifp_adopt(struct pim_instance *pim, struct interface *ifp)
{
	struct listnode *node;
	struct pim_dimt_tunnel *tun;
	struct pim_interface *pim_ifp;

	if (!pim->dimt_tunnel_list)
		return;

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_tunnel_list, node, tun)) {
		if (strncmp(tun->ifname, ifp->name, sizeof(tun->ifname)))
			continue;

		tun->ifindex = ifp->ifindex;

		pim_ifp = ifp->info;
		if (!pim_ifp)
			pim_ifp = pim_if_new(ifp, false /*gm*/, true /*pim*/,
					     false /*ispimreg*/,
					     false /*is_vxlan_term*/);
		if (!pim_ifp)
			return;

		pim_ifp->pim_enable = true;
		pim_ifp->pim_light_enable = true;

		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("DIMT: adopted %s (ifindex %d) for UMH %pPAs",
				   ifp->name, ifp->ifindex, &tun->umh);

		pim_dimt_iface_up(pim, ifp);
		return;
	}
}

/* ZEBRA_DIMT_TUNNEL_NOTIFY_OWNER -- the only acknowledgement that counts.
 * ZAPI carries no request-id, so correlation is the pimd-allocated
 * tunnel_id cookie re-echoed by zebra. */
void pim_dimt_tunnel_notify(struct pim_instance *pim,
			    const struct zapi_dimt_tunnel_notify *notify)
{
	struct pim_dimt_tunnel *tun;
	struct interface *ifp;

	tun = pim_dimt_tunnel_find_by_id(pim, notify->tunnel_id);
	if (!tun) {
		/* A notify for a cookie we no longer hold: the tunnel was
		 * torn down while the ack was in flight.  Nothing to do --
		 * zebra owns the netdev's fate from here. */
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("DIMT: notify for unknown tunnel_id %u (result %u)",
				   notify->tunnel_id, notify->result);
		return;
	}

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: notify id=%u umh=%pPAs result=%u ifindex=%d",
			   tun->tunnel_id, &tun->umh, notify->result,
			   notify->ifindex);

	switch (notify->result) {
	case ZAPI_DIMT_TUNNEL_INSTALLED:
		tun->state = PIM_DIMT_TUNNEL_INSTALLED;
		tun->ifindex = notify->ifindex;
		/* Positive netlink ack.  That is precondition (1) of three;
		 * readiness still needs the RPF pin and kernel MFC
		 * admission, which pim_dimt_forwarding_state() checks. */
		ifp = if_lookup_by_index(notify->ifindex, pim->vrf->vrf_id);
		if (ifp)
			pim_dimt_ifp_adopt(pim, ifp);
		break;
	case ZAPI_DIMT_TUNNEL_FAIL_INSTALL:
		/* Includes zebra's anti-recursion refusal: an outer endpoint
		 * that resolves through a DIMT interface is rejected here
		 * rather than building a tunnel through itself. */
		tun->state = PIM_DIMT_TUNNEL_FAILED;
		tun->ifindex = 0;
		break;
	case ZAPI_DIMT_TUNNEL_REMOVED:
		tun->ifindex = 0;
		if (tun->readd_pending) {
			tun->readd_pending = false;
			tun->state = pim_dimt_tunnel_send(tun, true)
					     ? PIM_DIMT_TUNNEL_REQUESTED
					     : PIM_DIMT_TUNNEL_IDLE;
			break;
		}
		listnode_delete(pim->dimt_tunnel_list, tun);
		pim_dimt_tunnel_free(tun);
		tun = NULL;
		break;
	case ZAPI_DIMT_TUNNEL_REMOVE_FAIL:
		/* The netdev survives.  Return to INSTALLED so the next
		 * demand edge re-drives a delete; do not spin. */
		tun->state = PIM_DIMT_TUNNEL_INSTALLED;
		break;
	}

	/* Readiness may have moved in either direction. */
	pim_dimt_readiness_update(pim);
}

/* The zebra session that owned every outstanding request is gone.  Drop the
 * *acknowledgement* state without sending anything -- nothing can be acked
 * over a dead socket -- but keep each tunnel's identity (tunnel_id and the
 * exact request bytes).
 *
 * Keeping identity is what makes reconnect non-destructive: the kernel
 * netdevs deliberately survive a zebra restart, and the byte-identical
 * re-ADD that reconcile issues next is answered by zebra re-adopting the
 * existing `dimt-%08x` link and re-notifying INSTALLED.  Forgetting the
 * cookie here would mint a new id, build a parallel netdev and strand the
 * original.
 *
 * Readiness collapses to PENDING because state goes back to IDLE, which is
 * exactly D4's requirement: readiness is re-derived from a fresh kernel
 * acknowledgement, never assumed from pre-restart intent.
 */
void pim_dimt_tunnel_session_reset(struct pim_instance *pim)
{
	struct listnode *node;
	struct pim_dimt_tunnel *tun;

	if (!pim->dimt_tunnel_list)
		return;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: zebra session reset; re-deriving %u tunnels from kernel state",
			   listcount(pim->dimt_tunnel_list));

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_tunnel_list, node, tun)) {
		tun->state = PIM_DIMT_TUNNEL_IDLE;
		tun->ifindex = 0;
		tun->readd_pending = false;
	}
}

/* ------------------------------------------------------------------------
 * Readiness aggregation (contract D3/D8.3)
 * ------------------------------------------------------------------------
 */

enum zapi_mvpn_sg_forwarding
pim_dimt_forwarding_state(struct pim_instance *pim, struct pim_upstream *up)
{
	struct pim_dimt_umh *umh;
	struct pim_dimt_tunnel *tun;
	struct pim_interface *pim_ifp;
	struct channel_oil *c_oil;
	struct interface *ifp;

	/* Not DIMT-steered: this contract proves DIMT forwarding and has
	 * nothing to say about a path it does not own.  PENDING is the
	 * fail-closed reading, and PR 4 gates its additive
	 * forwarding_ready on READY only.
	 *
	 * Keyed on the mapping, NOT on PIM_UPSTREAM_FLAG_SRC_DIMT: the flag
	 * means "already pinned", so reading it here would collapse "the
	 * tunnel failed" into "not ours" and lose FWD_FAILED entirely. */
	if (!pim_dimt_upstream_steered(pim, up, &umh))
		return ZAPI_MVPN_SG_FWD_PENDING;

	tun = pim_dimt_tunnel_find(pim, umh->umh);
	if (!tun)
		return ZAPI_MVPN_SG_FWD_PENDING;
	if (tun->state == PIM_DIMT_TUNNEL_FAILED)
		return ZAPI_MVPN_SG_FWD_FAILED;
	/* (1) positive netlink ack for the netdev. */
	if (tun->state != PIM_DIMT_TUNNEL_INSTALLED)
		return ZAPI_MVPN_SG_FWD_PENDING;

	/* (2) RPF actually pinned onto that netdev.  Interface-UP alone is
	 * explicitly insufficient (D8.3): a GRE link is admin-up regardless
	 * of whether the peer is reachable, so "up" proves nothing. */
	ifp = up->rpf.source_nexthop.interface;
	if (!ifp || ifp->ifindex != tun->ifindex)
		return ZAPI_MVPN_SG_FWD_PENDING;

	/* (3) MRT_ADD_MFC returned 0 AND the DIMT vif is the admitted
	 * incoming vif of that entry.  c_oil->installed is set only from the
	 * return of the actual MRT_ADD_MFC setsockopt, so this reads kernel
	 * acceptance rather than pimd's intent -- asking pimd whether pimd
	 * believes it programmed the OIL would be vacuous (G10).
	 *
	 * NOTE -- deliberate divergence from the contract's wording, not from
	 * its intent.  D3/D4/D6 each say "DIMT vif in the OIL" / "DIMT oif".
	 * Read literally that is wrong for the daemon that runs this code:
	 * this is the *requesting*, receiver-side router (D3 create: "Local
	 * join ... -> pimd resolves UMH -> ZEBRA_DIMT_TUNNEL_ADD"), so
	 * multicast ARRIVES over the tunnel.  The DIMT vif is therefore the
	 * incoming vif; a DIMT vif in that router's OIL would be a forwarding
	 * loop, and gating readiness on it would mean gating on a bug.
	 *
	 * The incoming-vif reading is also the only one that makes D3's three
	 * conjuncts independent: (1) is zebra's netlink ack, (2) is pimd's
	 * own control-plane RPF belief, and (3) is what the KERNEL actually
	 * admitted.  Under an OIL reading, (3) collapses into (2) and the
	 * contract loses exactly the control-plane-vs-kernel distinction it
	 * exists to enforce.  "OIL" is read as shorthand for "the kernel MFC
	 * entry".  Raised for a wording erratum on BLO-27738; the strict
	 * incoming-vif check is the stronger of the two readings, so it is
	 * safe to land ahead of that. */
	c_oil = up->channel_oil;
	if (!c_oil || !c_oil->installed)
		return ZAPI_MVPN_SG_FWD_PENDING;

	pim_ifp = ifp->info;
	if (!pim_ifp || pim_ifp->mroute_vif_index < 0)
		return ZAPI_MVPN_SG_FWD_PENDING;
	/* Compare through int: this file is in pim_common, so it is compiled
	 * for pim6d as well, where oil_incoming_vif() returns mifi_t rather
	 * than vifi_t (and vifi_t is an IPv4-only mroute type). int is wide
	 * enough for both and keeps the comparison free of -Wsign-compare. */
	if ((int)*oil_incoming_vif(c_oil) != (int)pim_ifp->mroute_vif_index)
		return ZAPI_MVPN_SG_FWD_PENDING;

	return ZAPI_MVPN_SG_FWD_READY;
}

void pim_dimt_readiness_update(struct pim_instance *pim)
{
	struct pim_upstream *up;

	frr_each (rb_pim_upstream, &pim->upstream_head, up)
		pim_gtm_forwarding_update(pim, up);
}

void pim_dimt_show_tunnel(struct pim_instance *pim, struct vty *vty, bool json)
{
	struct listnode *node;
	struct pim_dimt_tunnel *tun;
	json_object *jobj = NULL;
	static const char *const states[] = {
		[PIM_DIMT_TUNNEL_IDLE] = "idle",
		[PIM_DIMT_TUNNEL_REQUESTED] = "requested",
		[PIM_DIMT_TUNNEL_INSTALLED] = "installed",
		[PIM_DIMT_TUNNEL_FAILED] = "failed",
		[PIM_DIMT_TUNNEL_REMOVING] = "removing",
	};

	if (json)
		jobj = json_object_new_object();
	else
		vty_out(vty, "%-16s %-10s %-16s %-10s %-8s %s\n", "UMH", "TunnelId",
			"Interface", "State", "Refcount", "Ifindex");

	if (!pim->dimt_tunnel_list)
		goto done;

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_tunnel_list, node, tun)) {
		if (jobj) {
			json_object *jtun = json_object_new_object();
			char umh_str[PIM_ADDRSTRLEN];

			snprintfrr(umh_str, sizeof(umh_str), "%pPAs",
				   &tun->umh);
			json_object_int_add(jtun, "tunnelId", tun->tunnel_id);
			json_object_string_add(jtun, "interface", tun->ifname);
			json_object_string_add(jtun, "state",
					       states[tun->state]);
			json_object_int_add(jtun, "refcount", tun->refcount);
			json_object_int_add(jtun, "ifindex", tun->ifindex);
			json_object_object_add(jobj, umh_str, jtun);
		} else {
			vty_out(vty, "%-16pPAs %-10u %-16s %-10s %-8u %d\n",
				&tun->umh, tun->tunnel_id, tun->ifname,
				states[tun->state], tun->refcount,
				tun->ifindex);
		}
	}

done:
	if (jobj)
		vty_json(vty, jobj);
}

/*
 * Per-(S,G) readiness, the aggregation this PR exists to produce.
 *
 * Without this the verdict is unobservable: pim_dimt_forwarding_state() is
 * reachable only through pim_gtm_forwarding_update(), which drops it on the
 * floor unless `mvpn-gtm` is configured AND the upstream is gtm-announced,
 * and even then it leaves only as a zapi re-ADD toward bgpd.  A topotest
 * cannot assert D6's readiness boundary against a value that never surfaces.
 *
 * Reading this is NOT the evidence -- that would be the vacuous
 * control-plane read G10 forbids.  The evidence stays kernel-side (`ip -d
 * link show` for the netdev, /proc/net/ip_mr_cache for the admitted
 * incoming vif); this command exposes pimd's *aggregation* of those facts so
 * a test can assert the two agree.  Disagreement is precisely the bug class
 * the contract targets, and it is undetectable while one side is invisible.
 *
 * `refcount` and `interface` come from the tunnel; `forwarding` is recomputed
 * live rather than cached, so it can never report a stale edge.
 */
void pim_dimt_show_forwarding(struct pim_instance *pim, struct vty *vty,
			      bool json)
{
	struct pim_upstream *up;
	json_object *jobj = NULL;
	static const char *const fwd[] = {
		[ZAPI_MVPN_SG_FWD_PENDING] = "pending",
		[ZAPI_MVPN_SG_FWD_READY] = "ready",
		[ZAPI_MVPN_SG_FWD_FAILED] = "failed",
	};

	if (json)
		jobj = json_object_new_object();
	else
		vty_out(vty, "%-34s %-10s %-16s %s\n", "Source,Group",
			"Forwarding", "Interface", "UMH");

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		enum zapi_mvpn_sg_forwarding state;
		struct pim_dimt_umh *umh;
		struct interface *ifp;
		const char *ifname;
		char umh_str[PIM_ADDRSTRLEN];

		/* Only DIMT-steered upstreams: this contract has nothing to
		 * say about a path it does not own, and listing every
		 * upstream as "pending" would invite exactly that misreading.
		 *
		 * Steered-by-intent, not SRC_DIMT: a tunnel that failed to
		 * create was never pinned, and skipping it here is what made
		 * the D3 `failed` state invisible to the operator and to the
		 * D6 boundary that asserts it. */
		if (!pim_dimt_upstream_steered(pim, up, &umh))
			continue;

		state = pim_dimt_forwarding_state(pim, up);
		ifp = up->rpf.source_nexthop.interface;
		ifname = ifp ? ifp->name : "-";

		/* Non-NULL whenever the upstream is steered. */
		snprintfrr(umh_str, sizeof(umh_str), "%pPAs", &umh->umh);

		if (jobj) {
			json_object *jup = json_object_new_object();

			json_object_string_add(jup, "forwarding", fwd[state]);
			json_object_string_add(jup, "interface", ifname);
			json_object_string_add(jup, "umh", umh_str);
			/* The kernel-side conjunct, split out so a failing
			 * test says WHICH of the three did not hold. */
			json_object_boolean_add(jup, "mfcInstalled",
						up->channel_oil &&
							up->channel_oil
								->installed);
			json_object_object_add(jobj, up->sg_str, jup);
		} else {
			vty_out(vty, "%-34s %-10s %-16s %s\n", up->sg_str,
				fwd[state], ifname, umh_str);
		}
	}

	if (jobj)
		vty_json(vty, jobj);
}
