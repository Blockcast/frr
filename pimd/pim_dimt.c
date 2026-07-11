// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DIMT (draft-zzhang-mboned-dynamic-internet-mcast-tunnel) UMH consumer.
 *
 * bgpd extracts the Upstream Multicast Hop extended community from unicast
 * source routes and relays (prefix -> UMH) mappings here through zebra's
 * stateless UMH relay. For every (S,G) upstream whose source is covered by
 * a mapping, RPF is pinned to the PIM Light interface whose connected
 * subnet contains the UMH, with rpf_addr = UMH -- the pim_vxlan
 * "orig mroute" STATIC_IIF pattern. This replaces Phase A's per-source
 * static route.
 */

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "prefix.h"
#include "vty.h"
#include "json.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_iface.h"
#include "pim_rpf.h"
#include "pim_upstream.h"
#include "pim_oil.h"
#include "pim_mroute.h"
#include "pim_str.h"
#include "pim_dimt.h"

static void pim_dimt_umh_free(void *arg)
{
	XFREE(MTYPE_TMP, arg);
}

void pim_dimt_init(struct pim_instance *pim)
{
	pim->dimt_umh_list = list_new();
	pim->dimt_umh_list->del = pim_dimt_umh_free;
}

void pim_dimt_terminate(struct pim_instance *pim)
{
	if (pim->dimt_umh_list)
		list_delete(&pim->dimt_umh_list);
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

/* The light interface facing a UMH: pim-light enabled and a connected
 * (or ptp peer) subnet containing the UMH address. */
static struct interface *pim_dimt_light_iface(struct pim_instance *pim,
					      pim_addr umh_addr)
{
	struct interface *ifp;
	struct prefix pumh;

	pim_addr_to_prefix(&pumh, umh_addr);

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;
		struct connected *c;

		if (!pim_ifp || !pim_ifp->pim_light_enable ||
		    !if_is_operative(ifp))
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
	    !pim_addr_cmp(up->rpf.rpf_addr, umh->umh))
		return;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: pinning %s RPF to %s via UMH %pPAs",
			   up->sg_str, ifp->name, &umh->umh);

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
 * resolution. */
static void pim_dimt_upstream_unpin(struct pim_instance *pim,
				    struct pim_upstream *up)
{
	if (!PIM_UPSTREAM_FLAG_TEST_STATIC_IIF(up->flags))
		return;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: unpinning %s RPF", up->sg_str);

	PIM_UPSTREAM_FLAG_UNSET_STATIC_IIF(up->flags);
	up->rpf.rpf_addr = PIMADDR_ANY;

	(void)pim_rpf_update(pim, up, NULL, NULL, __func__);
	pim_upstream_update_use_rpt(up, false /*update_mroute*/);
	if (up->channel_oil)
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);
	pim_upstream_update_join_desired(pim, up);
}

void pim_dimt_upstream_apply(struct pim_instance *pim,
			     struct pim_upstream *up)
{
	struct pim_dimt_umh *umh;
	struct interface *ifp;

	if (pim_addr_is_any(up->sg.src))
		return;
	/* vxlan and other explicit STATIC_IIF owners keep theirs; only
	 * upstreams we pinned (rpf_addr set from a mapping) or unpinned
	 * ones are eligible. */
	if (PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN(up->flags))
		return;

	umh = pim_dimt_umh_lookup(pim, up->sg.src);
	if (!umh)
		return;

	/* We ARE the UMH (source-side PE: our own origination echoes back
	 * through the loc-RIB hook) -- normal RPF toward the local source
	 * applies, never a pin toward ourselves. */
	if (if_lookup_address_local(&umh->umh, PIM_AF, pim->vrf->vrf_id))
		return;

	ifp = pim_dimt_light_iface(pim, umh->umh);
	if (!ifp)
		return;

	pim_dimt_upstream_pin(pim, up, umh, ifp);
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
			umh = XCALLOC(MTYPE_TMP, sizeof(*umh));
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

		frr_each (rb_pim_upstream, &pim->upstream_head, up)
			pim_dimt_upstream_apply(pim, up);
	} else {
		if (!umh)
			return;

		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("DIMT: UMH del %pFX", &zumh->prefix);

		listnode_delete(pim->dimt_umh_list, umh);

		frr_each (rb_pim_upstream, &pim->upstream_head, up) {
			struct prefix psrc;

			if (pim_addr_is_any(up->sg.src))
				continue;
			pim_addr_to_prefix(&psrc, up->sg.src);
			if (!prefix_match(&umh->prefix, &psrc))
				continue;
			pim_dimt_upstream_unpin(pim, up);
			/* another, shorter mapping may still cover it */
			pim_dimt_upstream_apply(pim, up);
		}

		pim_dimt_umh_free(umh);
	}
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
