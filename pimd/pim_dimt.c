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
#include "frrevent.h"

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
#include "pim_jp_agg.h"
#include "pim_neighbor.h"
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
	event_cancel(&pim->dimt_umh_resync_timer);
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

static struct pim_dimt_tunnel *pim_dimt_tunnel_find(struct pim_instance *pim,
						    pim_addr umh);
static struct pim_dimt_endpoint *pim_dimt_endpoint_find(struct pim_instance *pim,
							pim_addr umh);

/* Is this interface usable as an RPF pin target?  pim_enable filters out
 * interfaces that cannot send joins and interfaces mid-teardown by
 * `no ip pim`; pim_light_enable is what makes a neighborless pin legal.
 *
 * pim_dimt_normal is the other way a pin becomes legal: a `pim-mode normal`
 * DIMT netdev runs hellos and holds a real adjacency, so its pin is legal for
 * the ordinary RFC 7761 reason instead of the RFC 9739 one.  Testing the DIMT
 * flag rather than dropping the light requirement outright keeps
 * pim_dimt_covering_iface()'s no-tunnel search unchanged: an interface pimd
 * did not build for a UMH is still only pinnable when it is light. */
static bool pim_dimt_iface_pinnable(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	if (!ifp)
		return false;

	pim_ifp = ifp->info;

	return pim_ifp && pim_ifp->pim_enable &&
	       (pim_ifp->pim_light_enable || pim_ifp->pim_dimt_normal) &&
	       if_is_operative(ifp);
}

/* First pinnable, *non-tunnel* light interface whose connected subnet (or ptp
 * peer) covers the UMH.  This is the Phase-B resolver, and it is retained
 * verbatim for the no-tunnel case -- but it is order-dependent by nature
 * (FOR_ALL_INTERFACES has no defined order w.r.t. netdev creation), so it is
 * never allowed to answer for a UMH that has a tunnel.  `skip` excludes the
 * DIMT netdev so the result is a genuine second candidate. */
static struct interface *pim_dimt_covering_iface(struct pim_instance *pim,
						 pim_addr umh_addr,
						 const struct interface *skip)
{
	struct interface *ifp;
	struct prefix pumh;

	pim_addr_to_prefix(&pumh, umh_addr);

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct connected *c;

		if (ifp == skip || !pim_dimt_iface_pinnable(ifp))
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

/* How a UMH's RPF pin resolved.  Recorded so the choice is observable:
 * the failure this exists to kill was silent precisely because a wrong
 * answer and a right answer were indistinguishable from the box. */
enum pim_dimt_pin_source {
	/* nothing resolves; no pin */
	PIM_DIMT_PIN_NONE = 0,
	/* the DIMT netdev serving this UMH */
	PIM_DIMT_PIN_TUNNEL,
	/* a configured pim-light interface covering the UMH (no tunnel) */
	PIM_DIMT_PIN_LIGHT,
	/* a tunnel is demanded but its netdev is not pinnable yet */
	PIM_DIMT_PIN_TUNNEL_PENDING,
	/*
	 * The tunnel for this UMH is in state `failed`, so nothing will
	 * become pinnable without a new demand edge.
	 *
	 * Distinct from TUNNEL_PENDING because the two need opposite
	 * responses and only differ by a field an operator cannot see from
	 * this command: a FAILED row keeps its place in dimt_tunnel_list with
	 * ifindex 0, so it is not-pinnable forever.  Reporting that as
	 * "pending" tells the operator to wait for something that will never
	 * arrive -- zebra's anti-recursion refusal lands here and never
	 * self-heals.  pim_dimt_forwarding_state() already separates them.
	 */
	PIM_DIMT_PIN_TUNNEL_FAILED,

	/* Sentinel, so the string table below can be size-checked.  Keep it
	 * last and add new sources above it. */
	PIM_DIMT_PIN_MAX,
};

/* Which resolver answered.  Not cosmetic: "tunnel-pending" and
 * "tunnel-failed" are the states that used to be indistinguishable from a
 * healthy pin, and from each other. */
static const char *const pim_dimt_pin_source_str[] = {
	[PIM_DIMT_PIN_NONE] = "none",
	[PIM_DIMT_PIN_TUNNEL] = "tunnel",
	[PIM_DIMT_PIN_LIGHT] = "light",
	[PIM_DIMT_PIN_TUNNEL_PENDING] = "tunnel-pending",
	[PIM_DIMT_PIN_TUNNEL_FAILED] = "tunnel-failed",
};

/*
 * This assert pins the table's EXTENT, and only that.
 *
 * The check has to be against the sentinel, not against
 * PIM_DIMT_PIN_TUNNEL_FAILED + 1: appending a source below FAILED changes
 * neither FAILED's value nor -- absent a new entry -- array_size(), so that
 * form would still compile and still read past the end.  PIM_DIMT_PIN_MAX
 * is the only expression here that grows with the enum.
 *
 * What it does NOT catch is an INSERTED source.  array_size() of a
 * designated-initializer array is (highest designated index + 1), so it
 * tracks the largest initialised index, not the count of non-NULL entries.
 * Put a new tunnel state between TUNNEL_PENDING and TUNNEL_FAILED -- the
 * obvious home, since the enum groups the tunnel states together -- and
 * FAILED shifts up, array_size() and PIM_DIMT_PIN_MAX both grow, the assert
 * still passes, and the vacated index is an implicit NULL hole.  Designated
 * initializers make holes legal, so no warning fires either.
 *
 * A NULL there is worse than an out-of-bounds read on one path:
 * json_object_string_add() hands the value to json_object_new_string(),
 * which takes strlen() of it with no NULL guard, so `show ip pim dimt umh
 * json` would fault rather than misprint.  Hence the accessor below: the
 * assert keeps the build-time half, and every read goes through the check
 * that covers the half the assert cannot see.
 */
static_assert(array_size(pim_dimt_pin_source_str) == PIM_DIMT_PIN_MAX,
	      "pim_dimt_pin_source_str is missing an entry for a pin source");

/* The only legal way to read the table.  Never index it directly. */
static const char *pim_dimt_pin_source_name(enum pim_dimt_pin_source source)
{
	/* Cast for the bound check so it holds whichever signedness the
	 * compiler picks for the enum, without a tautological comparison
	 * warning on the unsigned choice. */
	if ((unsigned int)source >= PIM_DIMT_PIN_MAX ||
	    !pim_dimt_pin_source_str[source])
		return "unknown";
	return pim_dimt_pin_source_str[source];
}

struct pim_dimt_pin {
	struct interface *ifp; /* pin target, NULL when unresolved */
	enum pim_dimt_pin_source source;
	/* A covering non-tunnel interface that did NOT get the pin.  Only the
	 * tunnel cases can shadow, and reporting it is the whole point: an
	 * operator can see which interface lost. */
	struct interface *shadowed;
};

/* Resolve the RPF pin for a UMH, deterministically.
 *
 * The rule: if a DIMT tunnel exists for this UMH, that tunnel's netdev is the
 * ONLY legal pin target.  Otherwise fall back to the Phase-B covering-subnet
 * search.
 *
 * Why the tunnel wins outright rather than merely being preferred: the old
 * resolver matched per-interface with no tunnel preference, so a `/24` underlay
 * covering the UMH was exactly as good a match as the tunnel's own `/32` ptp
 * peer, and FOR_ALL_INTERFACES order decided which won.  When the underlay won,
 * readiness conjunct (2) in pim_dimt_forwarding_state() -- rpf interface ==
 * tunnel ifindex -- could never hold, so the tunnel installed clean and never
 * forwarded, with no error and no log.  Preferring the ptp match would only
 * narrow that race (any other ptp link toward the UMH re-opens it); resolving
 * from the tunnel list closes it.
 *
 * Fail-closed while the tunnel is pending: no pin at all, rather than a
 * transient pin onto the underlay.  A pin the tunnel does not own can never
 * satisfy conjunct (2), so it buys no forwarding -- it only reintroduces the
 * ambiguity.  pim_dimt_ifp_adopt() -> pim_dimt_iface_up() re-resolves every
 * upstream the moment the netdev appears, which is what makes waiting safe.
 *
 * `want_shadowed` gates the second, purely diagnostic search.  It is the
 * expensive half: with no competing interface pim_dimt_covering_iface()
 * cannot short-circuit, so it walks every interface and every connected
 * address before returning NULL -- once per upstream, on a path that
 * pim_dimt_iface_up() drives across the whole upstream tree on every
 * connected-address change.  Nothing in the forwarding path reads it. */
static void pim_dimt_resolve_pin(struct pim_instance *pim, pim_addr umh_addr,
				 struct pim_dimt_pin *pin, bool want_shadowed)
{
	struct pim_dimt_tunnel *tun;
	struct interface *tun_ifp = NULL;
	struct interface *own_ifp;

	memset(pin, 0, sizeof(*pin));

	tun = pim_dimt_tunnel_find(pim, umh_addr);
	if (!tun) {
		pin->ifp = pim_dimt_covering_iface(pim, umh_addr, NULL);
		pin->source = pin->ifp ? PIM_DIMT_PIN_LIGHT : PIM_DIMT_PIN_NONE;
		return;
	}

	/* ifindex is 0 until the INSTALLED notify lands, and is reset to 0 on
	 * FAIL_INSTALL and REMOVED -- so a non-zero ifindex is exactly "zebra
	 * has acked a netdev for this tunnel". */
	if (tun->ifindex)
		tun_ifp = if_lookup_by_index(tun->ifindex, pim->vrf->vrf_id);

	if (pim_dimt_iface_pinnable(tun_ifp)) {
		pin->ifp = tun_ifp;
		pin->source = PIM_DIMT_PIN_TUNNEL;
	} else if (tun->state == PIM_DIMT_TUNNEL_FAILED) {
		/* Terminal until demand changes -- do not report it as a wait. */
		pin->source = PIM_DIMT_PIN_TUNNEL_FAILED;
	} else {
		/* Deliberately no fallback: see the comment above. */
		pin->source = PIM_DIMT_PIN_TUNNEL_PENDING;
	}

	if (!want_shadowed)
		return;

	/*
	 * Exclude the tunnel's own netdev by NAME, not by the pointer the
	 * ifindex resolved to -- that pointer is NULL exactly when the netdev
	 * is most likely to still be present.
	 *
	 * pim_dimt_tunnel_session_reset() zeroes ifindex while deliberately
	 * leaving the netdev built: it survives a zebra restart with pim-light
	 * still set from the earlier adopt and the UMH still its ptp peer, so
	 * it covers the UMH and matches itself.  Skipping on the
	 * ifindex-derived pointer would skip nothing there and name the tunnel
	 * as the interface that shadowed its own pin -- for the whole reconnect
	 * window, which is precisely when an operator reads this.  The name is
	 * stable across all of it.
	 */
	own_ifp = tun_ifp ? tun_ifp
			  : if_lookup_by_name(tun->ifname, pim->vrf->vrf_id);

	pin->shadowed = pim_dimt_covering_iface(pim, umh_addr, own_ifp);
}

/* The interface a UMH's RPF pin belongs on, or NULL. */
static struct interface *pim_dimt_light_iface(struct pim_instance *pim,
					      pim_addr umh_addr)
{
	struct pim_dimt_pin pin;

	/* The shadowed search is diagnostic only; skip it unless something
	 * will actually read the answer. */
	pim_dimt_resolve_pin(pim, umh_addr, &pin, PIM_DEBUG_PIM_TRACE);

	if (PIM_DEBUG_PIM_TRACE && pin.shadowed)
		zlog_debug("DIMT: UMH %pPAs pin resolves to %s (%s); covering interface %s does not carry it",
			   &umh_addr, pin.ifp ? pin.ifp->name : "nothing",
			   pim_dimt_pin_source_name(pin.source),
			   pin.shadowed->name);
	else if (PIM_DEBUG_PIM_TRACE &&
		 pin.source == PIM_DIMT_PIN_TUNNEL_PENDING)
		zlog_debug("DIMT: UMH %pPAs has a tunnel but its netdev is not pinnable yet; not pinning",
			   &umh_addr);
	else if (PIM_DEBUG_PIM_TRACE &&
		 pin.source == PIM_DIMT_PIN_TUNNEL_FAILED)
		zlog_debug("DIMT: UMH %pPAs has a failed tunnel; not pinning until demand changes",
			   &umh_addr);

	return pin.ifp;
}

/* ------------------------------------------------------------------------
 * Triggered Join/Prune on DIMT RPF moves
 *
 * STATIC_IIF makes pim_rpf_update() a no-op for a pinned upstream, and with
 * it the whole RFC 7761 4.5.7 "RPF'(S,G) changes" path: nothing sends
 * Join(S,G) toward the new RPF' or Prune(S,G) toward the old one.  An
 * upstream already in Joined state therefore sat silent on a new pin until
 * its periodic Join Timer fired -- up to t_periodic (60 s) of blackhole on
 * every tunnel bring-up and every steer, while the old UMH's copies were
 * RPF-dropped -- and a steered-away UMH never heard a prune at all, so it
 * kept forwarding into a deleted tunnel for its full J/P holdtime.  The
 * helpers below restore both halves for the moves DIMT itself makes.
 * ------------------------------------------------------------------------
 */

/* Can a Join/Prune leave on `ifp` right now?  A DIMT netdev is pinned on its
 * INSTALLED notify, before zebra's inner address has come back round as a
 * connected route, and pim_if_addr_add() only opens the PIM socket once that
 * address lands.  Sending before then fails in sendmsg (fd -1) and is simply
 * lost, which is why a join that cannot go out yet is left pending instead. */
static bool pim_dimt_jp_sendable(const struct interface *ifp)
{
	const struct pim_interface *pim_ifp;

	if (!ifp || !if_is_operative(ifp))
		return false;
	pim_ifp = ifp->info;
	return pim_ifp && pim_ifp->pim_enable && pim_ifp->pim_sock_fd >= 0 &&
	       !pim_addr_is_any(pim_ifp->primary_address);
}

/* Send the Join(S,G) a pin move owes the new RPF', if it can go out now.
 *
 * Only in Joined state: a NotJoined upstream owes no join, and the
 * NotJoined -> Joined transition in pim_upstream_switch() sends its own.  The
 * pending mark survives until a join is actually handed to a usable socket,
 * so the pin path's socket-ready re-entry (pim_if_addr_add() ->
 * pim_dimt_iface_up() -> the unchanged-pin branch below) completes it.  A
 * duplicate Join is harmless -- it is a refresh -- whereas a missing one costs
 * a full t_periodic of blackhole, so every doubt resolves toward sending. */
static void pim_dimt_join_flush(struct pim_upstream *up)
{
	struct interface *ifp = up->rpf.source_nexthop.interface;

	if (!up->dimt_join_pending || up->join_state != PIM_UPSTREAM_JOINED)
		return;
	if (!pim_dimt_jp_sendable(ifp) || pim_addr_is_any(up->rpf.rpf_addr))
		return;

	up->dimt_join_pending = false;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: triggered Join%s toward %pPAs on %s",
			   up->sg_str, &up->rpf.rpf_addr, ifp->name);

	pim_upstream_send_join(up);
	/* Restart the periodic timer from this join, per 4.5.7: the next
	 * refresh is due t_periodic after the triggered one, not after
	 * whatever the old RPF' was last sent. */
	join_timer_start(up);
}

/* Prune(S,G) toward the RPF' DIMT is moving this upstream away from.
 *
 * `old` is a copy taken before the move, because the move overwrites
 * up->rpf.  The prune goes out synchronously: pim_jp_agg_single_upstream_send()
 * builds and sendmsg()s it on the old interface's PIM socket before
 * returning, and a GRE netdev is noqueue, so by the time this returns the
 * encapsulated packet has been handed to the underlay.  Callers that go on
 * to request the old tunnel's deletion therefore need no wait: the ZAPI DEL
 * is written after this returns and zebra deletes the netdev later still, so
 * the teardown cannot overtake the prune -- and, having no timer, cannot
 * hang on it either. */
static void pim_dimt_prune_old(struct pim_upstream *up,
			       const struct pim_rpf *old)
{
	struct pim_rpf rpf = *old;

	if (up->join_state != PIM_UPSTREAM_JOINED)
		return;
	if (!pim_dimt_jp_sendable(rpf.source_nexthop.interface) ||
	    pim_addr_is_any(rpf.rpf_addr))
		return;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: Prune%s toward %pPAs on %s (RPF moved)",
			   up->sg_str, &rpf.rpf_addr,
			   rpf.source_nexthop.interface->name);

	pim_jp_agg_single_upstream_send(&rpf, up, false /* prune */);
}

/* Take the upstream off the J/P aggregation list of the neighbor `old`
 * points at.  Every DIMT move must do this BEFORE it overwrites up->rpf.
 *
 * join_timer_start() puts an upstream on nbr->upstream_jp_agg whenever a
 * neighbor exists for its RPF' -- and on a DIMT netdev one does as soon as
 * the UMH sends us any J/P (pim_pim.c creates a light neighbor for it; the
 * Prune Echo our own prune provokes is enough).  join_timer_stop() and
 * pim_rpf_update() only ever look the neighbor up from the CURRENT RPF, so
 * an entry left behind on the old neighbor is never removed: its jp timer
 * keeps sending Join(S,G) to the UMH we just pruned, undoing the prune, and
 * once the upstream is freed it builds that Join from a dangling js->up.
 * pim_zebra_upstream_rpf_changed() does this same removal for normal RPF
 * moves; STATIC_IIF keeps DIMT's moves out of that path. */
static void pim_dimt_jp_agg_detach(struct pim_upstream *up,
				   const struct pim_rpf *old)
{
	struct pim_neighbor *nbr;

	if (!old->source_nexthop.interface)
		return;

	nbr = pim_neighbor_find(old->source_nexthop.interface, old->rpf_addr,
				true);
	if (!nbr)
		return;

	pim_jp_agg_remove_group(nbr->upstream_jp_agg, up, nbr);
	pim_jp_agg_upstream_verification(up, false);
}

/*
 * The address a pin on `ifp` must write into rpf_addr -- i.e. the address the
 * Join(S,G) names as its upstream neighbour.
 *
 * Light mode: the UMH itself.  RFC 9739 allows a J/P with no adjacency behind
 * it, and the UMH is the only address of the far end we know.
 *
 * Normal mode: the neighbour's hello source address, which is NOT the UMH.
 * The UMH is a loopback on the far side, and RFC 7761 4.9 requires the
 * upstream-neighbour field to be RPF'(S,G) -- a *link* address.  A join
 * addressed to the loopback is dropped silently by Junos (lab T1c-1/T1c-3)
 * and counted as a Join/Prune Rx Error by cEOS (T4e).
 *
 * With no neighbour the answer is PIMADDR_ANY: deliberately unresolved, never
 * the UMH.  That is FRR's existing convention for an unresolved RPF' (see
 * pim_rpf_find_rpf_addr()), and the temptation it refuses -- "fall back to the
 * configured UMH, at least it is an address" -- reintroduces exactly the
 * silent-drop bug above, in the form that is hardest to see: a wrong address
 * and a right one are indistinguishable from the box.
 *
 * pim_neighbor_find_if() returns NULL unless there is exactly one neighbour,
 * so an ambiguous netdev also fails closed rather than picking arbitrarily.
 */
static pim_addr pim_dimt_pin_rpf_addr(struct interface *ifp,
				      const struct pim_dimt_umh *umh)
{
	const struct pim_interface *pim_ifp = ifp->info;
	struct pim_neighbor *nbr;

	if (!pim_ifp || !pim_ifp->pim_dimt_normal)
		return umh->umh;

	nbr = pim_neighbor_find_if(ifp);

	return nbr ? nbr->source_addr : PIMADDR_ANY;
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
	struct pim_rpf old_rpf;
	enum pim_upstream_state old_state;
	pim_addr rpf_addr = pim_dimt_pin_rpf_addr(ifp, umh);

	if (PIM_UPSTREAM_FLAG_TEST_STATIC_IIF(up->flags) &&
	    up->rpf.source_nexthop.interface == ifp &&
	    !pim_addr_cmp(up->rpf.rpf_addr, rpf_addr)) {
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
		/* The same ordering hazard strands the triggered join: the
		 * pin was made before the netdev had a PIM socket, so the join
		 * it owed could not go out.  This branch is where the socket
		 * becoming usable arrives (pim_if_addr_add() opens it, then
		 * calls pim_dimt_iface_up()), so finish it here rather than
		 * leaving it to the 60 s periodic timer. */
		pim_dimt_join_flush(up);
		return;
	}

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: pinning %s RPF to %s via UMH %pPAs (RPF' %pPAs)",
			   up->sg_str, ifp->name, &umh->umh, &rpf_addr);

	/* Whatever RPF' the upstream had -- a previous DIMT pin (a steer) or
	 * the normal unicast path (a first pin) -- is being replaced, and
	 * STATIC_IIF (set below) keeps pim_rpf_update() from ever noticing, so
	 * this is the only place the old RPF' can be cleaned up.  Detach it
	 * from the old neighbor's aggregation list now, while up->rpf still
	 * names that neighbor, and prune it once the new RPF is in place.  On
	 * a steer the prune must also precede the reconcile pass that follows,
	 * which may delete the old tunnel once it has no riders left. */
	old_rpf = up->rpf;
	pim_dimt_jp_agg_detach(up, &old_rpf);

	PIM_UPSTREAM_FLAG_SET_SRC_DIMT(up->flags);
	PIM_UPSTREAM_FLAG_SET_STATIC_IIF(up->flags);
	pim_upstream_fill_static_iif(up, ifp);
	up->rpf.source_nexthop.mrib_nexthop_addr = rpf_addr;
	up->rpf.rpf_addr = rpf_addr;

	/* Not when the "move" lands on the very neighbor we were already
	 * joined through (a first pin whose unicast RPF' was already the UMH
	 * on this netdev): a prune immediately followed by the join below
	 * would only blip the UMH's oif.
	 *
	 * And never when the new RPF' is unresolved.  In normal mode that is a
	 * neighbour expiry, and the pin is deliberately held across it (see
	 * pim_dimt_neighbor_change()).  A prune there would be an active
	 * instruction to stop exactly the traffic we still want, addressed to
	 * a router that by definition is not listening -- and the likeliest
	 * cause of an expiry is transient (a far-end pimd restart, or hello
	 * loss on a congested transit hop) while the GRE data path, being
	 * stateless, never went away. */
	if (!pim_addr_is_any(rpf_addr) && old_rpf.source_nexthop.interface &&
	    (old_rpf.source_nexthop.interface != ifp ||
	     pim_addr_cmp(old_rpf.rpf_addr, rpf_addr)))
		pim_dimt_prune_old(up, &old_rpf);

	pim_upstream_update_use_rpt(up, false /*update_mroute*/);
	if (up->channel_oil)
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);

	/* A NotJoined -> Joined edge sends its own join from
	 * pim_upstream_switch(); only an upstream that was ALREADY Joined
	 * owes one here, and that is the case the pin used to leave to the
	 * periodic timer.  If the switch's join could not go out (no socket
	 * yet) it was lost, so the mark stays set for the flush to redo. */
	old_state = up->join_state;
	up->dimt_join_pending = true;
	pim_upstream_update_join_desired(pim, up);

	/*
	 * Normal mode with no neighbour: the pin is held, the upstream keeps
	 * whatever join state its downstream interest justifies -- dropping to
	 * NotJoined would discard that interest and make re-deriving it on the
	 * neighbour's return a second bug -- but there is nobody to address a
	 * J/P to.  So stop only the periodic Join Timer and leave the join
	 * owed; pim_dimt_neighbor_change() sends it the moment hellos return.
	 *
	 * Leaving the timer armed would have it fire every t_periodic into
	 * pim_upstream_send_join() with an unresolved RPF', which is a wasted
	 * wakeup at best.
	 */
	if (pim_addr_is_any(up->rpf.rpf_addr)) {
		event_cancel(&up->t_join_timer);
		return;
	}

	if (old_state != PIM_UPSTREAM_JOINED &&
	    up->join_state == PIM_UPSTREAM_JOINED && pim_dimt_jp_sendable(ifp))
		up->dimt_join_pending = false;
	pim_dimt_join_flush(up);

	/* The detach above may have removed the only periodic refresh this
	 * upstream had.  If the join is still owed (no socket on the new
	 * netdev yet), keep a Join Timer running against the new RPF' so a
	 * socket that never comes up cannot leave a Joined upstream with no
	 * refresh at all; the socket-ready flush restarts it anyway. */
	if (up->dimt_join_pending && up->join_state == PIM_UPSTREAM_JOINED)
		join_timer_start(up);
}

/* Undo a pin (mapping removed): return the upstream to normal RPF
 * resolution.  Only touches upstreams DIMT itself pinned -- STATIC_IIF
 * owned by another user (pim_vxlan) is left alone. */
static void pim_dimt_upstream_unpin(struct pim_instance *pim,
				    struct pim_upstream *up)
{
	enum pim_upstream_state old_state;

	if (!PIM_UPSTREAM_FLAG_TEST_SRC_DIMT(up->flags))
		return;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: unpinning %s RPF", up->sg_str);

	/* The UMH this pin pointed at must hear a prune while the interface
	 * toward it still exists: an unpin is what a steer toward a tunnel
	 * that is not built yet, or a withdrawn mapping, looks like, and the
	 * reconcile pass that follows deletes the old tunnel.  When the unpin
	 * is BECAUSE the interface went away, it is no longer sendable and
	 * this is a no-op. */
	pim_dimt_jp_agg_detach(up, &up->rpf);
	pim_dimt_prune_old(up, &up->rpf);
	up->dimt_join_pending = false;

	PIM_UPSTREAM_FLAG_UNSET_SRC_DIMT(up->flags);
	PIM_UPSTREAM_FLAG_UNSET_STATIC_IIF(up->flags);
	/* Zeroing rpf_addr forces pim_rpf_update() to see a change, but it
	 * also blinds it to the old neighbor (it looks it up by the zeroed
	 * address) -- which is why the detach above cannot be left to it. */
	up->rpf.rpf_addr = PIMADDR_ANY;

	(void)pim_rpf_update(pim, up, NULL, NULL, __func__);
	pim_upstream_update_use_rpt(up, false /*update_mroute*/);
	if (up->channel_oil)
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);

	old_state = up->join_state;
	pim_upstream_update_join_desired(pim, up);

	/* RPF'(S,G) changed while Joined (4.5.7): Join the new RPF' and
	 * restart the Join Timer against it.  The restart is not optional:
	 * the detach above removed the only periodic refresh an upstream on a
	 * neighbor's aggregation list had.  A NotJoined -> Joined edge already
	 * did both from pim_upstream_switch(). */
	if (old_state == PIM_UPSTREAM_JOINED &&
	    up->join_state == PIM_UPSTREAM_JOINED) {
		if (pim_dimt_jp_sendable(up->rpf.source_nexthop.interface) &&
		    !pim_addr_is_any(up->rpf.rpf_addr))
			pim_upstream_send_join(up);
		join_timer_start(up);
	}
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

	if (!pim_ifp ||
	    !(pim_ifp->pim_light_enable || pim_ifp->pim_dimt_normal))
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

/*
 * A PIM neighbour appeared on, or expired from, `ifp`.
 *
 * Only normal-mode DIMT netdevs react.  There rpf_addr IS the neighbour's
 * hello source address, so the neighbour arriving or going away is an
 * RPF'(S,G) transition -- and STATIC_IIF makes pim_rpf_update() a no-op for a
 * pinned upstream, so none of the normal 4.5.7 machinery will notice.  Rerunning
 * the apply pass recomputes rpf_addr for each pinned upstream and, on the
 * neighbour's return, sends the triggered Join 4.5.7 owes it and restarts the
 * periodic timer (the RPF'(S,G) NULL -> neighbour case).
 *
 * The pin itself is NOT dropped on expiry.  It is config-derived --
 * `dimt tunnel-endpoint ... pim-mode normal` is an operator statement about
 * where this (S,G) comes from -- and a control-plane observation does not
 * revoke config, the same way a static `ip mroute` RPF override survives an
 * adjacency timing out.  Falling back to native RPF instead would flap the RPF
 * interface, and "native RPF" does not mean "no upstream" but *a different*
 * one: if that path can deliver, the overlap joins a second live source of the
 * same (S,G).  See doc/user/pim.rst.
 *
 * Deliberately no prune toward the departing neighbour: see the comment in
 * pim_dimt_upstream_pin().
 */
void pim_dimt_neighbor_change(struct pim_instance *pim, struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp ? ifp->info : NULL;
	struct pim_upstream *up;

	if (!pim || !pim_ifp || !pim_ifp->pim_dimt_normal)
		return;
	if (!pim->dimt_umh_list || !listcount(pim->dimt_umh_list))
		return;

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (!PIM_UPSTREAM_FLAG_TEST_SRC_DIMT(up->flags))
			continue;
		if (up->rpf.source_nexthop.interface != ifp)
			continue;

		pim_dimt_upstream_apply(pim, up);
	}

	/* An unresolved RPF' is not a forwarding-readiness change in itself --
	 * the netdev, the pin and the MFC entry all survive -- but the apply
	 * pass above can still have moved something, and the update is
	 * edge-triggered, so this is cheap when nothing changed. */
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
		/* A mapping the replay reasserts is live again, whether or not
		 * anything in it changed. */
		umh->stale = false;

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

/* Grace period for the UMH re-dump requested at zebra reconnect.
 *
 * Sized for a relay round trip (pimd -> zebra -> bgpd -> N ADDs -> zebra ->
 * pimd), which is sub-second in practice, with a wide margin for a busy or
 * concurrently-restarting bgpd.  It is not sized to cover BGP convergence:
 * a bgpd that restarted has an empty shadow table and re-announces each
 * mapping as it re-learns the route, through the ordinary add path, so
 * convergence does not depend on this timer at all.
 */
#define PIM_DIMT_UMH_RESYNC_GRACE_MSEC 30000

/* Grace expired: every mapping the replay did not reassert is gone. */
static void pim_dimt_umh_resync_sweep(struct event *t)
{
	struct pim_instance *pim = EVENT_ARG(t);
	struct listnode *node, *nnode;
	struct pim_dimt_umh *umh;
	struct pim_upstream *up;
	unsigned int swept = 0;

	for (ALL_LIST_ELEMENTS(pim->dimt_umh_list, node, nnode, umh)) {
		if (!umh->stale)
			continue;
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("DIMT: UMH %pFX -> %pPAs not replayed within grace; dropping",
				   &umh->prefix, &umh->umh);
		listnode_delete(pim->dimt_umh_list, umh);
		pim_dimt_umh_free(umh);
		swept++;
	}

	if (!swept)
		return;

	frr_each (rb_pim_upstream, &pim->upstream_head, up)
		pim_dimt_upstream_apply(pim, up);

	/* Only now can demand legitimately fall, so only now may a tunnel be
	 * torn down.  Tunnels still holding a kernel netdev leave by DEL, not
	 * by being forgotten -- see pim_dimt_tunnel::kernel_present. */
	pim_dimt_reconcile(pim);
	pim_dimt_readiness_update(pim);
}

void pim_dimt_umh_resync_begin(struct pim_instance *pim)
{
	struct listnode *node;
	struct pim_dimt_umh *umh;

	if (!pim->dimt_umh_list)
		return;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: holding %u UMH mappings pending replay",
			   listcount(pim->dimt_umh_list));

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_umh_list, node, umh))
		umh->stale = true;

	/* Re-arm from scratch: a second reconnect inside the window restarts
	 * the wait rather than expiring against the first one's deadline. */
	event_cancel(&pim->dimt_umh_resync_timer);
	event_add_timer_msec(router->master, pim_dimt_umh_resync_sweep, pim,
			     PIM_DIMT_UMH_RESYNC_GRACE_MSEC,
			     &pim->dimt_umh_resync_timer);
}

void pim_dimt_show_umh(struct pim_instance *pim, struct vty *vty, bool json)
{
	struct listnode *node;
	struct pim_dimt_umh *umh;
	json_object *jobj = NULL;

	if (json)
		jobj = json_object_new_object();
	else
		vty_out(vty, "%-22s %-16s %-10s %-4s %-16s %-14s %s\n", "Prefix",
			"UMH", "Type", "Pref", "Interface", "PinSource",
			"Shadowed");

	for (ALL_LIST_ELEMENTS_RO(pim->dimt_umh_list, node, umh)) {
		struct pim_dimt_pin pin;
		struct interface *ifp;
		const char *type = umh->umh_type == ZAPI_UMH_TYPE_PIM
					   ? "pim"
					   : (umh->umh_type ==
						      ZAPI_UMH_TYPE_AMT_RELAY
						      ? "amt-relay"
						      : "unknown");

		pim_dimt_resolve_pin(pim, umh->umh, &pin, true);
		ifp = pin.ifp;

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
			json_object_string_add(jumh, "pinSource",
					       pim_dimt_pin_source_name(pin.source));
			/* Present only when a covering interface actually lost,
			 * so its mere presence is the ambiguity signal. */
			if (pin.shadowed)
				json_object_string_add(jumh, "shadowedInterface",
						       pin.shadowed->name);
			json_object_object_add(jobj, pfx_str, jumh);
		} else {
			vty_out(vty,
				"%-22pFX %-16pPAs %-10s %-4u %-16s %-14s %s\n",
				&umh->prefix, &umh->umh, type,
				umh->preference, ifp ? ifp->name : "none",
				pim_dimt_pin_source_name(pin.source),
				pin.shadowed ? pin.shadowed->name : "-");
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
	struct pim_dimt_tunnel *tun;

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

	/* pim_normal is pimd-local and deliberately absent from the zapi
	 * request, so apply_change()'s memcmp cannot see a mode flip and --
	 * rightly -- does not rebuild an identical netdev for it.  Re-adopt so
	 * the interface flags follow the row instead. */
	tun = pim_dimt_tunnel_find(pim, ep->umh);
	if (tun && tun->ifindex) {
		struct interface *ifp =
			if_lookup_by_index(tun->ifindex, pim->vrf->vrf_id);

		if (ifp)
			pim_dimt_ifp_adopt(pim, ifp);
	}

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
		/* Column 0, NOT indented into the `router pim` block: this
		 * command is installed at CONFIG_NODE, and the written form
		 * has to parse back at the node it is installed at.  See
		 * pim_router_config_write() for what an indented row did on
		 * reload. */
		vty_out(vty, "dimt tunnel-endpoint %pPA inner-local %pIA outer-local %pIA outer %pIA encap %s",
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
		/* Only when normal: `light` is the default, so an untouched
		 * row round-trips byte-identically to what it was before this
		 * keyword existed. */
		if (ep->pim_normal)
			vty_out(vty, " pim-mode normal");
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
 * No timer, polling loop or hold-down participates in any tunnel state
 * transition -- that absence is the requirement Phase A structurally could
 * not meet, so it is load-bearing rather than stylistic.  The one timer in
 * this file is the resync grace timer armed by
 * pim_dimt_umh_resync_begin(); it gates expiry of stale UMH *mappings*
 * after a zebra reconnect and drives no transition here.  See the
 * pim_dimt.h header comment for why that carve-out is safe.
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
 * we resend the identical struct.
 *
 * The VRF is the instance's, not a hardcoded VRF_DEFAULT.  Only the default
 * VRF can hold endpoint rows today (the `dimt tunnel-endpoint` command lives
 * at CONFIG_NODE), so every tunnel that exists is a default-VRF tunnel and
 * the two agree -- but stating VRF_DEFAULT here made that coincidence look
 * like an invariant.  Should a row ever become configurable per-VRF, a
 * hardcoded id would address the ack to the wrong instance rather than fail,
 * which is the kind of bug that surfaces as an unexplained missing notify. */
static bool pim_dimt_zclient_usable(void)
{
	return pim_zclient && pim_zclient->sock >= 0;
}

static bool pim_dimt_tunnel_send(struct pim_instance *pim,
				 struct pim_dimt_tunnel *tun, bool add)
{
	struct stream *s;

	if (!pim_dimt_zclient_usable())
		return false;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("DIMT: tunnel %s id=%u umh=%pPAs", add ? "ADD" : "DEL",
			   tun->tunnel_id, &tun->umh);

	s = pim_zclient->obuf;
	zapi_dimt_tunnel_encode(s, add ? ZEBRA_DIMT_TUNNEL_ADD
				       : ZEBRA_DIMT_TUNNEL_DEL,
				pim->vrf->vrf_id, &tun->req);

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
		if (pim_dimt_tunnel_send(pim, tun, false)) {
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
		if (tun->kernel_present) {
			/* IDLE/FAILED says only that *this* session holds no
			 * acknowledgement -- after a zebra reconnect
			 * pim_dimt_tunnel_session_reset() sets IDLE while a
			 * netdev built by the previous session is still out
			 * there, and a FAIL_INSTALL refusal leaves the older
			 * netdev untouched.  Re-ADDing differing bytes over a
			 * live netdev is exactly what zebra refuses, so drive
			 * the replacement through a DEL and let the re-ADD
			 * ride the REMOVED notify. */
			if (pim_dimt_tunnel_send(pim, tun, false)) {
				tun->state = PIM_DIMT_TUNNEL_REMOVING;
				tun->readd_pending = true;
			}
			break;
		}
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

static struct interface *
pim_dimt_tunnel_ifp(struct pim_instance *pim,
		    const struct pim_dimt_tunnel *tun)
{
	struct interface *ifp = NULL;

	/* A stale ifindex can in principle be reused by another netdev, even
	 * another DIMT tunnel; trust it only while it still carries this
	 * tunnel's name, so a prune never lands on some other tunnel's
	 * riders. */
	if (tun->ifindex)
		ifp = if_lookup_by_index(tun->ifindex, pim->vrf->vrf_id);
	if (!ifp || strncmp(ifp->name, tun->ifname, sizeof(tun->ifname)))
		ifp = if_lookup_by_name(tun->ifname, pim->vrf->vrf_id);
	return ifp;
}

/* The tunnel is about to be deleted with upstreams still pinned to it.
 *
 * Demand is counted per UMH *with an endpoint row*, so refcount can reach 0
 * while upstreams remain pinned to the netdev -- `no dimt tunnel-endpoint`
 * does exactly that.  Those upstreams are not moving anywhere yet (the pin
 * goes when the netdev does, via pim_dimt_iface_down()), so no RPF-move path
 * prunes them; without this the UMH keeps forwarding into a tunnel that no
 * longer exists until its J/P holdtime runs out.  Prune them here, before the
 * DEL is written.  See pim_dimt_prune_old() for why no wait is needed.
 *
 * A one-off prune is not enough on its own: the rider's periodic refresh
 * (its own Join Timer, or the UMH neighbor's aggregation list) would send
 * Join(S,G) again if it fired before the netdev is gone, re-joining the UMH
 * we just pruned.  So take it off the neighbor's list and push its own timer
 * a full t_periodic out -- deferred, never stopped, so no path can leave a
 * Joined rider with no refresh at all -- and mark the join owed.  If the DEL
 * goes through, pim_dimt_iface_down() unpins the rider and restarts its
 * timer on whatever RPF' it lands on, long before the deferred one fires; if
 * it does not (the send fails, or zebra answers REMOVE_FAIL),
 * pim_dimt_tunnel_rejoin_riders() re-joins at once rather than leaving the
 * UMH pruned until that deferred refresh. */
static void pim_dimt_tunnel_prune_riders(struct pim_instance *pim,
					 const struct pim_dimt_tunnel *tun)
{
	struct interface *ifp = pim_dimt_tunnel_ifp(pim, tun);
	struct pim_upstream *up;

	if (!ifp)
		return;

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (!PIM_UPSTREAM_FLAG_TEST_SRC_DIMT(up->flags) ||
		    up->rpf.source_nexthop.interface != ifp)
			continue;
		pim_dimt_jp_agg_detach(up, &up->rpf);
		pim_dimt_prune_old(up, &up->rpf);
		if (up->join_state == PIM_UPSTREAM_JOINED) {
			up->dimt_join_pending = true;
			pim_upstream_join_timer_defer(up);
		}
	}
}

/* The teardown pim_dimt_tunnel_prune_riders() prepared for did not happen
 * and the netdev survives with riders still pinned to it: send each the
 * join it is owed and restart its periodic refresh. */
static void pim_dimt_tunnel_rejoin_riders(struct pim_instance *pim,
					  const struct pim_dimt_tunnel *tun)
{
	struct interface *ifp = pim_dimt_tunnel_ifp(pim, tun);
	struct pim_upstream *up;

	if (!ifp)
		return;

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (!PIM_UPSTREAM_FLAG_TEST_SRC_DIMT(up->flags) ||
		    up->rpf.source_nexthop.interface != ifp ||
		    !up->dimt_join_pending ||
		    up->join_state != PIM_UPSTREAM_JOINED)
			continue;
		/* If the socket is not usable the mark stays for the socket-
		 * ready re-entry, and the deferred timer is still running. */
		pim_dimt_join_flush(up);
	}
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
				if (pim_dimt_tunnel_send(pim, tun, true))
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
			/* No DEL can be written without zebra; pruning ahead
			 * of it would only be undone by the rejoin below, on
			 * every reconcile pass until zebra returns. */
			if (!pim_dimt_zclient_usable())
				break;
			pim_dimt_tunnel_prune_riders(pim, tun);
			if (pim_dimt_tunnel_send(pim, tun, false))
				tun->state = PIM_DIMT_TUNNEL_REMOVING;
			else
				pim_dimt_tunnel_rejoin_riders(pim, tun);
			break;
		case PIM_DIMT_TUNNEL_IDLE:
		case PIM_DIMT_TUNNEL_FAILED:
			if (tun->kernel_present) {
				/* Reached only after a zebra reconnect
				 * collapsed the ack state: the record says
				 * IDLE but a netdev built by the previous
				 * session is still out there.  Forgetting it
				 * here would strand that netdev with nothing
				 * left holding its name, so ask for the
				 * delete instead.  Harmless if zebra has no
				 * such tunnel -- an unknown id is answered
				 * REMOVED, which frees the record on the
				 * notify. */
				tun->readd_pending = false;
				/* Socket unusable: keep the record (and the
				 * name) so the next reconnect can retry. */
				if (!pim_dimt_zclient_usable())
					break;
				pim_dimt_tunnel_prune_riders(pim, tun);
				if (pim_dimt_tunnel_send(pim, tun, false)) {
					tun->state = PIM_DIMT_TUNNEL_REMOVING;
					break;
				}
				/* The send failed after all: keep the record
				 * so the next reconnect can retry. */
				pim_dimt_tunnel_rejoin_riders(pim, tun);
				break;
			}
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
		const struct pim_dimt_endpoint *ep;
		bool normal, changed;

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

		ep = pim_dimt_endpoint_find(pim, tun->umh);
		normal = ep && ep->pim_normal;
		changed = pim_ifp->pim_dimt_normal != normal;

		pim_ifp->pim_enable = true;
		/* Mutually exclusive, and written together so they cannot
		 * drift: pim_hello_send() suppresses hellos on any interface
		 * with pim_light_enable set, so normal mode is precisely the
		 * absence of that flag. */
		pim_ifp->pim_dimt_normal = normal;
		pim_ifp->pim_light_enable = !normal;

		/* The adjacency model itself changed, so anything learned
		 * under the old one is stale: a light neighbour is created
		 * from a received J/P and carries no hello state, while a
		 * hello neighbour outlives the hellos we just stopped sending.
		 * Either would be read by pim_dimt_pin_rpf_addr() as if it
		 * belonged to the new mode.
		 *
		 * After the flag writes, not before: pim_neighbor_delete()
		 * calls back into pim_dimt_neighbor_change(), which keys off
		 * pim_dimt_normal.  Doing it first would run that re-resolve
		 * under the mode being abandoned.  No-op on a first adopt into
		 * light mode, and on an empty neighbour list either way. */
		if (changed)
			pim_neighbor_delete_all(ifp, "DIMT pim-mode changed");

		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("DIMT: adopted %s (ifindex %d) for UMH %pPAs in %s mode",
				   ifp->name, ifp->ifindex, &tun->umh,
				   normal ? "normal" : "light");

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
		tun->kernel_present = true;
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
		 * rather than building a tunnel through itself.
		 *
		 * kernel_present is deliberately NOT cleared here.
		 * FAIL_INSTALL means "this ADD did not take", which is not
		 * the same claim as "no netdev with this id exists": zebra
		 * answers an ADD that differs from a live netdev with
		 * FAIL_INSTALL rather than mutating it in place, so the
		 * previous netdev provably survives the refusal.  Clearing
		 * the flag here would let the demand-drop path at
		 * pim_dimt_reconcile() free the record instead of sending a
		 * DEL, stranding a live dimt-%08x link with nothing holding
		 * its name.  REMOVED is the only result that proves absence,
		 * so it is the only result that clears the flag. */
		tun->state = PIM_DIMT_TUNNEL_FAILED;
		tun->ifindex = 0;
		break;
	case ZAPI_DIMT_TUNNEL_REMOVED:
		tun->ifindex = 0;
		tun->kernel_present = false;
		if (tun->readd_pending) {
			tun->readd_pending = false;
			tun->state = pim_dimt_tunnel_send(pim, tun, true)
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
		/* The riders were pruned and silenced ahead of the DEL; with
		 * the netdev still here they must be re-joined now, not left
		 * dark until something else happens to refresh them. */
		pim_dimt_tunnel_rejoin_riders(pim, tun);
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
		/* Whatever the old session had already built stays built:
		 * remember that a netdev may be out there, so that if demand
		 * does not survive the reconnect the tunnel leaves by DEL
		 * instead of being silently forgotten. */
		if (tun->state != PIM_DIMT_TUNNEL_IDLE)
			tun->kernel_present = true;
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
pim_dimt_forwarding_state(struct pim_instance *pim, struct pim_upstream *up,
			  struct pim_dimt_fwd_detail *detail)
{
	struct pim_dimt_umh *umh;
	struct pim_dimt_tunnel *tun;
	struct pim_interface *pim_ifp;
	struct channel_oil *c_oil;
	struct interface *ifp;
	struct pim_dimt_fwd_detail local_detail;

	/* Every non-READY return below must set a cause: bgpd emits
	 * `forwarding_lost` with a stable enum reason and has no way to
	 * re-derive which of these branches fired from the state byte alone.
	 * Writing through a local when the caller passed NULL keeps that
	 * total, so a later branch cannot forget to set one. */
	if (!detail)
		detail = &local_detail;
	memset(detail, 0, sizeof(*detail));
	detail->reason = ZAPI_MVPN_SG_FWD_REASON_UNSPECIFIED;

	/* Not DIMT-steered: this contract proves DIMT forwarding and has
	 * nothing to say about a path it does not own.  PENDING is the
	 * fail-closed reading, and PR 4 gates its additive
	 * forwarding_ready on READY only.
	 *
	 * Keyed on the mapping, NOT on PIM_UPSTREAM_FLAG_SRC_DIMT: the flag
	 * means "already pinned", so reading it here would collapse "the
	 * tunnel failed" into "not ours" and lose FWD_FAILED entirely. */
	if (!pim_dimt_upstream_steered(pim, up, &umh)) {
		detail->reason = ZAPI_MVPN_SG_FWD_REASON_TUNNEL_REMOVED;
		return ZAPI_MVPN_SG_FWD_PENDING;
	}

	tun = pim_dimt_tunnel_find(pim, umh->umh);
	if (!tun) {
		detail->reason = ZAPI_MVPN_SG_FWD_REASON_TUNNEL_REMOVED;
		return ZAPI_MVPN_SG_FWD_PENDING;
	}
	if (tun->state == PIM_DIMT_TUNNEL_FAILED) {
		/* Includes zebra's anti-recursion refusal, which lands in
		 * FAILED (see pim_dimt.c tunnel-ack handling).  pimd cannot
		 * tell the two apart from tunnel state alone, so this reports
		 * the install failure it can actually attest rather than
		 * claiming the more specific anti-recursion cause. */
		detail->reason = ZAPI_MVPN_SG_FWD_REASON_TUNNEL_FAIL_INSTALL;
		return ZAPI_MVPN_SG_FWD_FAILED;
	}
	/* (1) positive netlink ack for the netdev. */
	if (tun->state != PIM_DIMT_TUNNEL_INSTALLED) {
		detail->reason = ZAPI_MVPN_SG_FWD_REASON_TUNNEL_REMOVED;
		return ZAPI_MVPN_SG_FWD_PENDING;
	}

	/* (2) RPF actually pinned onto that netdev.  Interface-UP alone is
	 * explicitly insufficient (D8.3): a GRE link is admin-up regardless
	 * of whether the peer is reachable, so "up" proves nothing. */
	ifp = up->rpf.source_nexthop.interface;
	if (!ifp || ifp->ifindex != tun->ifindex) {
		detail->reason = ZAPI_MVPN_SG_FWD_REASON_RPF_UNPINNED;
		return ZAPI_MVPN_SG_FWD_PENDING;
	}

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
	if (!c_oil || !c_oil->installed) {
		detail->reason = ZAPI_MVPN_SG_FWD_REASON_MFC_EVICTED;
		return ZAPI_MVPN_SG_FWD_PENDING;
	}

	pim_ifp = ifp->info;
	if (!pim_ifp || pim_ifp->mroute_vif_index < 0) {
		detail->reason = ZAPI_MVPN_SG_FWD_REASON_MFC_EVICTED;
		return ZAPI_MVPN_SG_FWD_PENDING;
	}
	/* Compare through int: this file is in pim_common, so it is compiled
	 * for pim6d as well, where oil_incoming_vif() returns mifi_t rather
	 * than vifi_t (and vifi_t is an IPv4-only mroute type). int is wide
	 * enough for both and keeps the comparison free of -Wsign-compare. */
	if ((int)*oil_incoming_vif(c_oil) != (int)pim_ifp->mroute_vif_index) {
		detail->reason = ZAPI_MVPN_SG_FWD_REASON_MFC_EVICTED;
		return ZAPI_MVPN_SG_FWD_PENDING;
	}

	/* READY: name the netdev that actually carries the traffic.  Only
	 * meaningful here -- a non-READY verdict has no proven oif. */
	detail->reason = ZAPI_MVPN_SG_FWD_REASON_UNSPECIFIED;
	detail->ifindex = ifp->ifindex;
	strlcpy(detail->oif, ifp->name, sizeof(detail->oif));
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

		state = pim_dimt_forwarding_state(pim, up, NULL);
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
			/*
			 * What bgpd was actually told, as against the
			 * `forwarding` above, which is recomputed on every
			 * read of this command.
			 *
			 * The two are the same only while every readiness
			 * edge is announced, which is the property worth
			 * asserting -- a verdict that is right whenever an
			 * operator asks and wrong on the wire is the exact
			 * failure this field exists to expose.  Reading the
			 * recomputed value alone cannot see it.
			 */
			json_object_boolean_add(jup, "announced",
						up->gtm_announced);
			json_object_string_add(jup, "announcedForwarding",
					       fwd[up->gtm_forwarding]);
			json_object_object_add(jobj, up->sg_str, jup);
		} else {
			vty_out(vty, "%-34s %-10s %-16s %s\n", up->sg_str,
				fwd[state], ifname, umh_str);
		}
	}

	if (jobj)
		vty_json(vty, jobj);
}
