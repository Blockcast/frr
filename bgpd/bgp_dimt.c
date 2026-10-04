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
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_table.h"
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
 *    origin refuses a UMH identically in both. This determinacy test only
 *    runs where an origin AS is actually compared, i.e. on the eBGP arm.
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
 *            definition. Confederation members are on this arm too, and
 *            their AS_CONFED_SEQUENCE origin is not held against them.
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

	/* *why stays NULL only here, where there is no peer to name -- see the
	 * contract in bgp_dimt.h. A peer without a bgp instance DOES have a
	 * name, so it gets its own reason rather than falling through to the
	 * "no usable peer on the path" default, which would contradict the
	 * peer named alongside it in the same log line. */
	if (!pi || !pi->peer)
		return false;

	if (!pi->peer->bgp) {
		*why = "peer has no BGP instance";
		return false;
	}

	peer = pi->peer;

	/* Our own route-map put the EC there -- but only if we actually
	 * originated this path, which the peer pointer alone does not tell us.
	 * A VPN leak re-homes the path onto the TARGET instance's peer_self and
	 * discards the origin peer: leak_update() does
	 * info_make(..., BGP_ROUTE_IMPORTED, 0, to_bgp->peer_self, ...) in
	 * bgp_mplsvpn.c. The attribute is copied wholesale and the only
	 * ecommunity surgery on the way is ecommunity_strip_rts(), which
	 * removes subtype ECOMMUNITY_ROUTE_TARGET only, so a 0x80 UMH survives
	 * the trip intact. Trusting the peer pointer would therefore let an
	 * untrusted VPNv4 neighbour's UMH -- correctly refused and counted
	 * where it arrived -- re-enter a unicast table laundered as locally
	 * originated, and be honoured by both consumers: the pin path when the
	 * leak lands in the default instance, and the MVPN attestation lane in
	 * any instance.
	 *
	 * Refuse rather than inherit. The source instance's verdict is not
	 * carried on the path, so there is nothing to inherit even if we wanted
	 * to; an operator who means to honour a leaked UMH can re-originate it
	 * through a route-map, which is a decision the config then records.
	 *
	 * Keyed on sub_type -- "how did this path get here" -- because the peer
	 * pointer cannot answer it. And as an ALLOW-list rather than a deny-list
	 * of the laundering sub-types: the two partition the enum identically
	 * today, so this is not a behaviour change, but a sub_type added later
	 * inherits the fail-CLOSED verdict instead of the fail-open one. This
	 * gate's deny-list needed extending twice in two review rounds
	 * (BGP_ROUTE_IMPORTED, then BGP_ROUTE_AGGREGATE); that is the argument.
	 *
	 * bgpd has twelve producers that call info_make() with peer_self: the
	 * enumeration below accounts for eleven, and BGP_ROUTE_NORMAL's one is in
	 * the paragraph after it. A reader redoing this for a new table can check
	 * the count first -- but NO textual sweep reproduces it. The question at
	 * each info_make() is whether its peer ARGUMENT can evaluate to peer_self,
	 * and only data flow answers that: a literal grep at the call site finds
	 * nine, bgp_mvpn.c:402 receives it through a wrapper parameter, and two
	 * more inherit it from another path as parent_pi->peer. Expect that last
	 * form -- a path re-homed onto peer_self while carrying an attribute we
	 * did not author is the shape both prior bypasses here took. The two
	 * trusted arms are the only ones pairing a locally authored attribute
	 * with a route that can reach a unicast table -- the only table set this
	 * gate reads:
	 *   BGP_ROUTE_STATIC        bgp_route.c:8827, `network`
	 *   BGP_ROUTE_REDISTRIBUTE  bgp_route.c:11095, redistribution + route-map
	 * Scoped to unicast deliberately: five more are locally authored but
	 * originate outside unicast -- bgp_ls.c:742 (REDISTRIBUTE, SAFI_LINKSTATE),
	 * bgp_evpn.c:1722, bgp_evpn.c:2113, bgp_evpn_mh.c:516 (STATIC, EVPN), and
	 * bgp_mvpn.c:402 (STATIC, SAFI_MCAST_VPN), which bgp_mvpn_route_install()
	 * reaches with peer_self from bgp_mvpn.c:1578, :1673, :1785, :1958, :2076.
	 * That last one pairs peer_self with a TRUSTED sub_type, so only the table
	 * scoping keeps it out of reach -- which is why the scoping is the thing
	 * to re-derive, not the allow-list.
	 * No consumer of this gate can see them: bgp_dimt_route_update() returns
	 * at the safi != SAFI_UNICAST guard below, and
	 * bgp_mvpn_resolve_attested_umh() only ever gets a path selected out of
	 * bgp->rib[afi][SAFI_UNICAST] (bgp_mvpn.c:1447). The remaining four are
	 * refused by sub_type on their own arms below -- bgp_mplsvpn.c:1417,
	 * bgp_evpn.c:3151 and bgp_evpn_mh.c:292 (IMPORTED), bgp_route.c:9696
	 * (AGGREGATE) -- and for TWO of them it is the IMPORTED arm, not the
	 * scoping, that is load-bearing, because those two are the only
	 * peer_self producers outside the trusted pair that reach UNICAST:
	 *   bgp_mplsvpn.c:1417  the VPN leak described at the top of this block.
	 *                       vpn_leak_to_vrf_update_onevrf() fixes
	 *                       safi = SAFI_UNICAST (bgp_mplsvpn.c:2347), takes bn
	 *                       out of to_bgp->rib[afi][safi] (:2422), and hands
	 *                       both to leak_update() (:2661).
	 *   bgp_evpn.c:3151     install_evpn_route_entry_in_vrf() installs into
	 *                       bgp_vrf->rib[afi][SAFI_UNICAST] (:3241, :3245),
	 *                       for a parent that
	 *                       BGP_PATH_LOCAL_IMPORT_EVPN_RT2_MACIP marks as
	 *                       locally originated.
	 * bgp_evpn_mh.c:292 is NOT one of them: it installs into es->route_table
	 * (bgp_evpn_mh.c:278), which is not in bgp->rib[afi][SAFI_UNICAST], so
	 * the scoping covers it and the IMPORTED arm there is belt-and-braces.
	 * Do not understate this pair -- the IMPORTED arm is the only thing
	 * between a leaked or imported path and a unicast table, and the leak is
	 * the one bypass here already known to be real. That is 2 + 5 + 4 = 11
	 * here; the twelfth is BGP_ROUTE_NORMAL's, next paragraph.
	 *
	 * BGP_ROUTE_NORMAL is deliberately NOT on the list. Its one peer_self
	 * producer is bgp_unreach.c:922, which originates into SAFI_UNREACH, so
	 * by the same scoping no path this gate sees can carry it and refusing
	 * it costs nothing reachable. Excluding it matters because
	 * BGP_ROUTE_NORMAL is 0 (bgp_route.h:384): leaving it in would put the
	 * one value a zero-initialised or partially-constructed bgp_path_info
	 * carries on the TRUSTED side. The fail-closed default below protects
	 * against a sub-type someone adds later; this protects against a
	 * producer that never set the field -- which is the shape both prior
	 * bypasses took, a path re-homed onto peer_self carrying an attribute we
	 * did not author. If a future caller does run this gate against a
	 * non-unicast table (e.g. the BLO-36558 LC lane), re-derive this list
	 * for that table rather than widening it here. */
	if (peer == peer->bgp->peer_self) {
		switch (pi->sub_type) {
		case BGP_ROUTE_STATIC:
		case BGP_ROUTE_REDISTRIBUTE:
			return true;
		case BGP_ROUTE_IMPORTED:
			*why = "route was imported from another BGP instance";
			return false;
		case BGP_ROUTE_AGGREGATE:
			/* `aggregate-address ... as-set` merges each component
			 * route's WHOLE ecommunity into the aggregate --
			 * bgp_compute_aggregate_ecommunity() applies no sub-type
			 * filter -- so a neighbour's 0x80 UMH, correctly refused
			 * on the component, re-enters on the aggregate wearing
			 * peer_self. Wider blast radius than the leak: it steers
			 * joins for the whole aggregate, not one component. */
			*why = "route is an aggregate, which may carry a component's UMH";
			return false;
		default:
			/* BGP_ROUTE_NORMAL (0, and so the value an unset
			 * sub_type carries), BGP_ROUTE_RFP (VNC), and anything
			 * added later. */
			*why = "route was not originated by this speaker";
			return false;
		}
	}

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_DIMT_TRUSTED)) {
		*why = "neighbor is not dimt-trusted";
		return false;
	}

	/* Inside our own AS the border already applied this gate; see (2).
	 * This short-circuits BEFORE the determinacy test below, which only
	 * exists to make origin_as meaningful and which the internal arm never
	 * reads. Testing it here anyway would make the knob unusable in a
	 * confederation: a route from another member AS ends in an
	 * AS_CONFED_SEQUENCE, so every such route is "ambiguous" and a
	 * dimt-trusted BGP_PEER_CONFED neighbour would be refused outright. */
	if (peer->sort == BGP_PEER_IBGP || peer->sort == BGP_PEER_CONFED)
		return true;

	origin_as = aspath_origin_as(pi->attr ? pi->attr->aspath : NULL,
				     &ambiguous_reason, &path_is_empty);
	if (ambiguous_reason) {
		*why = ambiguous_reason;
		return false;
	}

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
 * answerable from `show bgp neighbor` without grepping logs.
 *
 * Callers must have a peer to charge: bgp_dimt_peer_is_trusted() can refuse
 * without one (no peer, no trust), and there is nothing to count or name in
 * that case. */
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
		    peer->host ? peer->host : "(unknown peer)",
		    why ? why : "no usable peer on the path");
}

/* Whether the wrong-family UMH hint in the route-update hook may be logged
 * now, charging @peer's throttle when it may. Same 60s basis as
 * bgp_dimt_umh_refuse(), on its own fields for the reason given at the call
 * site. The throttle state is written only when the hint is emitted, so a
 * suppressed call cannot push the window out.
 *
 * A NULL peer is never throttled: there is nowhere to keep the state, and a
 * wrong-family EC with nobody to charge is still worth saying.
 *
 * Exported for tests/bgpd/test_dimt_umh_trust.c. */
bool bgp_dimt_umh_xfam_should_log(struct peer *peer, time_t now)
{
	if (!peer)
		return true;
	if (peer->dimt_umh_xfam_log_seen && now - peer->dimt_umh_xfam_log_last < 60)
		return false;
	peer->dimt_umh_xfam_log_seen = true;
	peer->dimt_umh_xfam_log_last = now;
	return true;
}

/* A refusal on a path bgpd attributes to peer_self: the path reached the
 * loc-RIB wearing a local identity while carrying a UMH we did not author --
 * a VPN leak, or an as-set aggregate that merged a component's ecommunity.
 *
 * Reported separately from bgp_dimt_umh_refuse() rather than charged to
 * peer_self, because both halves of that function are wrong here. The counter
 * is surfaced by `show bgp neighbors`, which structurally never walks
 * peer_self, so a refusal charged there is written to a sink -- and this is
 * precisely the detection signal for the bypass the trust gate exists to
 * close. The log line names peer->host, which for peer_self is a pseudo-peer
 * string like "Static announcement": a line reading "from Static announcement
 * refused: route was imported from another BGP instance" names as a local
 * announcement the exact thing it is denying is one.
 *
 * Prefix plus instance is what identifies a laundered path; a peer does not.
 * Throttled on peer_self's own log state -- once a minute for the instance,
 * matching the per-peer rate everywhere else -- so a crafted feed cannot spam
 * it. No counter: whoever adds a surface for this should add one with a
 * per-instance home, not borrow an unreachable per-peer field.
 */
static void bgp_dimt_umh_refuse_local(struct bgp *bgp,
				      const struct bgp_path_info *pi,
				      const char *why)
{
	struct peer *self = bgp->peer_self;
	time_t now = monotime(NULL);

	if (self->dimt_umh_log_seen && now - self->dimt_umh_log_last < 60)
		return;

	self->dimt_umh_log_seen = true;
	self->dimt_umh_log_last = now;
	zlog_notice("DIMT: UMH extended community on locally-held route %pBD in instance %s refused: %s",
		    pi->net, bgp->name_pretty ? bgp->name_pretty : "(unnamed)",
		    why ? why : "route was not originated by this speaker");
}

/* Decode only: pull the best UMH EC (highest preference wins) out of a path's
 * extended communities, with no trust check. The IPv4 UMH rides the 8-byte
 * ecommunity list (type 0x01, Local Admin at byte 7); the IPv6 UMH rides the
 * 20-byte ipv6_ecommunity list (type 0x00, Local Admin at byte 19). Returns
 * true and fills a family-tagged umh/umh_type/preference on match.
 *
 * Split out from bgp_dimt_umh_from_path() so that "is a UMH present" can be
 * asked without charging a refusal: the wrong-family diagnostic in
 * bgp_dimt_route_update() is such a question. Going through the gated entry
 * point there would both suppress the hint (the gate refuses, so the warn
 * never fires) and charge the peer for an EC that could never have been
 * honoured anyway, contradicting the counter's invariant below.
 */
static bool bgp_dimt_umh_decode(const struct bgp_path_info *pi, afi_t afi,
				struct ipaddr *umh, uint8_t *umh_type,
				uint8_t *preference)
{
	const struct ecommunity *ecom;
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

	return found;
}

/* Decode a path's UMH EC and apply the trust gate to it.
 *
 * Refuses everything from a peer that fails bgp_dimt_peer_is_trusted(). That
 * gate lives HERE, not at the call sites, so every consumer of a 0x80 EC --
 * the pin path below and bgp_mvpn.c's settlement attestation lane alike --
 * inherits it. An attested settlement origin forged by a route server is as
 * damaging as a redirected join.
 *
 * This is a pure QUERY: it does not touch the refusal counter. Counting is
 * bgp_dimt_umh_audit()'s job and happens once, at arrival. The two are
 * separate because this function is called from lanes that RE-READ an
 * already-adjudicated path -- bgp_mvpn_resolve_attested_umh() runs against the
 * unicast source route's best path on every Type-7 origination and again for
 * every installed Type-7 in the re-emit sweep -- so counting here would charge
 * a fresh refusal for an EC that arrived once, driven by our own join activity
 * rather than by the neighbour's. See the counter contract in bgpd.h.
 *
 * Exported (see bgp_dimt.h): bgp_mvpn.c's settlement-event attestation lane
 * decodes 0x80 through this function rather than duplicating the layout.
 */
bool bgp_dimt_umh_from_path(const struct bgp_path_info *pi, afi_t afi,
			    struct ipaddr *umh, uint8_t *umh_type,
			    uint8_t *preference)
{
	const char *why = NULL;

	if (bgp_dimt_umh_decode(pi, afi, umh, umh_type, preference) &&
	    bgp_dimt_peer_is_trusted(pi, &why))
		return true;

	/* Fail closed. decode() has already written a fully populated UMH
	 * through the out-params by the time the gate refuses, so a caller that
	 * forgot to check the return value would read an untrusted neighbour's
	 * UMH as if it were honoured. Both current callers check, but this is
	 * the one function whose whole job is to be the place nobody can forget
	 * the gate, so it clears up after itself. */
	*umh = (struct ipaddr){};
	*umh_type = 0;
	*preference = 0;
	return false;
}

/* Charge one refusal for a UMH EC this path carries and is not entitled to
 * set. Arrival-time only: the caller is the loc-RIB update hook, which is the
 * one place a path is evaluated because the NEIGHBOUR announced something.
 * Every other consumer uses the non-counting query above.
 *
 * Trust is evaluated AFTER decoding rather than as an early return, so the
 * counter moves only when a path actually carried a UMH we would otherwise
 * have honoured; an untrusted neighbour sending ordinary routes must not
 * inflate it.
 *
 * Called per EC LIST rather than per route, because the two lists have
 * different consumers and a refusal in either is real: the pin path reads the
 * list matching the route's family, while bgp_mvpn_resolve_attested_umh()
 * reads the 8-byte v4 list whatever the C-S family is, so a v4 UMH riding a v6
 * route is refused by a consumer that would otherwise have honoured it. That
 * is also why this is not the same question as the wrong-family hint below,
 * which asks only whether the PIN path can use it.
 *
 * Returns true when it refused a UMH, whether or not there was a peer to
 * charge, so bgp_dimt_umh_audit_path() can record the verdict.
 */
static bool bgp_dimt_umh_audit(const struct bgp_path_info *pi, afi_t afi)
{
	struct ipaddr umh = {};
	uint8_t umh_type = 0;
	uint8_t preference = 0;
	const char *why = NULL;

	if (!bgp_dimt_umh_decode(pi, afi, &umh, &umh_type, &preference))
		return false;

	if (bgp_dimt_peer_is_trusted(pi, &why))
		return false;

	/* pi is const, but the peer it points at is not -- the refusal is a
	 * property of the peer, not of the path. A refusal with no peer to
	 * charge is still a refusal; there is just nobody to count it against.
	 *
	 * A path bgpd attributes to peer_self has a peer, but not one a counter
	 * or a log line can honestly name: see bgp_dimt_umh_refuse_local(). */
	if (!pi->peer)
		return true;

	if (pi->peer->bgp && pi->peer == pi->peer->bgp->peer_self)
		bgp_dimt_umh_refuse_local(pi->peer->bgp, pi, why);
	else
		bgp_dimt_umh_refuse(pi->peer, why);
	return true;
}

/* Audit both EC lists of a loc-RIB path, at most once per attribute set.
 *
 * The route-update hook also fires on re-processes that carry no new
 * announcement: with add-path transmit configured, bgp_process_main_one()
 * skips its unchanged-bestpath early return (the trailing
 * !bgp_addpath_is_addpath_used() clause), and without it an RPKI
 * revalidation, a multipath change or `clear ip bgp PREFIX` still gets
 * through. pi->dimt_umh_refused records the attribute set the last refusal
 * was charged for, so a pass that finds pi->attr unchanged is recognised as
 * a re-read and skipped. A re-announcement that changes the attributes -- an
 * origin-AS change reusing the same bgp_path_info included -- interns to a
 * different attr and is charged again, and a path that regains best after a
 * sibling leaves keeps its record and is not.
 *
 * The record holds an interned reference, which is what makes comparing
 * pointers sound. Without it bgp_update() frees the old attr when it swaps
 * in the new one, and the next same-sized allocation readily returns that
 * address for different attributes. Released here once the path stops being
 * refused, and in bgp_path_info_free() when the path goes away.
 *
 * Two cheaper discriminators are both WRONG, recorded so they are not
 * retried:
 *   - CHECK_FLAG(pi->flags, BGP_PATH_ATTR_CHANGED) always reads false here.
 *     bgp_route.c unsets that flag on new_select a dozen lines BEFORE
 *     calling this hook, so gating on it would silence the counter.
 *   - old_route != new_route suppresses the legitimate case too: the
 *     origin-AS change above has old == new, and the topotest's stage 3
 *     pins it as MUST count.
 */
static void bgp_dimt_umh_audit_path(struct bgp_path_info *pi)
{
	bool refused;

	if (!pi || pi->dimt_umh_refused == pi->attr)
		return;

	/* Not short-circuited: a refusal in either list is real. */
	refused = bgp_dimt_umh_audit(pi, AFI_IP);
	refused |= bgp_dimt_umh_audit(pi, AFI_IP6);

	/* Reassigned rather than left to bgp_attr_unintern(), which only NULLs
	 * the pointer when it frees the attr. */
	if (pi->dimt_umh_refused)
		bgp_attr_unintern(&pi->dimt_umh_refused);
	pi->dimt_umh_refused = refused ? bgp_attr_intern(pi->attr) : NULL;
}

/*
 * UMH LARGE community (RFC 8092 carrier, RFC 8195 layout) -- the one decoder,
 * shared by the MVPN Type-7 lane (bgp_mvpn.c) and the DIMT pin path below.
 * BLO-36558; the field-by-field contract is doc/dimt-lc-umh-mapping.md.
 *
 *   bytes 0-3  Global Administrator  the Source AS; must equal the origin AS
 *   bytes 4-7  Function              the lane's configured code point
 *   bytes 8-11 Parameter             the UMH IPv4 address, host-order u32
 *
 * The decoder owns the encoding and the origin-AS trust rule. It owns no
 * policy beyond that: each call site passes its own lane's function code
 * point and its own lane's counter + throttle, and the gates that belong to
 * one lane only (DIMT neighbour trust, the DIMT same-family rule) live at
 * that lane's call site, so the MVPN lane inherits neither -- vector p6 in
 * bgp_mvpn_gtm_umh_lc, a v4 UMH on a v6 C-S route, keeps resolving there.
 */

/* Per lane, so the MVPN log lines stay byte-identical to the ones the decoder
 * emitted before it was shared ("MVPN UMH resolved via large community" is the
 * live-proof signal the onprem README greps for). */
static const char *const umh_lc_lane_name[] = {
	[BGP_UMH_LC_LANE_MVPN] = "MVPN",
	[BGP_UMH_LC_LANE_DIMT] = "DIMT",
};

/* What the Parameter names on that lane: MVPN turns it into the upstream PE's
 * Route Target, DIMT into a PIM Light tunnel endpoint. */
static const char *const umh_lc_lane_noun[] = {
	[BGP_UMH_LC_LANE_MVPN] = "upstream PE",
	[BGP_UMH_LC_LANE_DIMT] = "UMH",
};

/* Whether a throttled line may be emitted now, charging @t when it may. The
 * state is written only on emit, so a suppressed call cannot push the window
 * out. */
static bool bgp_umh_lc_throttle_ok(struct bgp_umh_lc_throttle *t, time_t now)
{
	if (t->seen && now - t->last < 60)
		return false;
	t->seen = true;
	t->last = now;
	return true;
}

/* THE Function match. The decoder's walk and the call site's "is this route
 * on my lane at all" question both go through here, so they cannot disagree
 * on what a lane's tuple is. A full 32-bit compare. */
static bool bgp_umh_lc_tuple_is_fn(const uint8_t *lval, uint32_t fn)
{
	uint32_t tuple_fn;

	ptr_get_be32(lval + 4, &tuple_fn);
	return fn && tuple_fn == fn;
}

bool bgp_umh_lc_has_function(const struct lcommunity *lcom, uint32_t fn)
{
	int i;

	if (!lcom || !lcom->val || !fn)
		return false;

	for (i = 0; i < lcom->size; i++)
		if (bgp_umh_lc_tuple_is_fn(lcom->val + i * LCOMMUNITY_SIZE, fn))
			return true;
	return false;
}

/*
 * Decode the UMH large community for one lane.
 *
 * Trust: a tuple counts only when its Global Administrator equals the source
 * route's origin AS (rightmost AS_PATH entry; the local AS for a local route
 * or one whose AS_PATH is structurally empty), and only when that origin is
 * knowable at all -- an AS_SET/AS_CONFED_SET aggregates several origins, and
 * a path carrying AS 0 names no real one, so no tuple on either is trusted.
 * A transitive community survives more AS hops than any one operator can
 * vouch for -- this check is the border-scoping primitive that bounds who may
 * claim a UMH for a route.
 *
 * Ties: large communities are sorted and de-duplicated at attribute parse
 * (lcommunity_uniq_sort), so candidates iterate in ascending tuple order and
 * the first valid one -- the lowest tuple -- wins deterministically.
 *
 * Counting (lane != NULL), per doc/dimt-lc-umh-mapping.md "Reject counter":
 *   - once per ROUTE for an origin-ambiguous AS_PATH, at the first tuple with
 *     the lane's function, and the decode ends there: no tuple on such a
 *     route can resolve, and the per-tuple checks have no origin to test;
 *   - once per TUPLE for Global Administrator 0, Global Administrator !=
 *     origin AS, and an unusable UMH address -- on every tuple with the
 *     lane's function, INCLUDING tuples after the winner. Tuples sort by
 *     Global Administrator, the very field the GA checks test, so a crafted
 *     tuple with a GA above the origin AS sorts behind a legitimate one; an
 *     early "a lower tuple already won" skip would never count it. A tuple
 *     past the winner that passes the checks is ignored, not counted, and
 *     cannot change which tuple resolves.
 * A tuple with another function is an unrelated large community, not a
 * reject, and is never counted. The counter is the lane's and only moves
 * through this pointer; a return value cannot carry it (one bool per route
 * would under-count a route carrying three GA-mismatched tuples by two).
 *
 * Logging: the trust-boundary rejects (origin-ambiguous and the two GA
 * reasons) emit a notice throttled to once a minute on the LANE's own state,
 * so a probe on one lane cannot mask a distinct probe on the other inside
 * the same instance, any more than one VRF can mask another. An unusable
 * address is a debug line only and touches no throttle state: its tuple has
 * already passed origin-AS, so it is the originating AS naming a bad address
 * for its own route -- a misconfiguration to diagnose, not a probe.
 *
 * lane == NULL is a pure query: same result, no count, no notice. Debug
 * lines are unaffected.
 *
 * Selection is atomic: the winning tuple supplies BOTH outputs; when no tuple
 * wins the outputs are untouched.
 */
bool bgp_umh_lc_decode(struct bgp *bgp, const struct bgp_path_info *pi,
		       uint32_t fn, enum bgp_umh_lc_lane_id lane_id,
		       struct bgp_umh_lc_lane *lane, uint32_t *source_as,
		       struct in_addr *umh)
{
	const char *name = umh_lc_lane_name[lane_id];
	const char *noun = umh_lc_lane_noun[lane_id];
	const char *ambiguous_reason = NULL;
	struct lcommunity *lcom;
	uint32_t origin_as;
	bool path_is_empty;
	bool found = false;
	int i;

	if (!fn || !pi || !pi->attr)
		return false;

	lcom = bgp_attr_get_lcommunity(pi->attr);
	if (!lcom || !lcom->val)
		return false;

	/*
	 * Resolve the origin AS -- and first decide whether it is knowable at
	 * all. aspath_origin_as() owns that judgement (AS_SET / AS 0 /
	 * confederation-member origins are all unusable); it is shared with the
	 * DIMT UMH extended-community trust gate above so the two
	 * border-scoping checks cannot drift apart.
	 *
	 * The local-AS substitution stays here because it is caller policy, not
	 * AS_PATH parsing: an empty AS_PATH means the route never crossed an AS
	 * boundary, so the local AS genuinely is its origin and a tuple stamped
	 * GA == our AS is legitimate. It keys on the path being STRUCTURALLY
	 * empty, never on the lookup returning 0 -- see aspath_origin_as().
	 * peer->sort is only a belt-and-braces second gate here (it describes
	 * who advertised the route, not where it came from), and an empty
	 * AS_PATH is malformed over eBGP anyway (RFC 7606 treat-as-withdraw at
	 * parse).
	 */
	origin_as = aspath_origin_as(pi->attr->aspath, &ambiguous_reason,
				     &path_is_empty);
	if (!ambiguous_reason && path_is_empty && pi->peer &&
	    (pi->peer == bgp->peer_self || pi->peer->sort == BGP_PEER_IBGP))
		origin_as = bgp->as;

	for (i = 0; i < lcom->size; i++) {
		const uint8_t *lval = lcom->val + i * LCOMMUNITY_SIZE;
		uint32_t ga, tuple_fn, param;
		struct in_addr addr;

		if (!bgp_umh_lc_tuple_is_fn(lval, fn))
			continue;

		ptr_get_be32(lval, &ga);
		ptr_get_be32(lval + 4, &tuple_fn);
		ptr_get_be32(lval + 8, &param);

		if (ambiguous_reason) {
			/* A property of the route, not of this tuple: counted
			 * once and the decode ends, see above. */
			if (lane) {
				lane->rejected++;
				if (bgp_umh_lc_throttle_ok(&lane->log,
							   monotime(NULL)))
					zlog_notice("%s UMH large community %u:%u:%u rejected on %s: %s, origin AS is indeterminate",
						    name, ga, tuple_fn, param,
						    bgp->name_pretty,
						    ambiguous_reason);
			}
			return false;
		}

		if (ga == 0 || ga != origin_as) {
			/*
			 * Trust-boundary reject: someone is claiming a UMH for
			 * this route across an AS they do not originate. Surface
			 * it at notice (not debug) so a probe is visible in
			 * production, throttled to once a minute per lane per
			 * BGP instance so a flood of crafted tuples cannot spam
			 * the log, a probe on one VRF cannot mask a distinct
			 * probe on another, and a probe on one lane cannot mask
			 * one on the other.
			 */
			if (lane) {
				lane->rejected++;
				if (bgp_umh_lc_throttle_ok(&lane->log,
							   monotime(NULL)))
					zlog_notice("%s UMH large community %u:%u:%u rejected on %s: Global Administrator %u != origin AS %u",
						    name, ga, tuple_fn, param,
						    bgp->name_pretty, ga,
						    origin_as);
			}
			continue;
		}

		addr.s_addr = htonl(param);
		/*
		 * Usable-UMH gate on the parameter. This is a per-route trust
		 * decision, so the reject set is spelled out here rather than
		 * deferred to ipv4_unicast_valid(): that helper treats Class E
		 * (240/4) as usable unicast per draft-schoen-intarea-unicast-240,
		 * and gates 0/8 + 127/8 on the global "allow-reserved-ranges"
		 * toggle -- neither is acceptable for a UMH target an adversary
		 * can put on the wire. Reject, all unconditionally:
		 *   0.0.0.0/8      unspecified / "this network"
		 *   127.0.0.0/8    loopback
		 *   169.254.0.0/16 link-local: interface-scoped and NOT
		 *                  globally unique, so it either names nothing
		 *                  reachable or collides with a different box
		 *                  on some other link
		 *   224.0.0.0/4    multicast (Class D)
		 *   240.0.0.0/4    reserved (Class E), incl. 255.255.255.255
		 */
		if (IPV4_NET0(param) || IPV4_NET127(param) ||
		    IPV4_LINKLOCAL(param) || IPV4_CLASS_D(param) ||
		    IPV4_CLASS_E(param)) {
			if (lane)
				lane->rejected++;
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("%s UMH large community %u:%u:%u rejected: %pI4 is not a usable %s address",
					   name, ga, tuple_fn, param, &addr,
					   noun);
			continue;
		}

		if (found) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("%s UMH large community %u:%u:%u ignored: lower tuple already won",
					   name, ga, tuple_fn, param);
			continue;
		}

		*source_as = ga;
		*umh = addr;
		found = true;
		/* The value-checked "resolved via" line: the MVPN live proof
		 * greps for it under `debug bgp zebra` (an LC-resolved upstream
		 * RT is byte-identical to an EC-resolved one by design, so the
		 * log IS the signal). Debug-gated: re-resolution runs on every
		 * covering unicast best-path change, so an unconditional line
		 * would flood under route churn. */
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s UMH resolved via large community %u:%u:%u: %s %pI4, Source AS %u",
				   name, ga, tuple_fn, param, noun, &addr, ga);
	}

	return found;
}

/* The prefix for the DIMT call site's two notices, printed like its EC twins
 * (%pFX, no node pointer). NULL prints "(null)": a synthetic path in the unit
 * test has no node. */
static const struct prefix *bgp_dimt_umh_lc_prefix(const struct bgp_path_info *pi)
{
	return pi->net ? bgp_dest_get_prefix(pi->net) : NULL;
}

/* The DIMT call site's own name for who sent the path, for its two notices.
 * peer->host for peer_self is a pseudo-peer string ("Static announcement"),
 * which would name as a local announcement the very thing a refusal on an
 * imported or aggregate path is denying is one -- see
 * bgp_dimt_umh_refuse_local(). */
static const char *bgp_dimt_umh_lc_sender(const struct bgp_path_info *pi)
{
	if (!pi->peer)
		return "(unknown peer)";
	if (pi->peer->bgp && pi->peer == pi->peer->bgp->peer_self)
		return "this speaker (locally-held route)";
	return pi->peer->host ? pi->peer->host : "(unknown peer)";
}

/*
 * The DIMT lane of the UMH large community: may this path's LC-UMH steer the
 * pin path, and to where?
 *
 * Acts only when `bgp dimt umh-large-community` is set and the path carries a
 * tuple with that function (bgp_umh_lc_has_function(), the decoder's own
 * match). A route whose large communities carry only another function is not
 * on this lane at all and is never counted.
 *
 * Two gates the decoder must not own, in this order, each of which ends the
 * route's DIMT handling and counts ONCE PER ROUTE however many tuples it
 * carries (a route tripping both counts once, on the first):
 *
 *   1. Neighbour trust, bgp_dimt_peer_is_trusted() -- BEFORE decoding. The
 *      LC is the same claim as the 0x80 EC under another encoding; without
 *      this gate an untrusted route-server peer's refused EC would be
 *      accepted as an LC on the same route, with the same effect. Also
 *      charged to the neighbour's dimtUmhRejected, so `show bgp neighbors`
 *      moves for it the way it does for the EC.
 *   2. Family: AFI_IP only. A u32 parameter cannot carry an IPv6 UMH, and
 *      the pin path is same-family by design (a v4 UMH on a v6 route names
 *      no endpoint pim6d can build an adjacency to). This is where DIMT
 *      diverges from MVPN, which accepts p6; it lives here and not in the
 *      decoder for exactly that reason.
 *
 * Each gate logs on its own throttle pair, shared with neither the decoder's
 * lane nor the other gate, so a v6 LC-UMH flood (the common shape on an
 * IX-connected box) cannot silence the untrusted-neighbour line or the
 * decoder's detail.
 *
 * count == false is a pure query (no counter, no notice), for a re-read of an
 * attribute set already adjudicated. *on_lane, when non-NULL, is set to
 * whether the path carries a tuple with the DIMT function at all.
 *
 * The result is always an IPv4 UMH; the caller maps it as type PIM,
 * preference 0 -- the LC encodes neither (doc/dimt-lc-umh-mapping.md).
 */
bool bgp_dimt_umh_lc_resolve(struct bgp *bgp, const struct bgp_path_info *pi,
			     afi_t afi, bool count, struct in_addr *umh,
			     bool *on_lane)
{
	uint32_t fn = bgp ? bgp->dimt_umh_lc_function : 0;
	const char *why = NULL;
	uint32_t source_as = 0;

	if (on_lane)
		*on_lane = false;

	if (!fn || !pi || !pi->attr ||
	    !bgp_umh_lc_has_function(bgp_attr_get_lcommunity(pi->attr), fn))
		return false;

	if (on_lane)
		*on_lane = true;

	if (!bgp_dimt_peer_is_trusted(pi, &why)) {
		if (count) {
			bgp->dimt_umh_lc.rejected++;
			/* Never charged to peer_self: `show bgp neighbors`
			 * does not walk it, see stat_dimt_umh_rejected. */
			if (pi->peer && pi->peer->bgp &&
			    pi->peer != pi->peer->bgp->peer_self)
				pi->peer->stat_dimt_umh_rejected++;
			if (bgp_umh_lc_throttle_ok(&bgp->dimt_umh_lc_untrusted_log,
						   monotime(NULL)))
				zlog_notice("DIMT: UMH large community on %pFX from %s refused: %s",
					    bgp_dimt_umh_lc_prefix(pi),
					    bgp_dimt_umh_lc_sender(pi),
					    why ? why : "no usable peer on the path");
		}
		return false;
	}

	if (afi != AFI_IP) {
		/* Not the per-update cross-family EC warn's call site or its
		 * throttle: that one suits a rare wrong-family EC, while a v6
		 * route carrying an LC-UMH is routine on an IX-connected box.
		 * And the text names the attribute actually rejected, so the
		 * operator is not sent looking for a 0x80 that is not there. */
		if (count) {
			bgp->dimt_umh_lc.rejected++;
			if (bgp_umh_lc_throttle_ok(&bgp->dimt_umh_lc_xfam_log,
						   monotime(NULL)))
				zlog_warn("DIMT: %pFX from %s carries a UMH large community of the wrong address family; ignored (the UMH family must match the route family); further wrong-family UMH large communities on this instance suppressed for 60s",
					  bgp_dimt_umh_lc_prefix(pi),
					  bgp_dimt_umh_lc_sender(pi));
		}
		return false;
	}

	return bgp_umh_lc_decode(bgp, pi, fn, BGP_UMH_LC_LANE_DIMT,
				 count ? &bgp->dimt_umh_lc : NULL, &source_as,
				 umh);
}

/*
 * The DIMT lane at most once per attribute set: same contract as
 * bgp_dimt_umh_audit_path() for the extended community, on its own record.
 *
 * The route-update hook re-runs on re-processes that carry no new
 * announcement (add-path transmit, RPKI revalidation, `clear ip bgp PREFIX`,
 * a sibling path's event). pi->dimt_umh_lc_counted holds an interned
 * reference to the attribute set last evaluated with counting on, so an
 * unchanged pass is a pure query and charges nothing; a re-announcement that
 * changes the attributes interns to a different attr and is evaluated
 * afresh. The record is kept only for a path on the DIMT lane, so a route
 * carrying no DIMT tuple costs no reference. A knob change clears every
 * record (bgp_dimt_umh_lc_set_function()), because the verdict depends on the
 * function code point as much as on the attributes.
 *
 * Exported for tests/bgpd/test_dimt_umh_lc.c.
 */
bool bgp_dimt_umh_lc_from_path(struct bgp *bgp, struct bgp_path_info *pi,
			       afi_t afi, struct in_addr *umh)
{
	bool fresh;
	bool on_lane;
	bool has;

	if (!pi || !pi->attr)
		return false;

	fresh = pi->dimt_umh_lc_counted != pi->attr;
	has = bgp_dimt_umh_lc_resolve(bgp, pi, afi, fresh, umh, &on_lane);

	if (fresh) {
		/* Reassigned rather than left to bgp_attr_unintern(), which
		 * only NULLs the pointer when it frees the attr. */
		if (pi->dimt_umh_lc_counted)
			bgp_attr_unintern(&pi->dimt_umh_lc_counted);
		pi->dimt_umh_lc_counted = on_lane ? bgp_attr_intern(pi->attr)
						  : NULL;
	}

	return has;
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
	struct in_addr lc_umh = {};
	bool new_has;
	bool lc_has;

	/* IPv4/IPv6 unicast only. Extraction is same-family by choice: a v4 UMH
	 * EC is read from v4 routes and a v6 UMH EC from v6 routes; a
	 * cross-family UMH EC is deliberately ignored by the PIN path (BGP
	 * itself does not forbid one -- see the warn below). */
	if ((afi != AFI_IP && afi != AFI_IP6) || safi != SAFI_UNICAST)
		return 0;

	/* Adjudicate BEFORE the default-instance filter, and for both EC lists.
	 *
	 * This hook is the only point at which a path is evaluated because the
	 * NEIGHBOUR announced something, so it is the only honest place to move
	 * a per-peer counter -- every other consumer re-reads paths on our own
	 * schedule. It therefore has to cover what those consumers see, which is
	 * wider than what the pin path below uses:
	 *
	 *   - the MVPN settlement attestation lane runs in ANY instance, while
	 *     the pin path is default-instance only, so counting after the
	 *     filter would leave a VRF's refusals invisible;
	 *   - that same lane reads the v4 list regardless of the route's family,
	 *     so the cross-family EC the pin path cannot use is still an EC a
	 *     consumer would otherwise have honoured.
	 *
	 * Auditing both lists unconditionally is also what makes the counter
	 * match its contract in bgpd.h: refused ECs, counted once each, when
	 * they arrive. "Once" is per attribute set, which the hook alone cannot
	 * tell apart from a re-process; bgp_dimt_umh_audit_path() does. */
	bgp_dimt_umh_audit_path(new_route);

	/* The pin path proper is default-instance only. */
	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return 0;

	p = bgp_dest_get_prefix(dest);

	new_has = bgp_dimt_umh_from_path(new_route, afi, &new_umh, &new_type,
					 &new_pref);

	/* The UMH large community (BLO-36558). Evaluated on every pass so its
	 * own call-site gates count and log, but de-duplicated per attribute
	 * set inside bgp_dimt_umh_lc_from_path(). Returns false, having
	 * counted any reject, for a v6 route. */
	lc_has = bgp_dimt_umh_lc_from_path(bgp, new_route, afi, &lc_umh);

	/* LC vs EC precedence (doc/dimt-lc-umh-mapping.md, "Preference"): a
	 * valid LC-UMH wins over the UMH extended community on the same route,
	 * EXCEPT when the EC's selected tuple is typed amt-relay. The LC's PIM
	 * type is a default, not an assertion, while an amt-relay EC is an
	 * explicit one that pimd honours by NOT pinning; letting the LC win
	 * would turn that no-pin into a PIM Light join toward an AMT relay the
	 * moment the knob is set. Preference plays no part in this rule. */
	if (lc_has) {
		bool ec_amt = new_has && new_type == ZAPI_UMH_TYPE_AMT_RELAY;

		/* Unlike the MVPN lane's disagreement log, compare what 0x80
		 * actually carries: the address AND the type. An LC overridden
		 * by an amt-relay EC is logged even when both name the same
		 * address -- the case only the type comparison can catch. */
		if (new_has && BGP_DEBUG(zebra, ZEBRA) &&
		    (ec_amt || new_type != ZAPI_UMH_TYPE_PIM ||
		     !IS_IPADDR_V4(&new_umh) ||
		     new_umh.ipaddr_v4.s_addr != lc_umh.s_addr))
			zlog_debug("DIMT UMH large community disagrees with the UMH extended community on %pFX (LC: %pI4 type pim; EC: %pIA type %s): %s wins",
				   p, &lc_umh, &new_umh,
				   new_type == ZAPI_UMH_TYPE_AMT_RELAY ? "amt-relay" : "pim",
				   ec_amt ? "the amt-relay extended community"
					  : "the large community");

		if (!ec_amt) {
			new_umh = (struct ipaddr){};
			SET_IPADDR_V4(&new_umh);
			new_umh.ipaddr_v4 = lc_umh;
			new_type = ZAPI_UMH_TYPE_PIM;
			new_pref = 0;
			new_has = true;
		}
	}

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
		 * starts. Say why nothing happened.
		 *
		 * Decode-only on purpose: this asks "is there a UMH here at
		 * all", not "may it steer us". Asking through the gated entry
		 * point would suppress this hint for exactly the untrusted
		 * neighbours whose operator most needs it. Trust for this EC
		 * has already been adjudicated -- and charged, if it was
		 * refused -- by the bgp_dimt_umh_audit_path() pass above, so there
		 * is nothing left to decide here. */
		if (bgp_dimt_umh_decode(new_route,
					afi == AFI_IP ? AFI_IP6 : AFI_IP,
					&xf_umh, &xf_type, &xf_pref)) {
			struct peer *xf_peer = new_route->peer;
			time_t now = monotime(NULL);

			/* Throttled on the same 60s basis as
			 * bgp_dimt_umh_refuse(), but on its own state: this
			 * hook re-runs per path on a loc-RIB re-process, so an
			 * unthrottled warn floods on a storm exactly the way
			 * the refusal notice would. Its own fields, not the
			 * refusal's, for the decode-only reason given above --
			 * sharing them would let a refusal charged microseconds
			 * earlier in this same pass swallow the hint, which is
			 * the suppression this block exists to avoid.
			 *
			 * No peer means nowhere to keep the throttle, not a
			 * reason to drop the hint: a wrong-family EC with
			 * nobody to charge is still worth saying, the same way
			 * bgp_dimt_umh_audit() still counts a refusal it cannot
			 * attribute. That case keeps today's unthrottled
			 * behaviour; it is not the re-process storm this
			 * throttle is for, which is per-peer by construction. */
			if (bgp_dimt_umh_xfam_should_log(xf_peer, now))
				zlog_warn("DIMT: %pFX from %s carries a UMH extended community of the wrong address family; ignored (the UMH family must match the route family)%s",
					  p,
					  xf_peer && xf_peer->host ? xf_peer->host
								   : "(unknown peer)",
					  xf_peer ? "; further wrong-family UMH prefixes from this peer suppressed for 60s"
						  : "");
		}

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

/*
 * `bgp dimt umh-large-community`: set the DIMT lane's function code point and
 * re-evaluate every unicast route's DIMT mapping under it, the way the MVPN
 * knob re-resolves its joins. No session reset: the attributes have not
 * changed, only how we read them, so nothing needs re-sending -- re-running
 * the route-update hook on each selected path is the whole job. A mapping the
 * new setting no longer yields is DELeted (an LC-only route when the knob is
 * cleared), one it newly yields is ADDed, and an unchanged one is re-ADDed,
 * which pimd treats as an upsert.
 *
 * Every LC record is cleared first, on every path and not only the selected
 * one, because the verdict a record stands for was reached under the old
 * function code point: a re-announcement-free path must be adjudicated, and
 * counted, afresh under the new one. The EC lane's record is untouched -- its
 * verdict does not depend on this knob.
 *
 * Both families are walked: the v4 table for the mappings, the v6 table so
 * its wrong-family records are re-adjudicated under the new code point too.
 * Synchronous and O(unicast table); a no-op set (same value) walks nothing.
 */
void bgp_dimt_umh_lc_set_function(struct bgp *bgp, uint32_t fn)
{
	afi_t afi;

	if (bgp->dimt_umh_lc_function == fn)
		return;

	bgp->dimt_umh_lc_function = fn;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		struct bgp_table *table = bgp->rib[afi][SAFI_UNICAST];
		struct bgp_dest *dest;

		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			struct bgp_path_info *pi;
			struct bgp_path_info *sel = NULL;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				if (pi->dimt_umh_lc_counted) {
					bgp_attr_unintern(&pi->dimt_umh_lc_counted);
					pi->dimt_umh_lc_counted = NULL;
				}
				if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED) &&
				    !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
					sel = pi;
			}

			if (sel)
				bgp_dimt_route_update(bgp, afi, SAFI_UNICAST,
						      dest, sel, sel);
		}
	}
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
