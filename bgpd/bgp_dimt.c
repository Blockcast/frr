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
	 * bgpd has ten producers that call info_make() with peer_self: the
	 * enumeration below accounts for nine, and BGP_ROUTE_NORMAL's one is in
	 * the paragraph after it. A reader redoing this for a new table can check
	 * the count first -- but must follow peer_self THROUGH wrapper parameters
	 * to reproduce it. A literal grep for peer_self at the info_make() call
	 * finds only nine; bgp_mvpn.c:402 receives it as an argument. The two
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
	 * bgp->rib[afi][SAFI_UNICAST] (bgp_mvpn.c:1447). The remaining two are
	 * refused by sub_type on their own arms below: bgp_mplsvpn.c:1417
	 * (IMPORTED) and bgp_route.c:9696 (AGGREGATE). That is 2 + 5 + 2 = 9
	 * here; the tenth is BGP_ROUTE_NORMAL's, next paragraph.
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
 */
static void bgp_dimt_umh_audit(const struct bgp_path_info *pi, afi_t afi)
{
	struct ipaddr umh = {};
	uint8_t umh_type = 0;
	uint8_t preference = 0;
	const char *why = NULL;

	if (!bgp_dimt_umh_decode(pi, afi, &umh, &umh_type, &preference))
		return;

	if (bgp_dimt_peer_is_trusted(pi, &why))
		return;

	/* pi is const, but the peer it points at is not -- the refusal is a
	 * property of the peer, not of the path. A refusal with no peer to
	 * charge is still a refusal; there is just nobody to count it against.
	 *
	 * A path bgpd attributes to peer_self has a peer, but not one a counter
	 * or a log line can honestly name: see bgp_dimt_umh_refuse_local(). */
	if (!pi->peer)
		return;

	if (pi->peer->bgp && pi->peer == pi->peer->bgp->peer_self)
		bgp_dimt_umh_refuse_local(pi->peer->bgp, pi, why);
	else
		bgp_dimt_umh_refuse(pi->peer, why);
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
	 * they arrive.
	 *
	 * KNOWN CEILING (BLO-36553 review, not fixed here): with add-path
	 * transmit configured for the afi/safi, bgp_process_main_one() skips its
	 * unchanged-bestpath early return -- the trailing
	 * !bgp_addpath_is_addpath_used(&bgp->tx_addpath, afi, safi) clause -- so
	 * this hook also fires on re-processes that carry no new announcement
	 * (nexthop tracking, a peer event on a sibling path, a route-map
	 * refresh), and each one re-charges the refusal. `clear ip bgp PREFIX`
	 * is the same shape via BGP_NODE_USER_CLEAR.
	 *
	 * Two obvious fixes are both WRONG, recorded so they are not retried:
	 *   - CHECK_FLAG(new_route->flags, BGP_PATH_ATTR_CHANGED) always reads
	 *     false here. bgp_route.c unsets that flag on new_select a dozen
	 *     lines BEFORE calling this hook, so gating on it would silence the
	 *     counter permanently rather than stabilise it.
	 *   - old_route != new_route suppresses the legitimate case too. A
	 *     re-announce that changes attributes reuses the same
	 *     bgp_path_info, so old == new on a genuine origin-AS change --
	 *     which the topotest's stage 3 pins as MUST count.
	 * Discriminating them needs the previous attr pointer, i.e. per-path
	 * audit state that does not exist yet; that is a design decision, not a
	 * gate tweak. */
	bgp_dimt_umh_audit(new_route, AFI_IP);
	bgp_dimt_umh_audit(new_route, AFI_IP6);

	/* The pin path proper is default-instance only. */
	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
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
		 * starts. Say why nothing happened.
		 *
		 * Decode-only on purpose: this asks "is there a UMH here at
		 * all", not "may it steer us". Asking through the gated entry
		 * point would suppress this hint for exactly the untrusted
		 * neighbours whose operator most needs it. Trust for this EC
		 * has already been adjudicated -- and charged, if it was
		 * refused -- by the bgp_dimt_umh_audit() pass above, so there
		 * is nothing left to decide here. */
		if (bgp_dimt_umh_decode(new_route,
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
