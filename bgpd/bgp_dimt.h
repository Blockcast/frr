// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DIMT (draft-zzhang-mboned-dynamic-internet-mcast-tunnel) UMH origination:
 * extract the Upstream Multicast Hop extended community from unicast source
 * routes and relay it to pimd through zebra.
 */

#ifndef _FRR_BGP_DIMT_H
#define _FRR_BGP_DIMT_H

#include "lib/zclient.h"

struct bgp_path_info;

extern void bgp_dimt_init(void);
extern void bgp_dimt_terminate(void);
extern int bgp_dimt_umh_replay(ZAPI_CALLBACK_ARGS);
extern bool bgp_dimt_umh_xfam_should_log(struct peer *peer, time_t now);

/*
 * Pull the best UMH extended community (highest la_pref wins) off one path.
 * Exported so the MVPN settlement-event attestation lane decodes the DIMT wire
 * layout through this one implementation rather than a second copy of it --
 * ECOMMUNITY_UMH (0x80) is the DIMT encoding and only this function knows it.
 *
 * afi selects which EC list is read, NOT the address family of the route the
 * path describes: AFI_IP reads the 8-byte ecommunity list, AFI_IP6 the 20-byte
 * ipv6_ecommunity list. A v6 C-S route can carry an IPv4 UMH, so the caller
 * chooses the list it wants rather than inheriting the prefix's family.
 *
 * Returns true and fills a family-tagged umh/umh_type/preference on match.
 *
 * Returns false when the path carries no UMH in that list, or carries one the
 * sending neighbour is not entitled to set; see bgp_dimt_peer_is_trusted().
 *
 * This is a pure query and does NOT move the per-peer refusal counter: callers
 * re-read already-adjudicated paths on our own schedule, so counting here
 * would charge one arriving EC many times. Refusals are counted once, at
 * arrival, by the loc-RIB update hook in bgp_dimt.c.
 */
extern bool bgp_dimt_umh_from_path(const struct bgp_path_info *pi, afi_t afi,
				   struct ipaddr *umh, uint8_t *umh_type,
				   uint8_t *preference);

/*
 * May this path's UMH steer where we join? True for a route this speaker
 * originated itself, or one from a `dimt-trusted` neighbour whose AS the
 * route's origin authorises.
 *
 * "Originated itself" is an ALLOW-list of sub_types (STATIC, REDISTRIBUTE,
 * NORMAL), not the peer_self pointer: more than one thing re-homes a path onto
 * peer_self without this speaker having authored the attribute. A VPN leak
 * (BGP_ROUTE_IMPORTED) discards the sending neighbour while preserving the
 * UMH; an as-set aggregate (BGP_ROUTE_AGGREGATE) merges a component route's
 * whole ecommunity. Both would launder an untrusted neighbour's EC. The
 * allow-list is so that a sub_type added later fails closed here instead of
 * inheriting trust -- the deny-list this replaced needed extending twice.
 *
 * On false, *why is a short reason for the caller's log -- EXCEPT when the
 * path has no usable peer to name, where it stays NULL. A caller that logs
 * *why must tolerate that, and one that charges a per-peer counter must check
 * pi->peer first; there is nobody to charge in that case. A refusal on a
 * peer_self path has a peer but no honest one to charge either -- see
 * bgp_dimt_umh_refuse_local() in bgp_dimt.c.
 *
 * Exported for the UMH LARGE community lane (BLO-36558): an LC-UMH that
 * bypassed this gate would be an untrusted peer's refused EC accepted under a
 * different encoding, on the same route, with the same effect. One
 * implementation, one owner -- do not re-derive the rule.
 */
extern bool bgp_dimt_peer_is_trusted(const struct bgp_path_info *pi,
				     const char **why);

/*
 * The UMH LARGE community (BLO-36558; contract in doc/dimt-lc-umh-mapping.md).
 * One decoder for both lanes that read it -- the MVPN Type-7 lane and the
 * DIMT pin path -- so the encoding, the origin-AS trust rule and the reject
 * accounting cannot drift between them.
 */
enum bgp_umh_lc_lane_id {
	BGP_UMH_LC_LANE_MVPN,
	BGP_UMH_LC_LANE_DIMT,
};

struct bgp;
struct lcommunity;
struct bgp_umh_lc_lane;

/* Does the list carry a tuple with this function at all? THE function match:
 * the decoder uses it too, so "is this route on my lane" and "which tuples
 * does the decoder read" cannot disagree. False for fn == 0. */
extern bool bgp_umh_lc_has_function(const struct lcommunity *lcom, uint32_t fn);

/* Decode one lane's UMH large community off a path: lowest valid tuple with
 * function @fn wins, its Global Administrator into *source_as and its
 * Parameter (htonl'd) into *umh; both untouched on false. Applies the
 * origin-AS trust rule and the usable-address rule, and nothing lane-specific.
 *
 * Counts every reject into @lane (per tuple, or once per route for an
 * origin-ambiguous AS_PATH) and logs the trust-boundary ones on @lane's
 * throttle; @lane == NULL is a pure query that counts and notices nothing.
 * See the comment on the definition for the exact rules. */
extern bool bgp_umh_lc_decode(struct bgp *bgp, const struct bgp_path_info *pi,
			      uint32_t fn, enum bgp_umh_lc_lane_id lane_id,
			      struct bgp_umh_lc_lane *lane, uint32_t *source_as,
			      struct in_addr *umh);

/* The DIMT lane: bgp->dimt_umh_lc_function, then the neighbour-trust gate,
 * then the AFI_IP-only rule, then the decoder. count == false is a pure
 * query. *on_lane (may be NULL) reports whether the path carries a DIMT tuple
 * at all. Exported for tests/bgpd/test_dimt_umh_lc.c. */
extern bool bgp_dimt_umh_lc_resolve(struct bgp *bgp,
				    const struct bgp_path_info *pi, afi_t afi,
				    bool count, struct in_addr *umh,
				    bool *on_lane);

/* bgp_dimt_umh_lc_resolve() at most once per attribute set with counting on,
 * as the loc-RIB hook calls it. Exported for tests/bgpd/test_dimt_umh_lc.c. */
extern bool bgp_dimt_umh_lc_from_path(struct bgp *bgp, struct bgp_path_info *pi,
				      afi_t afi, struct in_addr *umh);

/* `bgp dimt umh-large-community`: set the function code point (0 = off) and
 * re-evaluate every unicast route's DIMT mapping under it, no session reset. */
extern void bgp_dimt_umh_lc_set_function(struct bgp *bgp, uint32_t fn);

#endif /* _FRR_BGP_DIMT_H */
