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

#endif /* _FRR_BGP_DIMT_H */
