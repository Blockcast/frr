// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MCAST-VPN (SAFI 5) NLRI codec and Global Table Multicast origination.
 *
 * Copyright (C) 2026 Blockcast, Inc.
 *
 * Implements RFC 6514 MCAST-VPN Route Types 1 (Intra-AS I-PMSI A-D), 5
 * (Source Active A-D) and 7 (C-multicast Source Tree Join), constrained to
 * Global Table Multicast (RFC 7716): the Route Distinguisher is always zero
 * (single global table) and only SSM groups are used (232.0.0.0/8 for IPv4,
 * ff3x::/32 for IPv6).
 */
#ifndef _FRR_BGP_MVPN_H
#define _FRR_BGP_MVPN_H

#include "prefix.h"
#include "stream.h"

#include "bgpd/bgpd.h"

/* RFC 6514 MCAST-VPN route types. Types 1 (Intra-AS I-PMSI A-D), 5 (GTM SSM
 * Source Active) and 7 (C-multicast Source Tree Join) are implemented.
 */
#define BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI   1
#define BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE    5
#define BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN 7

/*
 * RFC 6514 Section 4.1 Intra-AS I-PMSI A-D route, route-type-specific portion
 * for IPv4:  RD(8) + OriginatingRouterIP(4) = 12 octets. No C-S/C-G.
 */
#define BGP_MVPN_TYPE1_V4_SPEC_LEN 12

/* IPv6 (RFC 6515): RD(8) + OriginatingRouterIP(16) = 24 octets. */
#define BGP_MVPN_TYPE1_V6_SPEC_LEN 24

/*
 * RFC 6514 Section 4.5 Source Active A-D route, route-type-specific portion
 * for IPv4:  RD(8) + McastSrcLen(1) + McastSrc(4) + McastGrpLen(1)
 *          + McastGrp(4) = 18 octets.
 */
#define BGP_MVPN_TYPE5_V4_SPEC_LEN 18

/* IPv6 (RFC 6515): RD(8) + McastSrcLen(1) + McastSrc(16) + McastGrpLen(1)
 *               + McastGrp(16) = 42 octets. */
#define BGP_MVPN_TYPE5_V6_SPEC_LEN 42

/*
 * RFC 6514 Section 4.6 C-multicast Source Tree Join route, route-type-specific
 * portion for IPv4:  RD(8) + SourceAS(4) + McastSrcLen(1) + McastSrc(4)
 *                  + McastGrpLen(1) + McastGrp(4) = 22 octets.
 */
#define BGP_MVPN_TYPE7_V4_SPEC_LEN 22

/* IPv6 (RFC 6515): RD(8) + SourceAS(4) + McastSrcLen(1) + McastSrc(16)
 *               + McastGrpLen(1) + McastGrp(16) = 46 octets. */
#define BGP_MVPN_TYPE7_V6_SPEC_LEN 46

/*
 * Largest on-wire NLRI this codec emits: Route Type(1) + Length(1) + Type-7
 * IPv6 body(46) = 48 octets. Used to reserve stream room ahead of
 * bgp_mvpn_encode_prefix(); must stay >= what any encoder arm writes.
 */
#define BGP_MVPN_MAX_NLRI_LEN (2 + BGP_MVPN_TYPE7_V6_SPEC_LEN)

/* Fill a prefix_mvpn for a Type-5 (Source Active) route. C-S/C-G may be v4 or
 * v6 but must share a family. */
extern void bgp_mvpn_build_prefix_type5(struct prefix_mvpn *p, const struct ipaddr *src,
					const struct ipaddr *grp);

/*
 * Fill a prefix_mvpn for a Type-1 (Intra-AS I-PMSI A-D) route. The route has no
 * C-S/C-G; the Originating Router's IP Address (RFC 6514 Section 4.1) is stored
 * in the src slot (route_type keeps it distinct from Type-5/7).
 */
extern void bgp_mvpn_build_prefix_type1(struct prefix_mvpn *p, const struct ipaddr *orig_ip);

/* Fill a prefix_mvpn for a Type-7 (C-multicast Source Tree Join) route. */
extern void bgp_mvpn_build_prefix_type7(struct prefix_mvpn *p, uint32_t source_as,
					const struct ipaddr *src, const struct ipaddr *grp);

/* Encode any MCAST-VPN NLRI into the MP_REACH/MP_UNREACH stream, dispatching
 * on the prefix's route type (RFC 6514 Sections 4.1 / 4.5 / 4.6). */
extern void bgp_mvpn_encode_prefix(struct stream *s, const struct prefix *p, bool addpath_capable,
				   uint32_t addpath_tx_id);

/* Parse a received MCAST-VPN NLRI (fan-out target from bgp_nlri_parse()). */
extern int bgp_nlri_parse_mvpn(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			       bool mp_withdraw);

/* Configure/withdraw a locally-originated GTM Source Active route. C-S/C-G may
 * be v4 or v6 but must share a family. */
extern int bgp_mvpn_source_active_set(struct bgp *bgp, const struct ipaddr *src,
				      const struct ipaddr *grp, bool negate);

/*
 * Auto-originate this PE's Intra-AS I-PMSI A-D (Type-1) route with an
 * Ingress-Replication PMSI Tunnel attribute (RFC 6514 Section 4.1 + Section 5).
 * Idempotent and self-guarding: a no-op unless the GTM MVPN AF is active on the
 * instance and the router-id (Originating Router's IP) is known. Driven by both
 * the AF-activate and router-id-set lifecycle hooks.
 */
extern void bgp_mvpn_originate_type1(struct bgp *bgp);

/* Withdraw this PE's Type-1 route from one MCAST-VPN address family. */
extern void bgp_mvpn_withdraw_type1(struct bgp *bgp, afi_t afi);

/*
 * Originate/withdraw a local Type-7 (C-multicast Source Tree Join) route for a
 * pimd-reported receiver join, relayed through zebra (bgp_zebra_process_mvpn_sg).
 * The Source AS and the upstream PE (Global Administrator of the upstream-node
 * RT) are resolved from the unicast route toward C-S and the received Source
 * Active route (RFC 6514 Section 5).
 */
extern int bgp_mvpn_source_tree_join_set(struct bgp *bgp, const struct ipaddr *src,
					 const struct ipaddr *grp, bool negate);

/* running-config emission for `bgp mvpn source-active` under the AF node. */
extern void bgp_mvpn_config_write(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi);

/* True if the GTM MVPN AF (SAFI 5) is active on any peer of this instance, in
 * either AFI. Gate for the pimd->bgpd SG replay subscription. */
extern bool bgp_mvpn_gtm_active(struct bgp *bgp);

/* Withdraw the old Type-1 before a router-id change, or originate the new
 * Type-1 afterward. */
extern void bgp_mvpn_handle_router_id_update(struct bgp *bgp, bool withdraw);

/* `show bgp ipv4 mvpn [json]` printer. */
extern void bgp_mvpn_show_routes(struct vty *vty, struct bgp *bgp, afi_t afi, bool use_json);

#endif /* _FRR_BGP_MVPN_H */
