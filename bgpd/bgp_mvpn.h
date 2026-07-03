// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MCAST-VPN (SAFI 5) NLRI codec and Global Table Multicast origination.
 *
 * Copyright (C) 2026 Blockcast, Inc.
 *
 * Implements RFC 6514 MCAST-VPN Route Type 5 (Source Active A-D) constrained
 * to Global Table Multicast (RFC 7716): the Route Distinguisher is always zero
 * (single global table) and only SSM groups (232.0.0.0/8 for IPv4) are used.
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
 * Full on-wire NLRI length for a Type-1 IPv4 route:
 *   Route Type(1) + Length(1) + route-type-specific(12) = 14 octets.
 */
#define BGP_MVPN_TYPE1_V4_NLRI_LEN (2 + BGP_MVPN_TYPE1_V4_SPEC_LEN)

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
 * Full on-wire NLRI length for a Type-5 IPv4 route:
 *   Route Type(1) + Length(1) + route-type-specific(18) = 20 octets.
 */
#define BGP_MVPN_TYPE5_V4_NLRI_LEN (2 + BGP_MVPN_TYPE5_V4_SPEC_LEN)

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
 * Full on-wire NLRI length for a Type-7 IPv4 route:
 *   Route Type(1) + Length(1) + route-type-specific(22) = 24 octets.
 */
#define BGP_MVPN_TYPE7_V4_NLRI_LEN (2 + BGP_MVPN_TYPE7_V4_SPEC_LEN)

/*
 * Global Table Multicast is SSM-only: the customer group (C-G) must fall in the
 * IPv4 SSM range 232.0.0.0/8 (RFC 4607, 0xe8 == 232). Enforced on both
 * origination (VTY) and on receipt of a peer's Type-5/7 NLRI, so a
 * non-conforming peer cannot inject an ASM/unicast/bogon group into the global
 * table.
 */
static inline bool bgp_mvpn_group_is_ssm(struct in_addr grp)
{
	return (ntohl(grp.s_addr) & 0xff000000U) == 0xe8000000U;
}

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

/* Encode a Type-5 NLRI into the MP_REACH stream (RFC 6514 Section 4.5). */
extern void bgp_mvpn_encode_type5(struct stream *s, const struct prefix *p, bool addpath_capable,
				  uint32_t addpath_tx_id);

/* Encode a Type-1 NLRI into the MP_REACH stream (RFC 6514 Section 4.1). */
extern void bgp_mvpn_encode_type1(struct stream *s, const struct prefix *p, bool addpath_capable,
				  uint32_t addpath_tx_id);

/* Encode a Type-7 NLRI into the MP_REACH stream (RFC 6514 Section 4.6). */
extern void bgp_mvpn_encode_type7(struct stream *s, const struct prefix *p, bool addpath_capable,
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

/*
 * TEST-ONLY scaffold: originate/withdraw a local Type-7 (C-multicast Source
 * Tree Join) route. The upstream PE (Global Administrator of the upstream-node
 * RT) is taken explicitly when non-zero, else resolved from the Source Active
 * route's UMH. Plan 3 replaces this with pimd-driven origination.
 */
extern int bgp_mvpn_source_tree_join_set(struct bgp *bgp, uint32_t source_as,
					 const struct ipaddr *src, const struct ipaddr *grp,
					 struct in_addr upstream, bool negate);

/* running-config emission for `bgp mvpn source-active` under the AF node. */
extern void bgp_mvpn_config_write(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi);

/* True if the GTM MVPN AF (SAFI 5) is active on any peer of this instance, in
 * either AFI. Gate for the pimd->bgpd SG replay subscription. */
extern bool bgp_mvpn_gtm_active(struct bgp *bgp);

/* `show bgp ipv4 mvpn [json]` printer. */
extern void bgp_mvpn_show_routes(struct vty *vty, struct bgp *bgp, afi_t afi, bool use_json);

#endif /* _FRR_BGP_MVPN_H */
