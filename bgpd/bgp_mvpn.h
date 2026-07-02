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

/* RFC 6514 MCAST-VPN route types. Only Type 5 is implemented (GTM SSM). */
#define BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE 5

/*
 * RFC 6514 Section 4.5 Source Active A-D route, route-type-specific portion
 * for IPv4:  RD(8) + McastSrcLen(1) + McastSrc(4) + McastGrpLen(1)
 *          + McastGrp(4) = 18 octets.
 */
#define BGP_MVPN_TYPE5_V4_SPEC_LEN 18

/*
 * Full on-wire NLRI length for a Type-5 IPv4 route:
 *   Route Type(1) + Length(1) + route-type-specific(18) = 20 octets.
 */
#define BGP_MVPN_TYPE5_V4_NLRI_LEN (2 + BGP_MVPN_TYPE5_V4_SPEC_LEN)

/* Fill a prefix_mvpn for a Type-5 (Source Active) route. */
extern void bgp_mvpn_build_prefix_type5(struct prefix_mvpn *p, struct in_addr src,
					struct in_addr grp);

/* Encode a Type-5 NLRI into the MP_REACH stream (RFC 6514 Section 4.5). */
extern void bgp_mvpn_encode_type5(struct stream *s, const struct prefix *p, bool addpath_capable,
				  uint32_t addpath_tx_id);

/* Parse a received MCAST-VPN NLRI (fan-out target from bgp_nlri_parse()). */
extern int bgp_nlri_parse_mvpn(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			       bool mp_withdraw);

/* Configure/withdraw a locally-originated GTM Source Active route. */
extern int bgp_mvpn_source_active_set(struct bgp *bgp, struct in_addr src, struct in_addr grp,
				      bool negate);

/* running-config emission for `bgp mvpn source-active` under the AF node. */
extern void bgp_mvpn_config_write(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi);

/* `show bgp ipv4 mvpn [json]` printer. */
extern void bgp_mvpn_show_routes(struct vty *vty, struct bgp *bgp, afi_t afi, bool use_json);

#endif /* _FRR_BGP_MVPN_H */
