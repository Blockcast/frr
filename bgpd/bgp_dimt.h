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
 */
extern bool bgp_dimt_umh_from_path(const struct bgp_path_info *pi, afi_t afi,
				   struct ipaddr *umh, uint8_t *umh_type,
				   uint8_t *preference);

#endif /* _FRR_BGP_DIMT_H */
