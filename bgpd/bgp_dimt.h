// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DIMT (draft-zzhang-mboned-dynamic-internet-mcast-tunnel) UMH origination:
 * extract the Upstream Multicast Hop extended community from unicast source
 * routes and relay it to pimd through zebra.
 */

#ifndef _FRR_BGP_DIMT_H
#define _FRR_BGP_DIMT_H

#include "lib/zclient.h"

extern void bgp_dimt_init(void);
extern void bgp_dimt_terminate(void);
extern int bgp_dimt_umh_replay(ZAPI_CALLBACK_ARGS);

#endif /* _FRR_BGP_DIMT_H */
