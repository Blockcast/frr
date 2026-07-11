// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DIMT (draft-zzhang-mboned-dynamic-internet-mcast-tunnel) UMH consumer:
 * bgpd-learned Upstream Multicast Hop mappings steer (S,G) RPF onto the
 * PIM Light tunnel interface facing the UMH.
 */

#ifndef PIM_DIMT_H
#define PIM_DIMT_H

#include <zebra.h>

#include "zclient.h"
#include "prefix.h"

#include "pim_addr.h"

struct pim_instance;
struct pim_upstream;
struct vty;

/* One bgpd-learned UMH mapping: joins for sources covered by `prefix` go
 * toward `umh` (over the light interface owning the subnet containing it). */
struct pim_dimt_umh {
	struct prefix prefix;
	pim_addr umh;
	uint8_t umh_type;   /* enum zapi_umh_type; AMT stored/displayed only */
	uint8_t preference; /* 0-15, higher preferred */
};

void pim_dimt_init(struct pim_instance *pim);
void pim_dimt_terminate(struct pim_instance *pim);

/* ZEBRA_UMH_ADD / ZEBRA_UMH_DEL from bgpd (via zebra). */
void pim_dimt_umh_update(struct pim_instance *pim,
			 const struct zapi_umh *zumh, bool add);

/* Steer a (possibly new) upstream's RPF onto the light interface facing its
 * source's UMH; no-op when no mapping covers the source. */
void pim_dimt_upstream_apply(struct pim_instance *pim,
			     struct pim_upstream *up);

/* Unpin every upstream pinned to a light interface that went down/away
 * (STATIC_IIF suppresses the normal rpf-update repair paths). */
void pim_dimt_iface_down(struct pim_instance *pim, struct interface *ifp);

void pim_dimt_show_umh(struct pim_instance *pim, struct vty *vty, bool json);

#endif /* PIM_DIMT_H */
