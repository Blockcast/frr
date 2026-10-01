// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _ZEBRA_DIMT_H
#define _ZEBRA_DIMT_H

#include "zebra/zebra_dplane.h"

struct zserv;
struct zmsghdr;
struct stream;
struct interface;
struct zebra_vrf;

void zebra_dimt_tunnel_request(struct zserv *client, struct zmsghdr *hdr,
			       struct stream *msg, struct zebra_vrf *zvrf);
void zebra_dimt_tunnel_dplane_result(struct zebra_dplane_ctx *ctx);
void zebra_dimt_tunnel_if_update(struct interface *ifp);
void zebra_dimt_tunnel_if_change(struct interface *ifp);
/* The netdev behind ifp is gone (not renamed); ifp still holds its ifindex. */
void zebra_dimt_tunnel_if_delete(struct interface *ifp);
void zebra_dimt_tunnel_init(void);
void zebra_dimt_tunnel_cleanup(void);

#endif /* _ZEBRA_DIMT_H */
