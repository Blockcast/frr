// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Event-grade Type-7 (C-multicast Source Tree Join) install/withdraw/
 * origin-change emission for settlement-plane consumers.
 *
 * Copyright (C) 2026 Blockcast, Inc.
 *
 * This is the settlement-readiness gate for MVPN replication billing
 * (Paperclip BLO-17645, parent epic BLO-17642): `vtysh show bgp ipv4/ipv6
 * mvpn json` polling is dev-mode + reconciliation cross-check only, never
 * the production claim source. The event stream defined here is.
 *
 * Consumer: the amt-astats MVPN FlowSource (Paperclip BLO-17650), over a
 * local AF_UNIX SOCK_STREAM socket. Wire format and field semantics are
 * documented in doc/mvpn-events-schema.md and MUST stay in lockstep with the
 * normative MVPN Delivery Settlement Contract v1
 * (Blockcast/trafficcontrol docs/designs/mvpn-settlement-contract-v1.md,
 * Paperclip BLO-17643): in particular the `lc_umh_origin` string format
 * (`<sourceAS>:1:<UMH-u32>`) and the rule that `route_version` changes on
 * any install, withdraw, or LC-UMH origin change.
 */
#ifndef _FRR_BGP_MVPN_EVENTS_H
#define _FRR_BGP_MVPN_EVENTS_H

#include <netinet/in.h>

#include "prefix.h"
#include "ipaddr.h"

#include "bgpd/bgpd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Start the event-socket listener for a bgp instance if
 * `mvpn_event_socket_path` is configured and not already running on that
 * path. No-op otherwise, and a no-op re-call while already running on the
 * same path (a genuine (re)start bumps boot_epoch -- see the .c file header).
 * Only caller today is bgp_mvpn_events_set_socket(). */
extern void bgp_mvpn_events_start(struct bgp *bgp);

/* Tear down the listener and all connected clients, and free per-join
 * route-version state. Safe to call when nothing is running. Called from
 * `no bgp mvpn event-socket` and from bgp_delete(). */
extern void bgp_mvpn_events_stop(struct bgp *bgp);

/* Apply `bgp mvpn event-socket PATH` / `no bgp mvpn event-socket`: stores the
 * path on the bgp instance and (re)starts or stops the listener. Passing NULL
 * stops and clears any configured path. */
extern void bgp_mvpn_events_set_socket(struct bgp *bgp, const char *path);

/*
 * Called from bgp_mvpn_source_tree_join_set() exactly once per non-withdraw
 * invocation, after (source_as, umh) have been resolved for (src, grp) and
 * after the corresponding BGP and selective-route RIB updates complete.
 *
 * Diffs the newly-resolved values against this join's last-known values:
 *   - no prior state            -> emit "install" (generation 1, i.e.
 *                                  route_version "<boot_epoch>.1")
 *   - prior state, unchanged    -> no-op (redundant re-resolve)
 *   - prior state, changed      -> emit "origin_change" (route_version++,
 *                                  prior_route_version carried)
 * `umh` may be the "no upstream resolved" sentinel (INADDR_ANY); that is a
 * legitimate, distinct value from any resolved address.
 */
extern void bgp_mvpn_event_join_resolved(struct bgp *bgp, const struct ipaddr *src,
					 const struct ipaddr *grp, uint32_t source_as,
					 struct in_addr umh);

/*
 * Called from bgp_mvpn_source_tree_join_set() on withdraw (negate=true).
 * Emits "withdraw" (route_version++) when this join has prior state; a
 * withdraw of a join this sink never saw installed (e.g. socket configured
 * after the join was already up) is a no-op -- there is nothing to close a
 * billing window on.
 */
extern void bgp_mvpn_event_withdrawn(struct bgp *bgp, const struct ipaddr *src,
				     const struct ipaddr *grp);

/* `bgp mvpn event-socket ...` running-config emission, called from
 * bgp_mvpn_config_write() for AFI_IP only (one setting serves both planes,
 * same convention as the ipmsi-label knob). */
extern void bgp_mvpn_events_config_write(struct vty *vty, struct bgp *bgp);

/* `show bgp mvpn events [json]`: listener liveness (configured path vs
 * actually listening), boot_epoch, seq, connected-client count. The
 * "configured but not listening" state is the operator's only signal that a
 * bind/listen failure left the stream dead while running-config still
 * advertises it. */
extern void bgp_mvpn_events_show(struct vty *vty, struct bgp *bgp, bool use_json);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_MVPN_EVENTS_H */
