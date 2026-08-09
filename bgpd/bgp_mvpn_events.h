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
#include "buffer.h"

#include "bgpd/bgpd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Tear down the listener and all connected clients, and free per-join
 * route-version state. Safe to call when nothing is running. Called from
 * `no bgp mvpn event-socket` and from bgp_delete(). */
extern void bgp_mvpn_events_stop(struct bgp *bgp);

/* Apply `bgp mvpn event-socket PATH` / `no bgp mvpn event-socket`: stores the
 * path on the bgp instance only after a replacement listener is ready.
 * Passing NULL stops and clears any configured path. Returns CMD_SUCCESS or
 * CMD_WARNING_CONFIG_FAILED without disturbing the current listener. */
extern int bgp_mvpn_events_set_socket(struct bgp *bgp, const char *path);

/* A slow subscriber is disconnected once its live queued bytes would exceed
 * this cap. The decision is based on the current buffer, never lifetime bytes. */
#define BGP_MVPN_EVENT_SINK_MAX_BACKLOG (8 * 1024 * 1024)
extern bool bgp_mvpn_event_backlog_exceeded(const struct buffer *wb,
					     size_t append_len);

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

/*
 * Reconcile emitted per-leaf state against the Type-4 (Leaf A-D) routes in the
 * MVPN RIB, emitting "leaf_install" / "leaf_withdraw" for the difference.
 *
 * A join event is per (C-S, C-G) and describes this PE's own upstream
 * interest; a leaf event is one level deeper and names a receiving PE, so that
 * a root doing ingress replication can bill each leaf separately. The leaf
 * identity is the Type-4 leaf_originator, already in the RIB key.
 *
 * Only routes learned from a peer are emitted: our own Type-4 carries
 * bgp->router_id (this router advertising itself as a leaf) and billing it
 * would invoice the root for its own delivery.
 *
 * Safe and cheap to call on any MVPN RIB change. The walk is a full diff, so
 * it is idempotent and self-correcting: a trigger that fails to fire costs
 * latency until the next call, never a wrong or duplicated bill.
 */
extern void bgp_mvpn_events_reconcile_leaves(struct bgp *bgp);

/*
 * Coalescing front door for the above: schedules one reconcile on the event
 * loop instead of walking inline. Call this from route-processing paths.
 *
 * The walk is a full scan of both MVPN RIBs, so running it inline per update
 * turned a burst of N arriving leaves into N full scans -- O(N^2) on the main
 * route-processing path, worst in exactly the deployments large enough to want
 * per-leaf settlement. Repeated calls while one is pending are free.
 */
extern void bgp_mvpn_events_schedule_leaf_reconcile(struct bgp *bgp);

/* `bgp mvpn event-socket ...` running-config emission. This instance-wide
 * command must be written from BGP_NODE before any address-family block. */
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
