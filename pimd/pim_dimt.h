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
	uint8_t umh_type;   /* enum zapi_umh_type; only PIM mappings drive
			     * pins, AMT stored/displayed only */
	uint8_t preference; /* 0-15, higher preferred */
	/* Marked when a zebra reconnect asks bgpd to re-dump: the mapping is
	 * held, still driving demand, until the replay either refreshes it or
	 * the grace period expires.  See pim_dimt_umh_resync_begin(). */
	bool stale;
};

/*
 * One explicitly configured tunnel endpoint for a UMH (contract D2).
 *
 * D2 refuses the Phase-A `10.99.X.Y <-> 100.64.X.Y` derivation outright: it is
 * not injective, the v2/v3 shells disagree on `x.x.0.0` inputs, it cannot
 * express an IPv6 outer, and it couples the settlement identity (the UMH) to
 * subnet arithmetic.  So every field below is stated, never computed, and a
 * UMH with no row simply gets no tunnel -- there is deliberately no default,
 * no wildcard and no fallback mapping.
 *
 * The inner peer is not stored: it *is* the UMH, which is the list key.
 */
struct pim_dimt_endpoint {
	pim_addr umh; /* key; also the inner peer address */
	struct ipaddr inner_local;
	struct ipaddr outer_local;
	struct ipaddr outer_remote;
	uint8_t encap; /* enum zapi_dimt_tunnel_encap */
	uint16_t dport;
	uint32_t key;
	uint32_t mtu;
	bool key_set;
	bool mtu_set;
};

/*
 * Tunnel request/ack state (contract D3).  Every transition is edge-triggered
 * by a zapi notify, a routing event or an interface event; the tunnel state
 * machine has no timer, no poll and no hold-down anywhere in it.
 *
 * (The one timer DIMT owns is not in here: it bounds how long a zebra
 * reconnect waits for bgpd's UMH re-dump before declaring the unreplayed
 * mappings gone.  It gates *mapping* expiry, never a tunnel transition, so
 * no state below is entered or left on a clock.)
 */
enum pim_dimt_tunnel_state {
	/* no request outstanding and nothing installed */
	PIM_DIMT_TUNNEL_IDLE = 0,
	/* ZEBRA_DIMT_TUNNEL_ADD sent, awaiting NOTIFY_OWNER */
	PIM_DIMT_TUNNEL_REQUESTED,
	/* NOTIFY_OWNER carried INSTALLED: positive netlink ack */
	PIM_DIMT_TUNNEL_INSTALLED,
	/* NOTIFY_OWNER carried FAIL_INSTALL */
	PIM_DIMT_TUNNEL_FAILED,
	/* ZEBRA_DIMT_TUNNEL_DEL sent, awaiting NOTIFY_OWNER */
	PIM_DIMT_TUNNEL_REMOVING,
};

/* One native DIMT tunnel toward a UMH.  Demand is per-UMH, not per-(S,G):
 * several upstreams may ride the same tunnel, so `refcount` gates the
 * ADD/DEL edges. */
struct pim_dimt_tunnel {
	pim_addr umh; /* key */
	uint32_t tunnel_id;
	/* exact request last sent; zebra treats a byte-identical re-ADD as
	 * idempotent (memcmp), which is what makes reconnect replay safe */
	struct zapi_dimt_tunnel req;
	enum pim_dimt_tunnel_state state;
	ifindex_t ifindex;	 /* learned from the notify, 0 until then */
	char ifname[IFNAMSIZ];	 /* dimt-%08x, re-derived from tunnel_id */
	uint32_t refcount;	 /* upstreams demanding this tunnel */
	bool readd_pending;	 /* demand returned while REMOVING */
	/*
	 * A netdev for this tunnel may exist in the kernel right now.
	 *
	 * State alone cannot answer that after a zebra reconnect.  IDLE means
	 * two different things: "never requested, nothing exists" (free the
	 * record and no netdev is stranded) and "acknowledgement state was
	 * dropped because the session that owned it died, but the netdev
	 * deliberately outlives a zebra restart".  Freeing the record in the
	 * second case leaks the netdev with nothing left that knows its name.
	 * So teardown consults this rather than state: set it and a DEL goes
	 * out, clear it and the record is simply forgotten.
	 */
	bool kernel_present;
};

void pim_dimt_init(struct pim_instance *pim);
void pim_dimt_terminate(struct pim_instance *pim);

/* ZEBRA_UMH_ADD / ZEBRA_UMH_DEL from bgpd (via zebra). */
void pim_dimt_umh_update(struct pim_instance *pim,
			 const struct zapi_umh *zumh, bool add);

/*
 * Begin a mapping resync: hold every mapping, marked stale, while bgpd is
 * asked to re-dump.  Used when (re-)subscribing to the relay.
 *
 * The obvious thing -- drop every mapping and let the replay repopulate --
 * is wrong, because the emptied table is briefly indistinguishable from
 * "nobody wants anything".  Demand is recounted from that empty table, every
 * tunnel falls to zero refcount, and a control-socket bounce alone would
 * tear down a data plane that was never in question.  Holding the mappings
 * keeps demand truthful across the gap, so the tunnels are re-ADDed
 * byte-identically and zebra re-adopts the surviving netdevs.
 *
 * Expiry cannot be event-driven: the replay has no end marker, and bgpd
 * sends nothing at all when it has nothing (including when it is not
 * running), so "no message" is not evidence either way.  A bounded grace
 * period is the only available answer -- mappings the replay does not
 * refresh within it are declared gone and swept, which is what stops a dead
 * bgpd's mappings from living forever.
 */
void pim_dimt_umh_resync_begin(struct pim_instance *pim);

/* Steer a (possibly new) upstream's RPF onto the light interface facing its
 * source's UMH; no-op when no mapping covers the source. */
void pim_dimt_upstream_apply(struct pim_instance *pim,
			     struct pim_upstream *up);

/* Unpin every upstream pinned to a light interface that went down/away
 * (STATIC_IIF suppresses the normal rpf-update repair paths). */
void pim_dimt_iface_down(struct pim_instance *pim, struct interface *ifp);

/* Re-run pin resolution when a light interface becomes usable (up,
 * addressed, or light-enabled after the mapping arrived). */
void pim_dimt_iface_up(struct pim_instance *pim, struct interface *ifp);

void pim_dimt_show_umh(struct pim_instance *pim, struct vty *vty, bool json);
void pim_dimt_show_tunnel(struct pim_instance *pim, struct vty *vty, bool json);

/* Per-(S,G) readiness aggregation.  The verdict is otherwise unobservable:
 * pim_dimt_forwarding_state() only ever leaves pimd as a zapi re-ADD toward
 * bgpd, gated on `mvpn-gtm` plus gtm-announced, so D6's readiness boundary
 * has nothing to assert against without this. */
void pim_dimt_show_forwarding(struct pim_instance *pim, struct vty *vty,
			      bool json);

/* --- explicit endpoint configuration (D2) --- */

/* Install/replace the row for `umh`.  Returns false only on a malformed row
 * (mismatched families, gre-in-fou without a dport). */
bool pim_dimt_endpoint_set(struct pim_instance *pim,
			   const struct pim_dimt_endpoint *ep);
void pim_dimt_endpoint_unset(struct pim_instance *pim, pim_addr umh);
int pim_dimt_endpoint_config_write(struct pim_instance *pim, struct vty *vty);

/* --- tunnel request/ack state machine (D3) --- */

/* ZEBRA_DIMT_TUNNEL_NOTIFY_OWNER from zebra: the only ack that counts. */
void pim_dimt_tunnel_notify(struct pim_instance *pim,
			    const struct zapi_dimt_tunnel_notify *notify);

/* Recompute tunnel demand and readiness across every upstream.  Called on a
 * UMH change, an interface event, and on zebra reconnect. */
void pim_dimt_reconcile(struct pim_instance *pim);

/* Drop acknowledgement state for every tunnel without sending anything --
 * the zebra session that owned those requests is gone, so nothing can be
 * acked over it.  Tunnel identity (id + request bytes) is deliberately kept
 * so the reconnect re-ADD is byte-identical and re-adopts the surviving
 * netdev; kernel netdevs survive on purpose and zebra MUST NOT sweep them. */
void pim_dimt_tunnel_session_reset(struct pim_instance *pim);

/* True once zebra has positively acked the netdev backing this upstream's
 * UMH.  Readiness proper additionally requires the kernel MFC check. */
enum zapi_mvpn_sg_forwarding
pim_dimt_forwarding_state(struct pim_instance *pim, struct pim_upstream *up);

/* Re-evaluate readiness for every upstream and relay any edge to bgpd.
 * Cheap and idempotent: only a changed state produces a message. */
void pim_dimt_readiness_update(struct pim_instance *pim);

/* An interface pimd asked zebra to create just appeared (or got its inner
 * address): adopt it as a PIM Light interface so it can carry the pin and
 * become a vif.  No-op for interfaces we did not request. */
void pim_dimt_ifp_adopt(struct pim_instance *pim, struct interface *ifp);

#endif /* PIM_DIMT_H */
