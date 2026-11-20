// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DIMT `protect ipsec`: does the kernel's XFRM policy database force ESP on
 * a tunnel's outer flow?
 *
 * Pure policy model: parse XFRM_MSG_NEWPOLICY dump records and judge one
 * direction of a tunnel's outer flow against them.  No pimd state, so it is
 * unit-testable on its own; the netlink sockets that feed it live in
 * pim_dimt.c.
 */

#ifndef PIM_DIMT_XFRM_H
#define PIM_DIMT_XFRM_H

#include <zebra.h>

enum pim_dimt_xfrm_verdict {
	/* every packet of the flow meets a policy that requires ESP */
	PIM_DIMT_XFRM_PROTECTED = 0,
	/* no single policy covers the whole flow with ESP at level required */
	PIM_DIMT_XFRM_NO_POLICY,
	/* covered, but a policy of equal or higher precedence lets part of
	 * the flow through without ESP */
	PIM_DIMT_XFRM_BYPASSED,
	/* no clean policy dump to judge against (always, off Linux) */
	PIM_DIMT_XFRM_UNKNOWN,
};

const char *pim_dimt_xfrm_verdict_name(enum pim_dimt_xfrm_verdict verdict);

#ifdef __linux__

#include <linux/netlink.h>
#include <linux/xfrm.h>

#include "ipaddr.h"

/* One kernel policy, reduced to what the verdict reads. */
struct pim_dimt_xfrm_pol {
	struct xfrm_selector sel;
	uint32_t priority; /* lower value wins */
	uint8_t dir;	   /* XFRM_POLICY_IN / _OUT / _FWD */
	uint8_t action;	   /* XFRM_POLICY_ALLOW / _BLOCK */
	bool sub_type;	   /* XFRM_POLICY_TYPE_SUB: not modelled */
	bool esp_required; /* an ESP template with level required */
	bool if_id;	   /* XFRMA_IF_ID set: matches xfrm-interface traffic only */
	/* Matches only a subset of packets this module cannot see: a mark,
	 * a security context, or a selector ifindex. */
	bool narrowed;
};

/* One direction of a DIMT tunnel's outer flow. */
struct pim_dimt_xfrm_flow {
	uint8_t family;
	xfrm_address_t saddr;
	xfrm_address_t daddr;
	uint8_t proto;	/* IPPROTO_GRE, or IPPROTO_UDP for gre-in-fou */
	uint16_t dport; /* network order; gre-in-fou only */
};

/* Parse one XFRM_MSG_NEWPOLICY record.  False for anything else, including
 * a truncated record, which the caller must treat as a failed dump. */
bool pim_dimt_xfrm_parse(const struct nlmsghdr *nlh, struct pim_dimt_xfrm_pol *pol);

/* The outer flow of a tunnel from `local` to `remote` as seen in direction
 * `dir`: XFRM_POLICY_IN is remote -> local, XFRM_POLICY_OUT local -> remote.
 * `fou_dport` is the gre-in-fou UDP port (host order), 0 for plain GRE. */
void pim_dimt_xfrm_flow_init(struct pim_dimt_xfrm_flow *flow, uint8_t dir,
			     const struct ipaddr *local, const struct ipaddr *remote,
			     uint16_t fou_dport);

enum pim_dimt_xfrm_verdict pim_dimt_xfrm_check(const struct pim_dimt_xfrm_pol *pols, size_t npols,
					       uint8_t dir, const struct pim_dimt_xfrm_flow *flow);

#endif /* __linux__ */

#endif /* PIM_DIMT_XFRM_H */
