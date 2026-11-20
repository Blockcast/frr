// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DIMT `protect ipsec`: the XFRM policy model.  See pim_dimt_xfrm.h.
 *
 * What the kernel does, and therefore what this has to mirror:
 *
 * - Plain GRE is checked against the inbound policy before gre_rcv() runs:
 *   ip_protocol_deliver_rcu() calls xfrm4_policy_check() for every protocol
 *   without no_policy, and GRE does not set it (ip6_input.c does the same
 *   for IPv6).  A gre-in-fou packet is checked earlier, on the FOU UDP
 *   socket in udp_queue_rcv_one_skb(), before the encap hook decapsulates
 *   it -- so for FOU the selector has to cover UDP, not GRE.
 *
 * - The check picks the matching policy with the lowest priority value and
 *   rejects a packet without a secpath when that policy carries a template
 *   that is not optional (`level required`).  An optional template
 *   (`level use`), or no template, lets cleartext through.
 *
 * - The GRE key aliases into the flow's port fields (xfrm_flowi_sport() and
 *   xfrm_flowi_dport() in include/net/xfrm.h), and the sender picks it.
 *
 * Every judgement below fails closed: a policy that might match only part of
 * the flow never counts as covering it, and a cleartext policy that might
 * match any part of it counts as a bypass.
 */

#include <zebra.h>

#include "pimd/pim_dimt_xfrm.h"

static const char *const pim_dimt_xfrm_verdict_str[] = {
	[PIM_DIMT_XFRM_PROTECTED] = "protected",
	[PIM_DIMT_XFRM_NO_POLICY] = "no-policy",
	[PIM_DIMT_XFRM_BYPASSED] = "bypassed",
	[PIM_DIMT_XFRM_UNKNOWN] = "unknown",
};

const char *pim_dimt_xfrm_verdict_name(enum pim_dimt_xfrm_verdict verdict)
{
	if ((unsigned int)verdict >= array_size(pim_dimt_xfrm_verdict_str))
		return "unknown";
	return pim_dimt_xfrm_verdict_str[verdict];
}

#ifdef __linux__

#include <linux/rtnetlink.h>

bool pim_dimt_xfrm_parse(const struct nlmsghdr *nlh, struct pim_dimt_xfrm_pol *pol)
{
	const struct xfrm_userpolicy_info *info;
	const struct rtattr *rta;
	int len;

	if (nlh->nlmsg_type != XFRM_MSG_NEWPOLICY || nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*info)))
		return false;

	info = NLMSG_DATA(nlh);
	memset(pol, 0, sizeof(*pol));
	pol->sel = info->sel;
	pol->priority = info->priority;
	pol->dir = info->dir;
	pol->action = info->action;
	pol->narrowed = info->sel.ifindex != 0;

	len = (int)nlh->nlmsg_len - (int)NLMSG_SPACE(sizeof(*info));
	rta = (const struct rtattr *)((const char *)info + NLMSG_ALIGN(sizeof(*info)));
	for (; len > 0 && RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		size_t plen = RTA_PAYLOAD(rta);

		switch (rta->rta_type) {
		case XFRMA_TMPL: {
			const struct xfrm_user_tmpl *t = RTA_DATA(rta);
			size_t i;

			for (i = 0; i < plen / sizeof(*t); i++)
				if (t[i].id.proto == IPPROTO_ESP && !t[i].optional)
					pol->esp_required = true;
			break;
		}
		case XFRMA_POLICY_TYPE: {
			const struct xfrm_userpolicy_type *pt = RTA_DATA(rta);

			if (plen < sizeof(*pt))
				return false;
			pol->sub_type = pt->type != XFRM_POLICY_TYPE_MAIN;
			break;
		}
		case XFRMA_MARK: {
			const struct xfrm_mark *m = RTA_DATA(rta);

			if (plen < sizeof(*m))
				return false;
			if (m->m)
				pol->narrowed = true;
			break;
		}
		case XFRMA_SEC_CTX:
			pol->narrowed = true;
			break;
		case XFRMA_IF_ID:
			if (plen < sizeof(uint32_t))
				return false;
			if (*(const uint32_t *)RTA_DATA(rta))
				pol->if_id = true;
			break;
		}
	}

	return true;
}

void pim_dimt_xfrm_flow_init(struct pim_dimt_xfrm_flow *flow, uint8_t dir,
			     const struct ipaddr *local, const struct ipaddr *remote,
			     uint16_t fou_dport)
{
	const struct ipaddr *src = dir == XFRM_POLICY_IN ? remote : local;
	const struct ipaddr *dst = dir == XFRM_POLICY_IN ? local : remote;

	memset(flow, 0, sizeof(*flow));
	if (IS_IPADDR_V6(src)) {
		flow->family = AF_INET6;
		memcpy(&flow->saddr.in6, &src->ipaddr_v6, sizeof(struct in6_addr));
		memcpy(&flow->daddr.in6, &dst->ipaddr_v6, sizeof(struct in6_addr));
	} else {
		flow->family = AF_INET;
		flow->saddr.a4 = src->ipaddr_v4.s_addr;
		flow->daddr.a4 = dst->ipaddr_v4.s_addr;
	}
	/* shortcut: assumes the local FOU listener uses the same port as the
	 * remote one, which FRR does not configure; take a separate local
	 * port on the endpoint row if a deployment ever splits them. */
	flow->proto = fou_dport ? IPPROTO_UDP : IPPROTO_GRE;
	flow->dport = htons(fou_dport);
}

/* Is `addr` inside `net`/`plen`?  Both in network order. */
static bool pim_dimt_xfrm_addr_in(const xfrm_address_t *addr, const xfrm_address_t *net,
				  uint8_t plen, uint8_t family)
{
	const uint8_t *a = (const uint8_t *)addr;
	const uint8_t *n = (const uint8_t *)net;
	unsigned int bytes = plen / 8, bits = plen % 8;

	if (plen > (family == AF_INET ? 32 : 128))
		return false;
	if (memcmp(a, n, bytes))
		return false;
	return !bits || !((a[bytes] ^ n[bytes]) & (0xff << (8 - bits)));
}

/* Could this policy match at least one packet of the flow? */
static bool pim_dimt_xfrm_meets(const struct pim_dimt_xfrm_pol *pol,
				const struct pim_dimt_xfrm_flow *flow)
{
	const struct xfrm_selector *sel = &pol->sel;

	/* A cleartext packet arrives with if_id 0 and the kernel compares
	 * if_id exactly, so an xfrm-interface policy never sees it. */
	if (pol->if_id || sel->family != flow->family)
		return false;
	if (!pim_dimt_xfrm_addr_in(&flow->saddr, &sel->saddr, sel->prefixlen_s, flow->family) ||
	    !pim_dimt_xfrm_addr_in(&flow->daddr, &sel->daddr, sel->prefixlen_d, flow->family))
		return false;
	if (sel->proto && sel->proto != flow->proto)
		return false;
	/* The UDP source port and the GRE key are the sender's choice, so
	 * only the FOU destination port narrows the flow. */
	if (flow->proto == IPPROTO_UDP && ((flow->dport ^ sel->dport) & sel->dport_mask))
		return false;
	return true;
}

/* Does this policy match every packet of the flow? */
static bool pim_dimt_xfrm_covers(const struct pim_dimt_xfrm_pol *pol,
				 const struct pim_dimt_xfrm_flow *flow)
{
	if (pol->narrowed || !pim_dimt_xfrm_meets(pol, flow))
		return false;
	if (pol->sel.sport_mask)
		return false;
	return flow->proto == IPPROTO_UDP || !pol->sel.dport_mask;
}

enum pim_dimt_xfrm_verdict pim_dimt_xfrm_check(const struct pim_dimt_xfrm_pol *pols, size_t npols,
					       uint8_t dir, const struct pim_dimt_xfrm_flow *flow)
{
	const struct pim_dimt_xfrm_pol *best = NULL;
	size_t i;

	for (i = 0; i < npols; i++) {
		const struct pim_dimt_xfrm_pol *pol = &pols[i];

		if (pol->dir != dir || pol->sub_type || pol->action != XFRM_POLICY_ALLOW ||
		    !pol->esp_required || !pim_dimt_xfrm_covers(pol, flow))
			continue;
		if (!best || pol->priority < best->priority)
			best = pol;
	}
	if (!best)
		return PIM_DIMT_XFRM_NO_POLICY;

	for (i = 0; i < npols; i++) {
		const struct pim_dimt_xfrm_pol *pol = &pols[i];

		if (pol->dir != dir || !pim_dimt_xfrm_meets(pol, flow))
			continue;
		/* Sub policies combine with main ones in ways this does not
		 * model; refuse rather than guess. */
		if (pol->sub_type)
			return PIM_DIMT_XFRM_BYPASSED;
		/* Equal priority counts against: the kernel's tie-break is
		 * insertion order, which a dump does not reliably show. */
		if (pol->action == XFRM_POLICY_ALLOW && !pol->esp_required &&
		    pol->priority <= best->priority)
			return PIM_DIMT_XFRM_BYPASSED;
	}

	return PIM_DIMT_XFRM_PROTECTED;
}

#endif /* __linux__ */
