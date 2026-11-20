// SPDX-License-Identifier: GPL-2.0-or-later
/* DIMT `protect ipsec`: the XFRM policy model.
 *
 * Drives pim_dimt_xfrm_parse() with hand-built XFRM_MSG_NEWPOLICY records
 * and pim_dimt_xfrm_check() with policy sets shaped after the ways a
 * tunnel's outer flow can be left open: no policy, a template at level use,
 * a higher-precedence cleartext policy, a policy that only matches part of
 * the flow, and so on.  Output is compared against the .refout.
 */

#include <zebra.h>

#include <linux/rtnetlink.h>

#include "pimd/pim_dimt_xfrm.h"

static int failures;

static void expect(const char *name, bool ok)
{
	printf("%s: %s\n", name, ok ? "OK" : "FAIL");
	if (!ok)
		failures++;
}

static void verdict(const char *name, enum pim_dimt_xfrm_verdict got,
		    enum pim_dimt_xfrm_verdict want)
{
	printf("%s: %s%s\n", name, pim_dimt_xfrm_verdict_name(got), got == want ? "" : " (FAIL)");
	if (got != want)
		failures++;
}

static struct ipaddr ip(const char *s)
{
	struct ipaddr a = {};

	if (strchr(s, ':')) {
		a.ipa_type = IPADDR_V6;
		inet_pton(AF_INET6, s, &a.ipaddr_v6);
	} else {
		a.ipa_type = IPADDR_V4;
		inet_pton(AF_INET, s, &a.ipaddr_v4);
	}
	return a;
}

/* A MAIN-type ALLOW policy; tests adjust the fields they care about. */
static struct pim_dimt_xfrm_pol pol(uint8_t dir, const char *src, uint8_t slen, const char *dst,
				    uint8_t dlen, uint8_t proto, uint32_t prio, bool esp_required)
{
	struct pim_dimt_xfrm_pol p = {};
	int af = strchr(src, ':') ? AF_INET6 : AF_INET;

	p.sel.family = af;
	inet_pton(af, src, &p.sel.saddr);
	inet_pton(af, dst, &p.sel.daddr);
	p.sel.prefixlen_s = slen;
	p.sel.prefixlen_d = dlen;
	p.sel.proto = proto;
	p.priority = prio;
	p.dir = dir;
	p.action = XFRM_POLICY_ALLOW;
	p.esp_required = esp_required;
	return p;
}

#define LOCAL4	"192.0.2.2"
#define REMOTE4 "192.0.2.1"
#define LOCAL6	"2001:db8::2"
#define REMOTE6 "2001:db8::1"
#define FOU	5555

static enum pim_dimt_xfrm_verdict check(const struct pim_dimt_xfrm_pol *p, size_t n, uint8_t dir,
					bool v6, uint16_t fou)
{
	struct pim_dimt_xfrm_flow flow;
	struct ipaddr local = ip(v6 ? LOCAL6 : LOCAL4);
	struct ipaddr remote = ip(v6 ? REMOTE6 : REMOTE4);

	pim_dimt_xfrm_flow_init(&flow, dir, &local, &remote, fou);
	return pim_dimt_xfrm_check(p, n, dir, &flow);
}

#define IN  XFRM_POLICY_IN
#define OUT XFRM_POLICY_OUT

static void test_check(void)
{
	struct pim_dimt_xfrm_pol p[4];

	verdict("no policies", check(NULL, 0, IN, false, 0), PIM_DIMT_XFRM_NO_POLICY);

	/* The pair the docs show: host-to-host GRE, ESP required. */
	p[0] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_GRE, 100, true);
	p[1] = pol(OUT, LOCAL4, 32, REMOTE4, 32, IPPROTO_GRE, 100, true);
	verdict("gre in", check(p, 2, IN, false, 0), PIM_DIMT_XFRM_PROTECTED);
	verdict("gre out", check(p, 2, OUT, false, 0), PIM_DIMT_XFRM_PROTECTED);
	verdict("gre out missing", check(p, 1, OUT, false, 0), PIM_DIMT_XFRM_NO_POLICY);
	verdict("gre in, policy for another peer", check(&p[1], 1, IN, false, 0),
		PIM_DIMT_XFRM_NO_POLICY);

	p[0].dir = XFRM_POLICY_FWD;
	verdict("fwd policy does not count", check(p, 1, IN, false, 0), PIM_DIMT_XFRM_NO_POLICY);

	p[0] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_GRE, 100, false);
	verdict("level use", check(p, 1, IN, false, 0), PIM_DIMT_XFRM_NO_POLICY);

	p[0] = pol(IN, "192.0.2.0", 24, "192.0.2.0", 24, 0, 100, true);
	verdict("covering /24 any proto", check(p, 1, IN, false, 0), PIM_DIMT_XFRM_PROTECTED);
	p[0] = pol(IN, "192.0.2.4", 31, LOCAL4, 32, 0, 100, true);
	verdict("/31 that misses the remote", check(p, 1, IN, false, 0), PIM_DIMT_XFRM_NO_POLICY);
	p[0] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_UDP, 100, true);
	verdict("udp policy on a gre flow", check(p, 1, IN, false, 0), PIM_DIMT_XFRM_NO_POLICY);

	/* Precedence: lower priority value wins, ties count against. */
	p[0] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_GRE, 100, true);
	p[1] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_GRE, 50, false);
	verdict("higher-precedence clear policy", check(p, 2, IN, false, 0),
		PIM_DIMT_XFRM_BYPASSED);
	p[1].priority = 100;
	verdict("equal-priority clear policy", check(p, 2, IN, false, 0), PIM_DIMT_XFRM_BYPASSED);
	p[1].priority = 200;
	verdict("lower-precedence clear policy", check(p, 2, IN, false, 0),
		PIM_DIMT_XFRM_PROTECTED);
	p[1] = pol(IN, REMOTE4, 32, "192.0.2.0", 24, 0, 50, false);
	verdict("wider clear policy above", check(p, 2, IN, false, 0), PIM_DIMT_XFRM_BYPASSED);
	p[1] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_GRE, 50, false);
	p[1].sel.dport = htons(7);
	p[1].sel.dport_mask = 0xffff;
	verdict("key-specific clear policy above", check(p, 2, IN, false, 0),
		PIM_DIMT_XFRM_BYPASSED);
	p[1] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_GRE, 50, false);
	p[1].action = XFRM_POLICY_BLOCK;
	verdict("block policy above", check(p, 2, IN, false, 0), PIM_DIMT_XFRM_PROTECTED);
	p[1] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_GRE, 50, false);
	p[1].if_id = true;
	verdict("xfrm-interface clear policy above", check(p, 2, IN, false, 0),
		PIM_DIMT_XFRM_PROTECTED);
	p[1].if_id = false;
	p[1].narrowed = true;
	verdict("marked clear policy above", check(p, 2, IN, false, 0), PIM_DIMT_XFRM_BYPASSED);
	p[1] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_GRE, 200, true);
	p[1].sub_type = true;
	verdict("sub policy", check(p, 2, IN, false, 0), PIM_DIMT_XFRM_BYPASSED);

	/* A protector that matches only part of the flow does not cover it. */
	p[0] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_GRE, 100, true);
	p[0].if_id = true;
	verdict("xfrm-interface protector", check(p, 1, IN, false, 0), PIM_DIMT_XFRM_NO_POLICY);
	p[0].if_id = false;
	p[0].narrowed = true;
	verdict("marked protector", check(p, 1, IN, false, 0), PIM_DIMT_XFRM_NO_POLICY);
	p[0].narrowed = false;
	p[0].sel.dport = htons(7);
	p[0].sel.dport_mask = 0xffff;
	verdict("key-specific protector", check(p, 1, IN, false, 0), PIM_DIMT_XFRM_NO_POLICY);

	/* gre-in-fou: the check runs on UDP, at the FOU port. */
	p[0] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_UDP, 100, true);
	p[0].sel.dport = htons(FOU);
	p[0].sel.dport_mask = 0xffff;
	verdict("fou in", check(p, 1, IN, false, FOU), PIM_DIMT_XFRM_PROTECTED);
	p[0].sel.dport = htons(FOU + 1);
	verdict("fou other port", check(p, 1, IN, false, FOU), PIM_DIMT_XFRM_NO_POLICY);
	p[0].sel.dport_mask = 0;
	verdict("fou any port", check(p, 1, IN, false, FOU), PIM_DIMT_XFRM_PROTECTED);
	p[0].sel.sport = htons(1000);
	p[0].sel.sport_mask = 0xffff;
	verdict("fou fixed source port", check(p, 1, IN, false, FOU), PIM_DIMT_XFRM_NO_POLICY);
	p[0] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_GRE, 100, true);
	verdict("gre policy on a fou flow", check(p, 1, IN, false, FOU), PIM_DIMT_XFRM_NO_POLICY);
	p[0] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_UDP, 100, true);
	p[1] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_UDP, 50, false);
	p[1].sel.dport = htons(FOU + 1);
	p[1].sel.dport_mask = 0xffff;
	verdict("clear policy on another udp port", check(p, 2, IN, false, FOU),
		PIM_DIMT_XFRM_PROTECTED);

	/* IPv6 outer. */
	p[0] = pol(IN, REMOTE6, 128, LOCAL6, 128, IPPROTO_GRE, 100, true);
	verdict("v6 gre in", check(p, 1, IN, true, 0), PIM_DIMT_XFRM_PROTECTED);
	p[0] = pol(IN, "2001:db8::", 64, "2001:db8::", 64, 0, 100, true);
	verdict("v6 covering /64", check(p, 1, IN, true, 0), PIM_DIMT_XFRM_PROTECTED);
	p[0] = pol(IN, "2001:db8:1::", 64, LOCAL6, 128, 0, 100, true);
	verdict("v6 /64 that misses the remote", check(p, 1, IN, true, 0), PIM_DIMT_XFRM_NO_POLICY);
	p[0] = pol(IN, REMOTE4, 32, LOCAL4, 32, IPPROTO_GRE, 100, true);
	verdict("v4 policy on a v6 flow", check(p, 1, IN, true, 0), PIM_DIMT_XFRM_NO_POLICY);
}

/* ---- parser ---- */

static uint8_t msgbuf[1024] __attribute__((aligned(8)));

static struct nlmsghdr *msg_new(uint16_t type, uint8_t dir)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)msgbuf;
	struct xfrm_userpolicy_info *info;

	memset(msgbuf, 0, sizeof(msgbuf));
	nlh->nlmsg_type = type;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*info));
	info = NLMSG_DATA(nlh);
	info->sel.family = AF_INET;
	inet_pton(AF_INET, REMOTE4, &info->sel.saddr);
	inet_pton(AF_INET, LOCAL4, &info->sel.daddr);
	info->sel.prefixlen_s = info->sel.prefixlen_d = 32;
	info->sel.proto = IPPROTO_GRE;
	info->priority = 100;
	info->dir = dir;
	info->action = XFRM_POLICY_ALLOW;
	return nlh;
}

static void msg_attr(struct nlmsghdr *nlh, uint16_t type, const void *data, size_t len)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static void msg_tmpl(struct nlmsghdr *nlh, uint8_t proto1, bool optional1, uint8_t proto2,
		     bool optional2)
{
	struct xfrm_user_tmpl t[2] = {};

	t[0].id.proto = proto1;
	t[0].optional = optional1;
	t[1].id.proto = proto2;
	t[1].optional = optional2;
	msg_attr(nlh, XFRMA_TMPL, t, proto2 ? sizeof(t) : sizeof(t[0]));
}

static void test_parse(void)
{
	struct pim_dimt_xfrm_pol p = {};
	struct nlmsghdr *nlh;
	struct xfrm_mark mark = {};
	struct xfrm_userpolicy_type ptype = {};
	uint32_t if_id = 5;
	uint8_t ctx[sizeof(struct xfrm_user_sec_ctx) + 4] = {};

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	msg_tmpl(nlh, IPPROTO_ESP, false, 0, false);
	expect("parse esp required", pim_dimt_xfrm_parse(nlh, &p) && p.esp_required &&
					     !p.narrowed && !p.if_id && !p.sub_type &&
					     p.priority == 100 && p.dir == IN);
	verdict("parsed policy protects", check(&p, 1, IN, false, 0), PIM_DIMT_XFRM_PROTECTED);

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	msg_tmpl(nlh, IPPROTO_ESP, true, 0, false);
	expect("parse esp level use", pim_dimt_xfrm_parse(nlh, &p) && !p.esp_required);

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	msg_tmpl(nlh, IPPROTO_COMP, false, IPPROTO_ESP, true);
	expect("parse ipcomp required, esp level use",
	       pim_dimt_xfrm_parse(nlh, &p) && !p.esp_required);

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	msg_tmpl(nlh, IPPROTO_COMP, true, IPPROTO_ESP, false);
	expect("parse esp required second", pim_dimt_xfrm_parse(nlh, &p) && p.esp_required);

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	expect("parse no template", pim_dimt_xfrm_parse(nlh, &p) && !p.esp_required);

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	msg_attr(nlh, XFRMA_MARK, &mark, sizeof(mark));
	expect("parse zero mark", pim_dimt_xfrm_parse(nlh, &p) && !p.narrowed);
	mark.v = 1;
	mark.m = 0xff;
	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	msg_attr(nlh, XFRMA_MARK, &mark, sizeof(mark));
	expect("parse mark", pim_dimt_xfrm_parse(nlh, &p) && p.narrowed);

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	msg_attr(nlh, XFRMA_IF_ID, &if_id, sizeof(if_id));
	expect("parse if_id", pim_dimt_xfrm_parse(nlh, &p) && p.if_id);

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	msg_attr(nlh, XFRMA_SEC_CTX, ctx, sizeof(ctx));
	expect("parse security context", pim_dimt_xfrm_parse(nlh, &p) && p.narrowed);

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	((struct xfrm_userpolicy_info *)NLMSG_DATA(nlh))->sel.ifindex = 3;
	expect("parse selector ifindex", pim_dimt_xfrm_parse(nlh, &p) && p.narrowed);

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	ptype.type = XFRM_POLICY_TYPE_SUB;
	msg_attr(nlh, XFRMA_POLICY_TYPE, &ptype, sizeof(ptype));
	expect("parse sub type", pim_dimt_xfrm_parse(nlh, &p) && p.sub_type);

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	msg_attr(nlh, XFRMA_MARK, &mark, 2);
	expect("parse short mark refused", !pim_dimt_xfrm_parse(nlh, &p));

	nlh = msg_new(XFRM_MSG_NEWPOLICY, IN);
	nlh->nlmsg_len = NLMSG_LENGTH(4);
	expect("parse truncated refused", !pim_dimt_xfrm_parse(nlh, &p));

	nlh = msg_new(XFRM_MSG_DELPOLICY, IN);
	expect("parse other type refused", !pim_dimt_xfrm_parse(nlh, &p));
}

int main(int argc, char **argv)
{
	test_check();
	test_parse();
	printf("failures: %d\n", failures);
	return failures ? 1 : 0;
}
