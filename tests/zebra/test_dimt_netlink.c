// SPDX-License-Identifier: GPL-2.0-or-later
/* DIMT delete skip path and mixed-batch drain against a fake kernel.
 * Copyright (C) 2026 Blockcast
 *
 * BLO-38026: deterministic coverage for two paths the zebra_dimt_tunnel
 * topotest cannot pin down, because no dplane hold can order a link
 * notification against a queued delete.
 *
 * - The identity skip in netlink_put_dimt_tunnel_msg(): a DIMT delete
 *   whose link is gone, renamed or rebuilt with other endpoints is
 *   answered SUCCESS without a message, and that verdict is synthetic,
 *   so it must not be marked authoritative.
 * - kernel_update_multi() keeping such a context out of the batch's ack
 *   bookkeeping. Left in the list, the end-of-responses drain (or a read
 *   failure) rewrote its verdict to FAILURE from unrelated traffic.
 *
 * zebra/kernel_netlink.c is #included with its three socket calls
 * replaced by an in-memory kernel that ACKs (or fails) every request in
 * order. Every other zebra object is linked as built, so the encoder,
 * the identity matcher and the dplane context are the production ones.
 * Output is stdout only and compared against the .refout; zlog noise
 * from the error paths goes to stderr.
 */

#include <zebra.h>
#include <fcntl.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/filter.h>

/* Everything kernel_netlink.c includes, pulled in first so that the
 * include guards make its own copies no-ops and the fake-call macros
 * below cannot rewrite a declaration in a system header.
 */
#include "linklist.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "zebra/connected.h"
#include "table.h"
#include "memory.h"
#include "zebra/rib.h"
#include "frrevent.h"
#include "privs.h"
#include "nexthop.h"
#include "vrf.h"
#include "mpls.h"
#include "lib_errors.h"
#include "hash.h"
#include "lib/netlink_parser.h"

#include "zebra/zebra_router.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/debug.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "zebra/if_netlink.h"
#include "zebra/rule_netlink.h"
#include "zebra/tc_netlink.h"
#include "zebra/netconf_netlink.h"
#include "zebra/netlink_seq.h"
#include "zebra/zebra_errors.h"
#include "zebra/ge_netlink.h"
#include "zebra/zebra_trace.h"
#include "zebra/zebra_dplane.h"
#include "zebra/interface.h"

static ssize_t fake_sendmsg(int sock, const struct msghdr *msg, int flags);
static ssize_t fake_recv(int sock, void *buf, size_t len, int flags);
static ssize_t fake_recvmsg(int sock, struct msghdr *msg, int flags);

/* Function-like, so only a call is replaced, never a bare token. */
#define sendmsg(s, m, f) fake_sendmsg(s, m, f)
#define recv(s, b, l, f) fake_recv(s, b, l, f)
#define recvmsg(s, m, f) fake_recvmsg(s, m, f)
#include "zebra/kernel_netlink.c"
#undef sendmsg
#undef recv
#undef recvmsg

/*
 * main.o is not linked: these are the symbols other zebra objects take
 * from it. A NULL-privs zserv_privs gets zprivs_change_null from
 * zprivs_preinit(), so frr_with_privs() in netlink_send_msg() is a no-op.
 */
struct zebra_privs_t zserv_privs;
uint32_t rcvbufsize = 128 * 1024;
uint32_t rt_table_main_id = RT_TABLE_MAIN;

void zebra_finalize(struct event *event)
{
	abort();
}

void zebra_main_router_started(void)
{
}

#define TEST_NSID 7
#define TEST_SOCK 4242
#define TEST_KEY 0x1f
#define TEST_LOCAL 0xc0000201	/* 192.0.2.1 */
#define TEST_REMOTE 0xc6336401	/* 198.51.100.1 */
#define TEST_OTHER 0xc6336402	/* 198.51.100.2 */
#define IF_REAL 501
#define IF_GONE 509
#define IF_LATE 502
#define NAME_REAL "dimt-000001f5"
#define NAME_GONE "dimt-000001fd"
#define NAME_LATE "dimt-000001f6"
#define FAKE_MAX 16

/* The fake kernel. */
struct wire_msg {
	uint16_t type;
	int ifindex;
	uint32_t seq;
};

struct fake_reply {
	struct nlmsghdr n;
	struct nlmsgerr err;
};

static struct wire_msg wire[FAKE_MAX];
static int wire_cnt;
static struct fake_reply replies[FAKE_MAX];
static int reply_head, reply_cnt;
static int fake_errno;		/* 0 ACKs every request, -ENODEV fails it */
static bool fake_eof;		/* recvmsg() reports EOF: a read failure */
static void (*send_hook)(void); /* runs once, after the first send */

static void fake_reset(void)
{
	wire_cnt = 0;
	reply_head = reply_cnt = 0;
	fake_errno = 0;
	fake_eof = false;
	send_hook = NULL;
}

static ssize_t fake_sendmsg(int sock, const struct msghdr *msg, int flags)
{
	struct nlmsghdr *h = msg->msg_iov[0].iov_base;
	unsigned int len = msg->msg_iov[0].iov_len;
	void (*hook)(void) = send_hook;

	for (; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
		struct ifinfomsg *ifi = NLMSG_DATA(h);
		struct fake_reply *r;

		if (wire_cnt < FAKE_MAX) {
			wire[wire_cnt].type = h->nlmsg_type;
			wire[wire_cnt].ifindex = ifi->ifi_index;
			wire[wire_cnt].seq = h->nlmsg_seq;
			wire_cnt++;
		}

		/* One NLMSG_ERROR per request, echoing its header so the
		 * batch reader correlates it by sequence number.
		 */
		if (reply_cnt == FAKE_MAX)
			continue;
		r = &replies[reply_cnt++];
		memset(r, 0, sizeof(*r));
		r->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
		r->n.nlmsg_type = NLMSG_ERROR;
		r->n.nlmsg_seq = h->nlmsg_seq;
		r->n.nlmsg_pid = h->nlmsg_pid;
		r->err.error = fake_errno;
		r->err.msg = *h;
	}

	send_hook = NULL;
	if (hook)
		hook();

	return msg->msg_iov[0].iov_len;
}

static ssize_t fake_recv(int sock, void *buf, size_t len, int flags)
{
	if (!fake_eof && reply_head < reply_cnt)
		return sizeof(struct fake_reply);
	errno = EAGAIN;
	return -1;
}

static ssize_t fake_recvmsg(int sock, struct msghdr *msg, int flags)
{
	struct sockaddr_nl *snl = msg->msg_name;

	if (fake_eof)
		return 0;
	if (reply_head == reply_cnt) {
		/* Nothing left: the end-of-responses drain. */
		errno = EAGAIN;
		return -1;
	}

	memcpy(msg->msg_iov[0].iov_base, &replies[reply_head++],
	       sizeof(struct fake_reply));
	memset(snl, 0, sizeof(*snl));
	snl->nl_family = AF_NETLINK;
	msg->msg_namelen = sizeof(struct sockaddr_nl);

	return sizeof(struct fake_reply);
}

/* The fake namespace, registered under a non-default nsid. */
static struct zebra_ns tzns;

struct test_link {
	struct interface ifp;
	struct zebra_if zif;
};

static struct test_link links[2];

static void setup(void)
{
	struct nlsock *nl = &tzns.netlink_dplane_out;
	struct ns *ns;

	zprivs_preinit(&zserv_privs);
	kernel_router_init();

	strlcpy(tzns.name, "dimt-unit", sizeof(tzns.name));
	tzns.ns_id = TEST_NSID;
	nl->sock = TEST_SOCK;
	nl->seq = 200;
	nl->snl.nl_family = AF_NETLINK;
	nl->snl.nl_pid = TEST_SOCK;
	strlcpy(nl->name, "netlink-dp (dimt-unit)", sizeof(nl->name));
	nl->buf = XCALLOC(MTYPE_NL_BUF, 8192);
	nl->buflen = 8192;
	kernel_netlink_nlsock_insert(nl);

	ns = ns_get_created(NULL, NULL, TEST_NSID);
	ns->info = &tzns;
	tzns.ns = ns;
}

static void teardown(void)
{
	kernel_netlink_nlsock_remove(&tzns.netlink_dplane_out);
	XFREE(MTYPE_NL_BUF, tzns.netlink_dplane_out.buf);
	kernel_router_terminate();
}

static void ipv4(struct ipaddr *ip, uint32_t addr)
{
	memset(ip, 0, sizeof(*ip));
	ip->ipa_type = IPADDR_V4;
	ip->ipaddr_v4.s_addr = htonl(addr);
}

/* Bring up a GRE link in the fake namespace with the given identity. */
static struct interface *link_add(int slot, ifindex_t ifindex,
				  const char *name, uint32_t remote,
				  uint32_t key)
{
	struct test_link *l = &links[slot];
	struct zebra_l2info_gre *gre = &l->zif.l2info.gre;

	memset(l, 0, sizeof(*l));
	strlcpy(l->ifp.name, name, sizeof(l->ifp.name));
	l->ifp.ifindex = ifindex;
	l->ifp.info = &l->zif;
	l->zif.zif_type = ZEBRA_IF_GRE;
	ipv4(&gre->vtep_ip, TEST_LOCAL);
	ipv4(&gre->vtep_ip_remote, remote);
	gre->ikey = gre->okey = htonl(key);
	gre->encap_type = 0; /* TUNNEL_ENCAP_NONE; <linux/if_tunnel.h>
			      * clashes with <netinet/ip.h> here */
	zebra_ns_link_ifp(&tzns, &l->ifp);

	return &l->ifp;
}

static void links_del(void)
{
	for (size_t i = 0; i < array_size(links); i++) {
		if (links[i].ifp.info)
			zebra_ns_unlink_ifp(&links[i].ifp);
		memset(&links[i], 0, sizeof(links[i]));
	}
}

/* A DIMT delete as zebra_dimt.c would enqueue it; uses one sequence. */
static struct zebra_dplane_ctx *mk_del(ifindex_t ifindex, const char *ifname)
{
	struct zebra_dimt_tunnel_ctx t = {};
	struct zebra_dplane_ctx *ctx = dplane_ctx_alloc();

	t.tunnel.tunnel_id = ifindex;
	ipv4(&t.tunnel.outer_local, TEST_LOCAL);
	ipv4(&t.tunnel.outer_remote, TEST_REMOTE);
	t.tunnel.encap = ZAPI_DIMT_TUNNEL_ENCAP_GRE;
	t.tunnel.options = ZAPI_DIMT_TUNNEL_KEY_PRESENT;
	t.tunnel.key = TEST_KEY;
	strlcpy(t.ifname, ifname, sizeof(t.ifname));
	t.delete_ifindex = ifindex;
	t.phase = ZEBRA_DIMT_TUNNEL_DELETE;
	dplane_ctx_dimt_tunnel_init(ctx, DPLANE_OP_DIMT_TUNNEL_DEL, VRF_DEFAULT,
				    &tzns, &t);

	return ctx;
}

static uint32_t seq_of(const struct zebra_dplane_ctx *ctx)
{
	return dplane_ctx_get_ns(ctx)->seq;
}

static bool ok_of(const struct zebra_dplane_ctx *ctx)
{
	return dplane_ctx_get_status(ctx) == ZEBRA_DPLANE_REQUEST_SUCCESS;
}

static bool auth_of(const struct zebra_dplane_ctx *ctx)
{
	return dplane_ctx_get_dimt_tunnel(ctx)->result_authoritative;
}

/*
 * Fixed labels, never stringified conditions, so the .refout survives an
 * edit to how a check is computed.
 */
static const char *cur_case;
static int failures;

static void check(const char *label, bool cond)
{
	printf("%s: %s: %s\n", cur_case, label, cond ? "OK" : "FAIL");
	if (!cond)
		failures++;
}

static void begin(const char *name)
{
	cur_case = name;
	fake_reset();
}

static void end(struct zebra_dplane_ctx **ctxs, int n)
{
	for (int i = 0; i < n; i++)
		dplane_ctx_fini(&ctxs[i]);
	links_del();
}

/*
 * Run ctxs through kernel_update_multi(); true when the results come back
 * in input order, as zebra_dimt.c expects.
 */
static bool update_multi(struct zebra_dplane_ctx **ctxs, int n)
{
	struct dplane_ctx_list_head q;
	bool in_order = true;

	dplane_ctx_q_init(&q);
	for (int i = 0; i < n; i++)
		dplane_ctx_enqueue_tail(&q, ctxs[i]);

	kernel_update_multi(&q);

	for (int i = 0; i < n; i++)
		if (dplane_ctx_dequeue(&q) != ctxs[i])
			in_order = false;

	return in_order && dplane_ctx_dequeue(&q) == NULL;
}

static bool sent_one_del(int ifindex, uint32_t seq)
{
	return wire_cnt == 1 && wire[0].type == RTM_DELLINK &&
	       wire[0].ifindex == ifindex && wire[0].seq == seq;
}

/* The verdict every skipped delete must carry. */
static void check_skipped(struct zebra_dplane_ctx *ctx)
{
	check("nothing sent", wire_cnt == 0);
	check("skipped SUCCESS", ok_of(ctx));
	check("skipped not authoritative", !auth_of(ctx));
}

static void case_put(void)
{
	struct dplane_ctx_list_head out;
	struct zebra_dplane_ctx *ctx[1];
	struct nl_batch bth;
	enum netlink_msg_status res;

	dplane_ctx_q_init(&out);

	/*
	 * Positive control for (a): in the same fixture a matching link is
	 * NOT skipped, so the skip below is the identity check firing and
	 * not a lookup that cannot succeed.
	 */
	begin("A put-match");
	link_add(0, IF_REAL, NAME_REAL, TEST_REMOTE, TEST_KEY);
	ctx[0] = mk_del(IF_REAL, NAME_REAL);
	nl_batch_init(&bth, &out);
	res = netlink_put_dimt_tunnel_msg(&bth, ctx[0]);
	check("queued", res == FRR_NETLINK_QUEUED);
	check("one message batched", bth.msgcnt == 1);
	nl_batch_reset(&bth);
	end(ctx, 1);

	/*
	 * (a) The namespace is registered but does not list the ifindex.
	 * kernel_update_multi() presets a DIMT context to FAILURE before
	 * the put, so do the same: the skip must overwrite it.
	 */
	begin("a put-skip");
	ctx[0] = mk_del(IF_GONE, NAME_GONE);
	dplane_ctx_set_status(ctx[0], ZEBRA_DPLANE_REQUEST_FAILURE);
	nl_batch_init(&bth, &out);
	res = netlink_put_dimt_tunnel_msg(&bth, ctx[0]);
	check("handled without a message", res == FRR_NETLINK_SUCCESS);
	check("batch empty", bth.msgcnt == 0);
	check_skipped(ctx[0]);
	nl_batch_reset(&bth);
	end(ctx, 1);
}

static void case_multi_single(void)
{
	struct zebra_dplane_ctx *ctx[1];
	bool in_order;

	/* Positive control: a real delete is seen on the wire and its
	 * verdict comes from the ACK.
	 */
	begin("B multi-match");
	link_add(0, IF_REAL, NAME_REAL, TEST_REMOTE, TEST_KEY);
	ctx[0] = mk_del(IF_REAL, NAME_REAL);
	in_order = update_multi(ctx, 1);
	check("returned", in_order);
	check("one RTM_DELLINK for the link",
	      sent_one_del(IF_REAL, seq_of(ctx[0])));
	check("SUCCESS", ok_of(ctx[0]));
	check("authoritative", auth_of(ctx[0]));
	end(ctx, 1);

	/* ...and a NACK turns it, so the verdict is read from the reply. */
	begin("B2 multi-enodev");
	link_add(0, IF_REAL, NAME_REAL, TEST_REMOTE, TEST_KEY);
	ctx[0] = mk_del(IF_REAL, NAME_REAL);
	fake_errno = -ENODEV;
	in_order = update_multi(ctx, 1);
	check("returned", in_order);
	check("one RTM_DELLINK for the link",
	      sent_one_del(IF_REAL, seq_of(ctx[0])));
	check("FAILURE", !ok_of(ctx[0]));
	check("authoritative", auth_of(ctx[0]));
	end(ctx, 1);

	/*
	 * C-F: each way the link at delete_ifindex can stop being ours.
	 * With the put-time skip removed the encoder's recheck fails the
	 * delete as FAILURE + authoritative; with both removed, a stale
	 * RTM_DELLINK goes out.
	 */
	begin("C skip-absent");
	ctx[0] = mk_del(IF_GONE, NAME_GONE);
	check("returned", update_multi(ctx, 1));
	check_skipped(ctx[0]);
	end(ctx, 1);

	begin("D skip-renamed");
	link_add(0, IF_REAL, "dimt-other", TEST_REMOTE, TEST_KEY);
	ctx[0] = mk_del(IF_REAL, NAME_REAL);
	check("returned", update_multi(ctx, 1));
	check_skipped(ctx[0]);
	end(ctx, 1);

	begin("E skip-remote");
	link_add(0, IF_REAL, NAME_REAL, TEST_OTHER, TEST_KEY);
	ctx[0] = mk_del(IF_REAL, NAME_REAL);
	check("returned", update_multi(ctx, 1));
	check_skipped(ctx[0]);
	end(ctx, 1);

	begin("F skip-key");
	link_add(0, IF_REAL, NAME_REAL, TEST_REMOTE, TEST_KEY + 1);
	ctx[0] = mk_del(IF_REAL, NAME_REAL);
	check("returned", update_multi(ctx, 1));
	check_skipped(ctx[0]);
	end(ctx, 1);
}

/*
 * A real delete and a skipped one in one batch. errno and eof select the
 * reply; real_first selects the input order.
 */
static void run_mixed(const char *name, bool real_first, int err, bool eof)
{
	struct zebra_dplane_ctx *ctx[2];
	struct zebra_dplane_ctx *real, *skip;
	bool in_order;

	begin(name);
	link_add(0, IF_REAL, NAME_REAL, TEST_REMOTE, TEST_KEY);
	if (real_first) {
		real = ctx[0] = mk_del(IF_REAL, NAME_REAL);
		skip = ctx[1] = mk_del(IF_GONE, NAME_GONE);
	} else {
		skip = ctx[0] = mk_del(IF_GONE, NAME_GONE);
		real = ctx[1] = mk_del(IF_REAL, NAME_REAL);
	}
	fake_errno = err;
	fake_eof = eof;
	in_order = update_multi(ctx, 2);

	check("results in input order", in_order);
	check("one RTM_DELLINK for the real link",
	      sent_one_del(IF_REAL, seq_of(real)));
	if (eof) {
		/* The read failed: an uncertain outcome, not a verdict. */
		check("real FAILURE", !ok_of(real));
		check("real not authoritative", !auth_of(real));
	} else if (err) {
		check("real FAILURE", !ok_of(real));
		check("real authoritative", auth_of(real));
	} else {
		check("real SUCCESS", ok_of(real));
		check("real authoritative", auth_of(real));
	}
	check("skipped SUCCESS", ok_of(skip));
	check("skipped not authoritative", !auth_of(skip));
	end(ctx, 2);
}

static void case_mixed(void)
{
	/*
	 * G is the load-bearing order. The ack walk dequeues contexts up
	 * to the one a reply answers, so with [skipped, real] a skipped
	 * context left in the list is dequeued untouched; only [real,
	 * skipped] leaves it for the drain to flip.
	 */
	run_mixed("G mixed real,skip", true, 0, false);
	/* H does NOT catch the drain bug (see G); it pins the verdicts and
	 * the order for the other arrangement.
	 */
	run_mixed("H mixed skip,real", false, 0, false);
	/* I: the read-failure drain fails everything still listed. */
	run_mixed("I mixed eof", true, 0, true);
	/* I2: a NACK for the real delete stays with that context. */
	run_mixed("I2 mixed enodev", true, -ENODEV, false);
}

static bool late_hook_ran;

static void late_hook(void)
{
	/* A link notification lands while the first delete is flushed. */
	zebra_ns_unlink_ifp(&links[1].ifp);
	late_hook_ran = true;
}

static void case_encode_recheck(void)
{
	struct zebra_dplane_ctx *ctx[2];

	/*
	 * J: a 48-byte batch holds one 32-byte RTM_DELLINK. The second
	 * delete passes the put-time check, does not fit, and is encoded
	 * again after the flush -- by which time its link is gone, so only
	 * the encoder's own recheck keeps a stale delete off the wire.
	 *
	 * The second context's status is deliberately not checked: the
	 * encoder's 0 reads as "no room", so it ends FAILURE +
	 * authoritative for a link that is already gone. That is a
	 * separate question from this test.
	 */
	begin("J encode-recheck");
	netlink_set_batch_buffer_size(48, 4096, true);
	link_add(0, IF_REAL, NAME_REAL, TEST_REMOTE, TEST_KEY);
	link_add(1, IF_LATE, NAME_LATE, TEST_REMOTE, TEST_KEY);
	ctx[0] = mk_del(IF_REAL, NAME_REAL);
	ctx[1] = mk_del(IF_LATE, NAME_LATE);
	late_hook_ran = false;
	send_hook = late_hook;
	check("returned", update_multi(ctx, 2));
	check("link removed during the flush", late_hook_ran);
	check("one RTM_DELLINK for the first link",
	      sent_one_del(IF_REAL, seq_of(ctx[0])));
	check("first SUCCESS", ok_of(ctx[0]));
	check("first authoritative", auth_of(ctx[0]));
	netlink_set_batch_buffer_size(0, 0, false);
	end(ctx, 2);
}

int main(int argc, char **argv)
{
	setup();

	/*
	 * zebra_ns_lookup() falls back to the default namespace when an
	 * nsid is unknown, and the matcher then fails on !zns: every skip
	 * would pass for the wrong reason. Pin the fixture first.
	 */
	begin("P0 ns");
	check("lookup finds the test namespace",
	      zebra_ns_lookup(TEST_NSID) == &tzns);

	case_put();
	case_multi_single();
	case_mixed();
	case_encode_recheck();

	teardown();

	return failures ? 1 : 0;
}
