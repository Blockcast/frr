// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Blockcast, Inc. */

/* The UMH large community decoder and its DIMT lane, pinned with synthetic
 * paths -- no session, no topology.  BLO-36558; the contract is
 * doc/dimt-lc-umh-mapping.md.
 *
 * What this file owns that the topotest (tests/topotests/bgp_dimt_umh_lc)
 * cannot pin cheaply: the reject counter's exact arithmetic per tuple and per
 * route, every unusable-address range, the four throttle pairs' independence,
 * the lane == NULL pure query, and the once-per-attribute-set record.
 *
 * Throttle state is read, not timed: the decoder stamps it with the real
 * monotime(), so "independent" is asserted as "a notice on one pair leaves
 * every other pair unseen", which is the property that lets a flood on one
 * pair not silence another.
 */

#include <zebra.h>

#include "privs.h"
#include "printfrr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_dimt.h"

struct zebra_privs_t bgpd_privs = {};

#define FN_DIMT 7
#define FN_MVPN 1
#define LOCAL_AS 65000
#define NBR_AS 65001

/* 184549374 == 0x0AFFFFFE */
#define KA_PARAM "184549374"
#define KA_ADDR "10.255.255.254"

static struct bgp test_bgp;
static struct peer self_peer;
static struct peer trusted_ebgp; /* dimt-trusted, AS 65001 */
static struct peer trusted_ibgp; /* dimt-trusted, our AS */
static struct peer untrusted;	 /* eBGP AS 65001, not marked */
static char name_pretty[] = "VRF default";

static void fail(const char *name, const char *fmt, ...) PRINTFRR(2, 3);
static void fail(const char *name, const char *fmt, ...)
{
	va_list ap;
	char buf[512];

	va_start(ap, fmt);
	vsnprintfrr(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	fprintf(stderr, "FAIL %s: %s\n", name, buf);
	exit(1);
}

/* An interned attribute set: AS_PATH from @aspath ("" = empty), large
 * communities from @lcom (NULL = none). */
static struct attr *mkattr(const char *aspath, const char *lcom)
{
	struct attr attr = {};

	attr.aspath = aspath_str2aspath(aspath, ASNOTATION_PLAIN);
	if (!attr.aspath) {
		fprintf(stderr, "FAIL setup: aspath '%s' did not parse\n", aspath);
		exit(1);
	}
	if (lcom) {
		struct lcommunity *lc = lcommunity_str2com(lcom);

		if (!lc) {
			fprintf(stderr, "FAIL setup: lcom '%s' did not parse\n", lcom);
			exit(1);
		}
		bgp_attr_set_lcommunity(&attr, lc);
	}
	return bgp_attr_intern(&attr);
}

static struct bgp_path_info path(struct peer *peer, struct attr *attr)
{
	struct bgp_path_info pi = {};

	pi.peer = peer;
	pi.sub_type = BGP_ROUTE_NORMAL;
	pi.attr = attr;
	return pi;
}

static void reset_state(void)
{
	memset(&test_bgp.dimt_umh_lc, 0, sizeof(test_bgp.dimt_umh_lc));
	memset(&test_bgp.mvpn_umh_lc, 0, sizeof(test_bgp.mvpn_umh_lc));
	memset(&test_bgp.dimt_umh_lc_untrusted_log, 0,
	       sizeof(test_bgp.dimt_umh_lc_untrusted_log));
	memset(&test_bgp.dimt_umh_lc_xfam_log, 0,
	       sizeof(test_bgp.dimt_umh_lc_xfam_log));
	untrusted.stat_dimt_umh_rejected = 0;
	trusted_ebgp.stat_dimt_umh_rejected = 0;
	trusted_ibgp.stat_dimt_umh_rejected = 0;
}

static void want_count(const char *name, const char *lane, uint64_t got,
		       uint64_t want)
{
	if (got != want)
		fail(name, "%s counter is %" PRIu64 ", expected %" PRIu64, lane,
		     got, want);
}

static void want_umh(const char *name, bool got, struct in_addr umh,
		     const char *want)
{
	struct in_addr w;

	if (!want) {
		if (got)
			fail(name, "resolved to %pI4, expected no UMH", &umh);
		return;
	}
	inet_pton(AF_INET, want, &w);
	if (!got)
		fail(name, "no UMH, expected %s", want);
	if (umh.s_addr != w.s_addr)
		fail(name, "resolved to %pI4, expected %s", &umh, want);
}

/* Which of the four throttle pairs have ever emitted. */
static void want_seen(const char *name, bool dimt, bool mvpn, bool untr,
		      bool xfam)
{
	if (test_bgp.dimt_umh_lc.log.seen != dimt ||
	    test_bgp.mvpn_umh_lc.log.seen != mvpn ||
	    test_bgp.dimt_umh_lc_untrusted_log.seen != untr ||
	    test_bgp.dimt_umh_lc_xfam_log.seen != xfam)
		fail(name,
		     "throttle seen dimt=%d mvpn=%d untrusted=%d xfam=%d, expected %d %d %d %d",
		     test_bgp.dimt_umh_lc.log.seen,
		     test_bgp.mvpn_umh_lc.log.seen,
		     test_bgp.dimt_umh_lc_untrusted_log.seen,
		     test_bgp.dimt_umh_lc_xfam_log.seen, dimt, mvpn, untr, xfam);
}

/* The DIMT lane, counting, through the exported call-site function. */
static bool dimt(struct bgp_path_info *pi, afi_t afi, struct in_addr *umh,
		 bool *on_lane)
{
	umh->s_addr = 0;
	return bgp_dimt_umh_lc_resolve(&test_bgp, pi, afi, true, umh, on_lane);
}

/* --- 0: the function match --------------------------------------------- */
static void check_has_function(void)
{
	struct attr *a = mkattr("65001", "65001:7:1 65001:9:2");
	struct lcommunity *lc = bgp_attr_get_lcommunity(a);

	if (!bgp_umh_lc_has_function(lc, 7) || !bgp_umh_lc_has_function(lc, 9))
		fail("has_function", "present function not found");
	if (bgp_umh_lc_has_function(lc, 8))
		fail("has_function", "absent function found");
	if (bgp_umh_lc_has_function(lc, 0))
		fail("has_function", "fn 0 must never match");
	if (bgp_umh_lc_has_function(NULL, 7))
		fail("has_function", "NULL list must not match");
	bgp_attr_unintern(&a);
}

/* --- 1: known-answer vector -------------------------------------------- */
static void check_known_answer(void)
{
	struct attr *a = mkattr("65001", "65001:7:" KA_PARAM);
	struct bgp_path_info pi = path(&trusted_ebgp, a);
	struct in_addr umh = {};
	uint32_t source_as = 0;
	bool on_lane, got;

	reset_state();
	got = bgp_umh_lc_decode(&test_bgp, &pi, FN_DIMT, BGP_UMH_LC_LANE_DIMT,
				&test_bgp.dimt_umh_lc, &source_as, &umh);
	want_umh("known answer, decoder", got, umh, KA_ADDR);
	if (source_as != NBR_AS)
		fail("known answer, decoder", "source AS %u, expected %u",
		     source_as, NBR_AS);

	got = dimt(&pi, AFI_IP, &umh, &on_lane);
	want_umh("known answer, DIMT lane", got, umh, KA_ADDR);
	if (!on_lane)
		fail("known answer, DIMT lane", "on_lane false");
	want_count("known answer", "DIMT", test_bgp.dimt_umh_lc.rejected, 0);
	want_seen("known answer", false, false, false, false);
	bgp_attr_unintern(&a);
}

/* --- 2: lowest valid tuple + higher-GA mismatches ---------------------- */
static void check_lowest_tuple_and_mismatches(void)
{
	/* Sorted by GA, so the two forged tuples land AFTER the winner: an
	 * early "a lower tuple already won" skip would never count them. */
	struct attr *a = mkattr("65001", "65001:7:" KA_PARAM
					 " 65002:7:16843009 65003:7:16843010");
	/* Tuples sort on all 12 bytes, so under one GA the parameter orders
	 * them: 0.0.0.1 (unusable) < 10.255.255.254 < 192.168.1.1. */
	struct attr *b = mkattr("65001", "65001:7:1 65001:7:" KA_PARAM
					 " 65001:7:3232235777");
	struct bgp_path_info pi = path(&trusted_ebgp, a);
	struct in_addr umh;
	bool got;

	reset_state();
	got = dimt(&pi, AFI_IP, &umh, NULL);
	want_umh("lowest tuple + 2 higher-GA mismatches", got, umh, KA_ADDR);
	want_count("lowest tuple + 2 higher-GA mismatches", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 2);
	want_seen("lowest tuple + 2 higher-GA mismatches", true, false, false,
		  false);

	/* Same GA: an unusable lowest tuple is skipped (+1), the next valid
	 * one wins, and a valid tuple after the winner is ignored, not
	 * counted. */
	reset_state();
	pi = path(&trusted_ebgp, b);
	got = dimt(&pi, AFI_IP, &umh, NULL);
	want_umh("unusable lowest, valid next", got, umh, KA_ADDR);
	want_count("unusable lowest, valid next", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 1);
	bgp_attr_unintern(&a);
	bgp_attr_unintern(&b);
}

/* --- 3 + 4: origin-ambiguous AS_PATH ----------------------------------- */
static void check_as_set(void)
{
	struct attr *two = mkattr("65001 {65003,65004}",
				  "65001:7:" KA_PARAM " 65003:7:" KA_PARAM);
	struct attr *zero = mkattr("65001 {65003,65004}", "0:7:1 0:7:2");
	struct attr *other = mkattr("65001 {65003,65004}", "65001:9:" KA_PARAM);
	struct attr *none = mkattr("65001 {65003,65004}", NULL);
	const char *why = NULL;
	bool empty;
	struct bgp_path_info pi;
	struct in_addr umh;
	uint32_t source_as;
	bool got;

	/* Precondition: the string really built an AS_SET origin. */
	aspath_origin_as(two->aspath, &why, &empty);
	if (!why)
		fail("AS_SET precondition", "origin not reported ambiguous");

	/* Decoder, directly: once per ROUTE however many tuples. */
	reset_state();
	pi = path(&trusted_ebgp, two);
	got = bgp_umh_lc_decode(&test_bgp, &pi, FN_DIMT, BGP_UMH_LC_LANE_DIMT,
				&test_bgp.dimt_umh_lc, &source_as, &umh);
	want_umh("AS_SET, 2 DIMT tuples, decoder", got, umh, NULL);
	want_count("AS_SET, 2 DIMT tuples, decoder", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 1);

	/* Through the lane with an iBGP-trusted peer, whose trust gate does not
	 * read the origin, so the decoder is what refuses. */
	reset_state();
	pi = path(&trusted_ibgp, two);
	got = dimt(&pi, AFI_IP, &umh, NULL);
	want_umh("AS_SET, 2 DIMT tuples, lane", got, umh, NULL);
	want_count("AS_SET, 2 DIMT tuples, lane", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 1);

	reset_state();
	pi = path(&trusted_ibgp, zero);
	got = dimt(&pi, AFI_IP, &umh, NULL);
	want_umh("AS_SET, both tuples GA 0", got, umh, NULL);
	want_count("AS_SET, both tuples GA 0", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 1);

	/* Through the lane with an eBGP-trusted peer: refused by the trust
	 * gate (origin indeterminate) -- still once. */
	reset_state();
	pi = path(&trusted_ebgp, two);
	got = dimt(&pi, AFI_IP, &umh, NULL);
	want_umh("AS_SET, eBGP-trusted", got, umh, NULL);
	want_count("AS_SET, eBGP-trusted", "DIMT", test_bgp.dimt_umh_lc.rejected,
		   1);

	/* 4: nothing on the lane, nothing counted. */
	reset_state();
	pi = path(&trusted_ibgp, other);
	got = dimt(&pi, AFI_IP, &umh, NULL);
	want_umh("AS_SET, other function only", got, umh, NULL);
	got = bgp_umh_lc_decode(&test_bgp, &pi, FN_DIMT, BGP_UMH_LC_LANE_DIMT,
				&test_bgp.dimt_umh_lc, &source_as, &umh);
	want_umh("AS_SET, other function only, decoder", got, umh, NULL);
	pi = path(&trusted_ibgp, none);
	got = dimt(&pi, AFI_IP, &umh, NULL);
	want_umh("AS_SET, no LC", got, umh, NULL);
	got = bgp_umh_lc_decode(&test_bgp, &pi, FN_DIMT, BGP_UMH_LC_LANE_DIMT,
				&test_bgp.dimt_umh_lc, &source_as, &umh);
	want_umh("AS_SET, no LC, decoder", got, umh, NULL);
	want_count("AS_SET, other function / no LC", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 0);
	want_seen("AS_SET, other function / no LC", false, false, false, false);

	bgp_attr_unintern(&two);
	bgp_attr_unintern(&zero);
	bgp_attr_unintern(&other);
	bgp_attr_unintern(&none);
}

/* --- 5: another function is never a reject ----------------------------- */
static void check_other_function(void)
{
	/* GA-mismatched AND unusable, under a function that is not DIMT's. */
	struct attr *a = mkattr("65001", "65009:9:1 65009:9:3758096385");
	struct bgp_path_info pi = path(&trusted_ebgp, a);
	struct in_addr umh;
	bool on_lane = true, got;

	reset_state();
	got = dimt(&pi, AFI_IP, &umh, &on_lane);
	want_umh("wrong function", got, umh, NULL);
	if (on_lane)
		fail("wrong function", "on_lane true");
	got = dimt(&pi, AFI_IP6, &umh, NULL);
	pi = path(&untrusted, a);
	got |= dimt(&pi, AFI_IP, &umh, NULL);
	want_umh("wrong function, v6/untrusted", got, umh, NULL);
	want_count("wrong function", "DIMT", test_bgp.dimt_umh_lc.rejected, 0);
	want_count("wrong function", "peer", untrusted.stat_dimt_umh_rejected, 0);
	want_seen("wrong function", false, false, false, false);
	bgp_attr_unintern(&a);
}

/* --- 6: each unusable range -------------------------------------------- */
static void check_unusable_ranges(void)
{
	static const struct {
		const char *name;
		const char *param;
	} r[] = {
		{ "0.0.0.0/8 (0.0.0.1)", "1" },
		{ "0.0.0.0/8 (0.0.0.0)", "0" },
		{ "127.0.0.0/8 (127.0.0.1)", "2130706433" },
		{ "169.254.0.0/16 (169.254.1.1)", "2851995905" },
		{ "224.0.0.0/4 (224.0.0.1)", "3758096385" },
		{ "224.0.0.0/4 (239.255.255.255)", "4026531839" },
		{ "240.0.0.0/4 (240.0.0.1)", "4026531841" },
		{ "255.255.255.255", "4294967295" },
	};
	size_t i;

	for (i = 0; i < array_size(r); i++) {
		char lc[64];
		struct attr *a;
		struct bgp_path_info pi;
		struct in_addr umh;
		bool got;

		snprintf(lc, sizeof(lc), "65001:7:%s", r[i].param);
		a = mkattr("65001", lc);
		pi = path(&trusted_ebgp, a);

		reset_state();
		got = dimt(&pi, AFI_IP, &umh, NULL);
		want_umh(r[i].name, got, umh, NULL);
		want_count(r[i].name, "DIMT", test_bgp.dimt_umh_lc.rejected, 1);
		/* Debug-only: the originating AS naming a bad address for its
		 * own route is a misconfiguration, not a probe, and must not
		 * use up the lane's notice. */
		want_seen(r[i].name, false, false, false, false);
		bgp_attr_unintern(&a);
	}
}

/* --- 7: untrusted peer, once per route --------------------------------- */
static void check_untrusted(void)
{
	struct attr *a = mkattr("65001", "65002:7:" KA_PARAM " 65003:7:" KA_PARAM);
	struct bgp_path_info pi = path(&untrusted, a);
	struct in_addr umh;
	bool got;

	reset_state();
	got = dimt(&pi, AFI_IP, &umh, NULL);
	want_umh("untrusted, 2 GA-mismatched tuples", got, umh, NULL);
	want_count("untrusted, 2 GA-mismatched tuples", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 1);
	want_count("untrusted, 2 GA-mismatched tuples", "peer",
		   untrusted.stat_dimt_umh_rejected, 1);
	/* Refused before decoding: the decoder's notice is untouched. */
	want_seen("untrusted, 2 GA-mismatched tuples", false, false, true,
		  false);
	bgp_attr_unintern(&a);
}

/* --- 8: v6 -------------------------------------------------------------- */
static void check_v6(void)
{
	struct attr *a = mkattr("65001", "65001:7:" KA_PARAM " 65002:7:" KA_PARAM);
	struct attr *mvpn_only = mkattr("65001", "65001:1:" KA_PARAM);
	struct bgp_path_info pi = path(&trusted_ebgp, a);
	struct in_addr umh;
	bool got;

	reset_state();
	got = dimt(&pi, AFI_IP6, &umh, NULL);
	want_umh("v6, 2 DIMT tuples", got, umh, NULL);
	want_count("v6, 2 DIMT tuples", "DIMT", test_bgp.dimt_umh_lc.rejected, 1);
	want_seen("v6, 2 DIMT tuples", false, false, false, true);

	reset_state();
	pi = path(&untrusted, a);
	got = dimt(&pi, AFI_IP6, &umh, NULL);
	want_umh("v6 + untrusted", got, umh, NULL);
	want_count("v6 + untrusted", "DIMT", test_bgp.dimt_umh_lc.rejected, 1);
	/* Trust is the first gate, so the route stops there. */
	want_seen("v6 + untrusted", false, false, true, false);

	reset_state();
	pi = path(&trusted_ebgp, mvpn_only);
	got = dimt(&pi, AFI_IP6, &umh, NULL);
	want_umh("v6, MVPN function only", got, umh, NULL);
	want_count("v6, MVPN function only", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 0);
	want_seen("v6, MVPN function only", false, false, false, false);

	bgp_attr_unintern(&a);
	bgp_attr_unintern(&mvpn_only);
}

/* --- 9: throttle independence ------------------------------------------ */
static void check_throttle_independence(void)
{
	struct attr *mm_dimt = mkattr("65001", "65002:7:" KA_PARAM);
	struct attr *mm_mvpn = mkattr("65001", "65002:1:" KA_PARAM);
	struct bgp_path_info pi;
	struct in_addr umh;
	uint32_t source_as;
	struct bgp_umh_lc_throttle saved;

	reset_state();

	/* Each pair, in turn, fires without the others having moved. */
	pi = path(&trusted_ebgp, mm_dimt);
	dimt(&pi, AFI_IP6, &umh, NULL);
	want_seen("throttle: xfam first", false, false, false, true);

	pi = path(&untrusted, mm_dimt);
	dimt(&pi, AFI_IP, &umh, NULL);
	want_seen("throttle: untrusted after xfam", false, false, true, true);

	pi = path(&trusted_ebgp, mm_dimt);
	dimt(&pi, AFI_IP, &umh, NULL);
	want_seen("throttle: DIMT decoder after both gates", true, false, true,
		  true);

	pi = path(&trusted_ebgp, mm_mvpn);
	bgp_umh_lc_decode(&test_bgp, &pi, FN_MVPN, BGP_UMH_LC_LANE_MVPN,
			  &test_bgp.mvpn_umh_lc, &source_as, &umh);
	want_seen("throttle: MVPN after DIMT", true, true, true, true);

	/* Inside the window a pair is suppressed -- its stamp does not move
	 * on a suppressed call -- while its counter still counts. */
	saved = test_bgp.dimt_umh_lc.log;
	test_bgp.dimt_umh_lc.log.last = monotime(NULL);
	saved.last = test_bgp.dimt_umh_lc.log.last;
	pi = path(&trusted_ebgp, mm_dimt);
	dimt(&pi, AFI_IP, &umh, NULL);
	if (test_bgp.dimt_umh_lc.log.last != saved.last)
		fail("throttle: suppressed call", "stamp moved");
	/* wrong family + untrusted + the decoder's first reject + this one */
	want_count("throttle: suppressed call", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 4);

	/* And the reverse order: the MVPN lane firing first leaves DIMT's
	 * decoder pair free to fire. */
	reset_state();
	pi = path(&trusted_ebgp, mm_mvpn);
	bgp_umh_lc_decode(&test_bgp, &pi, FN_MVPN, BGP_UMH_LC_LANE_MVPN,
			  &test_bgp.mvpn_umh_lc, &source_as, &umh);
	want_seen("throttle: MVPN first", false, true, false, false);
	pi = path(&trusted_ebgp, mm_dimt);
	dimt(&pi, AFI_IP, &umh, NULL);
	want_seen("throttle: DIMT after MVPN", true, true, false, false);

	bgp_attr_unintern(&mm_dimt);
	bgp_attr_unintern(&mm_mvpn);
}

/* --- 10: lane == NULL / count == false is a pure query ----------------- */
static void check_pure_query(void)
{
	struct attr *ok = mkattr("65001", "65001:7:" KA_PARAM " 65002:7:1");
	struct attr *bad = mkattr("65001", "65002:7:" KA_PARAM " 65001:7:1");
	struct attr *set = mkattr("65001 {65003}", "65001:7:" KA_PARAM);
	struct attr *attrs[] = { ok, bad, set };
	struct peer *peers[] = { &trusted_ebgp, &trusted_ibgp, &untrusted };
	size_t i, j;

	reset_state();
	for (i = 0; i < array_size(attrs); i++) {
		for (j = 0; j < array_size(peers); j++) {
			struct bgp_path_info pi = path(peers[j], attrs[i]);
			struct in_addr u1 = {}, u2 = {};
			uint32_t s1 = 0;
			bool g1, g2;
			afi_t afi;

			g1 = bgp_umh_lc_decode(&test_bgp, &pi, FN_DIMT,
					       BGP_UMH_LC_LANE_DIMT, NULL, &s1,
					       &u1);
			for (afi = AFI_IP; afi <= AFI_IP6; afi++)
				g2 = bgp_dimt_umh_lc_resolve(&test_bgp, &pi, afi,
							     false, &u2, NULL);
			(void)g2;
			if (i == 0 && j < 2 &&
			    (!g1 || u1.s_addr != htonl(184549374)))
				fail("pure query", "valid route did not resolve");
		}
	}
	want_count("pure query", "DIMT", test_bgp.dimt_umh_lc.rejected, 0);
	want_count("pure query", "peer", untrusted.stat_dimt_umh_rejected, 0);
	want_seen("pure query", false, false, false, false);

	/* Same answer as the counting call. */
	{
		struct bgp_path_info pi = path(&trusted_ebgp, ok);
		struct in_addr u1 = {}, u2 = {};
		bool g1, g2;

		g1 = bgp_dimt_umh_lc_resolve(&test_bgp, &pi, AFI_IP, false, &u1,
					     NULL);
		g2 = bgp_dimt_umh_lc_resolve(&test_bgp, &pi, AFI_IP, true, &u2,
					     NULL);
		if (g1 != g2 || u1.s_addr != u2.s_addr)
			fail("pure query", "query and counting call disagree");
		want_count("pure query vs counting", "DIMT",
			   test_bgp.dimt_umh_lc.rejected, 1);
	}

	bgp_attr_unintern(&ok);
	bgp_attr_unintern(&bad);
	bgp_attr_unintern(&set);
}

/* --- 11: re-processing the same attribute set counts once -------------- */
static void check_reprocess_once(void)
{
	struct attr *a = mkattr("65001", "65001:7:" KA_PARAM " 65002:7:1");
	struct attr *b = mkattr("65001", "65001:7:" KA_PARAM " 65003:7:1");
	struct attr *off = mkattr("65001", "65001:9:" KA_PARAM);
	struct bgp_path_info pi = path(&trusted_ebgp, a);
	struct in_addr umh;
	bool got;

	reset_state();
	got = bgp_dimt_umh_lc_from_path(&test_bgp, &pi, AFI_IP, &umh);
	want_umh("re-process: first", got, umh, KA_ADDR);
	want_count("re-process: first", "DIMT", test_bgp.dimt_umh_lc.rejected, 1);
	if (pi.dimt_umh_lc_counted != a)
		fail("re-process: first", "record not taken");

	got = bgp_dimt_umh_lc_from_path(&test_bgp, &pi, AFI_IP, &umh);
	got &= bgp_dimt_umh_lc_from_path(&test_bgp, &pi, AFI_IP, &umh);
	want_umh("re-process: unchanged x2", got, umh, KA_ADDR);
	want_count("re-process: unchanged x2", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 1);

	pi.attr = b;
	bgp_dimt_umh_lc_from_path(&test_bgp, &pi, AFI_IP, &umh);
	want_count("re-process: new attribute set", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 2);
	bgp_dimt_umh_lc_from_path(&test_bgp, &pi, AFI_IP, &umh);
	want_count("re-process: new set, unchanged", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 2);

	/* Off the lane: the record is released, so the set coming back is a
	 * new arrival. */
	pi.attr = off;
	bgp_dimt_umh_lc_from_path(&test_bgp, &pi, AFI_IP, &umh);
	if (pi.dimt_umh_lc_counted)
		fail("re-process: off lane", "record kept for an off-lane path");
	pi.attr = b;
	bgp_dimt_umh_lc_from_path(&test_bgp, &pi, AFI_IP, &umh);
	want_count("re-process: back on the lane", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 3);

	/* Untrusted: the gate's count is once per set too, peer included. */
	reset_state();
	if (pi.dimt_umh_lc_counted)
		bgp_attr_unintern(&pi.dimt_umh_lc_counted);
	pi = path(&untrusted, a);
	bgp_dimt_umh_lc_from_path(&test_bgp, &pi, AFI_IP, &umh);
	bgp_dimt_umh_lc_from_path(&test_bgp, &pi, AFI_IP, &umh);
	bgp_dimt_umh_lc_from_path(&test_bgp, &pi, AFI_IP, &umh);
	want_count("re-process: untrusted x3", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 1);
	want_count("re-process: untrusted x3", "peer",
		   untrusted.stat_dimt_umh_rejected, 1);

	if (pi.dimt_umh_lc_counted)
		bgp_attr_unintern(&pi.dimt_umh_lc_counted);
	bgp_attr_unintern(&a);
	bgp_attr_unintern(&b);
	bgp_attr_unintern(&off);
}

/* --- 12: two knobs, two lanes ------------------------------------------ */
static void check_two_knobs(void)
{
	/* GA-mismatched under the MVPN function, valid under DIMT's. */
	struct attr *a = mkattr("65001", "65001:7:" KA_PARAM " 65002:1:" KA_PARAM);
	struct attr *m = mkattr("65001", "65002:1:" KA_PARAM);
	struct bgp_path_info pi = path(&trusted_ebgp, a);
	struct in_addr umh;
	uint32_t source_as;
	bool got, on_lane;

	reset_state();
	got = bgp_umh_lc_decode(&test_bgp, &pi, test_bgp.mvpn_umh_lc_function,
				BGP_UMH_LC_LANE_MVPN, &test_bgp.mvpn_umh_lc,
				&source_as, &umh);
	want_umh("two knobs, MVPN lane", got, umh, NULL);
	want_count("two knobs, MVPN lane", "MVPN", test_bgp.mvpn_umh_lc.rejected,
		   1);
	want_count("two knobs, MVPN lane", "DIMT", test_bgp.dimt_umh_lc.rejected,
		   0);

	got = dimt(&pi, AFI_IP, &umh, NULL);
	want_umh("two knobs, DIMT lane", got, umh, KA_ADDR);
	want_count("two knobs, DIMT lane", "MVPN", test_bgp.mvpn_umh_lc.rejected,
		   1);
	want_count("two knobs, DIMT lane", "DIMT", test_bgp.dimt_umh_lc.rejected,
		   0);

	/* An fn-1 route is not on the DIMT lane at all. */
	pi = path(&trusted_ebgp, m);
	got = dimt(&pi, AFI_IP, &umh, &on_lane);
	want_umh("two knobs, fn-1 only on DIMT", got, umh, NULL);
	if (on_lane)
		fail("two knobs, fn-1 only on DIMT", "on_lane true");
	want_count("two knobs, fn-1 only on DIMT", "DIMT",
		   test_bgp.dimt_umh_lc.rejected, 0);

	/* DIMT knob off: the DIMT lane goes quiet, MVPN is unaffected. */
	test_bgp.dimt_umh_lc_function = 0;
	pi = path(&trusted_ebgp, a);
	got = dimt(&pi, AFI_IP, &umh, &on_lane);
	want_umh("DIMT knob off", got, umh, NULL);
	if (on_lane)
		fail("DIMT knob off", "on_lane true");
	test_bgp.dimt_umh_lc_function = FN_DIMT;

	bgp_attr_unintern(&a);
	bgp_attr_unintern(&m);
}

int main(void)
{
	/* bgp_attr_unintern() reaches bgp_get_default(), so bm must exist. */
	qobj_init();
	bgp_master_init(event_master_create(NULL), BGP_SOCKET_SNDBUF_SIZE,
			list_new());
	bgp_attr_init();
	/* Interning a large community renders its string, which looks every
	 * tuple up in the community-alias table: bgpd creates it in
	 * bgp_init(), which this test does not run. */
	bgp_community_alias_init();

	test_bgp.as = LOCAL_AS;
	test_bgp.name_pretty = name_pretty;
	test_bgp.peer_self = &self_peer;
	test_bgp.dimt_umh_lc_function = FN_DIMT;
	test_bgp.mvpn_umh_lc_function = FN_MVPN;
	self_peer.bgp = &test_bgp;
	self_peer.as = LOCAL_AS;

	trusted_ebgp.bgp = &test_bgp;
	trusted_ebgp.as = NBR_AS;
	trusted_ebgp.sort = BGP_PEER_EBGP;
	trusted_ebgp.host = (char *)"192.0.2.1";
	SET_FLAG(trusted_ebgp.flags, PEER_FLAG_DIMT_TRUSTED);

	trusted_ibgp.bgp = &test_bgp;
	trusted_ibgp.as = LOCAL_AS;
	trusted_ibgp.sort = BGP_PEER_IBGP;
	trusted_ibgp.host = (char *)"192.0.2.2";
	SET_FLAG(trusted_ibgp.flags, PEER_FLAG_DIMT_TRUSTED);

	untrusted.bgp = &test_bgp;
	untrusted.as = NBR_AS;
	untrusted.sort = BGP_PEER_EBGP;
	untrusted.host = (char *)"192.0.2.3";

	check_has_function();
	check_known_answer();
	check_lowest_tuple_and_mismatches();
	check_as_set();
	check_other_function();
	check_unusable_ranges();
	check_untrusted();
	check_v6();
	check_throttle_independence();
	check_pure_query();
	check_reprocess_once();
	check_two_knobs();

	puts("DIMT UMH large community tests passed");
	return 0;
}
