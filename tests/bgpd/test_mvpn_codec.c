// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Blockcast, Inc. */

#include <zebra.h>

#include "privs.h"
#include "stream.h"

#include "bgpd/bgp_mvpn.h"

struct zebra_privs_t bgpd_privs = {};

static struct ipaddr ipaddr(const char *address)
{
	struct ipaddr ip = {};

	if (strchr(address, ':')) {
		ip.ipa_type = IPADDR_V6;
		assert(inet_pton(AF_INET6, address, &ip.ipaddr_v6) == 1);
	} else {
		ip.ipa_type = IPADDR_V4;
		assert(inet_pton(AF_INET, address, &ip.ipaddr_v4) == 1);
	}
	return ip;
}

static void assert_encoded(struct stream *s, const struct prefix_mvpn *p,
			   uint8_t route_type, uint8_t body_length)
{
	size_t start = stream_get_endp(s);
	const uint8_t *data;

	bgp_mvpn_encode_prefix(s, (const struct prefix *)p, false, 0);
	data = STREAM_DATA(s);
	assert(data[start] == route_type);
	assert(data[start + 1] == body_length);
	assert(stream_get_endp(s) - start == 2 + body_length);
}

int main(void)
{
	struct stream *s = stream_new(BGP_MVPN_MAX_NLRI_LEN * 8);
	struct prefix_mvpn p;
	struct ipaddr v4_src = ipaddr("10.0.0.1");
	struct ipaddr v4_grp = ipaddr("232.1.1.1");
	struct ipaddr v4_originator = ipaddr("192.0.2.1");
	struct ipaddr v4_leaf = ipaddr("192.0.2.2");
	struct ipaddr v6_src = ipaddr("2001:db8::1");
	struct ipaddr v6_grp = ipaddr("ff3e::1");
	struct ipaddr v6_originator = ipaddr("2001:db8:ffff::1");

	/* IPv4 wire lengths remain unchanged. */
	bgp_mvpn_build_prefix_type3(&p, &v4_src, &v4_grp, &v4_originator);
	assert_encoded(s, &p, BGP_MVPN_ROUTE_TYPE_S_PMSI_AD,
		       BGP_MVPN_TYPE3_V4_SPEC_LEN);
	bgp_mvpn_build_prefix_type4(&p, &v4_src, &v4_grp, &v4_originator,
				    &v4_leaf);
	assert_encoded(s, &p, BGP_MVPN_ROUTE_TYPE_LEAF_AD,
		       BGP_MVPN_TYPE4_V4_SPEC_LEN);

	/* The live IPv6 plane uses IPv4 router IDs for both originators. */
	bgp_mvpn_build_prefix_type3(&p, &v6_src, &v6_grp, &v4_originator);
	assert_encoded(s, &p, BGP_MVPN_ROUTE_TYPE_S_PMSI_AD,
		       BGP_MVPN_TYPE3_V6_V4_SPEC_LEN);
	bgp_mvpn_build_prefix_type4(&p, &v6_src, &v6_grp, &v4_originator,
				    &v4_leaf);
	assert_encoded(s, &p, BGP_MVPN_ROUTE_TYPE_LEAF_AD,
		       BGP_MVPN_TYPE4_V6_V4_SPEC_LEN);

	/* A following NLRI starts exactly after each advertised body. */
	bgp_mvpn_build_prefix_type1(&p, &v4_originator);
	assert_encoded(s, &p, BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI,
		       BGP_MVPN_TYPE1_V4_SPEC_LEN);
	bgp_mvpn_build_prefix_type1(&p, &v6_originator);
	assert_encoded(s, &p, BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI,
		       BGP_MVPN_TYPE1_V6_SPEC_LEN);

	stream_free(s);
	puts("MVPN codec tests passed");
	return 0;
}
