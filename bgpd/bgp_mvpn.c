// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MCAST-VPN (SAFI 5) NLRI codec and Global Table Multicast origination.
 *
 * Copyright (C) 2026 Blockcast, Inc.
 *
 * RFC 6514 Route Types 1 (Intra-AS I-PMSI A-D), 3 (S-PMSI A-D), 4 (Leaf
 * A-D), 5 (Source Active A-D) and 7 (C-multicast Source Tree Join), constrained
 * to Global Table Multicast
 * (RFC 7716): the Route Distinguisher is always zero (single global table)
 * and groups are SSM (232.0.0.0/8 for IPv4, ff3x::/32 for IPv6).
 */
#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "log.h"
#include "stream.h"
#include "json.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_mvpn.h"
#include "bgpd/bgp_zebra.h"

/* Bit-length key covering the whole mvpn_addr (route_type, C-S, C-G). Padding
 * inside the struct is memset-zeroed on build, so the radix key is stable.
 */
#define BGP_MVPN_PREFIXLEN (sizeof(struct mvpn_addr) * 8)

static void bgp_mvpn_leaf_from_type3_set(struct bgp *bgp,
					 const struct prefix_mvpn *type3, bool negate);
static bool bgp_mvpn_has_local_join(struct bgp *bgp,
				    const struct ipaddr *src,
				    const struct ipaddr *grp);
static bool bgp_mvpn_type3_leaf_required(struct bgp_dest *dest,
					 const struct bgp *bgp);

/*
 * True if the 8-octet Route Distinguisher is all zero. Under Global Table
 * Multicast (RFC 7716) the RD is always zero (single global table). A non-zero
 * RD denotes a VPN-scoped route this codec cannot represent -- mvpn_addr has no
 * RD field, so two routes differing only in RD would alias to one RIB key.
 */
static bool mvpn_rd_is_zero(const uint8_t rd[8])
{
	static const uint8_t zero[8] = { 0 };

	return memcmp(rd, zero, 8) == 0;
}

/* Wrap a v4 address as a struct ipaddr for the v4 origination paths; zeroes the
 * union's upper octets so the RIB key (whole-struct memcmp) stays stable. */
static struct ipaddr mvpn_ipaddr_v4(struct in_addr a)
{
	struct ipaddr ip = { .ipa_type = IPADDR_V4 };

	ip.ipaddr_v4 = a;
	return ip;
}

/* The AFI a C-multicast-bearing GTM route (Type-5/7) lives under is that of
 * its C-S/C-G: a v6 address keys the AFI_IP6 MCAST-VPN RIB, v4 the AFI_IP one.
 * The RD is always zero (GTM), so the AFI is the only table discriminator.
 * NOT valid for Type-1: its plane is the NLRI's AFI, not the originator's
 * family — RFC 6515 allows a v4 Originating Router address inside the IPv6
 * MCAST-VPN AF (Junos advertises exactly that), so callers must pass the
 * packet AFI for Type-1 instead of deriving it from the address. */
static afi_t bgp_mvpn_prefix_afi(const struct prefix_mvpn *p)
{
	return IS_IPADDR_V6(&p->prefix.src) ? AFI_IP6 : AFI_IP;
}

void bgp_mvpn_build_prefix_type5(struct prefix_mvpn *p, const struct ipaddr *src,
				 const struct ipaddr *grp)
{
	memset(p, 0, sizeof(*p));
	p->family = AF_MVPN;
	p->prefixlen = BGP_MVPN_PREFIXLEN;
	p->prefix.route_type = BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE;
	p->prefix.src = *src;
	p->prefix.grp = *grp;
}

/*
 * Fill a prefix_mvpn for a Type-1 (Intra-AS I-PMSI A-D) route. Memset-zeroed
 * first like the other builders so padding is deterministic and the radix key /
 * prefix_same() memcmp are stable. Type-1 (RFC 6514 Section 4.1) carries no
 * C-S/C-G: the Originating Router's IP Address is overloaded into the src slot
 * (route_type=1 in key byte 0 keeps it distinct from Type-5/7); grp and
 * source_as remain zero.
 */
void bgp_mvpn_build_prefix_type1(struct prefix_mvpn *p, const struct ipaddr *orig_ip)
{
	memset(p, 0, sizeof(*p));
	p->family = AF_MVPN;
	p->prefixlen = BGP_MVPN_PREFIXLEN;
	p->prefix.route_type = BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI;
	p->prefix.src = *orig_ip;
}

void bgp_mvpn_build_prefix_type3(struct prefix_mvpn *p, const struct ipaddr *src,
				 const struct ipaddr *grp, const struct ipaddr *originator)
{
	memset(p, 0, sizeof(*p));
	p->family = AF_MVPN;
	p->prefixlen = BGP_MVPN_PREFIXLEN;
	p->prefix.route_type = BGP_MVPN_ROUTE_TYPE_S_PMSI_AD;
	p->prefix.src = *src;
	p->prefix.grp = *grp;
	p->prefix.originator = *originator;
}

void bgp_mvpn_build_prefix_type4(struct prefix_mvpn *p, const struct ipaddr *src,
				 const struct ipaddr *grp, const struct ipaddr *originator,
				 const struct ipaddr *leaf_originator)
{
	bgp_mvpn_build_prefix_type3(p, src, grp, originator);
	p->prefix.route_type = BGP_MVPN_ROUTE_TYPE_LEAF_AD;
	p->prefix.leaf_originator = *leaf_originator;
}

/*
 * Fill a prefix_mvpn for a Type-7 (C-multicast Source Tree Join) route. Like
 * the Type-5 builder, the struct is memset-zeroed first so that padding is
 * deterministic and the radix key / prefix_same() memcmp are stable. The
 * Source AS is stored in host order in the RIB key so distinct upstream ASes
 * key to distinct routes and the value is renderable from the prefix.
 */
void bgp_mvpn_build_prefix_type7(struct prefix_mvpn *p, uint32_t source_as,
				 const struct ipaddr *src, const struct ipaddr *grp)
{
	memset(p, 0, sizeof(*p));
	p->family = AF_MVPN;
	p->prefixlen = BGP_MVPN_PREFIXLEN;
	p->prefix.route_type = BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN;
	p->prefix.source_as = source_as;
	p->prefix.src = *src;
	p->prefix.grp = *grp;
}

/*
 * Emit a C-address as <length octet><address>: IPv6 => 128 + 16 octets, IPv4
 * => 32 + 4 octets (RFC 6514 Section 4.5 / RFC 6515).
 */
static void bgp_mvpn_put_caddr(struct stream *s, const struct ipaddr *a)
{
	if (IS_IPADDR_V6(a)) {
		stream_putc(s, IPV6_MAX_BITLEN);
		stream_put(s, &a->ipaddr_v6, IPV6_MAX_BYTELEN);
	} else {
		stream_putc(s, IPV4_MAX_BITLEN);
		stream_put(s, &a->ipaddr_v4, IPV4_MAX_BYTELEN);
	}
}

static void bgp_mvpn_put_ipaddr(struct stream *s, const struct ipaddr *a)
{
	if (IS_IPADDR_V6(a))
		stream_put(s, &a->ipaddr_v6, IPV6_MAX_BYTELEN);
	else
		stream_put(s, &a->ipaddr_v4, IPV4_MAX_BYTELEN);
}

static void bgp_mvpn_put_type3_body(struct stream *s, const struct mvpn_addr *m)
{
	stream_put(s, NULL, 8); /* RD = 0 (GTM) */
	bgp_mvpn_put_caddr(s, &m->src);
	bgp_mvpn_put_caddr(s, &m->grp);
	bgp_mvpn_put_ipaddr(s, &m->originator);
}

/*
 * RFC 6514 Section 4.5 Source Active A-D route. The RD is emitted as 8 zero
 * octets per RFC 7716 Global Table Multicast. C-S/C-G are v4 or v6 (RFC 6515);
 * the route-type-specific Length and the per-address Length octets follow the
 * family carried in the prefix.
 */
static void bgp_mvpn_encode_type5(struct stream *s, const struct prefix *p, bool addpath_capable,
				  uint32_t addpath_tx_id)
{
	const struct mvpn_addr *m = &p->u.prefix_mvpn;
	bool v6 = IS_IPADDR_V6(&m->src);

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	stream_putc(s, m->route_type);		    /* Route Type = 5 */
	stream_putc(s, v6 ? BGP_MVPN_TYPE5_V6_SPEC_LEN : BGP_MVPN_TYPE5_V4_SPEC_LEN); /* Length */
	stream_put(s, NULL, 8);			    /* RD = 0 (GTM) */
	bgp_mvpn_put_caddr(s, &m->src);		    /* Multicast Source (C-S) */
	bgp_mvpn_put_caddr(s, &m->grp);		    /* Multicast Group (C-G) */
}

/*
 * RFC 6514 Section 4.6 C-multicast Source Tree Join route. Adds a 4-octet
 * Source AS after the (zero, GTM) RD relative to Type-5. Source AS is held in
 * host order in the prefix and emitted network order via stream_putl. C-S/C-G
 * are v4 or v6.
 */
static void bgp_mvpn_encode_type7(struct stream *s, const struct prefix *p, bool addpath_capable,
				  uint32_t addpath_tx_id)
{
	const struct mvpn_addr *m = &p->u.prefix_mvpn;
	bool v6 = IS_IPADDR_V6(&m->src);

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	stream_putc(s, m->route_type);		    /* Route Type = 7 */
	stream_putc(s, v6 ? BGP_MVPN_TYPE7_V6_SPEC_LEN : BGP_MVPN_TYPE7_V4_SPEC_LEN); /* Length */
	stream_put(s, NULL, 8);			    /* RD = 0 (GTM) */
	stream_putl(s, m->source_as);		    /* Source AS */
	bgp_mvpn_put_caddr(s, &m->src);		    /* Multicast Source (C-S) */
	bgp_mvpn_put_caddr(s, &m->grp);		    /* Multicast Group (C-G) */
}

/*
 * RFC 6514 Section 4.1 Intra-AS I-PMSI A-D route: RD (8, zero under GTM) +
 * Originating Router's IP Address (4 for v4, 16 for v6 per RFC 6515). Carries
 * no C-S/C-G; the endpoint is conveyed out-of-band in the PMSI Tunnel path
 * attribute (Section 5). The originator family is carried in the src slot.
 */
static void bgp_mvpn_encode_type1(struct stream *s, const struct prefix *p, bool addpath_capable,
				  uint32_t addpath_tx_id)
{
	const struct mvpn_addr *m = &p->u.prefix_mvpn;
	bool v6 = IS_IPADDR_V6(&m->src);

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	stream_putc(s, m->route_type);		    /* Route Type = 1 */
	stream_putc(s, v6 ? BGP_MVPN_TYPE1_V6_SPEC_LEN : BGP_MVPN_TYPE1_V4_SPEC_LEN); /* Length */
	stream_put(s, NULL, 8);			    /* RD = 0 (GTM) */
	if (v6)
		stream_put(s, &m->src.ipaddr_v6, IPV6_MAX_BYTELEN); /* Originating Router's IP */
	else
		stream_put(s, &m->src.ipaddr_v4, IPV4_MAX_BYTELEN);
}

static void bgp_mvpn_encode_type3(struct stream *s, const struct prefix *p, bool addpath_capable,
				  uint32_t addpath_tx_id)
{
	const struct mvpn_addr *m = &p->u.prefix_mvpn;
	bool v6 = IS_IPADDR_V6(&m->src);

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	stream_putc(s, BGP_MVPN_ROUTE_TYPE_S_PMSI_AD);
	stream_putc(s, v6 ? BGP_MVPN_TYPE3_V6_SPEC_LEN : BGP_MVPN_TYPE3_V4_SPEC_LEN);
	bgp_mvpn_put_type3_body(s, m);
}

static void bgp_mvpn_encode_type4(struct stream *s, const struct prefix *p, bool addpath_capable,
				  uint32_t addpath_tx_id)
{
	const struct mvpn_addr *m = &p->u.prefix_mvpn;
	bool v6 = IS_IPADDR_V6(&m->src);

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	stream_putc(s, BGP_MVPN_ROUTE_TYPE_LEAF_AD);
	stream_putc(s, v6 ? BGP_MVPN_TYPE4_V6_SPEC_LEN : BGP_MVPN_TYPE4_V4_SPEC_LEN);
	stream_putc(s, BGP_MVPN_ROUTE_TYPE_S_PMSI_AD);
	stream_putc(s, v6 ? BGP_MVPN_TYPE3_V6_SPEC_LEN : BGP_MVPN_TYPE3_V4_SPEC_LEN);
	bgp_mvpn_put_type3_body(s, m);
	bgp_mvpn_put_ipaddr(s, &m->leaf_originator);
}

/*
 * Encode any MCAST-VPN NLRI, dispatching on the prefix's route type. The
 * single entry point the generic path-attribute writer calls (mirroring
 * bgp_evpn_encode_prefix); route-type knowledge stays inside this module.
 */
void bgp_mvpn_encode_prefix(struct stream *s, const struct prefix *p, bool addpath_capable,
			    uint32_t addpath_tx_id)
{
	switch (p->u.prefix_mvpn.route_type) {
	case BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI:
		bgp_mvpn_encode_type1(s, p, addpath_capable, addpath_tx_id);
		break;
	case BGP_MVPN_ROUTE_TYPE_S_PMSI_AD:
		bgp_mvpn_encode_type3(s, p, addpath_capable, addpath_tx_id);
		break;
	case BGP_MVPN_ROUTE_TYPE_LEAF_AD:
		bgp_mvpn_encode_type4(s, p, addpath_capable, addpath_tx_id);
		break;
	case BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN:
		bgp_mvpn_encode_type7(s, p, addpath_capable, addpath_tx_id);
		break;
	default:
		bgp_mvpn_encode_type5(s, p, addpath_capable, addpath_tx_id);
		break;
	}
}

/*
 * Install (or refresh) an MCAST-VPN route (Type 1/5/7) in the SAFI_MCAST_VPN
 * table. Shared by local origination (peer = peer_self, sub_type = STATIC) and
 * the receive path (sub_type = NORMAL). GTM routes are control-plane markers,
 * so they are marked valid without next-hop resolution, mirroring EVPN
 * imported routes.
 */
static void bgp_mvpn_route_install(struct bgp *bgp, struct peer *peer, afi_t afi,
				   const struct prefix_mvpn *p, struct attr *attr, int sub_type)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct attr *attr_new;
	bool leaf_required = false;

	dest = bgp_afi_node_get(bgp->rib[afi][SAFI_MCAST_VPN], afi, SAFI_MCAST_VPN,
				(const struct prefix *)p, NULL);

	attr_new = bgp_attr_intern(attr);

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == peer && pi->type == ZEBRA_ROUTE_BGP && pi->sub_type == sub_type)
			break;

	if (pi) {
		if (attrhash_cmp(pi->attr, attr_new)) {
			bgp_dest_unlock_node(dest);
			bgp_attr_unintern(&attr_new);
			return;
		}
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;
		pi->uptime = monotime(NULL);
		bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);
	} else {
		pi = info_make(ZEBRA_ROUTE_BGP, sub_type, 0, peer, attr_new, dest);
		SET_FLAG(pi->flags, BGP_PATH_VALID);
		bgp_path_info_add(dest, pi);
	}

	bgp_process(bgp, dest, pi, afi, SAFI_MCAST_VPN);
	if (p->prefix.route_type == BGP_MVPN_ROUTE_TYPE_S_PMSI_AD &&
	    peer != bgp->peer_self && sub_type == BGP_ROUTE_NORMAL)
		leaf_required = bgp_mvpn_type3_leaf_required(dest, bgp);
	bgp_dest_unlock_node(dest);

	/* A receiver join and its matching Type-3 can arrive in either order,
	 * especially during bgpd/pimd restart replay. Reconcile when the remote
	 * Type-3 arrives as well as when pimd reports the join. */
	if (p->prefix.route_type == BGP_MVPN_ROUTE_TYPE_S_PMSI_AD &&
	    peer != bgp->peer_self && sub_type == BGP_ROUTE_NORMAL) {
		bgp_mvpn_leaf_from_type3_set(
			bgp, p,
			!leaf_required ||
				!bgp_mvpn_has_local_join(bgp, &p->prefix.src,
						 &p->prefix.grp));
	}
}

/* Withdraw an MCAST-VPN route matching (peer, sub_type) from the table. */
static void bgp_mvpn_route_remove(struct bgp *bgp, struct peer *peer, afi_t afi,
				  const struct prefix_mvpn *p, int sub_type)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	bool reconcile_leaf = false;
	bool leaf_required = false;

	dest = bgp_safi_node_lookup(bgp->rib[afi][SAFI_MCAST_VPN], SAFI_MCAST_VPN,
				    (const struct prefix *)p, NULL);
	if (!dest)
		return;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == peer && pi->type == ZEBRA_ROUTE_BGP && pi->sub_type == sub_type)
			break;

	if (pi) {
		bgp_unlink_nexthop(pi);
		bgp_path_info_mark_for_delete(dest, pi);
		bgp_process(bgp, dest, pi, afi, SAFI_MCAST_VPN);
		if (p->prefix.route_type == BGP_MVPN_ROUTE_TYPE_S_PMSI_AD &&
		    peer != bgp->peer_self && sub_type == BGP_ROUTE_NORMAL) {
			reconcile_leaf = true;
			leaf_required = bgp_mvpn_type3_leaf_required(dest, bgp);
		}
	}

	bgp_dest_unlock_node(dest);

	if (reconcile_leaf)
		bgp_mvpn_leaf_from_type3_set(
			bgp, p,
			!leaf_required ||
				!bgp_mvpn_has_local_join(bgp, &p->prefix.src,
						 &p->prefix.grp));
}

/*
 * Read one MCAST-VPN C-address preceded by its Length octet's value (len_bits,
 * already consumed by the caller): 32 => a 4-octet IPv4 address, 128 => a
 * 16-octet IPv6 address (RFC 6514 Section 4.5 / RFC 6515). Fills *a with the
 * matching family. Returns MVPN_CADDR_BADLEN for any other length and
 * MVPN_CADDR_TRUNC if the stream is short.
 */
enum mvpn_caddr_result { MVPN_CADDR_OK, MVPN_CADDR_BADLEN, MVPN_CADDR_TRUNC };

static enum mvpn_caddr_result bgp_mvpn_read_caddr(struct stream *s, struct ipaddr *a,
						  uint8_t len_bits)
{
	if (len_bits == IPV4_MAX_BITLEN) {
		a->ipa_type = IPADDR_V4;
		STREAM_GET(&a->ipaddr_v4, s, IPV4_MAX_BYTELEN);
	} else if (len_bits == IPV6_MAX_BITLEN) {
		a->ipa_type = IPADDR_V6;
		STREAM_GET(&a->ipaddr_v6, s, IPV6_MAX_BYTELEN);
	} else {
		return MVPN_CADDR_BADLEN;
	}
	return MVPN_CADDR_OK;
stream_failure:
	return MVPN_CADDR_TRUNC;
}

/*
 * Parse the (S,G)-bearing body shared by Type-3 (S-PMSI A-D), Type-5 (Source
 * Active) and Type-7 (C-multicast Source Tree Join): RD, the Type-7-only
 * 4-octet Source AS, then C-S and C-G each preceded by a per-address Length
 * octet cross-checked against the route-type-specific Length.
 *
 * Returns BGP_NLRI_PARSE_OK on success, a BGP_NLRI_PARSE_ERROR_* (logged) on
 * bad framing, or -1 on stream truncation (the caller's stream_failure path).
 */
static int bgp_mvpn_parse_sg_body(struct peer *peer, struct stream *data, uint8_t route_type,
				  uint8_t length, uint8_t rd[8], struct ipaddr *src,
				  struct ipaddr *grp, uint32_t *source_as)
{
	bool type7 = route_type == BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN;
	bool type3 = route_type == BGP_MVPN_ROUTE_TYPE_S_PMSI_AD;
	uint8_t v4_spec_len = type7   ? BGP_MVPN_TYPE7_V4_SPEC_LEN
			      : type3 ? BGP_MVPN_TYPE3_V4_SPEC_LEN
				      : BGP_MVPN_TYPE5_V4_SPEC_LEN;
	uint8_t v6_spec_len = type7   ? BGP_MVPN_TYPE7_V6_SPEC_LEN
			      : type3 ? BGP_MVPN_TYPE3_V6_SPEC_LEN
				      : BGP_MVPN_TYPE5_V6_SPEC_LEN;
	uint8_t src_len;
	uint8_t grp_len;

	if (length != v4_spec_len && length != v6_spec_len) {
		flog_err(EC_BGP_UPDATE_RCV,
			 "%s [Error] MVPN Type-%u bad length %u (expected %u or %u)", peer->host,
			 route_type, length, v4_spec_len, v6_spec_len);
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
	}

	/* RD (8 octets): read for validation after the body is fully consumed
	 * (GTM requires RD == 0). */
	STREAM_GET(rd, data, 8);

	if (type7)
		STREAM_GETL(data, *source_as);

	STREAM_GETC(data, src_len);
	switch (bgp_mvpn_read_caddr(data, src, src_len)) {
	case MVPN_CADDR_OK:
		break;
	case MVPN_CADDR_TRUNC:
		goto stream_failure;
	case MVPN_CADDR_BADLEN:
		flog_err(EC_BGP_UPDATE_RCV, "%s [Error] MVPN Type-%u bad source addr length %u",
			 peer->host, route_type, src_len);
		return BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
	}

	STREAM_GETC(data, grp_len);
	switch (bgp_mvpn_read_caddr(data, grp, grp_len)) {
	case MVPN_CADDR_OK:
		break;
	case MVPN_CADDR_TRUNC:
		goto stream_failure;
	case MVPN_CADDR_BADLEN:
		flog_err(EC_BGP_UPDATE_RCV, "%s [Error] MVPN Type-%u bad group addr length %u",
			 peer->host, route_type, grp_len);
		return BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
	}

	/* C-S and C-G share a family, and the route Length must match it. */
	if (src_len != grp_len ||
	    length != (src_len == IPV6_MAX_BITLEN ? v6_spec_len : v4_spec_len)) {
		flog_err(EC_BGP_UPDATE_RCV,
			 "%s [Error] MVPN Type-%u addr family/length mismatch (src %u grp %u len %u)",
			 peer->host, route_type, src_len, grp_len, length);
		return BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
	}

	return BGP_NLRI_PARSE_OK;
stream_failure:
	return -1;
}

static int bgp_mvpn_read_originator(struct stream *data, struct ipaddr *originator, bool v6)
{
	memset(originator, 0, sizeof(*originator));
	if (v6) {
		originator->ipa_type = IPADDR_V6;
		STREAM_GET(&originator->ipaddr_v6, data, IPV6_MAX_BYTELEN);
	} else {
		originator->ipa_type = IPADDR_V4;
		STREAM_GET(&originator->ipaddr_v4, data, IPV4_MAX_BYTELEN);
	}
	return BGP_NLRI_PARSE_OK;
stream_failure:
	return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
}

/*
 * Parse a received MCAST-VPN NLRI. Each NLRI is Route Type(1) + Length(1) +
 * route-type-specific. Types 1, 3, 4, 5 and 7 are decoded; other types are
 * skipped using the on-wire Length so the stream stays framed.
 *
 * Dual-stack (RFC 6515): C-S/C-G may be IPv4 or IPv6, distinguished by each
 * address's Length octet and cross-checked against the route-type-specific
 * Length. src and grp must share a family. Type-1's originator is likewise v4
 * or v6 per the route Length.
 */
int bgp_nlri_parse_mvpn(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			bool mp_withdraw)
{
	struct stream *data;
	struct prefix_mvpn p;
	uint8_t route_type;
	uint8_t length;
	uint8_t rd[8];
	struct ipaddr src;
	struct ipaddr grp;
	struct ipaddr originator;
	struct ipaddr leaf_originator;
	uint32_t source_as;
	bool addpath_capable;
	uint32_t addpath_id;
	bool is_withdraw;
	int ret = BGP_NLRI_PARSE_OK;

	/*
	 * A withdraw carrying only AFI/SAFI (empty NLRI, packet->length == 0) is
	 * valid and means "nothing to withdraw here". stream_new(0) asserts, so
	 * return success without allocating. The EVPN parser tolerates this
	 * implicitly by iterating pnt..lim; this codec wraps the NLRI in a stream
	 * sized by the (untrusted) length, so it must guard explicitly -- a peer
	 * sending a 3-octet MP_UNREACH (AFI+SAFI, no NLRI) would otherwise abort
	 * every bgpd in the AS with SAFI-5 active.
	 */
	if (packet->length == 0)
		return BGP_NLRI_PARSE_OK;

	data = stream_new(packet->length);
	stream_put(data, packet->nlri, packet->length);

	addpath_capable = bgp_addpath_encode_rx(peer, packet->afi, packet->safi);

	/*
	 * A NULL attr on the reachable path is BGP's treat-as-withdraw signal
	 * (RFC 7606): the UPDATE carried malformed attributes, so its NLRI must
	 * be withdrawn rather than installed. bgp_mvpn_route_install() would
	 * dereference the NULL attr (bgp_attr_intern), so fold it into the
	 * withdraw decision here. Both mp_withdraw and attr are loop-invariant.
	 */
	is_withdraw = mp_withdraw || attr == NULL;

	while (STREAM_READABLE(data) > 0) {
		addpath_id = 0;
		source_as = 0;
		/* Zero the C-address slots each iteration so a v4 read leaves the
		 * ipaddr union's upper octets clear -- the whole struct feeds the
		 * RIB key via prefix_same()/memcmp. */
		memset(&src, 0, sizeof(src));
		memset(&grp, 0, sizeof(grp));
		memset(&originator, 0, sizeof(originator));
		memset(&leaf_originator, 0, sizeof(leaf_originator));
		/* Consumed to stay framed; addpath is not plumbed into the MVPN
		 * install path (bgp_mvpn_route_install keys on peer alone). */
		if (addpath_capable)
			STREAM_GETL(data, addpath_id);

		STREAM_GETC(data, route_type);
		STREAM_GETC(data, length);

		if (STREAM_READABLE(data) < length) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%s [Error] MVPN NLRI length %u exceeds remaining %zu",
				 peer->host, length, STREAM_READABLE(data));
			ret = BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
			goto done;
		}

		switch (route_type) {
		case BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI:
			if (length != BGP_MVPN_TYPE1_V4_SPEC_LEN &&
			    length != BGP_MVPN_TYPE1_V6_SPEC_LEN) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-1 bad length %u (expected %u or %u)",
					 peer->host, length, BGP_MVPN_TYPE1_V4_SPEC_LEN,
					 BGP_MVPN_TYPE1_V6_SPEC_LEN);
				ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
				goto done;
			}

			/* RD (8 octets): read for validation after the body is
			 * fully consumed (GTM requires RD == 0). */
			STREAM_GET(rd, data, 8);

			/* Originating Router's IP Address -> src slot; v4 or v6
			 * per the route-type-specific Length. */
			if (length == BGP_MVPN_TYPE1_V6_SPEC_LEN) {
				src.ipa_type = IPADDR_V6;
				STREAM_GET(&src.ipaddr_v6, data, IPV6_MAX_BYTELEN);
			} else {
				src.ipa_type = IPADDR_V4;
				STREAM_GET(&src.ipaddr_v4, data, IPV4_MAX_BYTELEN);
			}

			bgp_mvpn_build_prefix_type1(&p, &src);
			break;

		case BGP_MVPN_ROUTE_TYPE_S_PMSI_AD: {
			bool v6 = length == BGP_MVPN_TYPE3_V6_SPEC_LEN;

			ret = bgp_mvpn_parse_sg_body(peer, data, route_type, length, rd, &src,
						     &grp, &source_as);
			if (ret == -1)
				goto stream_failure;
			if (ret != BGP_NLRI_PARSE_OK)
				goto done;
			ret = bgp_mvpn_read_originator(data, &originator, v6);
			if (ret != BGP_NLRI_PARSE_OK)
				goto stream_failure;
			bgp_mvpn_build_prefix_type3(&p, &src, &grp, &originator);
			break;
		}

		case BGP_MVPN_ROUTE_TYPE_LEAF_AD: {
			uint8_t key_type;
			uint8_t key_length;
			bool v6;

			if (length != BGP_MVPN_TYPE4_V4_SPEC_LEN &&
			    length != BGP_MVPN_TYPE4_V6_SPEC_LEN) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-4 bad length %u (expected %u or %u)",
					 peer->host, length, BGP_MVPN_TYPE4_V4_SPEC_LEN,
					 BGP_MVPN_TYPE4_V6_SPEC_LEN);
				ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
				goto done;
			}

			v6 = length == BGP_MVPN_TYPE4_V6_SPEC_LEN;
			STREAM_GETC(data, key_type);
			STREAM_GETC(data, key_length);
			if (key_type != BGP_MVPN_ROUTE_TYPE_S_PMSI_AD ||
			    key_length != (v6 ? BGP_MVPN_TYPE3_V6_SPEC_LEN
					      : BGP_MVPN_TYPE3_V4_SPEC_LEN)) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-4 malformed S-PMSI route key (type %u length %u)",
					 peer->host, key_type, key_length);
				/* The outer Type-4 length is valid, so its boundary is
				 * trustworthy even though the embedded route key is not.
				 * Discard this NLRI without resetting the BGP session. */
				stream_forward_getp(data, length - 2);
				continue;
			}

			ret = bgp_mvpn_parse_sg_body(peer, data, key_type, key_length, rd, &src,
						     &grp, &source_as);
			if (ret == -1)
				goto stream_failure;
			if (ret != BGP_NLRI_PARSE_OK)
				goto done;
			if (bgp_mvpn_read_originator(data, &originator, v6) != BGP_NLRI_PARSE_OK ||
			    bgp_mvpn_read_originator(data, &leaf_originator, v6) !=
				    BGP_NLRI_PARSE_OK)
				goto stream_failure;
			bgp_mvpn_build_prefix_type4(&p, &src, &grp, &originator, &leaf_originator);
			break;
		}

		case BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE:
		case BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN:
			ret = bgp_mvpn_parse_sg_body(peer, data, route_type, length, rd, &src,
						     &grp, &source_as);
			if (ret == -1)
				goto stream_failure;
			if (ret != BGP_NLRI_PARSE_OK)
				goto done;

			if (route_type == BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN)
				bgp_mvpn_build_prefix_type7(&p, source_as, &src, &grp);
			else
				bgp_mvpn_build_prefix_type5(&p, &src, &grp);
			break;

		default:
			/* Unsupported route type: skip its body, stay framed. */
			stream_forward_getp(data, length);
			continue;
		}

		/*
		 * Semantic validation on a fully-decoded, correctly-framed NLRI.
		 * Unlike the length checks above (which abort because the framing
		 * is untrustworthy), a valid-framing/bad-value NLRI is dropped and
		 * parsing continues (RFC 7606 treat-as-discard spirit) -- refusing
		 * to install without letting a misbehaving peer weaponize a
		 * session reset. getp is already at the next NLRI here.
		 */
		if (!mvpn_rd_is_zero(rd)) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%s [Error] MVPN Type-%u non-zero RD under GTM (RFC 7716); dropping route",
				 peer->host, route_type);
			continue;
		}

		if (route_type == BGP_MVPN_ROUTE_TYPE_S_PMSI_AD ||
		    route_type == BGP_MVPN_ROUTE_TYPE_LEAF_AD ||
		    route_type == BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE ||
		    route_type == BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN) {
			bool ssm = IS_IPADDR_V6(&grp) ? ipv6_mcast_ssm(&grp.ipaddr_v6)
						      : ipv4_mcast_ssm(&grp.ipaddr_v4);

			if (!ssm) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-%u group %pIA outside SSM range (232.0.0.0/8 or ff3x::/32); dropping route",
					 peer->host, route_type, &grp);
				continue;
			}
		}

		/*
		 * A GTM Type-1 (Intra-AS I-PMSI A-D) is only meaningful with an
		 * Ingress-Replication PMSI Tunnel attribute (RFC 6514 Section 5).
		 * Checked on install only; a withdraw (including the NULL-attr
		 * treat-as-withdraw case) matches on the NLRI key alone.
		 */
		if (route_type == BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI && !is_withdraw &&
		    bgp_attr_get_pmsi_tnl_type(attr) != PMSI_TNLTYPE_INGR_REPL) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%s [Error] MVPN Type-1 without Ingress-Replication PMSI Tunnel; dropping route",
				 peer->host);
			continue;
		}

		/* An S-PMSI A-D route binds its selective tunnel through the PMSI
		 * Tunnel attribute (RFC 6514 Section 5). Check installs only so an
		 * MP_UNREACH can still remove the NLRI by key without attributes. */
		if (route_type == BGP_MVPN_ROUTE_TYPE_S_PMSI_AD && !is_withdraw &&
		    bgp_attr_get_pmsi_tnl_type(attr) != PMSI_TNLTYPE_INGR_REPL) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%s [Error] MVPN Type-3 without Ingress-Replication PMSI Tunnel; dropping route",
				 peer->host);
			continue;
		}

		/* Type-1's plane is the AF the NLRI arrived on (RFC 6515 permits a
		 * v4 originator inside the IPv6 AF); Type-5/7 key off the C-S/C-G
		 * family, which the length checks above already tied to the body.
		 */
		afi_t rib_afi = (route_type == BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI)
					? packet->afi
					: bgp_mvpn_prefix_afi(&p);

		if (is_withdraw)
			bgp_mvpn_route_remove(peer->bgp, peer, rib_afi, &p, BGP_ROUTE_NORMAL);
		else
			bgp_mvpn_route_install(peer->bgp, peer, rib_afi, &p, attr,
					       BGP_ROUTE_NORMAL);
	}

done:
	stream_free(data);
	return ret;

stream_failure:
	flog_err(EC_BGP_UPDATE_RCV, "%s [Error] MVPN NLRI parse error (truncated NLRI of size %u)",
		 peer->host, packet->length);
	stream_free(data);
	return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
}

/*
 * Attach an IP-address-specific Route Target (Global Administrator = ga, Local
 * Administrator = 0, transitive) to a locally-originated route. Both GTM RTs
 * this codec emits share this shape and differ only by which address fills the
 * Global Administrator and by which route type carries them (RFC 7716): the
 * Type-7 C-multicast join carries the upstream PE address (Sections 2.2 / 2.9),
 * while the Intra-AS AD (Type-1) and Source Active (Type-5) routes carry the GTM
 * global-table RT (bgp_mvpn_attach_gtm_rt). The ecommunity is left un-interned;
 * the caller's route_install() interns it and a later bgp_attr_flush() releases
 * this stack reference.
 */
static void bgp_mvpn_attach_ip_rt(struct attr *attr, struct in_addr ga)
{
	struct ecommunity_val eval;
	struct ecommunity *ecom;

	encode_route_target_ip(&ga, 0, &eval, true);
	ecom = ecommunity_new();
	ecommunity_add_val(ecom, &eval, false, false);
	bgp_attr_set_ecommunity(attr, ecom);
}

/*
 * Attach the GTM global-table Route Target to a locally-originated
 * non-C-multicast MVPN route (Intra-AS AD Type-1, Source Active Type-5). Global
 * Table Multicast has no VRF and thus no configured RT; the import/export target
 * is a fixed IPv4-address-specific RT whose Global Administrator is 0.0.0.0 (the
 * global-table sentinel) and Local Administrator is 0. A GTM receiver imports the
 * route only on this exact RT -- it rejects an RT-less route and a group-address
 * RT alike. (Verified against Junos mpls-internet-multicast, whose auto-generated
 * __vrf-mvpn-import-target-*-internal__ policy matches exactly [target:0.0.0.0:0].)
 */
static void bgp_mvpn_attach_gtm_rt(struct attr *attr)
{
	struct in_addr gtm_global_table = { .s_addr = INADDR_ANY };

	bgp_mvpn_attach_ip_rt(attr, gtm_global_table);
}

/*
 * Read the RFC 6514 Section 5 communities off one path's attribute set:
 *
 *   *upstream (Upstream Multicast Hop / upstream PE, Section 5.1): the RT on
 *   the C-multicast join MUST equal the VRF Route Import extended community
 *   (IP-address-specific, sub-type 0x0b; Junos "rt-import") the source PE
 *   attaches to the unicast route toward C-S. The receiver echoes its Global
 *   Administrator as a Route Target on the Type-7; the source's auto-generated
 *   __vrf-mvpn-import-cmcast-*-internal__ policy imports the join only on
 *   exactly that RT (empirically confirmed on MX204 22.2R3: it keys the cmcast
 *   import on the lo0 PE address, e.g. target:10.255.255.254:0). A plain
 *   IP-address-specific Route Target (0x02) is the fallback, covering an
 *   FRR<->FRR source tagged with "set extcommunity rt <PE>:0".
 *
 *   *source_as (Section 4.6): from the Source-AS Extended Community
 *   (Four-Octet-AS-Specific, sub-type ECOMMUNITY_SOURCE_AS; Junos "src-as").
 *
 * Each output is written only when its community is present.
 */
static void bgp_mvpn_resolve_from_ecommunity(struct bgp_path_info *pi, uint32_t *source_as,
					     struct in_addr *upstream)
{
	struct ecommunity *ecom = bgp_attr_get_ecommunity(pi->attr);
	struct ecommunity_val *eval;

	if (!ecom)
		return;

	eval = ecommunity_lookup(ecom, ECOMMUNITY_ENCODE_AS4, ECOMMUNITY_SOURCE_AS);
	if (eval)
		/* Four-Octet-AS-Specific wire layout: type, subtype, Global
		 * Administrator (4-octet AS), Local Administrator (2). */
		ptr_get_be32(&eval->val[2], source_as);

	eval = ecommunity_lookup(ecom, ECOMMUNITY_ENCODE_IP, ECOMMUNITY_VRF_ROUTE_IMPORT);
	if (!eval)
		eval = ecommunity_lookup(ecom, ECOMMUNITY_ENCODE_IP, ECOMMUNITY_ROUTE_TARGET);
	if (eval)
		/* IP-address-specific wire layout: type, subtype, Global
		 * Administrator (4, network order), Local Administrator (2). */
		memcpy(&upstream->s_addr, &eval->val[2], IPV4_MAX_BYTELEN);
}

/*
 * Resolve the RFC 6514 Section 5 communities (Source AS, upstream PE) for a
 * pimd-driven Type-7 from the unicast route toward C-S, in one longest-match
 * lookup, reading the selected (best) path only.
 *
 * The route lives in the v4 or v6 unicast RIB per the C-S family; both
 * communities carry v4-core PE/AS values either way.
 *
 * Both values come off the ONE selected path, as a unit (RFC 6513 Section 5.1
 * describes UMH selection as picking a route, then reading its attributes): a
 * non-best path's communities describe an upstream the RIB will not forward
 * through, and filling each field from whichever path happens to carry it can
 * yield a (Source AS, upstream) pair no single advertisement carried.
 */
static void bgp_mvpn_resolve_from_source_route(struct bgp *bgp, const struct ipaddr *src,
					       uint32_t *source_as, struct in_addr *upstream)
{
	struct prefix psrc = {};
	afi_t afi = IS_IPADDR_V6(src) ? AFI_IP6 : AFI_IP;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	if (IS_IPADDR_V6(src)) {
		psrc.family = AF_INET6;
		psrc.prefixlen = IPV6_MAX_BITLEN;
		psrc.u.prefix6 = src->ipaddr_v6;
	} else {
		psrc.family = AF_INET;
		psrc.prefixlen = IPV4_MAX_BITLEN;
		psrc.u.prefix4 = src->ipaddr_v4;
	}

	dest = bgp_node_match(bgp->rib[afi][SAFI_UNICAST], &psrc);
	if (!dest)
		return;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
			break;

	if (pi && pi->type == ZEBRA_ROUTE_BGP)
		bgp_mvpn_resolve_from_ecommunity(pi, source_as, upstream);

	bgp_dest_unlock_node(dest);
}

/*
 * Upstream-PE fallback when the unicast route toward C-S carries no
 * route-import RT: the next hop of the received Source Active route. Only
 * correct when the SA originator's address is preserved end to end (iBGP, or a
 * peer that attaches no route-import RT such as FRR<->FRR); eBGP rewrites the
 * SA next hop to the peering address, so relying on it there produces a
 * non-matching RT. The upstream PE address is v4 in a v4 core for either C-S
 * family: the SA carries mp_nexthop_global_in = the originating PE's router-id
 * (see bgp_mvpn_source_active_set), so this arm serves both planes -- look up
 * the SA in the (C-S)-family MCAST-VPN RIB.
 */
static void bgp_mvpn_resolve_upstream_from_sa(struct bgp *bgp, const struct ipaddr *src,
					      const struct ipaddr *grp, struct in_addr *upstream)
{
	struct prefix_mvpn sa;
	afi_t afi = IS_IPADDR_V6(src) ? AFI_IP6 : AFI_IP;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	bgp_mvpn_build_prefix_type5(&sa, src, grp);
	dest = bgp_safi_node_lookup(bgp->rib[afi][SAFI_MCAST_VPN], SAFI_MCAST_VPN,
				    (const struct prefix *)&sa, NULL);
	if (!dest)
		return;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (pi->type != ZEBRA_ROUTE_BGP)
			continue;
		if (pi->attr->mp_nexthop_global_in.s_addr == INADDR_ANY)
			continue;
		*upstream = pi->attr->mp_nexthop_global_in;
		break;
	}

	bgp_dest_unlock_node(dest);
}

/*
 * Configure or withdraw a locally-originated GTM Source Active route. Attr is a
 * self-sourced IGP route with the router-id as next hop.
 */
int bgp_mvpn_source_active_set(struct bgp *bgp, const struct ipaddr *src, const struct ipaddr *grp,
			       bool negate)
{
	struct prefix_mvpn p;
	struct attr attr;

	bgp_mvpn_build_prefix_type5(&p, src, grp);

	if (negate) {
		bgp_mvpn_route_remove(bgp, bgp->peer_self, bgp_mvpn_prefix_afi(&p), &p,
				      BGP_ROUTE_STATIC);
		return CMD_SUCCESS;
	}

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	bgp_attr_set(&attr, BGP_ATTR_NEXT_HOP);
	attr.nexthop = bgp->router_id;
	attr.mp_nexthop_global_in = bgp->router_id;
	attr.mp_nexthop_len = IPV4_MAX_BYTELEN;

	/*
	 * GTM global-table Route Target (target:0.0.0.0:0). A GTM receiver imports
	 * the Source Active route only on this fixed target; it rejects an RT-less
	 * SA route and a group-address RT alike (RFC 7716 Section 2.2, verified
	 * against Junos mpls-internet-multicast).
	 */
	bgp_mvpn_attach_gtm_rt(&attr);

	bgp_mvpn_route_install(bgp, bgp->peer_self, bgp_mvpn_prefix_afi(&p), &p, &attr,
			       BGP_ROUTE_STATIC);

	/*
	 * route_install interned the attr (and with it the ecommunity, refcnt
	 * 0->1 held by the stored path). bgp_attr_flush is refcnt-aware: it frees
	 * the ecommunity only if it was never interned, so here it just releases
	 * this stack attr's borrowed pointer without a double free. aspath was
	 * interned by bgp_attr_default_set, so drop that local ref too.
	 */
	bgp_attr_flush(&attr);
	aspath_unintern(&attr.aspath);
	return CMD_SUCCESS;
}

static void bgp_mvpn_remove_local_selective_routes(struct bgp *bgp,
						   uint8_t route_type,
						   const struct ipaddr *src,
						   const struct ipaddr *grp,
						   const struct ipaddr *originator)
{
	afi_t afi;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		struct bgp_table *table = bgp->rib[afi][SAFI_MCAST_VPN];
		struct bgp_dest *dest;

		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix_mvpn *p =
				(const struct prefix_mvpn *)bgp_dest_get_prefix(dest);
			struct bgp_path_info *pi;

			if (p->family != AF_MVPN || p->prefix.route_type != route_type ||
			    (src && ipaddr_cmp(&p->prefix.src, src) != 0) ||
			    (grp && ipaddr_cmp(&p->prefix.grp, grp) != 0) ||
			    (originator &&
			     ipaddr_cmp(&p->prefix.originator, originator) != 0))
				continue;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
				if (pi->peer != bgp->peer_self ||
				    pi->sub_type != BGP_ROUTE_STATIC ||
				    CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
					continue;
				bgp_unlink_nexthop(pi);
				bgp_path_info_mark_for_delete(dest, pi);
				bgp_process(bgp, dest, pi, afi, SAFI_MCAST_VPN);
			}
		}
	}
}

int bgp_mvpn_selective_source_set(struct bgp *bgp, const struct ipaddr *src,
				  const struct ipaddr *grp, bool negate)
{
	struct prefix_mvpn p;
	struct attr attr;
	struct in6_addr tunn_id = {};
	struct ipaddr originator;

	/* GTM identifies PEs by the IPv4 BGP router-id in both planes (RFC 6515:
	 * a v4 Originating Router address inside the IPv6 MCAST-VPN AF), so v6
	 * selective origination reuses it -- no separate IPv6 PE address is
	 * needed. AFI is keyed off the source family via bgp_mvpn_prefix_afi(),
	 * mirroring the non-selective Source-Active path above. */
	if (!bgp->peer_self)
		return CMD_SUCCESS;
	if (negate) {
		bgp_mvpn_remove_local_selective_routes(
			bgp, BGP_MVPN_ROUTE_TYPE_S_PMSI_AD, src, grp, NULL);
		return CMD_SUCCESS;
	}
	if (bgp->router_id.s_addr == INADDR_ANY)
		return CMD_SUCCESS;

	originator = mvpn_ipaddr_v4(bgp->router_id);
	bgp_mvpn_build_prefix_type3(&p, src, grp, &originator);

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	bgp_attr_set(&attr, BGP_ATTR_NEXT_HOP);
	attr.nexthop = bgp->router_id;
	attr.mp_nexthop_global_in = bgp->router_id;
	attr.mp_nexthop_len = IPV4_MAX_BYTELEN;
	bgp_attr_set(&attr, BGP_ATTR_PMSI_TUNNEL);
	bgp_attr_set_pmsi_tnl_type(&attr, PMSI_TNLTYPE_INGR_REPL);
	bgp_attr_set_pmsi_tnl_flags(&attr,
				    PMSI_TNL_FLAG_LEAF_INFO_REQUIRED);
	ipv4_to_ipv4_mapped_ipv6(&tunn_id, bgp->router_id);
	bgp_attr_set_tunn_id(&attr, &tunn_id);
	attr.label = 0;
	bgp_mvpn_attach_gtm_rt(&attr);
	bgp_mvpn_route_install(bgp, bgp->peer_self, bgp_mvpn_prefix_afi(&p), &p, &attr,
			       BGP_ROUTE_STATIC);
	bgp_attr_flush(&attr);
	aspath_unintern(&attr.aspath);
	return CMD_SUCCESS;
}

bool bgp_mvpn_gtm_active(struct bgp *bgp)
{
	return bgp_afi_safi_peer_exists(bgp, AFI_IP, SAFI_MCAST_VPN) ||
	       bgp_afi_safi_peer_exists(bgp, AFI_IP6, SAFI_MCAST_VPN);
}

/*
 * Auto-originate this PE's Intra-AS I-PMSI A-D (Type-1) route (RFC 6514 Section
 * 4.1) with a PMSI Tunnel attribute (Section 5) advertising Ingress Replication
 * and this PE's unicast address (the router-id) as the tunnel endpoint. The
 * PMSI attribute reuses the existing EVPN ingress-replication encode path: the
 * generic path-attribute writer emits attr type 22 whenever the attr carries a
 * PMSI tunnel type, so no new encoder is needed.
 *
 * Self-guarding and idempotent. It is a no-op until BOTH the GTM MVPN AF is
 * active and the router-id (Originating Router's IP) is known; whichever of the
 * two lifecycle hooks (peer AF activate / router-id set) satisfies both first
 * installs the route, and re-invocation deduplicates via attrhash_cmp.
 *
 */
void bgp_mvpn_originate_type1(struct bgp *bgp)
{
	struct prefix_mvpn p;
	struct attr attr;
	struct in6_addr tunn_id = {};
	bool active[AFI_MAX] = {};
	afi_t afi;

	if (bgp->router_id.s_addr == INADDR_ANY || !bgp->peer_self)
		return;

	active[AFI_IP] = bgp_afi_safi_peer_exists(bgp, AFI_IP, SAFI_MCAST_VPN);
	active[AFI_IP6] = bgp_afi_safi_peer_exists(bgp, AFI_IP6, SAFI_MCAST_VPN);
	if (!active[AFI_IP] && !active[AFI_IP6])
		return;

	/* GTM just became (or remains) active: make sure the pimd SG relay
	 * subscription exists (no-op if zebra is not yet connected; the
	 * zebra-connect hook covers that ordering). */
	bgp_zebra_mvpn_sg_subscribe();

	struct ipaddr orig = mvpn_ipaddr_v4(bgp->router_id);

	bgp_mvpn_build_prefix_type1(&p, &orig);

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	bgp_attr_set(&attr, BGP_ATTR_NEXT_HOP);
	attr.nexthop = bgp->router_id;
	attr.mp_nexthop_global_in = bgp->router_id;
	attr.mp_nexthop_len = IPV4_MAX_BYTELEN;

	/* Attach the Ingress-Replication PMSI Tunnel attribute (endpoint = this
	 * PE). Mirrors the EVPN type-3 IMET path (bgp_evpn.c); the setter claims
	 * an attr_extra slot for the tunnel id, discarded below after intern.
	 */
	bgp_attr_set(&attr, BGP_ATTR_PMSI_TUNNEL);
	bgp_attr_set_pmsi_tnl_type(&attr, PMSI_TNLTYPE_INGR_REPL);
	ipv4_to_ipv4_mapped_ipv6(&tunn_id, bgp->router_id);
	bgp_attr_set_tunn_id(&attr, &tunn_id);

	/*
	 * RFC 6514 Section 5: a zero MPLS Label in the PMSI Tunnel attribute
	 * means the tunnel is unlabeled — which GTM label-free IP ingress
	 * replication is. The PMSI encoder emits attr->label's first three
	 * bytes verbatim, so bgp_attr_default_set's MPLS_INVALID_LABEL
	 * (0xFFFDFFFF) would otherwise go out as label 0xFFFFF; a Junos
	 * 22.2R3 GTM receiver imports such an A-D route but keeps it hidden,
	 * unable to instantiate an IR leaf against the bogus label.
	 */
	attr.label = 0;
	if (bgp->mvpn_ipmsi_label)
		/* Interop: Junos 22.2R3 tracks a label-0 (unlabeled) IR leaf but
		 * never instantiates a replication leg toward it, so a real
		 * downstream-assigned label is configurable. RFC 6514 Section 5
		 * places the label in the high-order 20 bits of the 3-octet field.
		 */
		vni2label(bgp->mvpn_ipmsi_label << 4, &attr.label);

	/*
	 * GTM global-table Route Target (target:0.0.0.0:0), the import/export target
	 * a GTM receiver (e.g. Junos mpls-internet-multicast) matches on the Intra-AS
	 * AD route; without it the route is rejected for want of a target community.
	 */
	bgp_mvpn_attach_gtm_rt(&attr);

	/* One Intra-AS I-PMSI A-D per active GTM plane: the v4 originator is
	 * legal in both AFs (RFC 6515), and a peer that negotiated only one of
	 * them must still learn this PE as an IR leaf for that plane. Junos
	 * mirrors this (its v6-AF Type-1 carries the v4 lo0 originator).
	 */
	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		if (!active[afi])
			continue;
		/* bgp_attr_intern's hash-miss path (bgp_attr_hash_alloc) takes
		 * ownership of a caller-owned attr->extra and NULLs it
		 * (bgp_attr_owns_extra), so a prior install can strip the PMSI
		 * tunnel info from this stack attr. Re-claim the slot before
		 * every install or a later plane interns a PMSI-flagged attr
		 * with no tunnel info, announced as a len-5 NO_INFO PMSI that
		 * a Junos GTM peer rejects as malformed (NOTIFICATION loop).
		 */
		if (!attr.extra) {
			bgp_attr_set_pmsi_tnl_type(&attr, PMSI_TNLTYPE_INGR_REPL);
			bgp_attr_set_tunn_id(&attr, &tunn_id);
		}
		bgp_mvpn_route_install(bgp, bgp->peer_self, afi, &p, &attr, BGP_ROUTE_STATIC);
	}

	/*
	 * bgp_attr_flush releases the borrowed ecommunity ref (refcnt-aware) and the
	 * PMSI attr_extra, mirroring bgp_mvpn_source_active_set; aspath was interned
	 * by bgp_attr_default_set, so drop that local ref separately.
	 */
	bgp_attr_flush(&attr);
	aspath_unintern(&attr.aspath);
}

void bgp_mvpn_withdraw_type1(struct bgp *bgp, afi_t afi)
{
	struct prefix_mvpn p;
	struct ipaddr orig;

	if (!bgp->peer_self || bgp->router_id.s_addr == INADDR_ANY)
		return;

	orig = mvpn_ipaddr_v4(bgp->router_id);
	bgp_mvpn_build_prefix_type1(&p, &orig);

	bgp_mvpn_route_remove(bgp, bgp->peer_self, afi, &p, BGP_ROUTE_STATIC);
}

void bgp_mvpn_handle_router_id_update(struct bgp *bgp, bool withdraw)
{
	afi_t afi;

	if (!withdraw) {
		bgp_mvpn_originate_type1(bgp);
		return;
	}

	/* The route may exist in either plane even if its last peer was just
	 * deactivated, so look up and remove both copies unconditionally. */
	for (afi = AFI_IP; afi <= AFI_IP6; afi++)
		bgp_mvpn_withdraw_type1(bgp, afi);
	bgp_mvpn_remove_local_selective_routes(
		bgp, BGP_MVPN_ROUTE_TYPE_S_PMSI_AD, NULL, NULL, NULL);
	bgp_mvpn_remove_local_selective_routes(
		bgp, BGP_MVPN_ROUTE_TYPE_LEAF_AD, NULL, NULL, NULL);
}

/*
 * Remove this PE's local Type-7 (C-multicast Source Tree Join) routes for
 * (C-S, C-G) whose Source AS differs from keep_source_as (0 = remove all).
 * source_as is part of the Type-7 NLRI key but is re-derived from the source
 * route on every (re-)origination and withdraw, and that value can differ
 * from the one a route was installed under -- the Source-AS extended
 * community may have changed, or the source route may be gone -- so an
 * exact-prefix remove would miss the originally originated route.  The
 * withdraw path removes every key (keep_source_as 0); the (re-)origination
 * path keeps the freshly derived key and clears any stale one, keeping the
 * PE at one local join per (C-S, C-G).
 */
static void bgp_mvpn_route_remove_type7_sg(struct bgp *bgp, struct peer *peer,
					   const struct ipaddr *src, const struct ipaddr *grp,
					   uint32_t keep_source_as)
{
	afi_t afi = IS_IPADDR_V6(src) ? AFI_IP6 : AFI_IP;
	struct bgp_table *table = bgp->rib[afi][SAFI_MCAST_VPN];
	struct bgp_dest *dest;

	if (!table)
		return;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		const struct prefix_mvpn *p = (const struct prefix_mvpn *)bgp_dest_get_prefix(dest);
		struct bgp_path_info *pi;

		if (p->family != AF_MVPN ||
		    p->prefix.route_type != BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN)
			continue;
		if (ipaddr_cmp(&p->prefix.src, src) != 0 || ipaddr_cmp(&p->prefix.grp, grp) != 0)
			continue;
		/* An originated key never carries Source AS 0 (the resolver
		 * falls back to the local AS), so 0 means "keep none". */
		if (keep_source_as != 0 && p->prefix.source_as == keep_source_as)
			continue;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (pi->peer != peer || pi->type != ZEBRA_ROUTE_BGP ||
			    pi->sub_type != BGP_ROUTE_STATIC)
				continue;
			bgp_unlink_nexthop(pi);
			bgp_path_info_mark_for_delete(dest, pi);
			bgp_process(bgp, dest, pi, afi, SAFI_MCAST_VPN);
			break;
		}
	}
}

static bool bgp_mvpn_has_local_join(struct bgp *bgp, const struct ipaddr *src,
				    const struct ipaddr *grp)
{
	afi_t afi = IS_IPADDR_V6(src) ? AFI_IP6 : AFI_IP;
	struct bgp_table *table = bgp->rib[afi][SAFI_MCAST_VPN];
	struct bgp_dest *dest;

	if (!table)
		return false;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		const struct prefix_mvpn *p =
			(const struct prefix_mvpn *)bgp_dest_get_prefix(dest);
		struct bgp_path_info *pi;

		if (p->family != AF_MVPN ||
		    p->prefix.route_type != BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN ||
		    ipaddr_cmp(&p->prefix.src, src) != 0 ||
		    ipaddr_cmp(&p->prefix.grp, grp) != 0)
			continue;
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			if (pi->peer == bgp->peer_self &&
			    pi->sub_type == BGP_ROUTE_STATIC &&
			    !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
				bgp_dest_unlock_node(dest);
				return true;
			}
	}
	return false;
}

static bool bgp_mvpn_type3_leaf_required(struct bgp_dest *dest,
					 const struct bgp *bgp)
{
	const struct bgp_path_info *pi;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer != bgp->peer_self &&
		    pi->sub_type == BGP_ROUTE_NORMAL &&
		    !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED) &&
		    bgp_attr_get_pmsi_tnl_type(pi->attr) ==
			    PMSI_TNLTYPE_INGR_REPL &&
		    CHECK_FLAG(bgp_attr_get_pmsi_tnl_flags(pi->attr),
			       PMSI_TNL_FLAG_LEAF_INFO_REQUIRED))
			return true;
	return false;
}

static void bgp_mvpn_leaf_from_type3_set(struct bgp *bgp,
					 const struct prefix_mvpn *type3, bool negate)
{
	struct prefix_mvpn leaf;
	struct ipaddr leaf_originator;
	struct attr attr;

	/* v6 leaf (Type-4) origination reuses the v4 router-id originator
	 * (RFC 6515), same as bgp_mvpn_selective_source_set(); AFI keyed by the
	 * source family. */
	if (!bgp->peer_self)
		return;
	if (negate) {
		bgp_mvpn_remove_local_selective_routes(
			bgp, BGP_MVPN_ROUTE_TYPE_LEAF_AD, &type3->prefix.src,
			&type3->prefix.grp, &type3->prefix.originator);
		return;
	}
	if (bgp->router_id.s_addr == INADDR_ANY)
		return;

	leaf_originator = mvpn_ipaddr_v4(bgp->router_id);
	bgp_mvpn_build_prefix_type4(&leaf, &type3->prefix.src, &type3->prefix.grp,
				    &type3->prefix.originator, &leaf_originator);

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	bgp_attr_set(&attr, BGP_ATTR_NEXT_HOP);
	attr.nexthop = bgp->router_id;
	attr.mp_nexthop_global_in = bgp->router_id;
	attr.mp_nexthop_len = IPV4_MAX_BYTELEN;
	bgp_mvpn_attach_ip_rt(&attr, type3->prefix.originator.ipaddr_v4);
	bgp_mvpn_route_install(bgp, bgp->peer_self, bgp_mvpn_prefix_afi(&leaf), &leaf, &attr,
			       BGP_ROUTE_STATIC);
	bgp_attr_flush(&attr);
	aspath_unintern(&attr.aspath);
}

static void bgp_mvpn_selective_join_set(struct bgp *bgp,
					const struct ipaddr *src,
					const struct ipaddr *grp, bool negate)
{
	afi_t afi = IS_IPADDR_V6(src) ? AFI_IP6 : AFI_IP;
	struct bgp_table *table = bgp->rib[afi][SAFI_MCAST_VPN];
	struct bgp_dest *dest;

	if (!table)
		return;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		const struct prefix_mvpn *p =
			(const struct prefix_mvpn *)bgp_dest_get_prefix(dest);
		bool leaf_required;

		if (p->family != AF_MVPN ||
		    p->prefix.route_type != BGP_MVPN_ROUTE_TYPE_S_PMSI_AD ||
		    ipaddr_cmp(&p->prefix.src, src) != 0 ||
		    ipaddr_cmp(&p->prefix.grp, grp) != 0)
			continue;
		leaf_required = bgp_mvpn_type3_leaf_required(dest, bgp);
		bgp_mvpn_leaf_from_type3_set(bgp, p,
					     negate || !leaf_required);
	}
}

/*
 * Originate or withdraw a local Type-7 (C-multicast Source Tree Join) route,
 * mirroring bgp_mvpn_source_active_set(). This is the pimd-driven join path:
 * pimd reports local receiver interest in (C-S, C-G) through the zebra SG
 * relay (bgp_zebra_process_mvpn_sg) and this PE originates the matching
 * C-multicast join toward the source's upstream PE.
 */
int bgp_mvpn_source_tree_join_set(struct bgp *bgp, const struct ipaddr *src,
				  const struct ipaddr *grp, bool negate)
{
	struct prefix_mvpn p;
	struct attr attr;
	uint32_t source_as = 0;
	struct in_addr umh = { .s_addr = INADDR_ANY };

	if (negate) {
		/* Withdraw removes by (C-S, C-G) ignoring the Source AS.  It is
		 * part of the Type-7 NLRI key but is re-derived from the source
		 * route, whose Source-AS extended community can change -- or the
		 * source route can be gone -- while a receiver stays joined; an
		 * exact-prefix remove keyed off the current value would miss the
		 * originally originated join and strand it, advertised
		 * indefinitely. */
		bgp_mvpn_route_remove_type7_sg(bgp, bgp->peer_self, src, grp, 0);
		bgp_mvpn_selective_join_set(bgp, src, grp, true);
		return CMD_SUCCESS;
	}

	/* RFC 6514 Section 5: the Source AS and the upstream PE both come off
	 * the unicast route toward C-S (Junos "src-as" / "rt-import"). */
	bgp_mvpn_resolve_from_source_route(bgp, src, &source_as, &umh);
	/* RFC 6514 4.6: the Source AS is the AS of the PE the source attaches
	 * to.  With no Source-AS extended community on the source route
	 * (single-AS GTM over iBGP), that is the local AS. */
	if (source_as == 0)
		source_as = bgp->as;

	/* A re-resolution (bgp_mvpn_reresolve_joins_for_route) can derive a
	 * DIFFERENT Source AS than the one this (C-S, C-G) join was last
	 * originated under -- the NLRI key changes, so installing the new
	 * route alone would strand the old one, advertised indefinitely.
	 * Clear any stale-keyed local join first; a same-key re-origination
	 * skips this walk's remove and stays an attrhash-dedup'd no-op. */
	bgp_mvpn_route_remove_type7_sg(bgp, bgp->peer_self, src, grp, source_as);

	bgp_mvpn_build_prefix_type7(&p, source_as, src, grp);

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	bgp_attr_set(&attr, BGP_ATTR_NEXT_HOP);
	attr.nexthop = bgp->router_id;
	attr.mp_nexthop_global_in = bgp->router_id;
	attr.mp_nexthop_len = IPV4_MAX_BYTELEN;

	/*
	 * RFC 7716 Section 2.2 / Section 2.9 upstream-node-identifying Route
	 * Target: an IP-address-specific RT whose Global Administrator is the
	 * upstream PE (the PE toward C-S) and Local Administrator is 0. Only that
	 * PE imports the C-multicast join -- it matches "an upstream-node-
	 * identifying RT whose Global Administrator identifies that PBR". When
	 * the source route carries no route-import RT, fall back to the Source
	 * Active route's next hop. A join with no resolvable upstream is
	 * originated RT-less (not yet targetable) and logged.
	 */
	if (umh.s_addr == INADDR_ANY)
		bgp_mvpn_resolve_upstream_from_sa(bgp, src, grp, &umh);
	if (umh.s_addr != INADDR_ANY)
		bgp_mvpn_attach_ip_rt(&attr, umh);
	else if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("MVPN Type-7 (%pIA, %pIA): no upstream PE resolved; originating without upstream RT",
			   src, grp);

	bgp_mvpn_route_install(bgp, bgp->peer_self, bgp_mvpn_prefix_afi(&p), &p, &attr,
			       BGP_ROUTE_STATIC);
	bgp_mvpn_selective_join_set(bgp, src, grp, false);

	bgp_attr_flush(&attr);
	aspath_unintern(&attr.aspath);
	return CMD_SUCCESS;
}

/*
 * Re-resolve locally-originated Type-7 joins after the unicast route toward a
 * C-S changes.
 *
 * The RFC 6514 Section 5 communities on a pimd-driven Type-7 (the upstream-PE
 * Route Target derived from the source route's VRF Route Import EC, and the
 * Source AS) are read from the unicast route toward C-S at origination time in
 * bgp_mvpn_source_tree_join_set(). A receiver can stay joined across changes to
 * that unicast route -- most importantly, the route can arrive (or gain its
 * rt-import EC) *after* the join, in which case the Type-7 was first originated
 * RT-less and never targets the correct upstream PE. This reconcile is the
 * missing reactive half: when a unicast best path changes, re-originate any
 * local Type-7 whose C-S the changed prefix covers, so the RT/Source-AS track
 * the source route. Re-origination is idempotent (bgp_mvpn_route_install dedups
 * an unchanged attr via attrhash_cmp), so an unrelated change is a cheap no-op.
 *
 * Called from the unicast best-path path only when GTM is active, so a non-GTM
 * instance pays nothing. The MCAST-VPN table walked here holds one entry per
 * local join (small), and the C-S family fixes which AFI's table to scan.
 */
void bgp_mvpn_reresolve_joins_for_route(struct bgp *bgp, afi_t afi, const struct prefix *changed)
{
	struct bgp_table *table = bgp->rib[afi][SAFI_MCAST_VPN];
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	if (!table || !bgp->peer_self || !changed)
		return;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		const struct prefix *pfx = bgp_dest_get_prefix(dest);
		const struct mvpn_addr *m = &pfx->u.prefix_mvpn;
		struct prefix csrc = {};

		if (pfx->family != AF_MVPN ||
		    m->route_type != BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN)
			continue;

		/* Only our own pimd-driven joins carry a resolvable upstream. */
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			if (pi->peer == bgp->peer_self &&
			    pi->sub_type == BGP_ROUTE_STATIC)
				break;
		if (!pi)
			continue;

		/* Does the changed unicast prefix cover this join's C-S? The
		 * Type-7's C-S family selects the table AFI, so it always matches
		 * `afi` here; build the host prefix and test containment. */
		if (IS_IPADDR_V6(&m->src)) {
			csrc.family = AF_INET6;
			csrc.prefixlen = IPV6_MAX_BITLEN;
			csrc.u.prefix6 = m->src.ipaddr_v6;
		} else {
			csrc.family = AF_INET;
			csrc.prefixlen = IPV4_MAX_BITLEN;
			csrc.u.prefix4 = m->src.ipaddr_v4;
		}
		if (changed->family != csrc.family ||
		    !prefix_match(changed, &csrc))
			continue;

		/* Re-derive RT + Source-AS from the (now changed) source route. */
		bgp_mvpn_source_tree_join_set(bgp, &m->src, &m->grp, false);
	}
}

void bgp_mvpn_config_write(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_table *table = bgp->rib[afi][safi];
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	/* The I-PMSI label knob lives under the ipv4 mvpn AF only (one Type-1
	 * serves both planes); write it once.
	 */
	if (afi == AFI_IP && bgp->mvpn_ipmsi_label)
		vty_out(vty, "  bgp mvpn ipmsi-label %u\n", bgp->mvpn_ipmsi_label);

	if (!table)
		return;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		const struct prefix *pfx = bgp_dest_get_prefix(dest);
		const struct mvpn_addr *m = &pfx->u.prefix_mvpn;

		if (pfx->family != AF_MVPN || m->route_type != BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE)
			continue;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (pi->peer != bgp->peer_self || pi->sub_type != BGP_ROUTE_STATIC)
				continue;

			vty_out(vty, "  bgp mvpn source-active %pIA group %pIA\n", &m->src,
				&m->grp);
			break;
		}
	}
}

void bgp_mvpn_show_routes(struct vty *vty, struct bgp *bgp, afi_t afi, bool use_json)
{
	struct bgp_table *table = bgp->rib[afi][SAFI_MCAST_VPN];
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	json_object *json = NULL;
	json_object *json_routes = NULL;

	if (use_json) {
		json = json_object_new_object();
		json_routes = json_object_new_array();
	}

	for (dest = table ? bgp_table_top(table) : NULL; dest; dest = bgp_route_next(dest)) {
		const struct prefix *pfx = bgp_dest_get_prefix(dest);
		const struct mvpn_addr *m = &pfx->u.prefix_mvpn;

		if (pfx->family != AF_MVPN)
			continue;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			bool self = (pi->peer == bgp->peer_self);
			struct ecommunity *ecom = bgp_attr_get_ecommunity(pi->attr);
			/* ecommunity_str() lazily builds and caches the display
			 * string (RFC 7716 Section 2.8.2 group-address RT on
			 * Type-5, and any RT a later route type carries). */
			const char *ecom_str = ecom ? ecommunity_str(ecom) : NULL;

			if (use_json) {
				json_object *jr = json_object_new_object();

				json_object_int_add(jr, "routeType", m->route_type);
				if (m->route_type == BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI) {
					json_object_string_addf(jr, "originator", "%pIA", &m->src);
					if (bgp_attr_get_pmsi_tnl_type(pi->attr) ==
					    PMSI_TNLTYPE_INGR_REPL) {
						json_object *jp = json_object_new_object();
						const struct in6_addr *tid =
							bgp_attr_get_tunn_id(pi->attr);

						json_object_string_add(jp, "type",
								       "ingressReplication");
						/* RFC 6514 Section 5 IR label; the
						 * origination stores ipmsi-label
						 * << 4 (label in the high-order 20
						 * bits), 0 for the unlabeled GTM
						 * default. */
						json_object_int_add(jp, "label",
								    label2vni(&pi->attr->label) >>
									    4);
						if (IS_MAPPED_IPV6(tid)) {
							struct in_addr ep;

							ipv4_mapped_ipv6_to_ipv4(tid, &ep);
							json_object_string_addf(jp, "endpoint",
										"%pI4", &ep);
						} else {
							json_object_string_addf(jp, "endpoint",
										"%pI6", tid);
						}
						json_object_object_add(jr, "pmsiTunnel", jp);
					}
				} else {
					json_object_string_addf(jr, "source", "%pIA", &m->src);
					json_object_string_addf(jr, "group", "%pIA", &m->grp);
					if (m->route_type == BGP_MVPN_ROUTE_TYPE_S_PMSI_AD ||
					    m->route_type == BGP_MVPN_ROUTE_TYPE_LEAF_AD)
						json_object_string_addf(jr, "originator", "%pIA",
									&m->originator);
					if (m->route_type == BGP_MVPN_ROUTE_TYPE_S_PMSI_AD &&
					    bgp_attr_get_pmsi_tnl_type(pi->attr) ==
						    PMSI_TNLTYPE_INGR_REPL) {
						json_object *jp = json_object_new_object();
						const struct in6_addr *tid =
							bgp_attr_get_tunn_id(pi->attr);

						json_object_string_add(jp, "type",
								       "ingressReplication");
						json_object_int_add(
							jp, "flags",
							bgp_attr_get_pmsi_tnl_flags(pi->attr));
						json_object_boolean_add(
							jp, "leafInfoRequired",
							CHECK_FLAG(
								bgp_attr_get_pmsi_tnl_flags(
									pi->attr),
								PMSI_TNL_FLAG_LEAF_INFO_REQUIRED));
						json_object_int_add(
							jp, "label",
							label2vni(&pi->attr->label) >> 4);
						if (IS_MAPPED_IPV6(tid)) {
							struct in_addr ep;

							ipv4_mapped_ipv6_to_ipv4(tid, &ep);
							json_object_string_addf(
								jp, "endpoint", "%pI4", &ep);
						} else
							json_object_string_addf(
								jp, "endpoint", "%pI6", tid);
						json_object_object_add(jr, "pmsiTunnel", jp);
					}
					if (m->route_type == BGP_MVPN_ROUTE_TYPE_LEAF_AD)
						json_object_string_addf(jr, "leafOriginator",
									"%pIA",
									&m->leaf_originator);
					if (m->route_type == BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN)
						json_object_int_add(jr, "sourceAs", m->source_as);
				}
				if (ecom) {
					json_object *je = json_object_new_object();

					json_object_string_add(je, "string", ecom_str);
					json_object_object_add(jr, "extendedCommunity", je);
				}
				json_object_boolean_add(jr, "selfOriginated", self);
				json_object_array_add(json_routes, jr);
			} else if (m->route_type == BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI) {
				vty_out(vty, " [%u] originator %pIA %s%s%s%s\n", m->route_type,
					&m->src,
					bgp_attr_get_pmsi_tnl_type(pi->attr) ==
							PMSI_TNLTYPE_INGR_REPL
						? "IR "
						: "",
					self ? "(local)" : "", ecom_str ? " " : "",
					ecom_str ? ecom_str : "");
			} else if (m->route_type == BGP_MVPN_ROUTE_TYPE_S_PMSI_AD) {
				vty_out(vty,
					" [%u] source %pIA group %pIA originator %pIA %s%s%s\n",
					m->route_type, &m->src, &m->grp, &m->originator,
					self ? "(local)" : "", ecom_str ? " " : "",
					ecom_str ? ecom_str : "");
			} else if (m->route_type == BGP_MVPN_ROUTE_TYPE_LEAF_AD) {
				vty_out(vty,
					" [%u] source %pIA group %pIA originator %pIA leaf-originator %pIA %s%s%s\n",
					m->route_type, &m->src, &m->grp, &m->originator,
					&m->leaf_originator, self ? "(local)" : "",
					ecom_str ? " " : "", ecom_str ? ecom_str : "");
			} else {
				vty_out(vty, " [%u] source %pIA group %pIA %s%s%s\n",
					m->route_type, &m->src, &m->grp, self ? "(local)" : "",
					ecom_str ? " " : "", ecom_str ? ecom_str : "");
			}
		}
	}

	if (use_json) {
		json_object_object_add(json, "routes", json_routes);
		vty_json(vty, json);
	}
}
