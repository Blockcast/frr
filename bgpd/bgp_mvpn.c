// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MCAST-VPN (SAFI 5) NLRI codec and Global Table Multicast origination.
 *
 * Copyright (C) 2026 Blockcast, Inc.
 *
 * RFC 6514 Route Type 5 (Source Active A-D), constrained to Global Table
 * Multicast (RFC 7716): the Route Distinguisher is always zero (single global
 * table) and groups are SSM (232.0.0.0/8 for IPv4).
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

/* Bit-length key covering the whole mvpn_addr (route_type, C-S, C-G). Padding
 * inside the struct is memset-zeroed on build, so the radix key is stable.
 */
#define BGP_MVPN_PREFIXLEN (sizeof(struct mvpn_addr) * 8)

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

/*
 * Fill a prefix_mvpn for a Type-7 (C-multicast Source Tree Join) route. Like
 * the Type-5 builder, the struct is memset-zeroed first so that padding is
 * deterministic and the radix key / prefix_same() memcmp are stable. The
 * Source AS is stored in host order in the RIB key so distinct upstream ASes
 * key to distinct routes and the value is renderable from the prefix.
 */
void bgp_mvpn_build_prefix_type7(struct prefix_mvpn *p, uint32_t source_as, const struct ipaddr *src,
				 const struct ipaddr *grp)
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

/*
 * RFC 6514 Section 4.5 Source Active A-D route. The RD is emitted as 8 zero
 * octets per RFC 7716 Global Table Multicast. C-S/C-G are v4 or v6 (RFC 6515);
 * the route-type-specific Length and the per-address Length octets follow the
 * family carried in the prefix.
 */
void bgp_mvpn_encode_type5(struct stream *s, const struct prefix *p, bool addpath_capable,
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
void bgp_mvpn_encode_type7(struct stream *s, const struct prefix *p, bool addpath_capable,
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
void bgp_mvpn_encode_type1(struct stream *s, const struct prefix *p, bool addpath_capable,
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

/*
 * Install (or refresh) a Type-5 route in the SAFI_MCAST_VPN table. Shared by
 * local origination (peer = peer_self, sub_type = STATIC) and the receive path
 * (sub_type = NORMAL). GTM SA routes are control-plane markers, so they are
 * marked valid without next-hop resolution, mirroring EVPN imported routes.
 */
static void bgp_mvpn_route_install(struct bgp *bgp, struct peer *peer, const struct prefix_mvpn *p,
				   struct attr *attr, int sub_type)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct attr *attr_new;

	/* AFI_IP is hardcoded: GTM MVPN is IPv4-only in this milestone (the v6-plan
	 * anchor; see bgp_nlri_parse_mvpn).
	 */
	dest = bgp_afi_node_get(bgp->rib[AFI_IP][SAFI_MCAST_VPN], AFI_IP, SAFI_MCAST_VPN,
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
	} else {
		pi = info_make(ZEBRA_ROUTE_BGP, sub_type, 0, peer, attr_new, dest);
		SET_FLAG(pi->flags, BGP_PATH_VALID);
		bgp_path_info_add(dest, pi);
	}

	bgp_process(bgp, dest, pi, AFI_IP, SAFI_MCAST_VPN);
	bgp_dest_unlock_node(dest);
}

/* Withdraw a Type-5 route matching (peer, sub_type) from the table. */
static void bgp_mvpn_route_remove(struct bgp *bgp, struct peer *peer, const struct prefix_mvpn *p,
				  int sub_type)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	/* AFI_IP is hardcoded: GTM MVPN is IPv4-only in this milestone (see
	 * bgp_nlri_parse_mvpn).
	 */
	dest = bgp_safi_node_lookup(bgp->rib[AFI_IP][SAFI_MCAST_VPN], SAFI_MCAST_VPN,
				    (const struct prefix *)p, NULL);
	if (!dest)
		return;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == peer && pi->type == ZEBRA_ROUTE_BGP && pi->sub_type == sub_type)
			break;

	if (pi) {
		bgp_unlink_nexthop(pi);
		bgp_path_info_mark_for_delete(dest, pi);
		bgp_process(bgp, dest, pi, AFI_IP, SAFI_MCAST_VPN);
	}

	bgp_dest_unlock_node(dest);
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
 * Parse a received MCAST-VPN NLRI. Each NLRI is Route Type(1) + Length(1) +
 * route-type-specific. Type 5 (Source Active) and Type 7 (C-multicast Source
 * Tree Join) are decoded; other types are skipped using the on-wire Length so
 * the stream stays framed.
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
	uint8_t src_len;
	uint8_t grp_len;
	uint8_t rd[8];
	struct ipaddr src;
	struct ipaddr grp;
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
		/* Zero the C-address slots each iteration so a v4 read leaves the
		 * ipaddr union's upper octets clear -- the whole struct feeds the
		 * RIB key via prefix_same()/memcmp. */
		memset(&src, 0, sizeof(src));
		memset(&grp, 0, sizeof(grp));
		if (addpath_capable) {
			STREAM_GET(&addpath_id, data, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
		}

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

		case BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE:
			if (length != BGP_MVPN_TYPE5_V4_SPEC_LEN &&
			    length != BGP_MVPN_TYPE5_V6_SPEC_LEN) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-5 bad length %u (expected %u or %u)",
					 peer->host, length, BGP_MVPN_TYPE5_V4_SPEC_LEN,
					 BGP_MVPN_TYPE5_V6_SPEC_LEN);
				ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
				goto done;
			}

			/* RD (8 octets): read for validation after the body is
			 * fully consumed (GTM requires RD == 0). */
			STREAM_GET(rd, data, 8);

			STREAM_GETC(data, src_len);
			switch (bgp_mvpn_read_caddr(data, &src, src_len)) {
			case MVPN_CADDR_OK:
				break;
			case MVPN_CADDR_TRUNC:
				goto stream_failure;
			case MVPN_CADDR_BADLEN:
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-5 bad source addr length %u",
					 peer->host, src_len);
				ret = BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
				goto done;
			}

			STREAM_GETC(data, grp_len);
			switch (bgp_mvpn_read_caddr(data, &grp, grp_len)) {
			case MVPN_CADDR_OK:
				break;
			case MVPN_CADDR_TRUNC:
				goto stream_failure;
			case MVPN_CADDR_BADLEN:
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-5 bad group addr length %u",
					 peer->host, grp_len);
				ret = BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
				goto done;
			}

			/* C-S and C-G share a family, and the route Length must
			 * match it (guards a lying outer Length). */
			if (src_len != grp_len ||
			    length != (src_len == IPV6_MAX_BITLEN ? BGP_MVPN_TYPE5_V6_SPEC_LEN
								  : BGP_MVPN_TYPE5_V4_SPEC_LEN)) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-5 addr family/length mismatch (src %u grp %u len %u)",
					 peer->host, src_len, grp_len, length);
				ret = BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
				goto done;
			}

			bgp_mvpn_build_prefix_type5(&p, &src, &grp);
			break;

		case BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN:
			if (length != BGP_MVPN_TYPE7_V4_SPEC_LEN &&
			    length != BGP_MVPN_TYPE7_V6_SPEC_LEN) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-7 bad length %u (expected %u or %u)",
					 peer->host, length, BGP_MVPN_TYPE7_V4_SPEC_LEN,
					 BGP_MVPN_TYPE7_V6_SPEC_LEN);
				ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
				goto done;
			}

			/* RD (8 octets): read for validation after the body is
			 * fully consumed (GTM requires RD == 0). */
			STREAM_GET(rd, data, 8);

			STREAM_GET(&source_as, data, 4);
			source_as = ntohl(source_as);

			STREAM_GETC(data, src_len);
			switch (bgp_mvpn_read_caddr(data, &src, src_len)) {
			case MVPN_CADDR_OK:
				break;
			case MVPN_CADDR_TRUNC:
				goto stream_failure;
			case MVPN_CADDR_BADLEN:
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-7 bad source addr length %u",
					 peer->host, src_len);
				ret = BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
				goto done;
			}

			STREAM_GETC(data, grp_len);
			switch (bgp_mvpn_read_caddr(data, &grp, grp_len)) {
			case MVPN_CADDR_OK:
				break;
			case MVPN_CADDR_TRUNC:
				goto stream_failure;
			case MVPN_CADDR_BADLEN:
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-7 bad group addr length %u",
					 peer->host, grp_len);
				ret = BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
				goto done;
			}

			/* C-S and C-G share a family, and the route Length must
			 * match it (guards a lying outer Length). */
			if (src_len != grp_len ||
			    length != (src_len == IPV6_MAX_BITLEN ? BGP_MVPN_TYPE7_V6_SPEC_LEN
								  : BGP_MVPN_TYPE7_V4_SPEC_LEN)) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-7 addr family/length mismatch (src %u grp %u len %u)",
					 peer->host, src_len, grp_len, length);
				ret = BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
				goto done;
			}

			bgp_mvpn_build_prefix_type7(&p, source_as, &src, &grp);
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

		if (route_type == BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE ||
		    route_type == BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN) {
			bool ssm = IS_IPADDR_V6(&grp) ? ipv6_mcast_ssm(&grp.ipaddr_v6)
						      : bgp_mvpn_group_is_ssm(grp.ipaddr_v4);

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

		if (is_withdraw)
			bgp_mvpn_route_remove(peer->bgp, peer, &p, BGP_ROUTE_NORMAL);
		else
			bgp_mvpn_route_install(peer->bgp, peer, &p, attr, BGP_ROUTE_NORMAL);
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
 * Resolve the Upstream Multicast Hop (upstream PE) for (C-S, C-G) -- the address
 * that identifies the PE toward C-S, used as the Global Administrator of the
 * upstream-node-identifying Route Target on the C-multicast (Type-7) join.
 *
 * RFC 6514 Section 5.1 / RFC 7716: that RT MUST equal the value of the VRF Route
 * Import extended community carried by the UMH-eligible *unicast* route toward
 * C-S. A conformant MVPN source attaches that community (IP-address-specific,
 * sub-type 0x0b; Junos "rt-import") with its PE address as the Global
 * Administrator. The receiver echoes that address as a Route Target on the
 * C-multicast (Type-7) join; the source's auto-generated
 * __vrf-mvpn-import-cmcast-*-internal__ policy imports the Type-7 only on
 * exactly that RT (empirically confirmed on MX204 22.2R3: it keys the cmcast
 * import on the lo0 PE address, e.g. target:10.255.255.254:0). So the correct
 * upstream identifier is the Global Administrator of the source route's
 * route-import community.
 *
 * NB: the sub-type a live Junos GTM source stamps on the *unicast* route
 * (VRF Route Import 0x0b vs a plain Route Target 0x02) is not yet wire-captured;
 * the lookup below tries 0x0b first then 0x02, so it is correct either way.
 *
 * Lookup order:
 *   1. RFC-canonical: the IP-address-specific route-import community on the
 *      unicast route to C-S -- VRF Route Import (0x0b), else Route Target (0x02).
 *   2. Fallback: the next hop of the received Source Active route. This is only
 *      correct when the SA originator's address is preserved end to end (iBGP,
 *      or a peer that attaches no route-import RT such as FRR<->FRR); eBGP
 *      rewrites the SA next hop to the peering address, so relying on it there
 *      produces a non-matching RT. Kept as best-effort so the test-join scaffold
 *      still resolves an upstream when no route-import RT is present.
 *
 * Returns true and fills *upstream on a hit; false when neither is available.
 */
static bool bgp_mvpn_resolve_upstream_pe(struct bgp *bgp, struct in_addr src, struct in_addr grp,
					 struct in_addr *upstream)
{
	struct prefix_mvpn sa;
	struct prefix psrc = { .family = AF_INET, .prefixlen = IPV4_MAX_BITLEN };
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct ecommunity *ecom;
	struct ecommunity_val *eval;

	/*
	 * (1) RFC 6514 5.1: UMH from the route-import RT on the unicast route
	 * toward C-S. AFI_IP: GTM MVPN is IPv4-only in this milestone.
	 */
	psrc.u.prefix4 = src;
	dest = bgp_node_match(bgp->rib[AFI_IP][SAFI_UNICAST], &psrc);
	if (dest) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (pi->type != ZEBRA_ROUTE_BGP)
				continue;
			ecom = bgp_attr_get_ecommunity(pi->attr);
			if (!ecom)
				continue;
			/*
			 * RFC 6514 Section 5.1: prefer the VRF Route Import EC
			 * (IP-address-specific, sub-type 0x0b) -- what a
			 * conformant MVPN source attaches to the unicast route
			 * toward C-S (Junos "rt-import"). Fall back to a plain
			 * IP-address-specific Route Target (0x02): this covers
			 * an FRR<->FRR source that tags its route with
			 * "set extcommunity rt <PE>:0", and any peer that keys
			 * the upstream on a Route Target rather than rt-import.
			 */
			eval = ecommunity_lookup(ecom, ECOMMUNITY_ENCODE_IP,
						 ECOMMUNITY_VRF_ROUTE_IMPORT);
			if (!eval)
				eval = ecommunity_lookup(ecom, ECOMMUNITY_ENCODE_IP,
							 ECOMMUNITY_ROUTE_TARGET);
			if (!eval)
				continue;
			/* IP-address-specific EC wire layout: type, subtype,
			 * Global Administrator (4 bytes), Local Administrator (2). */
			memcpy(&upstream->s_addr, &eval->val[2], IPV4_MAX_BYTELEN);
			bgp_dest_unlock_node(dest);
			return true;
		}
		bgp_dest_unlock_node(dest);
	}

	/* (2) Fallback: next hop of the received Source Active route. */
	{
		struct ipaddr isrc = mvpn_ipaddr_v4(src);
		struct ipaddr igrp = mvpn_ipaddr_v4(grp);

		bgp_mvpn_build_prefix_type5(&sa, &isrc, &igrp);
	}
	dest = bgp_safi_node_lookup(bgp->rib[AFI_IP][SAFI_MCAST_VPN], SAFI_MCAST_VPN,
				    (const struct prefix *)&sa, NULL);
	if (!dest)
		return false;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (pi->type != ZEBRA_ROUTE_BGP)
			continue;
		if (pi->attr->mp_nexthop_global_in.s_addr == INADDR_ANY)
			continue;
		*upstream = pi->attr->mp_nexthop_global_in;
		bgp_dest_unlock_node(dest);
		return true;
	}

	bgp_dest_unlock_node(dest);
	return false;
}

/*
 * Configure or withdraw a locally-originated GTM Source Active route. Attr is a
 * self-sourced IGP route with the router-id as next hop.
 */
int bgp_mvpn_source_active_set(struct bgp *bgp, struct in_addr src, struct in_addr grp, bool negate)
{
	struct prefix_mvpn p;
	struct attr attr;
	struct ipaddr isrc = mvpn_ipaddr_v4(src);
	struct ipaddr igrp = mvpn_ipaddr_v4(grp);

	bgp_mvpn_build_prefix_type5(&p, &isrc, &igrp);

	if (negate) {
		bgp_mvpn_route_remove(bgp, bgp->peer_self, &p, BGP_ROUTE_STATIC);
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

	bgp_mvpn_route_install(bgp, bgp->peer_self, &p, &attr, BGP_ROUTE_STATIC);

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

/* True if any peer on this instance has the GTM MVPN AF (AFI_IP, SAFI 5)
 * configured/activated. afc[] is set the moment a peer is activated for the AF,
 * so this is a valid "GTM MVPN in use" predicate for both lifecycle hooks.
 */
static bool bgp_mvpn_gtm_af_active(struct bgp *bgp)
{
	struct peer *peer;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer))
		if (peer->afc[AFI_IP][SAFI_MCAST_VPN])
			return true;

	return false;
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
 * KNOWN LIMITATION (GTM MVP): on a router-id X->Y change this originates the new
 * Type-1 keyed by Y but does not withdraw the stale one keyed by X, so the PE
 * briefly advertises two I-PMSI A-D routes until the session/AF refreshes. The
 * startup 0.0.0.0->addr path is clean (no prior route). Likewise, deactivating
 * the GTM MVPN AF (or tearing down the bgp instance) does not withdraw this
 * self-originated Type-1, leaving a stale I-PMSI A-D marker until peers age it
 * out. Follow-up (both cases): a bgp_mvpn_withdraw_type1(bgp, old_id) hook
 * called before re-originating and on AF-deactivate/teardown, as
 * bgp_evpn_handle_router_id_update does.
 */
void bgp_mvpn_originate_type1(struct bgp *bgp)
{
	struct prefix_mvpn p;
	struct attr attr;
	struct in6_addr tunn_id = {};

	if (bgp->router_id.s_addr == INADDR_ANY)
		return;
	if (!bgp_mvpn_gtm_af_active(bgp))
		return;

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
	 * GTM global-table Route Target (target:0.0.0.0:0), the import/export target
	 * a GTM receiver (e.g. Junos mpls-internet-multicast) matches on the Intra-AS
	 * AD route; without it the route is rejected for want of a target community.
	 */
	bgp_mvpn_attach_gtm_rt(&attr);

	bgp_mvpn_route_install(bgp, bgp->peer_self, &p, &attr, BGP_ROUTE_STATIC);

	/*
	 * bgp_attr_flush releases the borrowed ecommunity ref (refcnt-aware) and the
	 * PMSI attr_extra, mirroring bgp_mvpn_source_active_set; aspath was interned
	 * by bgp_attr_default_set, so drop that local ref separately.
	 */
	bgp_attr_flush(&attr);
	aspath_unintern(&attr.aspath);
}

/*
 * TEST-ONLY scaffold: originate or withdraw a local Type-7 (C-multicast Source
 * Tree Join) route, mirroring bgp_mvpn_source_active_set(). Plan 3 replaces
 * this with real pimd-driven origination; the CLI that drives it is likewise
 * test-only.
 */
int bgp_mvpn_source_tree_join_set(struct bgp *bgp, uint32_t source_as, struct in_addr src,
				  struct in_addr grp, struct in_addr upstream, bool negate)
{
	struct prefix_mvpn p;
	struct attr attr;
	struct in_addr umh = upstream;
	struct ipaddr isrc = mvpn_ipaddr_v4(src);
	struct ipaddr igrp = mvpn_ipaddr_v4(grp);

	bgp_mvpn_build_prefix_type7(&p, source_as, &isrc, &igrp);

	if (negate) {
		bgp_mvpn_route_remove(bgp, bgp->peer_self, &p, BGP_ROUTE_STATIC);
		return CMD_SUCCESS;
	}

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
	 * identifying RT whose Global Administrator identifies that PBR". When no
	 * upstream is passed explicitly, derive it from the Source Active route's
	 * UMH. A join with no resolvable upstream is originated RT-less (not yet
	 * targetable) and logged.
	 */
	if (umh.s_addr == INADDR_ANY)
		bgp_mvpn_resolve_upstream_pe(bgp, src, grp, &umh);
	if (umh.s_addr != INADDR_ANY)
		bgp_mvpn_attach_ip_rt(&attr, umh);
	else
		zlog_debug("MVPN Type-7 (%pI4, %pI4): no upstream PE resolved; originating without upstream RT",
			   &src, &grp);

	bgp_mvpn_route_install(bgp, bgp->peer_self, &p, &attr, BGP_ROUTE_STATIC);

	bgp_attr_flush(&attr);
	aspath_unintern(&attr.aspath);
	return CMD_SUCCESS;
}

void bgp_mvpn_config_write(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_table *table = bgp->rib[afi][safi];
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

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

			/* Populate the cached display string once (RFC 7716
			 * Section 2.8.2 group-address RT on Type-5, and any RT a
			 * later route type carries), mirroring the generic route
			 * detail path.
			 */
			if (ecom && !ecom->str)
				ecommunity_str(ecom);

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
					if (m->route_type == BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN)
						json_object_int_add(jr, "sourceAs", m->source_as);
				}
				if (ecom) {
					json_object *je = json_object_new_object();

					json_object_string_add(je, "string", ecom->str);
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
					self ? "(local)" : "", ecom ? " " : "",
					ecom ? ecom->str : "");
			} else {
				vty_out(vty, " [%u] source %pIA group %pIA %s%s%s\n", m->route_type,
					&m->src, &m->grp, self ? "(local)" : "", ecom ? " " : "",
					ecom ? ecom->str : "");
			}
		}
	}

	if (use_json) {
		json_object_object_add(json, "routes", json_routes);
		vty_json(vty, json);
	}
}
