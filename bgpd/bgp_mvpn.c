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

void bgp_mvpn_build_prefix_type5(struct prefix_mvpn *p, struct in_addr src, struct in_addr grp)
{
	memset(p, 0, sizeof(*p));
	p->family = AF_MVPN;
	p->prefixlen = BGP_MVPN_PREFIXLEN;
	p->prefix.route_type = BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE;
	p->prefix.src = src;
	p->prefix.grp = grp;
}

/*
 * Fill a prefix_mvpn for a Type-1 (Intra-AS I-PMSI A-D) route. Memset-zeroed
 * first like the other builders so padding is deterministic and the radix key /
 * prefix_same() memcmp are stable. Type-1 (RFC 6514 Section 4.1) carries no
 * C-S/C-G: the Originating Router's IP Address is overloaded into the src slot
 * (route_type=1 in key byte 0 keeps it distinct from Type-5/7); grp and
 * source_as remain zero.
 */
void bgp_mvpn_build_prefix_type1(struct prefix_mvpn *p, struct in_addr orig_ip)
{
	memset(p, 0, sizeof(*p));
	p->family = AF_MVPN;
	p->prefixlen = BGP_MVPN_PREFIXLEN;
	p->prefix.route_type = BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI;
	p->prefix.src = orig_ip;
}

/*
 * Fill a prefix_mvpn for a Type-7 (C-multicast Source Tree Join) route. Like
 * the Type-5 builder, the struct is memset-zeroed first so that padding is
 * deterministic and the radix key / prefix_same() memcmp are stable. The
 * Source AS is stored in host order in the RIB key so distinct upstream ASes
 * key to distinct routes and the value is renderable from the prefix.
 */
void bgp_mvpn_build_prefix_type7(struct prefix_mvpn *p, uint32_t source_as, struct in_addr src,
				 struct in_addr grp)
{
	memset(p, 0, sizeof(*p));
	p->family = AF_MVPN;
	p->prefixlen = BGP_MVPN_PREFIXLEN;
	p->prefix.route_type = BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN;
	p->prefix.source_as = source_as;
	p->prefix.src = src;
	p->prefix.grp = grp;
}

/*
 * RFC 6514 Section 4.5 Source Active A-D route (IPv4). The RD is emitted as 8
 * zero octets per RFC 7716 Global Table Multicast.
 */
void bgp_mvpn_encode_type5(struct stream *s, const struct prefix *p, bool addpath_capable,
			   uint32_t addpath_tx_id)
{
	const struct mvpn_addr *m = &p->u.prefix_mvpn;

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	stream_putc(s, m->route_type);		    /* Route Type = 5 */
	stream_putc(s, BGP_MVPN_TYPE5_V4_SPEC_LEN); /* Length */
	stream_put(s, NULL, 8);			    /* RD = 0 (GTM) */
	stream_putc(s, IPV4_MAX_BITLEN);	    /* Multicast Source Length */
	stream_put_in_addr(s, &m->src);		    /* Multicast Source (C-S) */
	stream_putc(s, IPV4_MAX_BITLEN);	    /* Multicast Group Length */
	stream_put_in_addr(s, &m->grp);		    /* Multicast Group (C-G) */
}

/*
 * RFC 6514 Section 4.6 C-multicast Source Tree Join route (IPv4). Adds a
 * 4-octet Source AS after the (zero, GTM) RD relative to Type-5. Source AS is
 * held in host order in the prefix and emitted network order via stream_putl.
 */
void bgp_mvpn_encode_type7(struct stream *s, const struct prefix *p, bool addpath_capable,
			   uint32_t addpath_tx_id)
{
	const struct mvpn_addr *m = &p->u.prefix_mvpn;

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	stream_putc(s, m->route_type);		    /* Route Type = 7 */
	stream_putc(s, BGP_MVPN_TYPE7_V4_SPEC_LEN); /* Length */
	stream_put(s, NULL, 8);			    /* RD = 0 (GTM) */
	stream_putl(s, m->source_as);		    /* Source AS */
	stream_putc(s, IPV4_MAX_BITLEN);	    /* Multicast Source Length */
	stream_put_in_addr(s, &m->src);		    /* Multicast Source (C-S) */
	stream_putc(s, IPV4_MAX_BITLEN);	    /* Multicast Group Length */
	stream_put_in_addr(s, &m->grp);		    /* Multicast Group (C-G) */
}

/*
 * RFC 6514 Section 4.1 Intra-AS I-PMSI A-D route (IPv4): RD (8, zero under GTM)
 * + Originating Router's IP Address (4). Carries no C-S/C-G; the endpoint is
 * conveyed out-of-band in the PMSI Tunnel path attribute (Section 5).
 */
void bgp_mvpn_encode_type1(struct stream *s, const struct prefix *p, bool addpath_capable,
			   uint32_t addpath_tx_id)
{
	const struct mvpn_addr *m = &p->u.prefix_mvpn;

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	stream_putc(s, m->route_type);		    /* Route Type = 1 */
	stream_putc(s, BGP_MVPN_TYPE1_V4_SPEC_LEN); /* Length */
	stream_put(s, NULL, 8);			    /* RD = 0 (GTM) */
	stream_put_in_addr(s, &m->src);		    /* Originating Router's IP */
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
 * Parse a received MCAST-VPN NLRI. Each NLRI is Route Type(1) + Length(1) +
 * route-type-specific. Type 5 (Source Active) and Type 7 (C-multicast Source
 * Tree Join) are decoded; other types are skipped using the on-wire Length so
 * the stream stays framed.
 *
 * GTM MVPN is IPv4-only in this milestone. The IPv6 MCAST-VPN AF negotiates the
 * capability (dual-stack SAFI-5 sessions per the design DoD) but v6 NLRI
 * encode/decode is a later plan; a received v6-shaped MVPN NLRI is rejected by
 * the v4 SPEC_LEN checks (fails safe, no corruption). The v4 prefixes built
 * below regardless of packet->afi are the v6-plan anchor.
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
	struct in_addr src;
	struct in_addr grp;
	uint32_t source_as;
	bool addpath_capable;
	uint32_t addpath_id;
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

	while (STREAM_READABLE(data) > 0) {
		addpath_id = 0;
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
			if (length != BGP_MVPN_TYPE1_V4_SPEC_LEN) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-1 bad length %u (expected %u)",
					 peer->host, length, BGP_MVPN_TYPE1_V4_SPEC_LEN);
				ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
				goto done;
			}

			/* RD (8 octets): read for validation after the body is
			 * fully consumed (GTM requires RD == 0). */
			STREAM_GET(rd, data, 8);

			/* Originating Router's IP Address -> src slot. */
			STREAM_GET(&src, data, IPV4_MAX_BYTELEN);

			bgp_mvpn_build_prefix_type1(&p, src);
			break;

		case BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE:
			if (length != BGP_MVPN_TYPE5_V4_SPEC_LEN) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-5 bad length %u (expected %u)",
					 peer->host, length, BGP_MVPN_TYPE5_V4_SPEC_LEN);
				ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
				goto done;
			}

			/* RD (8 octets): read for validation after the body is
			 * fully consumed (GTM requires RD == 0). */
			STREAM_GET(rd, data, 8);

			STREAM_GETC(data, src_len);
			STREAM_GET(&src, data, IPV4_MAX_BYTELEN);
			STREAM_GETC(data, grp_len);
			STREAM_GET(&grp, data, IPV4_MAX_BYTELEN);

			if (src_len != IPV4_MAX_BITLEN || grp_len != IPV4_MAX_BITLEN) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-5 non-v4 addr lengths (src %u grp %u)",
					 peer->host, src_len, grp_len);
				ret = BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
				goto done;
			}

			bgp_mvpn_build_prefix_type5(&p, src, grp);
			break;

		case BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN:
			if (length != BGP_MVPN_TYPE7_V4_SPEC_LEN) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-7 bad length %u (expected %u)",
					 peer->host, length, BGP_MVPN_TYPE7_V4_SPEC_LEN);
				ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
				goto done;
			}

			/* RD (8 octets): read for validation after the body is
			 * fully consumed (GTM requires RD == 0). */
			STREAM_GET(rd, data, 8);

			STREAM_GET(&source_as, data, 4);
			source_as = ntohl(source_as);
			STREAM_GETC(data, src_len);
			STREAM_GET(&src, data, IPV4_MAX_BYTELEN);
			STREAM_GETC(data, grp_len);
			STREAM_GET(&grp, data, IPV4_MAX_BYTELEN);

			if (src_len != IPV4_MAX_BITLEN || grp_len != IPV4_MAX_BITLEN) {
				flog_err(EC_BGP_UPDATE_RCV,
					 "%s [Error] MVPN Type-7 non-v4 addr lengths (src %u grp %u)",
					 peer->host, src_len, grp_len);
				ret = BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
				goto done;
			}

			bgp_mvpn_build_prefix_type7(&p, source_as, src, grp);
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

		if ((route_type == BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE ||
		     route_type == BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN) &&
		    !bgp_mvpn_group_is_ssm(grp)) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%s [Error] MVPN Type-%u group %pI4 outside SSM range 232.0.0.0/8; dropping route",
				 peer->host, route_type, &grp);
			continue;
		}

		/*
		 * A GTM Type-1 (Intra-AS I-PMSI A-D) is only meaningful with an
		 * Ingress-Replication PMSI Tunnel attribute (RFC 6514 Section 5).
		 * Checked on install only (the !mp_withdraw guard is load-bearing:
		 * a withdraw matches on the NLRI key alone, so its PMSI is
		 * irrelevant). The !attr term is defensive; the install path
		 * always carries an attr.
		 */
		if (route_type == BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI && !mp_withdraw &&
		    (!attr || bgp_attr_get_pmsi_tnl_type(attr) != PMSI_TNLTYPE_INGR_REPL)) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%s [Error] MVPN Type-1 without Ingress-Replication PMSI Tunnel; dropping route",
				 peer->host);
			continue;
		}

		if (mp_withdraw)
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
 * Configure or withdraw a locally-originated GTM Source Active route. Attr is a
 * self-sourced IGP route with the router-id as next hop.
 */
int bgp_mvpn_source_active_set(struct bgp *bgp, struct in_addr src, struct in_addr grp, bool negate)
{
	struct prefix_mvpn p;
	struct attr attr;

	bgp_mvpn_build_prefix_type5(&p, src, grp);

	if (negate) {
		bgp_mvpn_route_remove(bgp, bgp->peer_self, &p, BGP_ROUTE_STATIC);
		return CMD_SUCCESS;
	}

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	bgp_attr_set(&attr, BGP_ATTR_NEXT_HOP);
	attr.nexthop = bgp->router_id;
	attr.mp_nexthop_global_in = bgp->router_id;
	attr.mp_nexthop_len = IPV4_MAX_BYTELEN;

	bgp_mvpn_route_install(bgp, bgp->peer_self, &p, &attr, BGP_ROUTE_STATIC);

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
 * startup 0.0.0.0->addr path is clean (no prior route). Follow-up: withdraw the
 * old-router-id Type-1 before re-originating, as
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

	bgp_mvpn_build_prefix_type1(&p, bgp->router_id);

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

	bgp_mvpn_route_install(bgp, bgp->peer_self, &p, &attr, BGP_ROUTE_STATIC);

	aspath_unintern(&attr.aspath);
	bgp_attr_extra_discard(&attr);
}

/*
 * TEST-ONLY scaffold: originate or withdraw a local Type-7 (C-multicast Source
 * Tree Join) route, mirroring bgp_mvpn_source_active_set(). Plan 3 replaces
 * this with real pimd-driven origination; the CLI that drives it is likewise
 * test-only.
 */
int bgp_mvpn_source_tree_join_set(struct bgp *bgp, uint32_t source_as, struct in_addr src,
				  struct in_addr grp, bool negate)
{
	struct prefix_mvpn p;
	struct attr attr;

	bgp_mvpn_build_prefix_type7(&p, source_as, src, grp);

	if (negate) {
		bgp_mvpn_route_remove(bgp, bgp->peer_self, &p, BGP_ROUTE_STATIC);
		return CMD_SUCCESS;
	}

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	bgp_attr_set(&attr, BGP_ATTR_NEXT_HOP);
	attr.nexthop = bgp->router_id;
	attr.mp_nexthop_global_in = bgp->router_id;
	attr.mp_nexthop_len = IPV4_MAX_BYTELEN;

	bgp_mvpn_route_install(bgp, bgp->peer_self, &p, &attr, BGP_ROUTE_STATIC);

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

			vty_out(vty, "  bgp mvpn source-active %pI4 group %pI4\n", &m->src,
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

			if (use_json) {
				json_object *jr = json_object_new_object();

				json_object_int_add(jr, "routeType", m->route_type);
				if (m->route_type == BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI) {
					json_object_string_addf(jr, "originator", "%pI4", &m->src);
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
					json_object_string_addf(jr, "source", "%pI4", &m->src);
					json_object_string_addf(jr, "group", "%pI4", &m->grp);
					if (m->route_type == BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN)
						json_object_int_add(jr, "sourceAs", m->source_as);
				}
				json_object_boolean_add(jr, "selfOriginated", self);
				json_object_array_add(json_routes, jr);
			} else if (m->route_type == BGP_MVPN_ROUTE_TYPE_INTRA_AS_IPMSI) {
				vty_out(vty, " [%u] originator %pI4 %s%s\n", m->route_type, &m->src,
					bgp_attr_get_pmsi_tnl_type(pi->attr) ==
							PMSI_TNLTYPE_INGR_REPL
						? "IR "
						: "",
					self ? "(local)" : "");
			} else {
				vty_out(vty, " [%u] source %pI4 group %pI4 %s\n", m->route_type,
					&m->src, &m->grp, self ? "(local)" : "");
			}
		}
	}

	if (use_json) {
		json_object_object_add(json, "routes", json_routes);
		vty_json(vty, json);
	}
}
