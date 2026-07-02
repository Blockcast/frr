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
 * route-type-specific. Only Type 5 (Source Active) is decoded; other types are
 * skipped using the on-wire Length so the stream stays framed.
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
	struct in_addr src;
	struct in_addr grp;
	bool addpath_capable;
	uint32_t addpath_id;
	int ret = BGP_NLRI_PARSE_OK;

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

		if (route_type != BGP_MVPN_ROUTE_TYPE_SOURCE_ACTIVE) {
			/* Unsupported route type: skip its body, stay framed. */
			stream_forward_getp(data, length);
			continue;
		}

		if (length != BGP_MVPN_TYPE5_V4_SPEC_LEN) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%s [Error] MVPN Type-5 bad length %u (expected %u)", peer->host,
				 length, BGP_MVPN_TYPE5_V4_SPEC_LEN);
			ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
			goto done;
		}

		/* RD (8 octets) is always zero under GTM; read and ignore. */
		stream_forward_getp(data, 8);

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
				json_object_string_addf(jr, "source", "%pI4", &m->src);
				json_object_string_addf(jr, "group", "%pI4", &m->grp);
				json_object_boolean_add(jr, "selfOriginated", self);
				json_object_array_add(json_routes, jr);
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
