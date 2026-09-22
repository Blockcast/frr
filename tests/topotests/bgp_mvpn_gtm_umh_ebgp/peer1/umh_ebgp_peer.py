#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
umh_ebgp_peer.py: raw eBGP speaker that exercises the LC-UMH origin-AS trust
boundary. It peers with the PE over eBGP (its own AS 65010 != the PE's 65001)
and, in one session, advertises three source-covering unicast routes -- all
with a well-formed AS_SEQUENCE path (origin AS 65010) -- whose UMH large
community probes the trust check:

  1. local : UMH Global Administrator == the PE's OWN local AS (65001). The
             route's real origin over eBGP is 65010, so GA != origin and the
             crafted tuple must be rejected -- a neighbor one hop away cannot
             stamp "GA == your AS" and be believed. Falls back to the Route
             Import extended community.
  2. ga0   : UMH Global Administrator == 0. Must be rejected outright and fall
             back to the extended community.
  3. ok    : UMH Global Administrator == 65010 == the route's origin AS -- the
             legitimate case, which must be accepted (positive control:
             proves the rejects are origin-AS-specific, not a blanket refusal).

Note on scope: aspath_get_last_as() returns 0 only for an empty or bare-AS_SET
AS_PATH, both malformed for eBGP and discarded by FRR (RFC 7606) before the
resolver runs -- so the "unresolvable origin collapses to the local AS"
fail-open is not reachable over a real eBGP session (it is guarded for the
iBGP/locally-originated paths where an empty AS_PATH is legal). The
eBGP-reachable trust boundary is GA != origin, which cases 1-3 cover.

The UMH parameter is the same endian known-answer used elsewhere
(184549374 == 10.255.255.254).

It then sends two MCAST-VPN Type-5 (Source Active) NLRIs that probe the
receive path's AS-path loop check over this same eBGP session:

  loop : AS_PATH "65001 65010" -- contains the PE's OWN AS, the exact shape a
         PE sees when the PoP echoes the PE's route back. Must be DROPPED.
  ok   : AS_PATH "65010" -- the peer's own AS only. Must be INSTALLED.

The pair is what makes the check's reference AS observable. bgp_nlri_parse_mvpn()
must compare against the LOCAL AS (bgp->as); a check written against peer->as
would drop the "ok" route too, because over eBGP every route the peer sends
begins with the peer's AS. The iBGP crafter in bgp_mvpn_gtm_malformed cannot
see that distinction (there bgp->as == peer->as), which is why this case lives
here.

Usage: umh_ebgp_peer.py <peer_ip> <local_as> <local_id> <pe_as>
"""

import argparse
import socket
import struct
import sys
import time

MARKER = b"\xff" * 16
BGP_OPEN = 1
BGP_UPDATE = 2
BGP_NOTIFICATION = 3
BGP_KEEPALIVE = 4
BGP_VERSION = 4
HOLD_TIME = 90

AFI_IP = 1
SAFI_UNICAST = 1
SAFI_MCAST_VPN = 5

AS_SET = 1
AS_SEQUENCE = 2

MVPN_TYPE5 = 5
IPV4_BITLEN = 32

# MCAST-VPN Type-5 probes for the receive-path AS-path loop check. Both are
# valid GTM routes (RD 0, SSM group); they differ only in AS_PATH.
LOOP_SRC = "10.80.80.1"
LOOP_GRP = "232.80.80.1"
OK_SRC = "10.80.80.2"
OK_GRP = "232.80.80.2"

ECOMMUNITY_ENCODE_IP = 0x01
ECOMMUNITY_VRF_ROUTE_IMPORT = 0x0B

ATTR_LARGE_COMMUNITY = 32

# The UMH parameter carried in every crafted large community: 184549374 is the
# uint32 form of 10.255.255.254, the endian known-answer vector.
UMH_U32 = 184549374
# Function code point matching the PE's `bgp mvpn umh-large-community 1` knob.
FN = 1
# The Route Import extended community used as the fallback target for the two
# routes whose UMH tuple must be rejected.
RT_IMPORT = "10.9.9.9"

# The three crafted routes. Each covers a distinct multicast source /32. All
# use a well-formed AS_SEQUENCE path (origin = this speaker's AS 65010) -- a
# bare AS_SET, the only way to make aspath_get_last_as() return 0, is a
# malformed eBGP AS_PATH that FRR discards (RFC 7606) before the resolver runs,
# so origin-AS-unresolvable is not reachable over a real eBGP session; the
# eBGP-reachable trust boundary is GA != origin, which these exercise.
ROUTES = [
    {"prefix": "10.30.10.0", "as_path": "seq", "ga": "local", "rt_import": RT_IMPORT},
    {"prefix": "10.30.20.0", "as_path": "seq", "ga": 0, "rt_import": RT_IMPORT},
    {"prefix": "10.30.30.0", "as_path": "seq", "ga": "origin", "rt_import": None},
]
PREFIXLEN = 24


def build_open(local_as, router_id):
    rid = socket.inet_aton(router_id)
    mp_uni = struct.pack("!BB", 1, 4) + struct.pack("!HBB", AFI_IP, 0, SAFI_UNICAST)
    mp_mvpn = struct.pack("!BB", 1, 4) + struct.pack("!HBB", AFI_IP, 0, SAFI_MCAST_VPN)
    as4_cap = struct.pack("!BB", 65, 4) + struct.pack("!I", local_as)
    caps = mp_uni + mp_mvpn + as4_cap
    opt_params = struct.pack("!BB", 2, len(caps)) + caps
    as_field = local_as if local_as < 65536 else 23456  # AS_TRANS
    payload = (
        struct.pack("!BHH4sB", BGP_VERSION, as_field, HOLD_TIME, rid, len(opt_params))
        + opt_params
    )
    return MARKER + struct.pack("!HB", 19 + len(payload), BGP_OPEN) + payload


def build_keepalive():
    return MARKER + struct.pack("!HB", 19, BGP_KEEPALIVE)


def _as_path_attr(mode, local_as):
    """Craft the AS_PATH: a one-AS AS_SEQUENCE (AS4), origin == local_as."""
    seg = struct.pack("!BB", AS_SEQUENCE, 1) + struct.pack("!I", local_as)
    return struct.pack("!BBB", 0x40, 2, len(seg)) + seg


def _large_community_attr(ga, fn, param):
    val = struct.pack("!III", ga, fn, param)
    return struct.pack("!BBB", 0xC0, ATTR_LARGE_COMMUNITY, len(val)) + val


def _rt_import_attr(rt_import):
    ec = struct.pack(
        "!BB4sH", ECOMMUNITY_ENCODE_IP, ECOMMUNITY_VRF_ROUTE_IMPORT,
        socket.inet_aton(rt_import), 0,
    )
    return struct.pack("!BBB", 0xC0, 16, len(ec)) + ec


def _type5_nlri(src, grp):
    """MVPN Type-5 NLRI: RouteType, Length, RD(8, zero under GTM), S, G."""
    body = (
        b"\x00" * 8
        + struct.pack("!B", IPV4_BITLEN)
        + socket.inet_aton(src)
        + struct.pack("!B", IPV4_BITLEN)
        + socket.inet_aton(grp)
    )
    return struct.pack("!BB", MVPN_TYPE5, len(body)) + body


def build_mvpn_update(src, grp, next_hop, as_path):
    """UPDATE carrying one MCAST-VPN Type-5 with an explicit AS_PATH.

    as_path is a list of ASNs emitted in order as one AS_SEQUENCE segment of
    the ordinary AS_PATH attribute (type 2). The OPEN negotiates the 4-octet-AS
    capability, so each ASN is 4 bytes wide. No LOCAL_PREF: this is eBGP.
    """
    nh = socket.inet_aton(next_hop)
    mp_reach_val = (
        struct.pack("!HB", AFI_IP, SAFI_MCAST_VPN)
        + struct.pack("!B", len(nh))
        + nh
        + struct.pack("!B", 0)
        + _type5_nlri(src, grp)
    )

    seg = struct.pack("!BB", AS_SEQUENCE, len(as_path)) + b"".join(
        struct.pack("!I", asn) for asn in as_path
    )
    attrs = struct.pack("!BBBB", 0x40, 1, 1, 0)  # ORIGIN = IGP
    attrs += struct.pack("!BBB", 0x40, 2, len(seg)) + seg  # AS_PATH
    attrs += struct.pack("!BBB", 0x80, 14, len(mp_reach_val)) + mp_reach_val

    payload = struct.pack("!H", 0) + struct.pack("!H", len(attrs)) + attrs
    return MARKER + struct.pack("!HB", 19 + len(payload), BGP_UPDATE) + payload


def build_update(route, next_hop, local_as):
    ga = route["ga"]
    if ga == "local":
        ga = LOCAL_PEER_AS  # the PE's own AS (crafted "trust me, I am you")
    elif ga == "origin":
        ga = local_as

    attrs = b""
    attrs += struct.pack("!BBBB", 0x40, 1, 1, 0)  # ORIGIN = IGP
    attrs += _as_path_attr(route["as_path"], local_as)
    attrs += struct.pack("!BBB", 0x40, 3, 4) + socket.inet_aton(next_hop)  # NEXT_HOP
    attrs += _large_community_attr(ga, FN, UMH_U32)
    if route["rt_import"]:
        attrs += _rt_import_attr(route["rt_import"])

    nlri = struct.pack("!B", PREFIXLEN) + socket.inet_aton(route["prefix"])[:3]
    payload = struct.pack("!H", 0) + struct.pack("!H", len(attrs)) + attrs + nlri
    return MARKER + struct.pack("!HB", 19 + len(payload), BGP_UPDATE) + payload


def recv_msg(sock):
    header = b""
    while len(header) < 19:
        data = sock.recv(19 - len(header))
        if not data:
            raise ConnectionError("Connection closed")
        header += data
    length = struct.unpack("!H", header[16:18])[0]
    msg_type = header[18]
    remaining = length - 19
    payload = b""
    while len(payload) < remaining:
        data = sock.recv(remaining - len(payload))
        if not data:
            raise ConnectionError("Connection closed")
        payload += data
    return msg_type, payload


def handshake(peer_ip, local_as, router_id):
    last_err = None
    for attempt in range(30):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((peer_ip, 179))
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            print("attempt {}: TCP connected".format(attempt), flush=True)
            sock.sendall(build_open(local_as, router_id))
            mt, _ = recv_msg(sock)
            if mt != BGP_OPEN:
                raise ConnectionError("expected OPEN, got {}".format(mt))
            sock.sendall(build_keepalive())
            for _ in range(10):
                mt, _ = recv_msg(sock)
                if mt == BGP_KEEPALIVE:
                    break
                if mt == BGP_NOTIFICATION:
                    raise ConnectionError("peer sent NOTIFICATION")
            return sock
        except (ConnectionError, ConnectionRefusedError, OSError, socket.timeout) as e:
            last_err = "{}: {}".format(type(e).__name__, e)
            print("attempt {} failed: {}".format(attempt, last_err), flush=True)
            if sock:
                sock.close()
            time.sleep(2)
    raise SystemExit(
        "ERROR: could not establish BGP session with {} (last: {})".format(
            peer_ip, last_err
        )
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("peer_ip")
    parser.add_argument("local_as", type=int)
    parser.add_argument("local_id")
    parser.add_argument("pe_as", type=int, help="the PE's local AS (for the GA==local craft)")
    args = parser.parse_args()

    global LOCAL_PEER_AS
    LOCAL_PEER_AS = args.pe_as

    sock = handshake(args.peer_ip, args.local_as, args.local_id)
    print("eBGP session established with {}".format(args.peer_ip), flush=True)

    for route in ROUTES:
        sock.sendall(build_update(route, args.local_id, args.local_as))
        print(
            "advertised {}/{} as_path={} ga={}".format(
                route["prefix"], PREFIXLEN, route["as_path"], route["ga"]
            ),
            flush=True,
        )

    # MCAST-VPN loop-check probes. Order matters: the "ok" control is sent
    # LAST, so a test that waits for it knows the "loop" route was already
    # decided on.
    sock.sendall(
        build_mvpn_update(LOOP_SRC, LOOP_GRP, args.local_id, [args.local_as, args.pe_as])
    )
    print("advertised MVPN Type-5 {} as_path=[{}, {}] (loop)".format(
        LOOP_SRC, args.local_as, args.pe_as), flush=True)
    sock.sendall(build_mvpn_update(OK_SRC, OK_GRP, args.local_id, [args.local_as]))
    print("advertised MVPN Type-5 {} as_path=[{}] (ok)".format(
        OK_SRC, args.local_as), flush=True)

    sock.settimeout(1)
    while True:
        try:
            mt, _ = recv_msg(sock)
            if mt == BGP_KEEPALIVE:
                sock.sendall(build_keepalive())
            elif mt == BGP_NOTIFICATION:
                break
        except socket.timeout:
            try:
                sock.sendall(build_keepalive())
            except OSError:
                break
        except (ConnectionError, BrokenPipeError, OSError, struct.error):
            break
    sys.exit(0)


if __name__ == "__main__":
    main()
