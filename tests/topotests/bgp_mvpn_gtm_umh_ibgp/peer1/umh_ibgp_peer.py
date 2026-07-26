#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
umh_ibgp_peer.py: four AS_PATH shapes that each defeat a different naive
origin-AS lookup, for the LC-UMH trust check.

The resolver trusts a UMH tuple only when its Global Administrator equals the
AS that ORIGINATED the covering route. Determining that origin from an AS_PATH
is where the traps are, because aspath_get_last_as() returns the last member of
the last AS_SEQUENCE segment and skips set segments outright:

  1. empty      : no segments. The route has not crossed an AS boundary, so the
                  local AS genuinely is the origin. A tuple stamped
                  GA == our AS must be ACCEPTED. (Positive control: without it
                  the suite could pass by refusing everything.)
  2. as_set     : one bare AS_SET `{65002,65003}` -- what
                  `aggregate-address ... as-set` originates. Lookup returns 0,
                  same as the empty path, but the origin is genuinely unknown
                  and none of the set members is us. iBGP does not prepend, so
                  the receiving PE cannot tell this from an internal route by
                  looking at the peer. GA == our AS must be REJECTED.
  3. mixed      : AS_SEQUENCE [65010] then AS_SET {65002,65003} -- an aggregate
                  relayed by 65010. Lookup skips the set and returns 65010, so
                  it is NOT 0 and a hop-count guard never fires; but 65010 is
                  the aggregator, a transit AS, not the origin. RFC 4271 gives
                  this path no determinable origin at all. GA == 65010 must be
                  REJECTED -- otherwise any AS that aggregates a route can
                  claim a UMH for an origin it merely transits.
  4. confed_set : one bare AS_CONFED_SET. Lookup returns 0 AND
                  aspath_count_hops() returns 0, because hop counting treats an
                  AS_SET as one hop but ignores confederation segments
                  entirely. A hop-count test therefore reads this as an empty,
                  locally-originated path. GA == our AS must be REJECTED.

Every route carries an identical fallback Route Import extended community and
the same UMH parameter, so the AS_PATH shape and the stamped GA are the only
things that vary. Only shape 1 may resolve from the tuple; 2-4 must fall back
to the EC. That combination cannot hold unless the resolver treats any
set-bearing path as origin-ambiguous rather than trusting a single "last AS".

The UMH parameter is the usual endian known-answer (184549374 == 10.255.255.254).

Usage: umh_ibgp_peer.py <peer_ip> <local_as> <local_id>
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
AS_CONFED_SEQUENCE = 3
AS_CONFED_SET = 4

ECOMMUNITY_ENCODE_IP = 0x01
ECOMMUNITY_VRF_ROUTE_IMPORT = 0x0B

ATTR_LARGE_COMMUNITY = 32

# 184549374 == 10.255.255.254, the endian known-answer vector.
UMH_U32 = 184549374
# Function code point matching the PE's `bgp mvpn umh-large-community 1`.
FN = 1
# Fallback Route Import EC, carried by BOTH routes so the AS_PATH shape is the
# only difference between them.
RT_IMPORT = "10.9.9.9"

# The ASes an aggregate would carry in its AS_SET. Deliberately not the PE's.
AS_SET_MEMBERS = [65002, 65003]
# The AS that performed the aggregation, and so appears as the sole
# AS_SEQUENCE member to the left of the set in the `mixed` vector. It is a
# transit AS, NOT the origin -- but it is what aspath_get_last_as() reports.
AGGREGATOR_AS = 65010

# "ga" is the Global Administrator to stamp: "local" means the PE's own AS.
ROUTES = [
    {"prefix": "10.40.10.0", "as_path": "empty", "ga": "local"},
    {"prefix": "10.40.20.0", "as_path": "as_set", "ga": "local"},
    {"prefix": "10.40.30.0", "as_path": "mixed", "ga": AGGREGATOR_AS},
    {"prefix": "10.40.40.0", "as_path": "confed_set", "ga": "local"},
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


def _seg(seg_type, ases):
    return struct.pack("!BB", seg_type, len(ases)) + b"".join(
        struct.pack("!I", a) for a in ases
    )


def _as_path_attr(mode):
    """Four shapes, all of which defeat a naive origin lookup differently:

    empty      : no segments. The legal iBGP shape for a route originated
                 inside our own AS -- the only one where "origin == us".
    as_set     : one bare AS_SET, what `aggregate-address ... as-set`
                 originates. aspath_get_last_as() -> 0.
    mixed      : AS_SEQUENCE [65010] then AS_SET {65002,65003} -- an aggregate
                 relayed by 65010. aspath_get_last_as() skips the set and
                 returns 65010, the AGGREGATOR, so an unguarded resolver
                 believes a tuple stamped GA == 65010 even though 65010 did
                 not originate the route and the true origin is unknowable.
    confed_set : one bare AS_CONFED_SET. aspath_get_last_as() -> 0 AND
                 aspath_count_hops() -> 0 (it counts AS_SET as one hop but
                 ignores confed segments entirely), so a hop-count test reads
                 this as an empty, locally-originated path.
    """
    if mode == "empty":
        seg = b""
    elif mode == "as_set":
        seg = _seg(AS_SET, AS_SET_MEMBERS)
    elif mode == "mixed":
        seg = _seg(AS_SEQUENCE, [AGGREGATOR_AS]) + _seg(AS_SET, AS_SET_MEMBERS)
    elif mode == "confed_set":
        seg = _seg(AS_CONFED_SET, AS_SET_MEMBERS)
    else:
        raise ValueError("unknown as_path mode {}".format(mode))
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


def build_update(route, next_hop, local_as):
    attrs = b""
    attrs += struct.pack("!BBBB", 0x40, 1, 1, 0)  # ORIGIN = IGP
    attrs += _as_path_attr(route["as_path"])
    attrs += struct.pack("!BBB", 0x40, 3, 4) + socket.inet_aton(next_hop)  # NEXT_HOP
    attrs += struct.pack("!BBBI", 0x40, 5, 4, 100)  # LOCAL_PREF (iBGP well-known)
    # Each route is stamped with the GA that an unguarded resolver would
    # believe for its AS_PATH shape: the PE's own AS where the origin lookup
    # yields 0, the aggregator where the lookup skips the set and yields
    # 65010. Only the empty path makes that claim truthfully.
    ga = local_as if route["ga"] == "local" else route["ga"]
    attrs += _large_community_attr(ga, FN, UMH_U32)
    attrs += _rt_import_attr(RT_IMPORT)

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
    args = parser.parse_args()

    sock = handshake(args.peer_ip, args.local_as, args.local_id)
    print("iBGP session established with {}".format(args.peer_ip), flush=True)

    for route in ROUTES:
        sock.sendall(build_update(route, args.local_id, args.local_as))
        print(
            "advertised {}/{} as_path={} ga={}".format(
                route["prefix"], PREFIXLEN, route["as_path"], route["ga"]
            ),
            flush=True,
        )

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
