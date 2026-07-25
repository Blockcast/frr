#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
umh_ibgp_peer.py: raw iBGP speaker that separates "the AS_PATH is empty" from
"the AS_PATH is a bare AS_SET" for the LC-UMH origin-AS trust check.

aspath_get_last_as() walks every segment but reads only AS_SEQUENCE members,
so it returns 0 for BOTH of those paths -- and the resolver used to treat that
0 as "origin is us" for any iBGP-learned route. The two are not equivalent:

  1. empty  : no segments at all. The route has not crossed an AS boundary, so
              the local AS genuinely is the origin. A tuple stamped
              GA == our AS must be ACCEPTED.
  2. as_set : one bare AS_SET segment, `{65002,65003}` -- what
              `aggregate-address ... as-set` originates. The ASes in the set
              are the aggregated routes' origins and none of them is us. Such
              a path arrives over iBGP with no AS prepended (iBGP does not
              prepend), so the receiving PE cannot tell it apart from an
              internal route by looking at the peer. A tuple stamped
              GA == our AS here was stamped by whichever external AS's route
              got aggregated, and must be REJECTED.

Both routes carry an identical UMH large community (GA == the PE's own AS) and
an identical fallback Route Import extended community, so the ONLY thing that
differs between them is the AS_PATH shape -- which is exactly the condition
under test. Accepting #1 and rejecting #2 cannot both happen unless the
resolver distinguishes empty from AS_SET.

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

ROUTES = [
    {"prefix": "10.40.10.0", "as_path": "empty"},
    {"prefix": "10.40.20.0", "as_path": "as_set"},
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


def _as_path_attr(mode):
    """empty -> a zero-length AS_PATH (no segments), the legal iBGP shape for a
    route originated inside our own AS. as_set -> a single AS_SET segment, the
    shape `aggregate-address ... as-set` produces; note there is no preceding
    AS_SEQUENCE, which is what makes aspath_get_last_as() return 0 rather than
    the last sequence member."""
    if mode == "empty":
        seg = b""
    else:
        seg = struct.pack("!BB", AS_SET, len(AS_SET_MEMBERS)) + b"".join(
            struct.pack("!I", a) for a in AS_SET_MEMBERS
        )
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
    # GA == the PE's own AS on BOTH routes: legitimate on the empty path,
    # a forged claim on the aggregate.
    attrs += _large_community_attr(local_as, FN, UMH_U32)
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
            "advertised {}/{} as_path={}".format(
                route["prefix"], PREFIXLEN, route["as_path"]
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
