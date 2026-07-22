#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
umh_peer.py: minimal raw BGP speaker that iBGP-peers with the PE under test
and advertises the multicast source's covering unicast route with a
caller-chosen LOCAL_PREF and any combination of the two RFC 6514 Section 5
communities the PE's Type-7 resolver reads:

  --source-as N    Source AS extended community (four-octet-AS-specific,
                   type 0x02, subtype 0x09, GA = N, LA = 0)
  --rt-import IP   VRF Route Import extended community (IPv4-address-
                   specific, type 0x01, subtype 0x0b, GA = IP, LA = 0;
                   Junos "rt-import")

Two instances with different LOCAL_PREFs give the PE a multipath source
route whose best and non-best paths carry different communities -- the
scaffold for asserting the resolver reads the selected path only, and reads
both values off that one path as a unit.

Usage: umh_peer.py <peer_ip> <local_as> <local_id> <localpref>
                   [--source-as N] [--rt-import IP]
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
ECOMMUNITY_ENCODE_IP = 0x01
ECOMMUNITY_ENCODE_AS4 = 0x02
ECOMMUNITY_SOURCE_AS = 0x09
ECOMMUNITY_VRF_ROUTE_IMPORT = 0x0B

# The multicast source's covering unicast route (covers source 10.10.10.10).
SRC_PREFIX = "10.10.10.0"
SRC_PREFIXLEN = 24


def build_open(local_as, router_id):
    """OPEN advertising the IPv4-unicast MP capability and 4-octet AS."""
    rid = socket.inet_aton(router_id)
    mp_cap = struct.pack("!BB", 1, 4) + struct.pack("!HBB", AFI_IP, 0, SAFI_UNICAST)
    # Also negotiate MCAST-VPN so the PE's ipv4 mvpn AF has an established
    # neighbor and will originate the local Type-7 (the PE advertises the
    # Type-7 back to us; our recv loop just ignores it).
    mp_cap_mvpn = struct.pack("!BB", 1, 4) + struct.pack("!HBB", AFI_IP, 0, SAFI_MCAST_VPN)
    as4_cap = struct.pack("!BB", 65, 4) + struct.pack("!I", local_as)
    caps = mp_cap + mp_cap_mvpn + as4_cap
    opt_params = struct.pack("!BB", 2, len(caps)) + caps
    as_field = local_as if local_as < 65536 else 23456  # AS_TRANS
    payload = (
        struct.pack("!BHH4sB", BGP_VERSION, as_field, HOLD_TIME, rid, len(opt_params))
        + opt_params
    )
    return MARKER + struct.pack("!HB", 19 + len(payload), BGP_OPEN) + payload


def build_keepalive():
    return MARKER + struct.pack("!HB", 19, BGP_KEEPALIVE)


def build_source_update(next_hop, localpref, source_as, rt_import):
    """A legacy IPv4-unicast UPDATE for SRC_PREFIX carrying the requested
    LOCAL_PREF and extended communities."""
    ecs = b""
    if source_as is not None:
        # Source AS: type 0x02 (four-octet-AS-specific, transitive),
        # subtype 0x09, GA = 4-octet AS, LA = 0.
        ecs += struct.pack(
            "!BBIH", ECOMMUNITY_ENCODE_AS4, ECOMMUNITY_SOURCE_AS, source_as, 0
        )
    if rt_import is not None:
        # VRF Route Import: type 0x01 (IPv4-address-specific, transitive),
        # subtype 0x0b, GA = IPv4 address, LA = 0.
        ecs += struct.pack(
            "!BB4sH",
            ECOMMUNITY_ENCODE_IP,
            ECOMMUNITY_VRF_ROUTE_IMPORT,
            socket.inet_aton(rt_import),
            0,
        )

    attrs = b""
    # ORIGIN: well-known transitive, type 1, len 1, IGP(0)
    attrs += struct.pack("!BBBB", 0x40, 1, 1, 0)
    # AS_PATH: well-known transitive, type 2, len 0 (empty, iBGP)
    attrs += struct.pack("!BBB", 0x40, 2, 0)
    # NEXT_HOP: well-known transitive, type 3, len 4
    attrs += struct.pack("!BBB", 0x40, 3, 4) + socket.inet_aton(next_hop)
    # LOCAL_PREF: well-known transitive, type 5, len 4 (mandatory for iBGP)
    attrs += struct.pack("!BBB", 0x40, 5, 4) + struct.pack("!I", localpref)
    if ecs:
        # EXTENDED COMMUNITIES: optional transitive (0xC0), type 16
        attrs += struct.pack("!BBB", 0xC0, 16, len(ecs)) + ecs

    # NLRI: <prefix-length octet><ceil(len/8) prefix octets>
    nlri = struct.pack("!B", SRC_PREFIXLEN) + socket.inet_aton(SRC_PREFIX)[:3]
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
    parser.add_argument("localpref", type=int)
    parser.add_argument("--source-as", type=int, default=None)
    parser.add_argument("--rt-import", default=None)
    args = parser.parse_args()

    sock = handshake(args.peer_ip, args.local_as, args.local_id)
    print("BGP session established with {}".format(args.peer_ip), flush=True)

    sock.sendall(
        build_source_update(args.local_id, args.localpref, args.source_as, args.rt_import)
    )
    print(
        "advertised {}/{} localpref={} source-as={} rt-import={}".format(
            SRC_PREFIX, SRC_PREFIXLEN, args.localpref, args.source_as, args.rt_import
        ),
        flush=True,
    )

    # Keepalive loop so the session stays up until the test stops us; the
    # process exit (test kill) is what withdraws the source route.
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
