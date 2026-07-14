#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
srcas_peer.py: minimal raw BGP speaker that iBGP-peers with the PE under
test and advertises the multicast source's unicast route carrying a Source
AS extended community (RFC 6514 Section 4.6: four-octet-AS-specific,
type 0x02, subtype 0x09) whose value the PE would NOT derive locally.

The PE originates a Type-7 (C-multicast Source Tree Join) keyed by that
Source AS when a receiver joins.  The test then STOPS this speaker so the
source route is withdrawn, and the receiver leaves: bgpd must withdraw the
Type-7 by (C-S, C-G) match.  Keying the withdraw off the re-derived Source
AS -- now the local AS, because the source route is gone -- would build a
different NLRI key and strand the originally originated route.

Usage: srcas_peer.py <peer_ip> <local_as> <local_id> <source_as>
"""

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
ECOMMUNITY_ENCODE_AS4 = 0x02
ECOMMUNITY_SOURCE_AS = 0x09

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


def build_source_update(next_hop, source_as):
    """A legacy IPv4-unicast UPDATE for SRC_PREFIX carrying a Source AS EC."""
    # Source AS extended community: type 0x02 (four-octet-AS-specific,
    # transitive), subtype 0x09 (Source AS), GA = 4-octet AS, LA = 0.
    srcas_ec = struct.pack(
        "!BBIH", ECOMMUNITY_ENCODE_AS4, ECOMMUNITY_SOURCE_AS, source_as, 0
    )

    attrs = b""
    # ORIGIN: well-known transitive, type 1, len 1, IGP(0)
    attrs += struct.pack("!BBBB", 0x40, 1, 1, 0)
    # AS_PATH: well-known transitive, type 2, len 0 (empty, iBGP)
    attrs += struct.pack("!BBB", 0x40, 2, 0)
    # NEXT_HOP: well-known transitive, type 3, len 4
    attrs += struct.pack("!BBB", 0x40, 3, 4) + socket.inet_aton(next_hop)
    # LOCAL_PREF: well-known transitive, type 5, len 4 (mandatory for iBGP)
    attrs += struct.pack("!BBB", 0x40, 5, 4) + struct.pack("!I", 100)
    # EXTENDED COMMUNITIES: optional transitive (0xC0), type 16
    attrs += struct.pack("!BBB", 0xC0, 16, len(srcas_ec)) + srcas_ec

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
    if len(sys.argv) != 5:
        print("Usage: srcas_peer.py <peer_ip> <local_as> <local_id> <source_as>")
        sys.exit(1)
    peer_ip = sys.argv[1]
    local_as = int(sys.argv[2])
    local_id = sys.argv[3]
    source_as = int(sys.argv[4])

    sock = handshake(peer_ip, local_as, local_id)
    print("BGP session established with {}".format(peer_ip), flush=True)

    sock.sendall(build_source_update(local_id, source_as))
    print(
        "advertised {}/{} with Source AS {}".format(
            SRC_PREFIX, SRC_PREFIXLEN, source_as
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
