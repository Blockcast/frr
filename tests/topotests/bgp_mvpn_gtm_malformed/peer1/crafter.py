#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
crafter.py: minimal raw BGP speaker that negotiates the MCAST-VPN (AFI 1,
SAFI 5) address family and sends deliberately crafted MVPN Route Type 5
(Source Active) NLRIs to exercise the receive-path hardening in
bgp_nlri_parse_mvpn().

It sends, in order:

  A. VALID Type-5 (RD 0, SSM group) -- POSITIVE CONTROL, must be installed.
  B. non-SSM Type-5 (group outside 232.0.0.0/8) -- must be dropped.
  C. non-zero-RD Type-5 (RD != 0 under GTM) -- must be dropped.
  D. empty MP_UNREACH_NLRI (AFI+SAFI only, zero withdrawn NLRI) -- must NOT
     crash the receiver. Before the fix this hit stream_new(0) -> assert(0)
     and aborted bgpd.

The positive control is essential: it proves the crafted NLRI encoding and
the AF negotiation are correct, so that "route absent" for B and C means the
reject logic fired, not that the whole path is broken.

Usage: crafter.py <peer_ip> <local_as> <local_id>
"""

import select
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
SAFI_MCAST_VPN = 5
MVPN_TYPE5 = 5
MVPN_TYPE5_SPEC_LEN = 18
IPV4_BITLEN = 32

# Crafted (S,G)s. Distinct per case so the test can assert each independently.
VALID_SRC = "10.9.9.9"
VALID_GRP = "232.9.9.9"       # in SSM 232/8, RD 0 -> must install
NONSSM_SRC = "10.20.20.1"
NONSSM_GRP = "239.1.1.1"      # ASM range -> must be dropped
NONRD_SRC = "10.20.20.2"
NONRD_GRP = "232.2.2.2"       # valid SSM group, but RD != 0 -> must be dropped


def build_open(local_as, router_id):
    """OPEN advertising the MCAST-VPN MP capability and 4-octet AS."""
    rid = socket.inet_aton(router_id)

    # Multiprotocol Extensions capability (code 1): AFI(2) Reserved(1) SAFI(1)
    mp_cap = struct.pack("!BB", 1, 4) + struct.pack("!HBB", AFI_IP, 0, SAFI_MCAST_VPN)
    # 4-octet AS capability (code 65): AS(4)
    as4_cap = struct.pack("!BB", 65, 4) + struct.pack("!I", local_as)
    caps = mp_cap + as4_cap
    # Optional parameter type 2 (Capabilities)
    opt_params = struct.pack("!BB", 2, len(caps)) + caps

    as_field = local_as if local_as < 65536 else 23456  # AS_TRANS
    payload = (
        struct.pack("!BHH4sB", BGP_VERSION, as_field, HOLD_TIME, rid, len(opt_params))
        + opt_params
    )
    return MARKER + struct.pack("!HB", 19 + len(payload), BGP_OPEN) + payload


def build_keepalive():
    return MARKER + struct.pack("!HB", 19, BGP_KEEPALIVE)


def _type5_nlri(rd, src, grp):
    """MVPN Type-5 NLRI: RouteType, Length, RD(8), SrcLen, Src, GrpLen, Grp."""
    return (
        struct.pack("!BB", MVPN_TYPE5, MVPN_TYPE5_SPEC_LEN)
        + rd
        + struct.pack("!B", IPV4_BITLEN)
        + socket.inet_aton(src)
        + struct.pack("!B", IPV4_BITLEN)
        + socket.inet_aton(grp)
    )


def build_mvpn_update(local_id, rd, src, grp):
    """UPDATE with ORIGIN, empty AS_PATH (iBGP) and an MP_REACH Type-5 NLRI."""
    nlri = _type5_nlri(rd, src, grp)

    # MP_REACH_NLRI value: AFI(2) SAFI(1) NHLen(1) NH(4) Reserved(1) NLRI
    mp_reach_val = (
        struct.pack("!HB", AFI_IP, SAFI_MCAST_VPN)
        + struct.pack("!B", 4)
        + socket.inet_aton(local_id)
        + struct.pack("!B", 0)
        + nlri
    )

    attrs = b""
    # ORIGIN: well-known transitive (0x40), type 1, len 1, IGP(0)
    attrs += struct.pack("!BBBB", 0x40, 1, 1, 0)
    # AS_PATH: well-known transitive, type 2, len 0 (empty path, iBGP)
    attrs += struct.pack("!BBB", 0x40, 2, 0)
    # LOCAL_PREF: well-known transitive, type 5, len 4 (mandatory for iBGP)
    attrs += struct.pack("!BBB", 0x40, 5, 4) + struct.pack("!I", 100)
    # MP_REACH_NLRI: optional (0x80), type 14
    attrs += struct.pack("!BBB", 0x80, 14, len(mp_reach_val)) + mp_reach_val

    payload = struct.pack("!H", 0) + struct.pack("!H", len(attrs)) + attrs
    return MARKER + struct.pack("!HB", 19 + len(payload), BGP_UPDATE) + payload


def build_empty_mp_unreach():
    """UPDATE with an MP_UNREACH_NLRI carrying AFI+SAFI only (no NLRI).

    The attribute value is exactly 3 bytes, so the MVPN parser sees a
    zero-length NLRI. This is the crash-on-empty-withdraw (stream_new(0))
    case the fix guards.
    """
    mp_unreach_val = struct.pack("!HB", AFI_IP, SAFI_MCAST_VPN)  # 3 bytes, no NLRI
    attrs = struct.pack("!BBB", 0x80, 15, len(mp_unreach_val)) + mp_unreach_val
    payload = struct.pack("!H", 0) + struct.pack("!H", len(attrs)) + attrs
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
            # Drain until we see the peer's KEEPALIVE (it may send more caps/RR).
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
    if len(sys.argv) != 4:
        print("Usage: crafter.py <peer_ip> <local_as> <local_id>")
        sys.exit(1)
    peer_ip = sys.argv[1]
    local_as = int(sys.argv[2])
    local_id = sys.argv[3]

    sock = handshake(peer_ip, local_as, local_id)
    print("BGP session established with {}".format(peer_ip), flush=True)

    zero_rd = b"\x00" * 8
    nonzero_rd = struct.pack("!Q", 1)  # 8-octet RD, value 1 (non-zero)

    # A: positive control -- valid Type-5, must install.
    sock.sendall(build_mvpn_update(local_id, zero_rd, VALID_SRC, VALID_GRP))
    # B: non-SSM group -- must be dropped.
    sock.sendall(build_mvpn_update(local_id, zero_rd, NONSSM_SRC, NONSSM_GRP))
    # C: non-zero RD -- must be dropped.
    sock.sendall(build_mvpn_update(local_id, nonzero_rd, NONRD_SRC, NONRD_GRP))
    # D: empty MP_UNREACH -- must not crash the receiver.
    sock.sendall(build_empty_mp_unreach())
    print("crafted UPDATEs sent", flush=True)

    # Keepalive loop so the session stays up for the test to observe steady state.
    # Exits cleanly (0) on teardown -- the peer socket is torn down under us.
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
