#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
crafter.py: minimal raw BGP speaker that negotiates the IPv4 and IPv6
MCAST-VPN address families and sends deliberately crafted MVPN Route Type 3,
4 and 5 NLRIs to exercise the receive path in bgp_nlri_parse_mvpn().

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
AFI_IP6 = 2
SAFI_MCAST_VPN = 5
MVPN_TYPE3 = 3
MVPN_TYPE4 = 4
MVPN_TYPE5 = 5
MVPN_TYPE1 = 1
IPV4_BITLEN = 32
IPV6_BITLEN = 128
PMSI_FLAG_LEAF_INFO_REQUIRED = 1
SELECTIVE_LABEL = 0x12345

# Crafted (S,G)s. Distinct per case so the test can assert each independently.
VALID_SRC = "10.9.9.9"
VALID_GRP = "232.9.9.9"       # in SSM 232/8, RD 0 -> must install
NONSSM_SRC = "10.20.20.1"
NONSSM_GRP = "239.1.1.1"      # ASM range -> must be dropped
NONRD_SRC = "10.20.20.2"
NONRD_GRP = "232.2.2.2"       # valid SSM group, but RD != 0 -> must be dropped
SELECTIVE_SRC = "10.30.30.1"
SELECTIVE_GRP = "232.30.30.1"
TYPE3_ORIGINATOR = "10.0.0.2"
TYPE4_LEAF = "10.0.0.3"
NO_PMSI_SRC = "10.30.30.9"
NO_PMSI_GRP = "232.30.30.9"
MALFORMED_SRC = "10.30.30.2"
MALFORMED_GRP = "232.30.30.2"
RECOVER_SRC = "10.40.40.1"
RECOVER_GRP = "232.40.40.1"   # valid SSM; trailing NLRI after a malformed one
V6_SELECTIVE_SRC = "2001:db8:30::1"
V6_SELECTIVE_GRP = "ff3e::30"
V6_TYPE3_ORIGINATOR = "10.0.0.2"
V6_TYPE4_LEAF = "10.0.0.3"
V6_RECOVER_SRC = "2001:db8:40::1"
V6_RECOVER_GRP = "ff3e::40"
V6_TYPE4_RECOVER_SRC = "2001:db8:40::2"
V6_TYPE4_RECOVER_GRP = "ff3e::41"
V6_TRUNC_RECOVER_SRC = "2001:db8:40::3"
V6_TRUNC_RECOVER_GRP = "ff3e::42"
REFLECTED_TYPE1_ORIGINATOR = "10.0.0.1"


def build_open(local_as, router_id):
    """OPEN advertising the MCAST-VPN MP capability and 4-octet AS."""
    rid = socket.inet_aton(router_id)

    # Multiprotocol Extensions capability (code 1): AFI(2) Reserved(1) SAFI(1)
    mp_cap = b"".join(
        struct.pack("!BBHBB", 1, 4, afi, 0, SAFI_MCAST_VPN)
        for afi in (AFI_IP, AFI_IP6)
    )
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
    bitlen = IPV6_BITLEN if ":" in src else IPV4_BITLEN
    body = (
        rd
        + struct.pack("!B", bitlen)
        + _packed_addr(src)
        + struct.pack("!B", bitlen)
        + _packed_addr(grp)
    )
    return struct.pack("!BB", MVPN_TYPE5, len(body)) + body


def _type1_nlri(rd, originator):
    body = rd + _packed_addr(originator)
    return struct.pack("!BB", MVPN_TYPE1, len(body)) + body


def _packed_addr(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return socket.inet_pton(family, address)


def _type3_nlri(rd, src, grp, originator, length=None):
    v6 = ":" in src
    bitlen = IPV6_BITLEN if v6 else IPV4_BITLEN
    body = (
        rd
        + struct.pack("!B", bitlen)
        + _packed_addr(src)
        + struct.pack("!B", bitlen)
        + _packed_addr(grp)
        + _packed_addr(originator)
    )
    if length is None:
        length = len(body)
    return struct.pack("!BB", MVPN_TYPE3, length) + body


def _type3_source_only_nlri(rd, src):
    """Type-3 whose declared body ends immediately after its C-source."""
    body = rd + struct.pack("!B", IPV6_BITLEN) + _packed_addr(src)
    return struct.pack("!BB", MVPN_TYPE3, len(body)) + body


def _type4_nlri(rd, src, grp, originator, leaf, nested_length=None):
    route_key = _type3_nlri(rd, src, grp, originator, nested_length)
    body = route_key + _packed_addr(leaf)
    return struct.pack("!BB", MVPN_TYPE4, len(body)) + body


def build_mvpn_update(
    local_id, nlri, afi=AFI_IP, include_pmsi=False,
    pmsi_flags=PMSI_FLAG_LEAF_INFO_REQUIRED,
    pmsi_label=0,
):
    """UPDATE with ORIGIN, empty AS_PATH (iBGP) and one MCAST-VPN NLRI."""

    # MP_REACH_NLRI value: AFI(2) SAFI(1) NHLen(1) NH(4) Reserved(1) NLRI
    next_hop = _packed_addr(local_id)
    mp_reach_val = (
        struct.pack("!HB", afi, SAFI_MCAST_VPN)
        + struct.pack("!B", len(next_hop))
        + next_hop
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
    if include_pmsi:
        # Optional-transitive PMSI Tunnel: leaf-info flag, ingress replication,
        # 20-bit MPLS label in the high bits, tunnel endpoint=local_id.
        label = struct.pack("!I", pmsi_label << 4)[1:]
        pmsi = struct.pack("!BB", pmsi_flags, 6) + label + next_hop
        attrs += struct.pack("!BBB", 0xC0, 22, len(pmsi)) + pmsi
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
    sock.sendall(build_mvpn_update(local_id, _type5_nlri(zero_rd, VALID_SRC, VALID_GRP)))
    # B: non-SSM group -- must be dropped.
    sock.sendall(build_mvpn_update(local_id, _type5_nlri(zero_rd, NONSSM_SRC, NONSSM_GRP)))
    # C: non-zero RD -- must be dropped.
    sock.sendall(build_mvpn_update(local_id, _type5_nlri(nonzero_rd, NONRD_SRC, NONRD_GRP)))
    # D: valid S-PMSI A-D and Leaf A-D positive controls.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type3_nlri(zero_rd, SELECTIVE_SRC, SELECTIVE_GRP, TYPE3_ORIGINATOR),
            include_pmsi=True,
            pmsi_label=SELECTIVE_LABEL,
        )
    )
    # D2: Type-3 without a usable selective-tunnel binding must be dropped.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type3_nlri(zero_rd, NO_PMSI_SRC, NO_PMSI_GRP, TYPE3_ORIGINATOR),
        )
    )
    # G: dual-stack codec controls in AFI 2 with IPv4 router-id originators.
    sock.sendall(
        build_mvpn_update(
            "2001:db8:1::2",
            _type3_nlri(
                zero_rd, V6_SELECTIVE_SRC, V6_SELECTIVE_GRP,
                V6_TYPE3_ORIGINATOR,
            ) + _type5_nlri(zero_rd, V6_RECOVER_SRC, V6_RECOVER_GRP),
            afi=AFI_IP6,
            include_pmsi=True,
        )
    )
    # G2: a reflected local Type-1 must not coexist with the self route.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type1_nlri(zero_rd, REFLECTED_TYPE1_ORIGINATOR),
            include_pmsi=True,
        )
    )
    sock.sendall(
        build_mvpn_update(
            "2001:db8:1::2",
            _type4_nlri(
                zero_rd, V6_SELECTIVE_SRC, V6_SELECTIVE_GRP,
                V6_TYPE3_ORIGINATOR, V6_TYPE4_LEAF,
            ) + _type5_nlri(
                zero_rd, V6_TYPE4_RECOVER_SRC, V6_TYPE4_RECOVER_GRP,
            ),
            afi=AFI_IP6,
        )
    )
    # G3: the declared Type-3 body ends after C-S. Its missing C-G length must
    # not consume the following Type-5 route-type byte.
    sock.sendall(
        build_mvpn_update(
            "2001:db8:1::2",
            _type3_source_only_nlri(zero_rd, V6_SELECTIVE_SRC)
            + _type5_nlri(zero_rd, V6_TRUNC_RECOVER_SRC, V6_TRUNC_RECOVER_GRP),
            afi=AFI_IP6,
            include_pmsi=True,
        )
    )
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type4_nlri(
                zero_rd,
                SELECTIVE_SRC,
                SELECTIVE_GRP,
                TYPE3_ORIGINATOR,
                TYPE4_LEAF,
            ),
        )
    )
    # E: outer Type-4 length is valid but its embedded Type-3 length lies.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type4_nlri(
                zero_rd,
                MALFORMED_SRC,
                MALFORMED_GRP,
                TYPE3_ORIGINATOR,
                TYPE4_LEAF,
                nested_length=21,
            ),
        )
    )
    # E2: intra-packet framing recovery -- a malformed Type-4 (lying embedded
    # Type-3 length, as in E) immediately followed by a WELL-FORMED Type-5 in the
    # SAME MP_REACH. Proves the receiver skips the malformed NLRI by its outer
    # length (the length-2 skip arithmetic) and still parses the trailing valid
    # NLRI, not merely that it survives a lone malformed NLRI. (BLO-15578.)
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type4_nlri(
                zero_rd,
                MALFORMED_SRC,
                MALFORMED_GRP,
                TYPE3_ORIGINATOR,
                TYPE4_LEAF,
                nested_length=21,
            )
            + _type5_nlri(zero_rd, RECOVER_SRC, RECOVER_GRP),
        )
    )
    # F: empty MP_UNREACH -- must not crash the receiver.
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
