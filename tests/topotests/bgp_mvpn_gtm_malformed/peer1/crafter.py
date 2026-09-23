#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
crafter.py: minimal raw BGP speaker that negotiates the IPv4 and IPv6
MCAST-VPN address families and sends deliberately crafted MVPN Route Type 3,
4 and 5 NLRIs to exercise the receive path in bgp_nlri_parse_mvpn().

Cases, in the order main() sends them. The letters are historical; each send
site in main() carries the matching label.

  A.  VALID Type-5 (RD 0, SSM group) -- POSITIVE CONTROL, must be installed.
  B.  non-SSM Type-5 (group outside 232.0.0.0/8) -- must be dropped.
  C.  non-zero-RD Type-5 (RD != 0 under GTM) -- must be dropped.
  D.  valid Type-3 (S-PMSI A-D) with an IR PMSI Tunnel -- must install.
  D2. Type-3 with no usable PMSI binding -- must be dropped.
  G.  IPv6-AF Type-3 + trailing Type-5 (dual-stack codec control).
  G2. Type-1 reflecting our own originator -- must be dropped as a duplicate.
  G3. Type-3 whose body ends after C-S, then a Type-5 -- framing recovery.
  E.  Type-4 whose embedded Type-3 length lies -- must be dropped.
  E2. that malformed Type-4 followed by a well-formed Type-5 in the SAME
      MP_REACH -- the trailing Type-5 must still install.
  E3. Type-4 with an allowed nested length but malformed C-G framing, then a
      Type-5 -- the trailing Type-5 must still install.
  H1. Type-5 at LOOP (S,G) with a foreign-only AS_PATH (65010) -- must
      install. This is the copy that case H later denies, so the denial has
      something to withdraw (see H).
  H3. Type-3 at LOOP_TYPE3 (S,G) with an IR PMSI Tunnel and the same
      foreign-only AS_PATH -- must install; the Type-3 twin of H1.
  H2. Type-5 with a NON-EMPTY foreign-only AS_PATH (65010) at its own (S,G)
      -- POSITIVE CONTROL for H: proves a non-empty AS_PATH is encoded and
      accepted, and must SURVIVE H, proving the denial withdraws by NLRI key
      rather than flushing the peer.
  F.  empty MP_UNREACH_NLRI (AFI+SAFI only, zero withdrawn NLRI) -- must NOT
      crash the receiver. Before the fix this hit stream_new(0) -> assert(0)
      and aborted bgpd.
  Z.  SENTINEL valid Type-5, sent LAST in this burst. A test that asserts on
      the absence of an earlier case gates on this instead of on case A, so
      "absent" means "the receiver processed the whole stream and rejected
      it", not "the receiver has not reached that UPDATE yet".

Then, ONLY once the test sends SIGUSR1 (after it has seen H1 and H3
installed, so the handoff is observable rather than a race):

  H.  the H1 Type-5 and the H3 Type-3 again, byte-identical except that the
      AS_PATH now also contains the receiver's OWN AS (65001) -- both must be
      DENIED, and the denial must WITHDRAW the installed H1/H3 copies.
      bgp_nlri_parse_mvpn() installs straight into the MCAST-VPN RIB and
      never runs bgp_update()'s aspath_loop_check(), so before the fix a
      neighbour's echo of our own route was accepted and re-advertised with
      our AS prepended again, ping-ponging every MVPN route forever. A denied
      install is an implicit withdraw (RFC 4271 Section 9): the receiver must
      drop the copy it already holds, which is only reachable when that copy
      exists, hence the two-phase send. The Type-3 twin additionally reaches
      the Type-3 leaf reconcile on the removal path. The live trigger was an
      eBGP session; the check keys on the local AS rather than the peer's, so
      it fires identically on this suite's iBGP session.
      bgp_mvpn_gtm_umh_ebgp carries the same case over a real eBGP session.

WARNING: case H is the ONLY case whose AS_PATH may contain 65001, and it sends
exactly two NLRIs. The test asserts the neighbour's aspathLoop denial counter
is exactly 2, which catches double-counting; another looping NLRI would have
to update that assertion.

The positive control is essential: it proves the crafted NLRI encoding and
the AF negotiation are correct, so that "route absent" for B and C means the
reject logic fired, not that the whole path is broken.

Usage: crafter.py <peer_ip> <local_as> <local_id>
"""

import select
import signal
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
V6_NESTED_RECOVER_SRC = "2001:db8:40::4"
V6_NESTED_RECOVER_GRP = "ff3e::43"
REFLECTED_TYPE1_ORIGINATOR = "10.0.0.1"
LOOP_SRC = "10.50.50.1"
LOOP_GRP = "232.50.50.1"      # installed by H1, then denied+withdrawn by H
LOOP_TYPE3_SRC = "10.60.60.1"
LOOP_TYPE3_GRP = "232.60.60.1"  # Type-3 twin: installed by H3, withdrawn by H
FOREIGN_SRC = "10.50.50.2"
FOREIGN_GRP = "232.50.50.2"   # valid SSM/RD 0, AS_PATH = 65010 only -> install
SENTINEL_SRC = "10.70.70.1"
SENTINEL_GRP = "232.70.70.1"  # last UPDATE on the wire; see case Z above
RECEIVER_AS = 65001
FOREIGN_AS = 65010
AS_SEQUENCE = 2


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


def _type4_bad_nested_body_nlri(rd, src, leaf):
    """Type-4 with an allowed 46-byte key whose C-G cannot fit its body."""
    key_body = (
        rd
        + struct.pack("!B", IPV6_BITLEN)
        + _packed_addr(src)
        + struct.pack("!B", 255)
        + b"\x00" * 20
    )
    route_key = struct.pack("!BB", MVPN_TYPE3, len(key_body)) + key_body
    body = route_key + _packed_addr(leaf)
    return struct.pack("!BB", MVPN_TYPE4, len(body)) + body


def build_mvpn_update(
    local_id, nlri, afi=AFI_IP, include_pmsi=False,
    pmsi_flags=PMSI_FLAG_LEAF_INFO_REQUIRED,
    pmsi_label=0,
    as_path=None,
):
    """UPDATE with ORIGIN, AS_PATH and one or more MCAST-VPN NLRI.

    as_path is None for the empty AS_PATH legal on this iBGP session, else a
    list of ASNs emitted in order as one AS_SEQUENCE segment of the ordinary
    AS_PATH attribute (type 2, not AS4_PATH/type 17). build_open() negotiates
    the 4-octet-AS capability, so each ASN in it is 4 bytes wide.
    """

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
    # AS_PATH: well-known transitive, type 2. Empty (iBGP) unless as_path.
    if as_path:
        seg = struct.pack("!BB", AS_SEQUENCE, len(as_path)) + b"".join(
            struct.pack("!I", asn) for asn in as_path
        )
        attrs += struct.pack("!BBB", 0x40, 2, len(seg)) + seg
    else:
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


def _loop_updates(local_id, zero_rd, as_path):
    """The two NLRIs case H denies: a Type-5 and a Type-3 at the LOOP (S,G)s.

    Called twice with different as_path values; everything else is identical,
    so the only difference between the installed copy and the denied copy is
    the AS_PATH.
    """
    return [
        build_mvpn_update(
            local_id, _type5_nlri(zero_rd, LOOP_SRC, LOOP_GRP), as_path=as_path
        ),
        build_mvpn_update(
            local_id,
            _type3_nlri(zero_rd, LOOP_TYPE3_SRC, LOOP_TYPE3_GRP, TYPE3_ORIGINATOR),
            include_pmsi=True,
            pmsi_label=SELECTIVE_LABEL,
            as_path=as_path,
        ),
    ]


def main():
    if len(sys.argv) != 4:
        print("Usage: crafter.py <peer_ip> <local_as> <local_id>")
        sys.exit(1)
    peer_ip = sys.argv[1]
    local_as = int(sys.argv[2])
    local_id = sys.argv[3]

    # Installed before the handshake: SIGUSR1's default action would kill us.
    loop_requested = []
    signal.signal(signal.SIGUSR1, lambda *_: loop_requested.append(True))

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
    # E3: the nested key length is allowed, but its C-G framing is malformed.
    # The trustworthy outer Type-4 boundary must preserve the trailing Type-5.
    sock.sendall(
        build_mvpn_update(
            "2001:db8:1::2",
            _type4_bad_nested_body_nlri(
                zero_rd, V6_SELECTIVE_SRC, V6_TYPE4_LEAF,
            )
            + _type5_nlri(
                zero_rd, V6_NESTED_RECOVER_SRC, V6_NESTED_RECOVER_GRP,
            ),
            afi=AFI_IP6,
        )
    )
    # H1/H3: the clean copies that case H will deny later. Sent with a
    # foreign-only AS_PATH so they install; H re-sends the same NLRIs with
    # our AS added, which must withdraw these.
    for update in _loop_updates(local_id, zero_rd, [FOREIGN_AS]):
        sock.sendall(update)
    # H2: positive control for H -- a non-empty, foreign-only AS_PATH installs.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type5_nlri(zero_rd, FOREIGN_SRC, FOREIGN_GRP),
            as_path=[FOREIGN_AS],
        )
    )
    # F: empty MP_UNREACH -- must not crash the receiver.
    sock.sendall(build_empty_mp_unreach())
    # Z: sentinel, always last. Tests that assert an earlier case was REJECTED
    # gate on this one being installed, which proves the receiver consumed the
    # whole stream rather than merely the first few UPDATEs.
    sock.sendall(
        build_mvpn_update(local_id, _type5_nlri(zero_rd, SENTINEL_SRC, SENTINEL_GRP))
    )
    print("crafted UPDATEs sent", flush=True)

    # Keepalive loop so the session stays up for the test to observe steady state.
    # Exits cleanly (0) on teardown -- the peer socket is torn down under us.
    # Case H is sent from here when the test raises SIGUSR1, after it has seen
    # the H1/H3 copies installed. The handler only flags; the send happens in
    # this loop so it cannot interleave with a keepalive already in flight.
    sock.settimeout(1)
    while True:
        if loop_requested:
            loop_requested.clear()
            # H: AS_PATH already contains the receiver's own AS -- must be
            # denied, and the denial must withdraw the H1/H3 copies. Shaped
            # like the live PE<->PoP ping-pong: "65010 65001" as seen by 65001.
            for update in _loop_updates(local_id, zero_rd, [FOREIGN_AS, RECEIVER_AS]):
                sock.sendall(update)
            print("looping UPDATEs sent", flush=True)
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
