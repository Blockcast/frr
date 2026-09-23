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
  D3. TWO Type-3s sharing ONE PMSI Tunnel attribute in ONE MP_REACH -- BOTH
      must install WITH the PMSI binding. bgp_nlri_parse_mvpn() hands the
      packet's single attr to every NLRI; before the fix the first install's
      bgp_attr_intern() stole (hash miss) or freed (hash hit) attr->extra, so
      every later Type-1/Type-3 in the same UPDATE read no PMSI and was
      dropped. Observed live: a 17-Type-3 UPDATE of which only the first could
      have been kept. D3's attributes are byte-identical to D's, which makes
      its intern a hash HIT -- the free-on-hit half of the bug.
  D4. Same shape as D3 but with a PMSI label no other case uses, so its intern
      is a hash MISS -- the steal-on-miss half. Both halves are needed: each is
      a different branch of bgp_attr_intern().
  D5. Type-1 + Type-3 behind one PMSI attribute in one MP_REACH, the shape seen
      live. The Type-1 has its own PMSI gate and its own RIB-afi selection, so
      it is not covered by the Type-3-only pairs above.
  D2. Type-3 with no usable PMSI binding -- must be dropped.
  G.  IPv6-AF Type-3 + trailing Type-5 (dual-stack codec control).
  G2. Type-1 reflecting our own originator -- must be dropped as a duplicate.
  G3. Type-3 whose body ends after C-S, then a Type-5 -- framing recovery.
  E.  Type-4 whose embedded Type-3 length lies -- must be dropped.
  E2. that malformed Type-4 followed by a well-formed Type-5 in the SAME
      MP_REACH -- the trailing Type-5 must still install.
  E3. Type-4 with an allowed nested length but malformed C-G framing, then a
      Type-5 -- the trailing Type-5 must still install.
  H.  Type-5 whose AS_PATH contains the receiver's OWN AS (65001) -- must be
      dropped. bgp_nlri_parse_mvpn() installs straight into the MCAST-VPN RIB
      and never runs bgp_update()'s aspath_loop_check(), so before the fix a
      neighbour's echo of our own route was accepted and re-advertised with
      our AS prepended again, ping-ponging every MVPN route forever. The live
      trigger was an eBGP session; the check keys on the local AS rather than
      the peer's, so it fires identically on this suite's iBGP session.
      bgp_mvpn_gtm_umh_ebgp carries the same case over a real eBGP session.
  H2. Type-5 with a NON-EMPTY foreign-only AS_PATH (65010) -- POSITIVE
      CONTROL for H: proves a non-empty AS_PATH is encoded and accepted, so
      H's absence is the loop check, not a rejected attribute.
  H3. Type-5 with a foreign-only AS_PATH (65010) at its own (S,G) -- must
      install. It is the route H4 later replaces.
  F.  empty MP_UNREACH_NLRI (AFI+SAFI only, zero withdrawn NLRI) -- must NOT
      crash the receiver. Before the fix this hit stream_new(0) -> assert(0)
      and aborted bgpd.
  Z.  SENTINEL valid Type-5, sent LAST. A test that asserts on the absence of
      an earlier case gates on this instead of on case A, so "absent" means
      "the receiver processed the whole stream and rejected it", not "the
      receiver has not reached that UPDATE yet".

PHASE 2 (fires when the test touches its trigger file, then sentinel Z2). Every
case here was advertised ACCEPTABLY in phase 1 and is now re-advertised in a
form the receiver must reject, which is the only way to tell "rejected and
withdrew the earlier copy" from "rejected and stranded it":

  P1. Type-3 (STRAND_T3) re-sent WITHOUT its PMSI Tunnel attribute -- same
      NLRI, attribute removed, so RFC 4271 Section 9 makes it a replacement
      route and the earlier copy MUST be gone.
  P2. Type-1 (STRAND_T1_ORIGINATOR) re-sent WITHOUT PMSI -- same, for the
      Type-1 gate and its separate RIB-AFI selection.
  P3. Type-5 (RDKEEP) re-sent with RD 1 for the SAME (S,G) -- a DIFFERENT
      NLRI, so the earlier RD-0 route MUST SURVIVE. This is the regression
      guard for the deliberate RD exception: our RIB key drops the RD, so a
      reject that withdrew here would silently delete a valid route.
  Z2. Phase-2 sentinel.

PHASE 3 (on trigger) re-advertises the two routes phase 2 got withdrawn, this
time WELL-FORMED again:

  R1/R2. Type-3 and Type-1 with their PMSI Tunnel attribute back -- both MUST
      reappear. A path marked for delete is not reaped until the work queue
      drains, so a re-advertisement that lands first has to resurrect it
      (bgp_path_info_restore). Without that the attrhash_cmp fast path hands
      back a doomed path and the route is black-holed: the peer's adj-rib-out
      still says "advertised", so it never re-sends.
  Z3. Phase-3 sentinel.

PHASE 4 (on trigger) exercises the REAL withdraw path, which nothing else in
the tree covers -- every other MP_UNREACH here carries zero NLRI:

  W1. MP_UNREACH carrying the Type-3 NLRI by key -- must remove it.
  Z4. Phase-4 sentinel.

PHASE H4 (fires when the test touches trigger file "h4", after it has seen
H3 installed):

  H4. H3's (S,G) again, now with 65001 in its AS_PATH -- must be denied, and
      the denial is an implicit withdraw (RFC 4271 Section 9): H3's copy must
      be REMOVED, not left stranded. H alone cannot show this -- it is the
      first UPDATE at its (S,G), so bgp_mvpn_route_remove() finds no dest and
      returns before it deletes anything. H4 is deferred rather than sent
      straight after H3 so the test can prove H3 installed before asserting
      that it is gone.

WARNING: case H is the ONLY case in the phase-1 stream whose AS_PATH may
contain 65001. The test asserts the neighbour's aspathLoop denial counter is
exactly 1 before H4 fires, which catches double-counting; a second looping
case would have to update that assertion. H4 moves it by exactly one more.

The positive control is essential: it proves the crafted NLRI encoding and
the AF negotiation are correct, so that "route absent" for B and C means the
reject logic fired, not that the whole path is broken.

Usage: crafter.py <peer_ip> <local_as> <local_id> [trigger_dir]
"""

import os
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
PAIR_A_SRC = "10.60.60.1"
PAIR_A_GRP = "232.60.60.1"    # first of two Type-3s sharing one PMSI attribute
PAIR_B_SRC = "10.60.60.2"
PAIR_B_GRP = "232.60.60.2"    # second: must keep the PMSI binding too
MISS_A_SRC = "10.61.61.1"
MISS_A_GRP = "232.61.61.1"    # D4 pair, behind a never-before-seen PMSI label
MISS_B_SRC = "10.61.61.2"
MISS_B_GRP = "232.61.61.2"
MIX_T1_ORIGINATOR = "10.0.0.4"  # foreign Type-1 originator for the D5 mix
MIX_T3_SRC = "10.62.62.1"
MIX_T3_GRP = "232.62.62.1"
# D3 deliberately reuses SELECTIVE_LABEL so its intern is a hash HIT; D4 must
# use a label no other UPDATE carries so its intern is a hash MISS.
MISS_LABEL = 0x23456
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
LOOP_GRP = "232.50.50.1"      # valid SSM/RD 0, but AS_PATH contains 65001
FOREIGN_SRC = "10.50.50.2"
FOREIGN_GRP = "232.50.50.2"   # valid SSM/RD 0, AS_PATH = 65010 only -> install
WITHDRAW_SRC = "10.50.50.3"
WITHDRAW_GRP = "232.50.50.3"  # H3 installs it, H4 must implicitly withdraw it
SENTINEL_SRC = "10.70.70.1"
SENTINEL_GRP = "232.70.70.1"  # last UPDATE of phase 1; see case Z above

# Phase-2 (see below): routes advertised well-formed in phase 1, then RE-sent
# in a way that must be rejected. They prove a reject either withdraws the
# earlier copy or deliberately leaves it alone.
STRAND_T3_SRC = "10.90.90.1"
STRAND_T3_GRP = "232.90.90.1"   # Type-3 with PMSI, then re-sent without it
STRAND_T1_ORIGINATOR = "10.0.0.7"  # Type-1 with PMSI, then re-sent without it
RDKEEP_SRC = "10.91.91.1"
RDKEEP_GRP = "232.91.91.1"      # Type-5 RD 0, then RD 1 for the SAME (S,G)
SENTINEL2_SRC = "10.92.92.1"
SENTINEL2_GRP = "232.92.92.1"   # last UPDATE of phase 2
SENTINEL3_SRC = "10.93.93.1"
SENTINEL3_GRP = "232.93.93.1"   # last UPDATE of phase 3
SENTINEL4_SRC = "10.94.94.1"
SENTINEL4_GRP = "232.94.94.1"   # last UPDATE of phase 4
# Phases 2-4 fire when the TEST touches a trigger file, not on a timer. A timer
# would race the test: whichever ran first would decide whether the phase-1
# state was still observable, and a lost race reports as "route not installed",
# indistinguishable from a real parse regression.
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


def build_mp_unreach(nlri=b""):
    """UPDATE with an MP_UNREACH_NLRI carrying AFI+SAFI and optional NLRI.

    With nlri empty this is the zero-length withdraw that used to crash the
    receiver. With NLRI bytes it is an ordinary withdraw by key.

    The attribute value is exactly 3 bytes, so the MVPN parser sees a
    zero-length NLRI. This is the crash-on-empty-withdraw (stream_new(0))
    case the fix guards.
    """
    mp_unreach_val = struct.pack("!HB", AFI_IP, SAFI_MCAST_VPN) + nlri
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
    if len(sys.argv) not in (4, 5):
        print("Usage: crafter.py <peer_ip> <local_as> <local_id> [trigger_dir]")
        sys.exit(1)
    trigger_dir = sys.argv[4] if len(sys.argv) == 5 else None
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
    # D3: two Type-3s behind ONE PMSI Tunnel attribute in ONE MP_REACH. The
    # second NLRI is the one that used to lose the attribute. The attributes
    # are byte-identical to case D's, so the first NLRI's bgp_attr_intern() is
    # a hash HIT and this case covers the free-on-hit half of the bug.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type3_nlri(zero_rd, PAIR_A_SRC, PAIR_A_GRP, TYPE3_ORIGINATOR)
            + _type3_nlri(zero_rd, PAIR_B_SRC, PAIR_B_GRP, TYPE3_ORIGINATOR),
            include_pmsi=True,
            pmsi_label=SELECTIVE_LABEL,
        )
    )
    # D4: the same shape behind a PMSI label no other case uses, so the first
    # NLRI's intern is a hash MISS and bgp_attr_hash_alloc() -- the steal-on-miss
    # half -- runs instead. Without both cases a regression confined to one
    # branch of bgp_attr_intern() would pass.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type3_nlri(zero_rd, MISS_A_SRC, MISS_A_GRP, TYPE3_ORIGINATOR)
            + _type3_nlri(zero_rd, MISS_B_SRC, MISS_B_GRP, TYPE3_ORIGINATOR),
            include_pmsi=True,
            pmsi_label=MISS_LABEL,
        )
    )
    # D5: Type-1 + Type-3 behind one PMSI attribute, the shape seen live. The
    # Type-1 carries a FOREIGN originator (a reflection of ours is case G2) and
    # has its own PMSI gate, so the Type-3-only pairs do not cover it.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type1_nlri(zero_rd, MIX_T1_ORIGINATOR)
            + _type3_nlri(zero_rd, MIX_T3_SRC, MIX_T3_GRP, TYPE3_ORIGINATOR),
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
    # H: AS_PATH already contains the receiver's own AS -- must be dropped.
    # Shaped like the live PE<->PoP ping-pong: "65010 65001" as seen by 65001.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type5_nlri(zero_rd, LOOP_SRC, LOOP_GRP),
            as_path=[FOREIGN_AS, RECEIVER_AS],
        )
    )
    # H2: positive control for H -- a non-empty, foreign-only AS_PATH installs.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type5_nlri(zero_rd, FOREIGN_SRC, FOREIGN_GRP),
            as_path=[FOREIGN_AS],
        )
    )
    # H3: a foreign-only AS_PATH at WITHDRAW_SG -- installs; H4 replaces it.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type5_nlri(zero_rd, WITHDRAW_SRC, WITHDRAW_GRP),
            as_path=[FOREIGN_AS],
        )
    )
    # F: empty MP_UNREACH -- must not crash the receiver.
    sock.sendall(build_mp_unreach())
    # Phase-1 halves of the phase-2 probes: all three must INSTALL here.
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type3_nlri(zero_rd, STRAND_T3_SRC, STRAND_T3_GRP, TYPE3_ORIGINATOR),
            include_pmsi=True,
            pmsi_label=SELECTIVE_LABEL,
        )
    )
    sock.sendall(
        build_mvpn_update(
            local_id,
            _type1_nlri(zero_rd, STRAND_T1_ORIGINATOR),
            include_pmsi=True,
            pmsi_label=SELECTIVE_LABEL,
        )
    )
    sock.sendall(
        build_mvpn_update(local_id, _type5_nlri(zero_rd, RDKEEP_SRC, RDKEEP_GRP))
    )
    # Z: phase-1 sentinel (later phases add their own). Tests that assert an earlier case was REJECTED
    # gate on this one being installed, which proves the receiver consumed the
    # whole stream rather than merely the first few UPDATEs.
    sock.sendall(
        build_mvpn_update(local_id, _type5_nlri(zero_rd, SENTINEL_SRC, SENTINEL_GRP))
    )
    print("crafted UPDATEs sent", flush=True)

    # Keepalive loop so the session stays up for the test to observe steady state.
    # Exits cleanly (0) on teardown -- the peer socket is torn down under us.
    # Keepalive loop. Each later phase fires once, when the test touches its
    # trigger file, so the test controls ordering and nothing races a sleep.
    def _fired(name):
        return trigger_dir and os.path.exists(os.path.join(trigger_dir, name))

    def _send_phase(num, messages):
        """Send one phase with a longer timeout than the 1 s keepalive poll.

        A socket.timeout inside sendall is an OSError that gives no indication
        of how many bytes went out, so a mid-UPDATE timeout would desynchronise
        the stream and the receiver would reset the session -- taking every
        other test in the suite with it."""
        sock.settimeout(10)
        try:
            for m in messages:
                sock.sendall(m)
            print("phase {} sent".format(num), flush=True)
            return True
        except OSError as exc:
            print("phase {} send failed: {}".format(num, exc), flush=True)
            return False
        finally:
            sock.settimeout(1)

    done = set()
    sock.settimeout(1)
    while True:
        if 2 not in done and _fired("phase2"):
            if not _send_phase(2, [
                # P1: same Type-3 NLRI, PMSI removed -> must withdraw.
                build_mvpn_update(local_id, _type3_nlri(zero_rd, STRAND_T3_SRC,
                                                        STRAND_T3_GRP, TYPE3_ORIGINATOR)),
                # P2: same Type-1 NLRI, PMSI removed -> must withdraw.
                build_mvpn_update(local_id, _type1_nlri(zero_rd, STRAND_T1_ORIGINATOR)),
                # P3: DIFFERENT NLRI (RD 1) for an installed (S,G) -> must NOT touch it.
                build_mvpn_update(local_id, _type5_nlri(nonzero_rd, RDKEEP_SRC, RDKEEP_GRP)),
                build_mvpn_update(local_id, _type5_nlri(zero_rd, SENTINEL2_SRC,
                                                        SENTINEL2_GRP)),
            ]):
                break
            done.add(2)
        if 3 not in done and _fired("phase3"):
            if not _send_phase(3, [
                # R1/R2: the same two NLRI, well-formed again -> must come back.
                build_mvpn_update(local_id,
                                  _type3_nlri(zero_rd, STRAND_T3_SRC, STRAND_T3_GRP,
                                              TYPE3_ORIGINATOR),
                                  include_pmsi=True, pmsi_label=SELECTIVE_LABEL),
                build_mvpn_update(local_id, _type1_nlri(zero_rd, STRAND_T1_ORIGINATOR),
                                  include_pmsi=True, pmsi_label=SELECTIVE_LABEL),
                build_mvpn_update(local_id, _type5_nlri(zero_rd, SENTINEL3_SRC,
                                                        SENTINEL3_GRP)),
            ]):
                break
            done.add(3)
        if 4 not in done and _fired("phase4"):
            if not _send_phase(4, [
                # W1: a REAL withdraw, by NLRI key.
                build_mp_unreach(_type3_nlri(zero_rd, STRAND_T3_SRC, STRAND_T3_GRP,
                                             TYPE3_ORIGINATOR)),
                build_mvpn_update(local_id, _type5_nlri(zero_rd, SENTINEL4_SRC,
                                                        SENTINEL4_GRP)),
            ]):
                break
            done.add(4)
        # H4, once the test has seen H3 installed: the same (S,G) with our
        # own AS in the AS_PATH, which must withdraw H3's copy implicitly.
        if "h4" not in done and _fired("h4"):
            if not _send_phase("H4", [
                build_mvpn_update(local_id,
                                  _type5_nlri(zero_rd, WITHDRAW_SRC, WITHDRAW_GRP),
                                  as_path=[FOREIGN_AS, RECEIVER_AS]),
            ]):
                break
            done.add("h4")
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
