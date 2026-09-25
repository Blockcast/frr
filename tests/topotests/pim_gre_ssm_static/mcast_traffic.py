#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 Blockcast
#

"""Bounded SSM sender / receiver for pim_gre_ssm_static.

lib/mcast-tester.py cannot answer this suite's question.  Its --send mode is
unbounded (it loops until the topotest socket closes) and its payload is
b"test %d" % counter, whose LENGTH changes at seq 10 and 100 -- so it can
support "packets kept flowing" but never "exactly 50 packets arrived, with
the bytes unchanged".  Byte-exactness is the point here: a GRE tunnel is
where a stream gets silently truncated or fragmented by an MTU mismatch, and
a packet-count-only assertion passes straight through that bug.

payload() is the single definition of what a packet contains, imported by
the test for its expectation rather than re-spelled there, so the sender and
the assertion cannot drift apart (the convention .github/scripts uses for
testcase_id()).

Modes:
  --send N     transmit exactly N packets, then exit 0.
  --recv N     SSM-join (S,G), collect up to N packets or until --timeout,
               print one JSON object to stdout, exit 0.

The receiver ALWAYS prints its JSON, including on timeout with zero packets.
A caller must be able to tell "joined, received nothing" (the no-join and
negative-control assertions both depend on that being a real, parseable 0)
from "the helper died", which is a parse failure.
"""

import argparse
import hashlib
import ipaddress
import json
import socket
import struct
import subprocess
import sys
import time

# Fixed on purpose: a constant-length payload means a short read is a
# truncation bug, not an artifact of the sequence number getting wider.
PAYLOAD_LEN = 100

# Linux IPv4 source-specific membership.  socket.IP_ADD_SOURCE_MEMBERSHIP is
# absent from some Python builds, so spell the value, as lib/mcast-tester.py
# does.
IP_ADD_SOURCE_MEMBERSHIP = 39


def payload(seq):
    """The exact bytes of packet `seq`: 4-byte big-endian seq + filler.

    The filler is derived from seq so that a packet delivered out of order,
    duplicated, or corrupted in place changes the digest.  A constant filler
    would make every packet's tail identical and hide a swapped body.
    """
    head = struct.pack("!I", seq)
    filler = hashlib.sha256(head).digest()  # 32 bytes
    body = (filler * ((PAYLOAD_LEN - 4) // len(filler) + 1))[: PAYLOAD_LEN - 4]
    return head + body


def digest(seqs):
    """Digest of the packets `seqs`, in the order given."""
    h = hashlib.sha256()
    for seq in seqs:
        h.update(payload(seq))
    return h.hexdigest()


def _iface_address(ifname):
    """The interface's primary IPv4 address, packed -- the imr_interface of
    the source-specific join.  Returns None if it has none."""
    out = subprocess.check_output("ip -j addr show dev " + ifname, shell=True)
    for entry in json.loads(out):
        for addr in entry.get("addr_info", []):
            if addr.get("family") == "inet":
                return ipaddress.ip_address(addr["local"]).packed
    return None


def send(group, port, ifname, count, interval, ttl):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # SO_BINDTODEVICE: pin the stream to the source LAN so the result cannot
    # depend on which interface the host's route table happens to pick.
    sock.setsockopt(
        socket.SOL_SOCKET, 25, struct.pack("%ds" % len(ifname), ifname.encode())
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", ttl))
    sock.setblocking(True)
    for seq in range(count):
        sock.sendto(payload(seq), (group, port))
        time.sleep(interval)
    sock.close()


def recv(group, port, ifname, source, count, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((group, port))

    local = _iface_address(ifname)
    if local is None:
        raise RuntimeError("no IPv4 address on {}".format(ifname))
    mreq = (
        ipaddress.ip_address(group).packed
        + local
        + ipaddress.ip_address(source).packed
    )
    sock.setsockopt(socket.IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, mreq)

    # Tell the caller the join is in the kernel.  Without this the test has
    # to sleep-and-hope before starting the sender, and a slow join reads as
    # lost packets.
    print(json.dumps({"event": "joined"}), flush=True)

    sock.settimeout(0.2)
    deadline = time.time() + timeout
    seqs = []
    bad = []
    while len(seqs) < count and time.time() < deadline:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if len(data) != PAYLOAD_LEN:
            bad.append({"reason": "length", "len": len(data)})
            continue
        seq = struct.unpack("!I", data[:4])[0]
        if data != payload(seq):
            bad.append({"reason": "body", "seq": seq})
            continue
        seqs.append(seq)
    sock.close()

    print(
        json.dumps(
            {
                "count": len(seqs),
                "seqs": seqs,
                "sha256": digest(seqs),
                "corrupt": bad,
            },
            sort_keys=True,
        ),
        flush=True,
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("group")
    ap.add_argument("interface")
    ap.add_argument("--port", type=int, default=1000)
    ap.add_argument("--ttl", type=int, default=16)
    ap.add_argument("--source", help="SSM source, required with --recv")
    ap.add_argument("--send", type=int, metavar="N")
    ap.add_argument("--recv", type=int, metavar="N")
    ap.add_argument("--interval", type=float, default=0.05)
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()

    if args.send is not None:
        send(
            args.group,
            args.port,
            args.interface,
            args.send,
            args.interval,
            args.ttl,
        )
    elif args.recv is not None:
        if not args.source:
            ap.error("--recv requires --source")
        recv(
            args.group,
            args.port,
            args.interface,
            args.source,
            args.recv,
            args.timeout,
        )
    else:
        ap.error("one of --send/--recv is required")


if __name__ == "__main__":
    main()
