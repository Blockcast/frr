#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

import argparse
import ipaddress
import json
import os
import socket
import struct
import sys


MARKER = 254
VERSION = 6
VRF_DEFAULT = 0
ZEBRA_ROUTE_PIM = 11
ZEBRA_HELLO = 19
ZEBRA_DIMT_TUNNEL_ADD = 153
ZEBRA_DIMT_TUNNEL_DEL = 154
ZEBRA_DIMT_TUNNEL_NOTIFY_OWNER = 155

# Exit status of a --follow/--barrier session that gave up waiting.
EXIT_TIMEOUT = 3


def header(command, payload=b""):
    length = 10 + len(payload)
    return struct.pack("!HBBIH", length, MARKER, VERSION, VRF_DEFAULT, command) + payload


def ipaddr(value):
    address = ipaddress.ip_address(value)
    return struct.pack("!H", socket.AF_INET if address.version == 4 else socket.AF_INET6) + address.packed


def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("zebra closed the ZAPI socket")
        data += chunk
    return data


def recv_notify(sock, tunnel_ids):
    """Return the next owner notify for any tunnel id in `tunnel_ids`."""
    while True:
        raw_header = recv_exact(sock, 10)
        length, marker, version, _vrf, command = struct.unpack("!HBBIH", raw_header)
        if marker != MARKER or version != VERSION or length < 10:
            raise RuntimeError("invalid ZAPI response header")
        payload = recv_exact(sock, length - 10)
        if command != ZEBRA_DIMT_TUNNEL_NOTIFY_OWNER:
            continue
        response_id, ifindex, result = struct.unpack("!IIB", payload)
        if response_id in tunnel_ids:
            return {"tunnel_id": response_id, "ifindex": ifindex, "result": result}


def emit(record):
    print(json.dumps(record), flush=True)


def follow(sock, tunnel_id, barrier, count):
    """Print notifies for `tunnel_id`, one JSON line each, as they arrive.

    The anchor is the barrier's own notify when --barrier was given, and the
    tunnel's first notify otherwise; `count` more tunnel notifies are printed
    after it.  zebra serves one session's messages in order, so every notify
    for the tunnel printed before {"barrier": true} was sent before zebra had
    even read the barrier DEL -- i.e. it answered the request directly.
    """
    # The barrier's REMOVED must not be mistaken for the tunnel's own notify.
    assert barrier != tunnel_id, "--barrier must differ from the tunnel id"
    ids = {tunnel_id} if barrier is None else {tunnel_id, barrier}
    anchored = False
    remaining = count
    try:
        while not anchored or remaining > 0:
            notify = recv_notify(sock, ids)
            if barrier is not None and notify["tunnel_id"] == barrier:
                # Only the first answer for the barrier id is the barrier.
                ids.discard(barrier)
                anchored = True
                emit({"barrier": True})
                continue
            emit(notify)
            if anchored:
                remaining -= 1
            elif barrier is None:
                anchored = True
    except socket.timeout:
        emit({"timeout": True})
        sys.exit(EXIT_TIMEOUT)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("add", "del"))
    parser.add_argument("tunnel_id", type=int)
    parser.add_argument("--encap", choices=("gre", "fou"), default="gre")
    parser.add_argument("--socket", default="/var/run/frr/zserv.api")
    # The OUTER endpoints are the GRE tunnel's kernel identity. Two links
    # sharing a (local, remote) tuple cannot coexist -- the second create is
    # refused with EEXIST whatever the link is named and whether or not the
    # first is up -- so a test needing two DIMT tunnels alive at once must
    # vary one of them. Defaults match every other test in the module.
    parser.add_argument("--outer-local", default="192.0.2.1")
    parser.add_argument("--outer-remote", default="192.0.2.2")
    # A client whose request is deliberately held in zebra's dataplane waits
    # as long as the hold; the default only has to cover an ordinary round
    # trip.  Under --follow/--barrier it bounds each wait for the next notify.
    parser.add_argument("--timeout", type=float, default=10)
    # HELLO with synchronous=0.  zebra withholds capabilities, VRF and
    # interface updates from a synchronous client but sends DIMT owner
    # notifies -- unsolicited ones included -- to either kind, so no test
    # here needs it; it exists to mirror pimd's own session when one does.
    parser.add_argument("--async", dest="async_session", action="store_true")
    # Keep the owner session open after the first notify and print this many
    # more for the tunnel, one JSON line each.  On timeout {"timeout": true}
    # is printed and the client exits 3.
    parser.add_argument("--follow", type=int, default=0, metavar="N")
    # After the request, send a DEL for this id -- one zebra does not track,
    # so it is answered REMOVED at once from the no-entry branch -- and treat
    # that REMOVED as an ordering barrier: tunnel notifies printed before
    # {"barrier": true} are zebra's direct answer to the request, and --follow
    # counts from the barrier instead of from the first notify.
    parser.add_argument("--barrier", type=int, metavar="ID")
    args = parser.parse_args()

    session_id = 0xD1000000 | (os.getpid() & 0xFFFF)
    synchronous = 0 if args.async_session else 1
    hello = struct.pack("!BHIB", ZEBRA_ROUTE_PIM, 0, session_id, synchronous)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(args.timeout)
        sock.connect(args.socket)
        sock.sendall(header(ZEBRA_HELLO, hello))
        if args.action == "add":
            encap = 2 if args.encap == "fou" else 1
            dport = 5555 if args.encap == "fou" else 0
            payload = struct.pack("!I", args.tunnel_id)
            payload += ipaddr("10.200.0.1") + ipaddr("10.200.0.2")
            payload += ipaddr(args.outer_local) + ipaddr(args.outer_remote)
            payload += struct.pack("!BHB", encap, dport, 0)
            command = ZEBRA_DIMT_TUNNEL_ADD
        else:
            payload = struct.pack("!I", args.tunnel_id)
            command = ZEBRA_DIMT_TUNNEL_DEL
        sock.sendall(header(command, payload))
        if args.barrier is not None:
            sock.sendall(
                header(ZEBRA_DIMT_TUNNEL_DEL, struct.pack("!I", args.barrier))
            )
        if args.follow or args.barrier is not None:
            follow(sock, args.tunnel_id, args.barrier, args.follow)
            return
        print(json.dumps(recv_notify(sock, {args.tunnel_id})))


if __name__ == "__main__":
    main()
