#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

import argparse
import ipaddress
import json
import os
import socket
import struct


MARKER = 254
VERSION = 6
VRF_DEFAULT = 0
ZEBRA_ROUTE_PIM = 10
ZEBRA_HELLO = 19
ZEBRA_DIMT_TUNNEL_ADD = 153
ZEBRA_DIMT_TUNNEL_DEL = 154
ZEBRA_DIMT_TUNNEL_NOTIFY_OWNER = 155


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


def recv_notify(sock, tunnel_id):
    while True:
        raw_header = recv_exact(sock, 10)
        length, marker, version, _vrf, command = struct.unpack("!HBBIH", raw_header)
        if marker != MARKER or version != VERSION or length < 10:
            raise RuntimeError("invalid ZAPI response header")
        payload = recv_exact(sock, length - 10)
        if command != ZEBRA_DIMT_TUNNEL_NOTIFY_OWNER:
            continue
        response_id, ifindex, result = struct.unpack("!IIB", payload)
        if response_id == tunnel_id:
            return {"tunnel_id": response_id, "ifindex": ifindex, "result": result}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("add", "del"))
    parser.add_argument("tunnel_id", type=int)
    parser.add_argument("--encap", choices=("gre", "fou"), default="gre")
    parser.add_argument("--socket", default="/var/run/frr/zserv.api")
    args = parser.parse_args()

    session_id = 0xD1000000 | (os.getpid() & 0xFFFF)
    hello = struct.pack("!BHIB", ZEBRA_ROUTE_PIM, 0, session_id, 1)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(args.socket)
        sock.sendall(header(ZEBRA_HELLO, hello))
        if args.action == "add":
            encap = 2 if args.encap == "fou" else 1
            dport = 5555 if args.encap == "fou" else 0
            payload = struct.pack("!I", args.tunnel_id)
            payload += ipaddr("10.200.0.1") + ipaddr("10.200.0.2")
            payload += ipaddr("192.0.2.1") + ipaddr("192.0.2.2")
            payload += struct.pack("!BHB", encap, dport, 0)
            command = ZEBRA_DIMT_TUNNEL_ADD
        else:
            payload = struct.pack("!I", args.tunnel_id)
            command = ZEBRA_DIMT_TUNNEL_DEL
        sock.sendall(header(command, payload))
        print(json.dumps(recv_notify(sock, args.tunnel_id)))


if __name__ == "__main__":
    main()
