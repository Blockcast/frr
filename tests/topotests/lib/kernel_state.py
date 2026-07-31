# SPDX-License-Identifier: ISC

import ipaddress
import re
import shlex
import socket


def _proc_ipv4(value):
    """Decode the host-order hexadecimal IPv4 format used by /proc/net/ip_mr_cache."""
    return str(ipaddress.IPv4Address(socket.ntohl(int(value, 16))))


def parse_ip_mr_cache(output):
    """Return kernel multicast forwarding cache entries from procfs text."""
    lines = output.splitlines()
    if not lines or lines[0].split() != [
        "Group",
        "Origin",
        "Iif",
        "Pkts",
        "Bytes",
        "Wrong",
        "Oifs",
    ]:
        raise ValueError("invalid /proc/net/ip_mr_cache header")

    entries = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        try:
            oifs = {
                int(oif.split(":", 1)[0])
                for oif in fields[6:]
                if ":" in oif
            }
            entries.append(
                {
                    "group": _proc_ipv4(fields[0]),
                    "source": _proc_ipv4(fields[1]),
                    "iif": int(fields[2]),
                    "oifs": oifs,
                }
            )
        except ValueError:
            continue
    return entries


def check_ip_mr_cache(router, source, group, oil_vif, expected=True):
    """Check an (S,G) and output vif directly in the Linux multicast cache."""
    output = router.run("cat /proc/net/ip_mr_cache 2>&1")
    try:
        entries = parse_ip_mr_cache(output)
    except ValueError as error:
        return "kernel MFC state unavailable: {}: {}".format(error, output.strip())

    matches = [
        entry
        for entry in entries
        if entry["source"] == source and entry["group"] == group
    ]
    found = any(oil_vif in entry["oifs"] for entry in matches)
    if found == expected:
        return None
    if expected:
        return "kernel MFC ({},{}) missing OIL vif {}; entries: {}".format(
            source, group, oil_vif, matches
        )
    return "kernel MFC ({},{}) unexpectedly contains OIL vif {}; entries: {}".format(
        source, group, oil_vif, matches
    )


def check_gre_link(router, interface, local, remote, mtu=None, expected_up=True):
    """Check GRE endpoint and link attributes from `ip -d link show`."""
    output = router.run(
        "ip -d link show dev {} 2>&1".format(shlex.quote(interface))
    )
    lines = output.splitlines()
    if not lines or not re.search(
        r"^\d+:\s+{}(?:@\S+)?:".format(re.escape(interface)), lines[0]
    ):
        return "kernel link {} is missing: {}".format(interface, output.strip())

    flags = re.search(r"<([^>]*)>", lines[0])
    is_up = bool(flags and "UP" in flags.group(1).split(","))
    if is_up != expected_up:
        return "kernel link {} UP={} (expected {}): {}".format(
            interface, is_up, expected_up, output.strip()
        )

    if mtu is not None and not re.search(r"\bmtu\s+{}\b".format(mtu), lines[0]):
        return "kernel link {} has wrong MTU (expected {}): {}".format(
            interface, mtu, output.strip()
        )

    detail = " ".join(lines[1:])
    if "link/gre" not in detail:
        return "kernel link {} is not GRE: {}".format(interface, output.strip())
    if not re.search(r"\bremote\s+{}\b".format(re.escape(remote)), detail):
        return "kernel GRE {} has wrong remote (expected {}): {}".format(
            interface, remote, output.strip()
        )
    if not re.search(r"\blocal\s+{}\b".format(re.escape(local)), detail):
        return "kernel GRE {} has wrong local (expected {}): {}".format(
            interface, local, output.strip()
        )
    return None
