# SPDX-License-Identifier: ISC

from lib.kernel_state import (
    check_gre_link,
    check_ip_mr_cache,
    check_ip_mr_cache_iif,
    check_link_absent,
    check_no_ip_mr_cache,
    link_names,
    parse_ip_mr_cache,
    parse_ip_mr_vif,
    resolve_mr_vif,
)


MR_CACHE = """Group    Origin   Iif     Pkts    Bytes    Wrong Oifs
010101EF 0100000A 1 12 840 0 2:1 7:1
020101EF 0200000A 3 4 280 0 9:1
"""

MR_VIF = """Interface      BytesIn  PktsIn  BytesOut PktsOut Flags Local    Remote
 1 dimt-0000002a        0       0         0       0 00000 00000000 00000000
 3 eth0                 0       0         0       0 00000 00000000 00000000
"""

GRE_LINK = """\
17: dimt-00000001@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1476 \
qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/gre 192.0.2.1 peer 192.0.2.2 promiscuity 0 minmtu 0 maxmtu 0
    gre remote 192.0.2.2 local 192.0.2.1 ttl inherit
"""

LINK_ABSENT = 'Device "dimt-00000001" does not exist.\n'

# `ip -o link show` output: the positive enumeration check_link_absent()
# derives absence from.  The loopback is what makes the enumeration
# trustworthy -- see link_names().
LINK_ENUM_WITH_DIMT = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN \\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP \\    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
17: dimt-00000001@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1476 qdisc noqueue state UNKNOWN \\    link/gre 192.0.2.1 peer 192.0.2.2
"""

# The same namespace after the tunnel is torn down: `lo` and `eth0` remain,
# so the enumeration is trustworthy and the dimt device is provably gone.
LINK_ENUM_WITHOUT_DIMT = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN \\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP \\    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
"""


class FakeRouter:
    def __init__(
        self,
        link=GRE_LINK,
        cache=MR_CACHE,
        vif=MR_VIF,
        enum=LINK_ENUM_WITH_DIMT,
        name="r1",
    ):
        self.link = link
        self.cache = cache
        self.vif = vif
        self.enum = enum
        # check_link_absent() reports the router it could not enumerate.
        self.name = name

    def run(self, command):
        # Must precede the bare `ip -o link show` arm below: link_ifindex()
        # asks about one device with the same prefix.
        if command.startswith("ip -o link show dev "):
            return self.link
        if command.startswith("ip -o link show"):
            return self.enum
        if command.startswith("ip -d link show"):
            return self.link
        if command.startswith("ip link show dev "):
            return self.link
        if command == "cat /proc/net/ip_mr_cache 2>&1":
            return self.cache
        if command == "cat /proc/net/ip_mr_vif 2>&1":
            return self.vif
        raise AssertionError("unexpected command: {}".format(command))


def test_parse_ip_mr_cache_decodes_addresses_and_oifs():
    entries = parse_ip_mr_cache(MR_CACHE)

    assert entries == [
        {"group": "239.1.1.1", "source": "10.0.0.1", "iif": 1, "oifs": {2, 7}},
        {"group": "239.1.1.2", "source": "10.0.0.2", "iif": 3, "oifs": {9}},
    ]


def test_check_gre_link_accepts_matching_kernel_state():
    assert (
        check_gre_link(
            FakeRouter(),
            "dimt-00000001",
            local="192.0.2.1",
            remote="192.0.2.2",
            mtu=1476,
        )
        is None
    )


def test_check_gre_link_rejects_missing_and_wrong_kernel_state():
    missing = check_gre_link(
        FakeRouter(link="Device 'dimt-00000001' does not exist.\n"),
        "dimt-00000001",
        local="192.0.2.1",
        remote="192.0.2.2",
    )
    wrong_remote = check_gre_link(
        FakeRouter(),
        "dimt-00000001",
        local="192.0.2.1",
        remote="198.51.100.9",
    )

    assert "is missing" in missing
    assert "wrong remote" in wrong_remote


def test_check_ip_mr_cache_positive_and_negative_assertions():
    router = FakeRouter()

    assert check_ip_mr_cache(router, "10.0.0.1", "239.1.1.1", 7) is None
    assert check_ip_mr_cache(router, "10.0.0.1", "239.1.1.1", 9, expected=False) is None


def test_check_ip_mr_cache_rejects_wrong_or_unexpected_oil():
    router = FakeRouter()

    wrong_oil = check_ip_mr_cache(router, "10.0.0.1", "239.1.1.1", 9)
    unexpected_oil = check_ip_mr_cache(
        router, "10.0.0.1", "239.1.1.1", 7, expected=False
    )

    assert "missing OIL vif 9" in wrong_oil
    assert "unexpectedly contains OIL vif 7" in unexpected_oil


def test_check_ip_mr_cache_rejects_unreadable_procfs_on_negative_assertion():
    unavailable = check_ip_mr_cache(
        FakeRouter(cache="cat: /proc/net/ip_mr_cache: No such file or directory\n"),
        "10.0.0.1",
        "239.1.1.1",
        7,
        expected=False,
    )

    assert "kernel MFC state unavailable" in unavailable


def test_check_ip_mr_cache_rejects_malformed_matching_row_on_negative_assertion():
    malformed_rows = (
        "010101EF 0100000A 1 12 840 0 invalid-oif",
        "010101EF 0100000A 1 12 840 0 2:not-a-number",
        "010101EF 0100000A invalid-iif 12 840 0 2:1",
    )

    for row in malformed_rows:
        result = check_ip_mr_cache(
            FakeRouter(cache="Group Origin Iif Pkts Bytes Wrong Oifs\n{}\n".format(row)),
            "10.0.0.1",
            "239.1.1.1",
            7,
            expected=False,
        )

        assert "kernel MFC state unavailable" in result
        assert "invalid /proc/net/ip_mr_cache" in result


def test_parse_ip_mr_vif_decodes_interface_indexes():
    assert parse_ip_mr_vif(MR_VIF) == {"dimt-0000002a": 1, "eth0": 3}


def test_parse_ip_mr_vif_rejects_invalid_header_and_rows():
    for bad in ("", "Interface BytesIn PktsIn\n", "not a header at all\n"):
        try:
            parse_ip_mr_vif(bad)
        except ValueError as error:
            assert "invalid /proc/net/ip_mr_vif header" in str(error)
        else:
            raise AssertionError("expected ValueError for header: {!r}".format(bad))

    for bad_row in ("dimt-0000002a 1", "1"):
        try:
            parse_ip_mr_vif(MR_VIF.splitlines()[0] + "\n" + bad_row + "\n")
        except ValueError as error:
            assert "invalid /proc/net/ip_mr_vif row" in str(error)
        else:
            raise AssertionError("expected ValueError for row: {!r}".format(bad_row))


def test_resolve_mr_vif_returns_the_kernel_allocated_index():
    index, error = resolve_mr_vif(FakeRouter(), "dimt-0000002a")

    assert (index, error) == (1, None)


def test_resolve_mr_vif_reports_missing_interface_and_unreadable_table():
    missing_index, missing = resolve_mr_vif(FakeRouter(), "dimt-deadbeef")
    unavailable_index, unavailable = resolve_mr_vif(
        FakeRouter(vif="cat: /proc/net/ip_mr_vif: No such file or directory\n"),
        "dimt-0000002a",
    )

    assert missing_index is None
    assert "has no vif for dimt-deadbeef" in missing
    assert unavailable_index is None
    assert "kernel vif table unavailable" in unavailable


def test_check_ip_mr_cache_iif_positive_and_negative_assertions():
    router = FakeRouter()

    assert check_ip_mr_cache_iif(router, "10.0.0.1", "239.1.1.1", 1) is None
    assert (
        check_ip_mr_cache_iif(router, "10.0.0.1", "239.1.1.1", 3, expected=False) is None
    )


def test_check_ip_mr_cache_iif_rejects_wrong_or_unexpected_incoming_vif():
    router = FakeRouter()

    wrong_iif = check_ip_mr_cache_iif(router, "10.0.0.1", "239.1.1.1", 3)
    unexpected_iif = check_ip_mr_cache_iif(
        router, "10.0.0.1", "239.1.1.1", 1, expected=False
    )

    assert "has no entry with incoming vif 3" in wrong_iif
    assert "unexpectedly has incoming vif 1" in unexpected_iif


def test_check_ip_mr_cache_iif_does_not_read_the_oil():
    """(10.0.0.1,239.1.1.1) has iif 1 and OIL {2,7}: an OIL vif is not an iif."""
    router = FakeRouter()

    assert check_ip_mr_cache(router, "10.0.0.1", "239.1.1.1", 7) is None
    assert "has no entry with incoming vif 7" in check_ip_mr_cache_iif(
        router, "10.0.0.1", "239.1.1.1", 7
    )


def test_check_ip_mr_cache_iif_negative_assertion_is_vacuous_when_sg_absent():
    """A missing (S,G) satisfies `expected=False` -- use check_no_ip_mr_cache().

    Pins the PR-2 convention rather than endorsing it: "the iif is not vif N"
    is trivially true when the kernel holds no entry at all, so a leave test
    that asserts teardown with expected=False would pass on an (S,G) that was
    never installed. check_no_ip_mr_cache() is the assertion with teeth.
    """
    router = FakeRouter()

    assert (
        check_ip_mr_cache_iif(router, "198.51.100.9", "239.9.9.9", 1, expected=False)
        is None
    )
    assert "still holds" not in (
        check_no_ip_mr_cache(router, "198.51.100.9", "239.9.9.9") or ""
    )


def test_check_ip_mr_cache_iif_rejects_unreadable_procfs():
    unavailable = check_ip_mr_cache_iif(
        FakeRouter(cache="cat: /proc/net/ip_mr_cache: No such file or directory\n"),
        "10.0.0.1",
        "239.1.1.1",
        1,
    )

    assert "kernel MFC state unavailable" in unavailable


def test_check_no_ip_mr_cache_positive_and_negative_assertions():
    router = FakeRouter()

    assert check_no_ip_mr_cache(router, "198.51.100.9", "239.9.9.9") is None
    assert "still holds (10.0.0.1,239.1.1.1)" in check_no_ip_mr_cache(
        router, "10.0.0.1", "239.1.1.1"
    )


def test_check_no_ip_mr_cache_rejects_unreadable_procfs():
    unavailable = check_no_ip_mr_cache(
        FakeRouter(cache="cat: /proc/net/ip_mr_cache: No such file or directory\n"),
        "10.0.0.1",
        "239.1.1.1",
    )

    assert "kernel MFC state unavailable" in unavailable


def test_check_link_absent_positive_and_negative_assertions():
    """Absence is proven from a positive enumeration, never from a failure.

    The three cases are deliberately distinct: a device present in a good
    enumeration, a device missing from a good enumeration, and an
    enumeration that did not run.  The old contract collapsed the last two,
    which is the fail-open reading check_link_absent() exists to refuse.
    """
    present = check_link_absent(FakeRouter(), "dimt-00000001")
    absent = check_link_absent(
        FakeRouter(enum=LINK_ENUM_WITHOUT_DIMT), "dimt-00000001"
    )
    other_device = check_link_absent(FakeRouter(), "dimt-00000002")

    assert "still present" in present
    assert absent is None
    assert other_device is None


def test_check_link_absent_refuses_to_prove_absence_from_a_failed_enumeration():
    """`ip` failing is not evidence of absence.

    The device-not-found diagnostic is what a per-device query returns; it
    enumerates nothing, so it cannot establish that anything is gone.
    Reading it as absence is precisely the fail-open bug this checker was
    rewritten to remove, so it must report "unproven" instead of None.
    """
    unproven = check_link_absent(FakeRouter(enum=LINK_ABSENT), "dimt-00000001")

    assert unproven is not None
    assert "unproven" in unproven
    assert "r1" in unproven


def test_link_names_requires_the_loopback_to_trust_an_enumeration():
    """A parseable line is not an enumeration; every namespace has `lo`.

    Without this guard a single stray line would be treated as the complete
    set of kernel links, and every device not named in it would read as
    absent.
    """
    assert link_names(FakeRouter(enum=LINK_ENUM_WITHOUT_DIMT)) == {"lo", "eth0"}
    assert link_names(FakeRouter(enum="17: dimt-00000001@NONE: <UP>\n")) is None
    assert link_names(FakeRouter(enum="")) is None
