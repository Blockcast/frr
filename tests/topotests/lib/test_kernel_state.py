# SPDX-License-Identifier: ISC

from lib.kernel_state import check_gre_link, check_ip_mr_cache, parse_ip_mr_cache


MR_CACHE = """Group    Origin   Iif     Pkts    Bytes    Wrong Oifs
010101EF 0100000A 1 12 840 0 2:1 7:1
020101EF 0200000A 3 4 280 0 9:1
"""

GRE_LINK = """\
17: dimt-00000001@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1476 \
qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/gre 192.0.2.1 peer 192.0.2.2 promiscuity 0 minmtu 0 maxmtu 0
    gre remote 192.0.2.2 local 192.0.2.1 ttl inherit
"""


class FakeRouter:
    def __init__(self, link=GRE_LINK, cache=MR_CACHE):
        self.link = link
        self.cache = cache

    def run(self, command):
        if command.startswith("ip -d link show"):
            return self.link
        if command == "cat /proc/net/ip_mr_cache 2>&1":
            return self.cache
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
