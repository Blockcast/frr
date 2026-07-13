#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Self-contained test for tools/dimt-reconcile-v3.sh (SCAFFOLD).  Needs
# no root, no network, no FRR: a fake `vtysh` on PATH serves canned
# `show` output from flat files and logs every config invocation.  The
# v2 tunnel delegation is exercised through a fake dimt-reconcile.sh
# that just logs its argv.  Run as: sh tools/dimt-reconcile-v3-test.sh
#
# What is pinned here (the O1 findings, as regressions):
#   1. the RPF override is NEXTHOP-form -- `ip mroute S/32 10.99.x.y`,
#      never the interface form (which makes the PE drop the join);
#   2. source-pe mode answers a segment-IIF mroute with an explicit
#      `ip igmp join G S` on the segment interface (snooping fabrics
#      deliver nothing to a bare PIM join);
#   3. teardown: receiver/mroute gone -> hold-down -> withdrawal of
#      exactly the state this daemon installed.

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
V3="$SCRIPT_DIR/dimt-reconcile-v3.sh"
RUN_SH="${DIMT_TEST_SH:-sh}"

TESTDIR=$(mktemp -d "${TMPDIR:-/tmp}/dimt-v3-test.XXXXXX") || exit 1
trap 'rm -rf "$TESTDIR"' EXIT INT TERM

BIN="$TESTDIR/bin"
STATE="$TESTDIR/state"
mkdir -p "$BIN" "$STATE"

# fake vtysh: `-c 'show X'` cats $FAKEVTY_DIR/<slug>; anything with
# 'configure terminal' is appended to vty.log and succeeds.
cat > "$BIN/vtysh" <<'FAKEVTY'
#!/bin/sh
set -u
: "${FAKEVTY_DIR:?FAKEVTY_DIR not set}"
conf=0
for a in "$@"; do
	[ "$a" = "configure terminal" ] && conf=1
done
if [ "$conf" = 1 ]; then
	echo "$*" >>"$FAKEVTY_DIR/vty.log"
	exit 0
fi
prev=""
for a in "$@"; do
	if [ "$prev" = "-c" ]; then
		slug=$(echo "$a" | tr ' /' '--')
		[ -f "$FAKEVTY_DIR/$slug" ] && cat "$FAKEVTY_DIR/$slug"
	fi
	prev="$a"
done
exit 0
FAKEVTY
chmod +x "$BIN/vtysh"

cat > "$BIN/dimt-reconcile.sh" <<'FAKEV2'
#!/bin/sh
echo "$*" >>"${FAKEVTY_DIR:?}/v2.log"
FAKEV2
chmod +x "$BIN/dimt-reconcile.sh"

export FAKEVTY_DIR="$TESTDIR"
export PATH="$BIN:$PATH"

FAILED=0
check() { # <desc> <cmd...>
	desc="$1"; shift
	if "$@" >/dev/null 2>&1; then
		echo "ok   - $desc"
	else
		echo "FAIL - $desc"
		FAILED=1
	fi
}

# --- receiver mode ----------------------------------------------------

cat > "$TESTDIR/show-ip-igmp-sources" <<'EOF'
Interface        Group           Source          Timer Fwd Uptime
br-lan           239.255.255.250 *               04:16   Y 05:41:44
br-lan           232.0.0.1       69.25.95.102    04:10   Y 00:00:17
dimt-0-47        232.0.0.1       69.25.95.200    04:10   Y 00:00:17
br-lan           224.9.9.9       10.0.0.1        04:10   Y 00:00:17
EOF
cat > "$TESTDIR/show-ip-pim-upstream" <<'EOF'
 Iif        Source        Group            State  Uptime    JoinTimer
 Unknown    *             239.255.255.250  NotJ   05:40:55  --:--:--
EOF
echo "69.25.95.102 100.64.0.47" > "$TESTDIR/source-peers"

$RUN_SH "$V3" --mode receiver --self 100.64.0.40 \
	--source-map "$TESTDIR/source-peers" --state-dir "$STATE" \
	--v2 "$BIN/dimt-reconcile.sh" --once >/dev/null 2>&1

check "receiver: nexthop-form mroute installed (O1 finding 1)" \
	grep -q "ip mroute 69.25.95.102/32 10.99.0.47" "$TESTDIR/vty.log"
check "receiver: interface-form mroute NEVER emitted" \
	sh -c "! grep 'ip mroute' '$TESTDIR/vty.log' | grep -q 'dimt-'"
check "receiver: ASM (*) membership ignored" \
	sh -c "! grep -q '239.255.255.250' '$TESTDIR/vty.log'"
check "receiver: non-SSM group ignored" \
	sh -c "! grep -q '224.9.9.9' '$TESTDIR/vty.log'"
check "receiver: membership on a dimt-* iface ignored" \
	sh -c "! grep -q '69.25.95.200' '$TESTDIR/vty.log'"
check "receiver: v2 invoked with dynamic peer in union" \
	grep -q "100.64.0.47" "$TESTDIR/v2.log"
check "receiver: state recorded" test -f "$STATE/mroute-69.25.95.102"

# receiver leaves -> holddown 0 -> withdraw
cat > "$TESTDIR/show-ip-igmp-sources" <<'EOF'
Interface        Group           Source          Timer Fwd Uptime
EOF
: > "$TESTDIR/vty.log"
$RUN_SH "$V3" --mode receiver --self 100.64.0.40 \
	--source-map "$TESTDIR/source-peers" --state-dir "$STATE" \
	--v2 "$BIN/dimt-reconcile.sh" --holddown 0 --once >/dev/null 2>&1

check "receiver: mroute withdrawn on leave (holddown 0)" \
	grep -q "no ip mroute 69.25.95.102/32 10.99.0.47" "$TESTDIR/vty.log"
check "receiver: state cleaned" sh -c "! test -f '$STATE/mroute-69.25.95.102'"
check "receiver: last leave GCs via v2 --allow-empty (no leaked tunnel)" \
	grep -q -- "--allow-empty" "$TESTDIR/v2.log"

# --- receiver mode: O2 BGP UMH discovery ------------------------------

cat > "$TESTDIR/show-ip-igmp-sources" <<'EOF'
Interface        Group           Source          Timer Fwd Uptime
br-lan           232.0.0.1       69.25.95.102    04:10   Y 00:00:17
EOF
# two ECs on one line: preference 9 must beat preference 5; the amt
# record must never match (pim tunnels only).
cat > "$TESTDIR/show-bgp-ipv4-unicast-69.25.95.102-32" <<'EOF'
BGP routing table entry for 69.25.95.102/32, version 2
  65001
    100.64.0.47 from 100.64.0.47 (100.64.0.47)
      Origin IGP, metric 0, valid, external, best (First path received)
      Extended Community: UMH:10.99.0.47:pim:5 UMH:10.99.0.99:pim:9 UMH:10.99.0.66:amt:15
EOF
: > "$TESTDIR/vty.log"; : > "$TESTDIR/v2.log"
$RUN_SH "$V3" --mode receiver --self 100.64.0.40 \
	--source-map "$TESTDIR/no-such-map" --state-dir "$STATE" \
	--v2 "$BIN/dimt-reconcile.sh" --once >/dev/null 2>&1

check "O2: peer discovered via BGP UMH (no map)" \
	grep -q "ip mroute 69.25.95.102/32 10.99.0.99" "$TESTDIR/vty.log"
check "O2: highest preference wins (9 over 5)" \
	sh -c "! grep -q 'ip mroute 69.25.95.102/32 10.99.0.47' '$TESTDIR/vty.log'"
check "O2: amt-type UMH never selected" \
	sh -c "! grep -q '10.99.0.66' '$TESTDIR/vty.log'"
check "O2: tunnel outer derived from UMH inner (v2 sees 100.64.0.99)" \
	grep -q "100.64.0.99" "$TESTDIR/v2.log"

# map entry overrides BGP discovery (local provisioning wins)
cat > "$TESTDIR/show-ip-igmp-sources" <<'EOF'
Interface        Group           Source          Timer Fwd Uptime
br-lan           232.0.0.1       69.25.95.102    04:10   Y 00:00:17
EOF
echo "69.25.95.102 100.64.0.88" > "$TESTDIR/source-peers"
rm -f "$STATE"/mroute-* "$STATE"/seen-*
: > "$TESTDIR/vty.log"
$RUN_SH "$V3" --mode receiver --self 100.64.0.40 \
	--source-map "$TESTDIR/source-peers" --state-dir "$STATE" \
	--v2 "$BIN/dimt-reconcile.sh" --once >/dev/null 2>&1

check "O2: static map overrides BGP UMH" \
	grep -q "ip mroute 69.25.95.102/32 10.99.0.88" "$TESTDIR/vty.log"

# neither map nor a pim-type UMH -> no state installed
cat > "$TESTDIR/show-bgp-ipv4-unicast-69.25.95.102-32" <<'EOF'
BGP routing table entry for 69.25.95.102/32, version 2
      Extended Community: UMH:10.99.0.66:amt:15
EOF
rm -f "$STATE"/mroute-* "$STATE"/seen-*
: > "$TESTDIR/vty.log"
$RUN_SH "$V3" --mode receiver --self 100.64.0.40 \
	--source-map "$TESTDIR/no-such-map" --state-dir "$STATE" \
	--v2 "$BIN/dimt-reconcile.sh" --once >/dev/null 2>&1

check "O2: amt-only UMH -> no peer, no mroute" \
	sh -c "! grep -q 'ip mroute' '$TESTDIR/vty.log'"

# cleanup for the source-pe block
rm -f "$TESTDIR/show-bgp-ipv4-unicast-69.25.95.102-32" "$STATE"/mroute-* "$STATE"/seen-*

# --- receiver mode: v6 (MLDv2) -----------------------------------------

cat > "$TESTDIR/show-ip-igmp-sources" <<'EOF'
Interface        Group           Source          Timer Fwd Uptime
br-lan           232.0.0.1       69.25.95.102    04:10   Y 00:00:17
EOF
cat > "$TESTDIR/show-ipv6-mld-joins" <<'EOF'
Group                           Source                          State               LastSeen  NonTrkSeen     Created

On interface br-lan:
ff3e::1:1                       fd69::193                       JOIN                00:00:02           -    00:01:12
ff02::16                        *                               JOIN                00:00:02           -    04:00:21
On interface dimt-0-47:
ff3e::9:9                       fd69::999                       JOIN                00:00:02           -    00:01:12
EOF
cat > "$TESTDIR/show-ipv6-pim-upstream" <<'EOF'
 Iif      Source  Group    State  Uptime    JoinTimer  RSTimer   KATimer   RefCnt
EOF
# v6 UMH via BGP: pim pref 7 wins; amt never matches.  The dual-stack
# pass must also keep resolving the v4 source (map row below).
cat > "$TESTDIR/show-bgp-ipv6-unicast-fd69::193-128" <<'EOF'
BGP routing table entry for fd69::193/128, version 3
  65001
    fd7a:115c:a1e0::2f from fd7a:115c:a1e0::2f (100.64.0.47)
      Origin IGP, metric 0, valid, external, best (First path received)
      Extended IPv6 Community: UMH:fd99::99:pim:7 UMH:fd99::66:amt:15
EOF
echo "69.25.95.102 100.64.0.47" > "$TESTDIR/source-peers"
: > "$TESTDIR/vty.log"; : > "$TESTDIR/v2.log"
$RUN_SH "$V3" --mode receiver --self 100.64.0.40 \
	--source-map "$TESTDIR/source-peers" --state-dir "$STATE" \
	--v2 "$BIN/dimt-reconcile.sh" --once >/dev/null 2>&1

check "v6: static /128 RPF override via BGP UMH6 (inner6 nexthop)" \
	grep -q "ipv6 route fd69::193/128 fd99::99" "$TESTDIR/vty.log"
check "v6: amt-type UMH6 never selected" \
	sh -c "! grep -q 'fd99::66' '$TESTDIR/vty.log'"
check "v6: ASM (*) membership ignored" \
	sh -c "! grep -q 'ff02::16' '$TESTDIR/vty.log'"
check "v6: membership on a dimt-* iface ignored" \
	sh -c "! grep -q 'fd69::999' '$TESTDIR/vty.log'"
check "v6: dual-stack pass still installs the v4 override" \
	grep -q "ip mroute 69.25.95.102/32 10.99.0.47" "$TESTDIR/vty.log"
check "v6: outer derived from UMH6 inner (v2 union has 100.64.0.99)" \
	grep -q "100.64.0.99" "$TESTDIR/v2.log"
check "v6: state recorded" test -f "$STATE/mroute6-fd69::193"

# v6 map row overrides BGP
cat > "$TESTDIR/source-peers" <<'EOF'
69.25.95.102 100.64.0.47
fd69::193 100.64.0.88
EOF
rm -f "$STATE"/mroute6-* "$STATE"/seen6-*
: > "$TESTDIR/vty.log"
$RUN_SH "$V3" --mode receiver --self 100.64.0.40 \
	--source-map "$TESTDIR/source-peers" --state-dir "$STATE" \
	--v2 "$BIN/dimt-reconcile.sh" --once >/dev/null 2>&1

check "v6: static map overrides BGP UMH6" \
	grep -q "ipv6 route fd69::193/128 fd99::88" "$TESTDIR/vty.log"

# v6 receiver leaves -> holddown 0 -> withdraw
cat > "$TESTDIR/show-ipv6-mld-joins" <<'EOF'
Group                           Source                          State               LastSeen  NonTrkSeen     Created
EOF
: > "$TESTDIR/vty.log"
$RUN_SH "$V3" --mode receiver --self 100.64.0.40 \
	--source-map "$TESTDIR/source-peers" --state-dir "$STATE" \
	--v2 "$BIN/dimt-reconcile.sh" --holddown 0 --once >/dev/null 2>&1

check "v6: /128 override withdrawn on leave (holddown 0)" \
	grep -q "no ipv6 route fd69::193/128 fd99::88" "$TESTDIR/vty.log"
check "v6: state cleaned" sh -c "! test -f '$STATE/mroute6-fd69::193'"

rm -f "$TESTDIR/show-ipv6-mld-joins" "$TESTDIR/show-bgp-ipv6-unicast-fd69::193-128" \
	"$STATE"/mroute-* "$STATE"/mroute6-* "$STATE"/seen-* "$STATE"/seen6-*

# --- source-pe mode ---------------------------------------------------

cat > "$TESTDIR/show-ip-mroute" <<'EOF'
 Source        Group      Flags  Proto  Input   Output     TTL  Uptime
 69.25.95.102  232.0.0.1  SFT    PIM    eth0    dimt-0-40  1    00:00:28
 69.25.95.193  232.1.1.1  ST     PIM    mcast0  dimt-0-40  1    05:46:18
EOF
: > "$TESTDIR/vty.log"
$RUN_SH "$V3" --mode source-pe --segment-iface eth0 \
	--state-dir "$STATE" --once >/dev/null 2>&1

check "source-pe: igmp join emitted for segment-IIF mroute (O1 finding 2)" \
	grep -q "interface eth0 -c ip igmp join 232.0.0.1 69.25.95.102" "$TESTDIR/vty.log"
check "source-pe: non-segment-IIF mroute (mcast0) ignored" \
	sh -c "! grep -q '232.1.1.1' '$TESTDIR/vty.log'"

# v6 segment pull
cat > "$TESTDIR/show-ipv6-mroute" <<'EOF'
 Source     Group      Flags  Proto  Input   Output     TTL  Uptime
 fd69::193  ff3e::1:1  SFT    PIM    eth0    dimt-0-40  1    00:00:28
 fd69::777  ff3e::7:7  ST     PIM    mcast0  dimt-0-40  1    05:46:18
EOF
: > "$TESTDIR/vty.log"
$RUN_SH "$V3" --mode source-pe --segment-iface eth0 \
	--state-dir "$STATE" --once >/dev/null 2>&1

check "source-pe v6: mld join emitted for segment-IIF mroute" \
	grep -q "interface eth0 -c ipv6 mld join ff3e::1:1 fd69::193" "$TESTDIR/vty.log"
check "source-pe v6: non-segment-IIF v6 mroute ignored" \
	sh -c "! grep -q 'fd69::777' '$TESTDIR/vty.log'"

# v6 mroute gone -> holddown 0 -> mld leave
cat > "$TESTDIR/show-ipv6-mroute" <<'EOF'
 Source     Group      Flags  Proto  Input   Output     TTL  Uptime
EOF
: > "$TESTDIR/vty.log"
$RUN_SH "$V3" --mode source-pe --segment-iface eth0 \
	--state-dir "$STATE" --holddown 0 --once >/dev/null 2>&1

check "source-pe v6: mld join removed when mroute gone" \
	grep -q "no ipv6 mld join ff3e::1:1 fd69::193" "$TESTDIR/vty.log"

# mroute gone -> holddown 0 -> leave
cat > "$TESTDIR/show-ip-mroute" <<'EOF'
 Source        Group      Flags  Proto  Input   Output     TTL  Uptime
EOF
: > "$TESTDIR/vty.log"
$RUN_SH "$V3" --mode source-pe --segment-iface eth0 \
	--state-dir "$STATE" --holddown 0 --once >/dev/null 2>&1

check "source-pe: igmp join removed when mroute gone" \
	grep -q "no ip igmp join 232.0.0.1 69.25.95.102" "$TESTDIR/vty.log"

if [ "$FAILED" = 0 ]; then
	echo "all tests passed"
else
	echo "FAILURES (see above)"
	exit 1
fi
