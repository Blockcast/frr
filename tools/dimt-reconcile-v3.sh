#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# DIMT dynamic join reconciler v3 -- SCAFFOLD
# (draft-zzhang-mboned-dynamic-internet-mcast-tunnel, Phase A of the
# dynamic-tunnel dogfood; design: onprem-k8s/.planning/
# 2026-07-12-dimt-dynamic-tunnel-design.md, O1 probe 2026-07-13).
#
# dimt-reconcile.sh (v2) owns the REGISTRY-driven tunnel set: one
# GRE-in-FOU netdev per listed peer, pim-light enrolled.  This daemon
# adds the DYNAMIC layer on top -- state that exists only while a
# receiver (or a remote join) exists, and is torn down afterwards:
#
#   --mode receiver   (PoP border, e.g. the nbg6817)
#     Watches IGMPv3 (S,G) memberships on downstream interfaces.  For a
#     source S with no usable PIM upstream: resolve the source-side peer
#     (static map now; TYPE260 DIMT-tier DNS later, open item O2),
#     ensure the tunnel (delegated to v2 via a dynamic peers overlay),
#     and install the RPF override that lets pim-light send the join:
#
#         ip mroute <S>/32 <inner4(peer)>
#
#     NEXTHOP-form is load-bearing (O1 finding 1): the interface form
#     resolves the RPF nexthop to the source itself, the Join goes out
#     with upstream-neighbor=<S>, and the PE silently drops it.  The
#     nexthop must be the peer's inner tunnel address.
#     On last-receiver leave: hold-down, then withdraw the mroute and
#     drop the peer from the dynamic overlay (v2 GCs the tunnel unless
#     it is also a registry peer).
#
#   --mode source-pe  (PE with a passive segment leg, e.g. eth0)
#     Prereq (NOT daemon-managed): `ip pim` + `ip pim passive` on the
#     segment interface.  Watches for (S,G) mroutes whose IIF is the
#     segment interface (created by remote pim-light joins).  While one
#     exists, keeps an IGMPv3 (S,G) membership on the segment so
#     snooping fabrics (pve vmbr*, MX) actually deliver the stream
#     (O1 finding 2 -- a PIM join alone pulls nothing):
#
#         interface <seg>; ip igmp join <G> <S>
#
#     Removes the join (after hold-down) when the mroute is gone, so
#     no receivers => no standing segment pull.
#
# Both modes only ever remove state recorded in --state-dir; nothing
# hand-configured is touched.  "No static routing" means no *standing
# hand-config*: everything here is protocol-driven transient state, the
# same state pimd would keep internally once this moves in-daemon
# (Phase B, alongside the FRRouting upstream work).
#
# Usage:
#   dimt-reconcile-v3.sh --mode receiver --self <overlay-ipv4>
#       [--source-map /etc/dimt/source-peers] [--ssm-prefix 232.]
#       [--interval 5] [--holddown 300] [--state-dir /var/run/dimt-v3]
#       [--v2 /usr/sbin/dimt-reconcile.sh] [--no-v2]
#       [--dry-run] [--once]
#   dimt-reconcile-v3.sh --mode source-pe --segment-iface <dev>
#       [--interval 5] [--holddown 60] [--state-dir /var/run/dimt-v3]
#       [--dry-run] [--once]
#
# --source-map lines: "<source-ip> <peer-overlay-ipv4>"  ('#' comments).
#   A line "default <peer>" catches all unmatched SSM sources.
#   TODO(O2): DNS discovery -- reverse TYPE260 on S selecting the
#   non-geo DIMT-tier record -- replaces the map as the primary path;
#   the map stays as an override.

set -u

MODE=""
SELF="${DIMT_SELF:-}"
SOURCE_MAP="${DIMT_SOURCE_MAP:-/etc/dimt/source-peers}"
SSM_PREFIX="${DIMT_SSM_PREFIX:-232.}"
INTERVAL=5
HOLDDOWN=""
STATE_DIR="${DIMT_V3_STATE_DIR:-/var/run/dimt-v3}"
V2="${DIMT_V2:-/usr/sbin/dimt-reconcile.sh}"
DO_V2=1
SEG_IFACE=""
DRY=0
ONCE=0

log() { echo "dimt-reconcile-v3: $*" >&2; }

run() {
	if [ "$DRY" = 1 ]; then
		log "DRY: $*"
	else
		"$@"
	fi
}

usage() {
	awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--mode) MODE="$2"; shift 2 ;;
	--self) SELF="$2"; shift 2 ;;
	--source-map) SOURCE_MAP="$2"; shift 2 ;;
	--ssm-prefix) SSM_PREFIX="$2"; shift 2 ;;
	--interval) INTERVAL="$2"; shift 2 ;;
	--holddown) HOLDDOWN="$2"; shift 2 ;;
	--state-dir) STATE_DIR="$2"; shift 2 ;;
	--v2) V2="$2"; shift 2 ;;
	--no-v2) DO_V2=0; shift ;;
	--segment-iface) SEG_IFACE="$2"; shift 2 ;;
	--dry-run) DRY=1; shift ;;
	--once) ONCE=1; shift ;;
	*) usage ;;
	esac
done

case "$MODE" in
receiver)
	[ -n "$SELF" ] || { log "--self <overlay-ipv4> is required in receiver mode"; exit 1; }
	[ -n "$HOLDDOWN" ] || HOLDDOWN=300
	;;
source-pe)
	[ -n "$SEG_IFACE" ] || { log "--segment-iface <dev> is required in source-pe mode"; exit 1; }
	[ -n "$HOLDDOWN" ] || HOLDDOWN=60
	;;
*) usage ;;
esac

command -v vtysh >/dev/null 2>&1 || { log "vtysh not found; nothing to reconcile against"; exit 1; }

# --- shared helpers ---------------------------------------------------

# Must match dimt-reconcile.sh inner_of(): inner4(X) = 10.99.<o3>.<o4>.
inner_of() {
	echo "$1" | awk -F. '{ printf "10.99.%s.%s", $3, $4 }'
}

now() { date +%s; }

# Timestamps live IN the state files (busybox `date -r` / `stat -c` are
# not guaranteed on OpenWrt).
mark_seen() { [ "$DRY" = 1 ] || now >"$1"; }
seen_at() { cat "$1" 2>/dev/null || echo 0; }

# vtysh config helper: errors arrive on stdout with exit 0 as
# '%'-prefixed lines (same caveat as v2 frr_iface); mgmtd's benign
# "no changes found" note is not an error.
vty_conf() {
	if [ "$DRY" = 1 ]; then
		log "DRY: vtysh -c 'configure terminal' $(printf -- "-c '%s' " "$@")"
		return 0
	fi
	out=$(vtysh -c 'configure terminal' "$@" 2>&1)
	rc=$?
	if [ $rc -ne 0 ] || printf '%s\n' "$out" |
		 grep -vE 'No changes found|Configuration applied with notes' | grep -q '^%'; then
		log "vtysh config failed: $out"
		return 1
	fi
	return 0
}

# --- receiver mode ----------------------------------------------------

# Emit "S G" per active downstream (S,G) membership: Fwd=Y, source-
# specific (INCL), group in the SSM prefix, iface not a dimt-* tunnel.
#   vtysh$ show ip igmp sources
#   Interface  Group      Source        Timer Fwd Uptime
#   br-lan     232.0.0.1  69.25.95.102  04:10   Y 00:00:17
receiver_wants() {
	vtysh -c 'show ip igmp sources' 2>/dev/null | awk -v ssm="$SSM_PREFIX" '
		NR == 1 || NF < 5 { next }
		$1 ~ /^dimt-/     { next }
		$3 == "*"         { next }
		index($2, ssm) != 1 { next }
		$5 == "Y" || $4 == "Y" { print $3, $2 }
	' | sort -u
}

# True (0) when pim already has a usable upstream for (S,G).
#   vtysh$ show ip pim upstream
#   Iif        Source        Group      State ...
#   dimt-0-47  69.25.95.102  232.0.0.1  J     ...
upstream_usable() { # <S> <G>
	vtysh -c 'show ip pim upstream' 2>/dev/null | awk -v s="$1" -v g="$2" '
		$2 == s && $3 == g && $1 != "Unknown" { found = 1 }
		END { exit found ? 0 : 1 }
	'
}

# Resolve the source-side DIMT peer for source S.
# 1. static map (--source-map): "S peer" / "default peer" lines.
# 2. TODO(O2): DNS -- reverse TYPE260 on S, select the non-geo
#    DIMT-tier AMTRELAY record (NOT the geo-routed AMT relay FQDN --
#    that would hand us our own site's relay).  Sketch:
#      dig +short TYPE260 $(reverse_of $S).in-addr.arpa
#    then map the DIMT-tier target to its overlay address.
resolve_peer() { # <S>
	[ -r "$SOURCE_MAP" ] || return 1
	awk -v s="$1" '
		/^[ \t]*#/ || NF < 2 { next }
		$1 == s        { print $2; found = 1; exit }
		$1 == "default" { dflt = $2 }
		END { if (!found && dflt) print dflt; exit (found || dflt) ? 0 : 1 }
	' "$SOURCE_MAP"
}

mroute_state() { echo "$STATE_DIR/mroute-$1"; }

install_mroute() { # <S> <peer-overlay>
	nh=$(inner_of "$2")
	# NEXTHOP-form, never the interface form (O1 finding 1).
	vty_conf -c "ip mroute $1/32 $nh" || return 1
	[ "$DRY" = 1 ] || {
		echo "peer=$2"
		echo "nexthop=$nh"
		echo "since=$(now)"
	} >"$(mroute_state "$1")"
	log "installed RPF override $1/32 -> $nh (peer $2)"
}

remove_mroute() { # <S>
	st=$(mroute_state "$1")
	[ -f "$st" ] || return 0
	nh=$(sed -n 's/^nexthop=//p' "$st")
	vty_conf -c "no ip mroute $1/32 $nh" || return 1
	run rm -f "$st"
	log "withdrew RPF override $1/32 -> $nh"
}

# Rebuild the dynamic peers overlay and hand the union (registry file
# untouched, it stays v2's input) to v2 so tunnel ensure/GC has ONE
# owner.  With --no-v2 (dogfood over a pre-existing static tunnel) this
# is skipped and only the mroute layer is managed.
sync_tunnels() {
	[ "$DO_V2" = 1 ] || return 0
	[ -x "$V2" ] || { log "v2 reconciler $V2 not executable; --no-v2 to silence"; return 0; }
	overlay="$STATE_DIR/peers.dynamic"
	sed -n 's/^peer=//p' "$STATE_DIR"/mroute-* 2>/dev/null | sort -u >"$overlay.tmp"
	mv "$overlay.tmp" "$overlay"
	union=$( { sed 's/#.*//' /etc/dimt/peers 2>/dev/null; cat "$overlay"; } |
		tr -d ' \t\r' | grep . | sort -u | tr '\n' ',' | sed 's/,$//')
	[ -n "$union" ] || return 0
	run "$V2" --self "$SELF" --peers "$union"
}

receiver_pass() {
	wants=$(receiver_wants)
	nowts=$(now)

	# 1. new receivers with unresolved upstream -> peer + tunnel + mroute
	echo "$wants" | while read -r s g; do
		[ -n "$s" ] || continue
		mark_seen "$STATE_DIR/seen-$s"
		[ -f "$(mroute_state "$s")" ] && continue
		upstream_usable "$s" "$g" && continue
		peer=$(resolve_peer "$s") || {
			log "no peer for source $s (no map entry; DNS discovery TODO O2)"
			continue
		}
		install_mroute "$s" "$peer" && sync_tunnels
	done

	# 2. receivers gone -> hold-down -> withdraw
	for st in "$STATE_DIR"/mroute-*; do
		[ -f "$st" ] || continue
		s=${st##*/mroute-}
		if echo "$wants" | grep -q "^$s "; then
			mark_seen "$STATE_DIR/seen-$s"
			continue
		fi
		last=$(seen_at "$STATE_DIR/seen-$s")
		if [ $((nowts - last)) -ge "$HOLDDOWN" ]; then
			remove_mroute "$s" && run rm -f "$STATE_DIR/seen-$s" && sync_tunnels
		fi
	done
}

# --- source-pe mode ---------------------------------------------------

# Emit "S G" per (S,G) mroute pulled from the segment by a remote join.
#   vtysh$ show ip mroute
#   Source        Group      Flags  Proto  Input  Output     TTL  Uptime
#   69.25.95.102  232.0.0.1  SFT    PIM    eth0   dimt-0-40  1    00:00:28
segment_pulls() {
	vtysh -c 'show ip mroute' 2>/dev/null | awk -v seg="$SEG_IFACE" '
		NF < 6 || $1 == "Source" { next }
		$5 == seg && $4 == "PIM" { print $1, $2 }
	' | sort -u
}

join_state() { echo "$STATE_DIR/join-$1-$2"; }

ensure_seg_join() { # <S> <G>
	[ -f "$(join_state "$1" "$2")" ] && return 0
	vty_conf -c "interface $SEG_IFACE" -c "ip igmp join $2 $1" || return 1
	[ "$DRY" = 1 ] || echo "since=$(now)" >"$(join_state "$1" "$2")"
	log "joined ($1, $2) on $SEG_IFACE (segment pull)"
}

remove_seg_join() { # <S> <G>
	vty_conf -c "interface $SEG_IFACE" -c "no ip igmp join $2 $1" || return 1
	run rm -f "$(join_state "$1" "$2")"
	log "left ($1, $2) on $SEG_IFACE"
}

source_pe_pass() {
	pulls=$(segment_pulls)
	nowts=$(now)

	echo "$pulls" | while read -r s g; do
		[ -n "$s" ] || continue
		mark_seen "$STATE_DIR/pseen-$s-$g"
		ensure_seg_join "$s" "$g"
	done

	for st in "$STATE_DIR"/join-*; do
		[ -f "$st" ] || continue
		sg=${st##*/join-}
		s=${sg%-*}; g=${sg##*-}
		if echo "$pulls" | grep -q "^$s $g\$"; then
			continue
		fi
		last=$(seen_at "$STATE_DIR/pseen-$s-$g")
		if [ $((nowts - last)) -ge "$HOLDDOWN" ]; then
			remove_seg_join "$s" "$g" && run rm -f "$STATE_DIR/pseen-$s-$g"
		fi
	done
}

# --- main loop --------------------------------------------------------

mkdir -p "$STATE_DIR" || { log "cannot create state dir $STATE_DIR"; exit 1; }

while :; do
	case "$MODE" in
	receiver) receiver_pass ;;
	source-pe) source_pe_pass ;;
	esac
	[ "$ONCE" = 1 ] && break
	sleep "$INTERVAL"
done
