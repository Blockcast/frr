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
#       [--trigger-iface <dev>] [--dry-run] [--once]
#   dimt-reconcile-v3.sh --mode source-pe --segment-iface <dev>
#       [--interval 5] [--holddown 60] [--state-dir /var/run/dimt-v3]
#       [--trigger-iface <dev>] [--dry-run] [--once]
#
# --trigger-iface: event-assisted reconciliation for sub-second join
#   latency. A respawning line-buffered tcpdump co-process watches the
#   named interface for the mode's control packets (receiver: IGMP on
#   the downstream iface; source-pe: PIM on the tunnel iface) and kicks
#   an immediate pass, so cold-start latency is bounded by packet
#   arrival + one pass instead of the poll interval. --interval remains
#   the correctness/GC fallback. Needs tcpdump; degrades to pure
#   polling without it. On shells whose `read` lacks -t (dash), event
#   waits degrade to 1s sub-polls of the event pipe.
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
TRIGGER_IFACE=""
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
	--trigger-iface) TRIGGER_IFACE="$2"; shift 2 ;;
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
	# State first, then tunnel, then mroute: for a NEW peer the tunnel
	# netdev must exist before pimd can resolve the nexthop and emit the
	# join, and sync_tunnels derives the dynamic peer set from the state
	# files. On vtysh failure the state (and tunnel claim) is rolled back.
	[ "$DRY" = 1 ] || {
		echo "peer=$2"
		echo "nexthop=$nh"
		echo "since=$(now)"
	} >"$(mroute_state "$1")"
	sync_tunnels
	# NEXTHOP-form, never the interface form (O1 finding 1).
	if ! vty_conf -c "ip mroute $1/32 $nh"; then
		run rm -f "$(mroute_state "$1")"
		sync_tunnels
		return 1
	fi
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
	# An EMPTY union is passed explicitly (--allow-empty, registry file
	# overridden) so the LAST leave GCs the last tunnel -- a fully-dynamic
	# site (empty registry) would otherwise leak the final tunnel forever.
	if [ -n "$union" ]; then
		run "$V2" --self "$SELF" --peers "$union"
	else
		run "$V2" --self "$SELF" --peers-file /dev/null --allow-empty
	fi
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
		install_mroute "$s" "$peer"
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

# Event-assisted mode: a respawning tcpdump co-process writes one line
# per matching control packet into a FIFO; the main loop waits on the
# FIFO with the poll interval as timeout, so a cold join is handled at
# packet-arrival time while GC/correctness still runs every INTERVAL.
#
# Safeguards (a broken or hostile client spamming reports must not spin
# vtysh):
#   - the BPF filter matches only the mode's join-carrying packets
#     (IGMPv3/v2 membership reports; PIM Join/Prune) -- queries and
#     hellos never wake us;
#   - MIN-GAP: at most one *triggered* pass per second (events landing
#     inside the gap are absorbed by that pass or the next tick);
#   - BURST budget: >10 triggered passes in a 10s window disables the
#     trigger until the window rolls (logged once per storm), leaving
#     interval polling in charge. Worst case under storm == pre-trigger
#     behavior.
EVENTS=0
if [ -n "$TRIGGER_IFACE" ] && [ "$ONCE" = 0 ]; then
	if command -v tcpdump >/dev/null 2>&1; then
		case "$MODE" in
		receiver) TFILT="igmp[0] == 0x22 or igmp[0] == 0x16" ;; # v3 report / v2 report
		source-pe) TFILT="pim and ip[9] == 103 and ip[20] & 0x0f == 3" ;; # PIM Join/Prune
		esac
		FIFO="$STATE_DIR/.events"
		rm -f "$FIFO"; mkfifo "$FIFO" || { log "mkfifo failed; polling only"; FIFO=""; }
		if [ -n "$FIFO" ]; then
			( while :; do
				tcpdump -l -n -p -i "$TRIGGER_IFACE" "$TFILT" 2>/dev/null
				sleep 2
			  done >"$FIFO" ) &
			TCPDUMP_LOOP=$!
			trap 'pkill -P $TCPDUMP_LOOP 2>/dev/null; kill $TCPDUMP_LOOP 2>/dev/null; rm -f "$FIFO"' EXIT INT TERM
			exec 3<>"$FIFO"   # <> so open never blocks and EOF never surfaces
			# `read -t` probe: EOF on /dev/null exits 1 with the option
			# accepted; an unsupported option (dash) exits 2.
			(read -r -t 0 _ </dev/null) 2>/dev/null
			case $? in 0 | 1) READ_T=1 ;; *) READ_T=0 ;; esac
			EVENTS=1
			log "trigger armed on $TRIGGER_IFACE (filter: $TFILT; read -t: $READ_T)"
		fi
	else
		log "tcpdump not found; --trigger-iface ignored (polling only)"
	fi
fi

LAST_TRIG=0
WIN_START=0
WIN_COUNT=0
STORM=0

wait_next() {
	if [ "$EVENTS" = 0 ]; then
		sleep "$INTERVAL"
		return 1  # timeout -> periodic pass
	fi
	if [ "$READ_T" = 1 ]; then
		read -r -t "$INTERVAL" _ <&3 && return 0 || return 1
	fi
	# dash fallback: 1s sub-polls of the pipe via non-blocking dd
	i=0
	while [ "$i" -lt "$INTERVAL" ]; do
		sleep 1
		if dd bs=512 count=1 iflag=nonblock <&3 2>/dev/null | grep -q .; then
			return 0
		fi
		i=$((i + 1))
	done
	return 1
}

do_pass() {
	case "$MODE" in
	receiver) receiver_pass ;;
	source-pe) source_pe_pass ;;
	esac
	LAST_PASS=$(now)
}

do_pass
[ "$ONCE" = 1 ] && exit 0

while :; do
	if wait_next; then
		nowts=$(now)
		# GC starvation guard: a continuous event stream must not defer
		# the periodic pass indefinitely.
		if [ $((nowts - LAST_PASS)) -ge "$INTERVAL" ]; then
			do_pass
			continue
		fi
		# rolling 10s burst window
		if [ $((nowts - WIN_START)) -ge 10 ]; then
			WIN_START=$nowts; WIN_COUNT=0
			[ "$STORM" = 1 ] && { STORM=0; log "trigger storm cleared"; }
		fi
		WIN_COUNT=$((WIN_COUNT + 1))
		if [ "$STORM" = 1 ] || [ "$WIN_COUNT" -gt 10 ]; then
			[ "$STORM" = 0 ] && log "trigger storm (>10 events/10s); rate-limiting to interval polling"
			STORM=1
			continue
		fi
		[ "$nowts" -le "$LAST_TRIG" ] && continue  # min-gap 1s
		LAST_TRIG=$nowts
	fi
	do_pass
done
