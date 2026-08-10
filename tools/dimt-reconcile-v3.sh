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
#     Watches IGMPv3 AND MLDv2 (S,G) memberships on downstream
#     interfaces.  For a source S with no usable PIM upstream: resolve
#     the source-side peer (static map override, else the BGP UMH
#     extended community, O2), ensure the tunnel (delegated to v2 via a
#     dynamic peers overlay), and install the RPF override that lets
#     pim-light send the join:
#
#         ip mroute <S>/32 <inner4(peer)>          (v4)
#         ipv6 route <S>/128 <inner6(peer)>        (v6; FRR has no
#             `ipv6 mroute` -- pim6d RPF-resolves via the unicast RIB,
#             so a distance-1 static /128 via the tunnel inner IS the
#             override.  It also steers v6 unicast for S through the
#             tunnel while a receiver exists: harmless for ULA source
#             labels, revisit if a source is ever a global address.)
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
#         interface <seg>; ip igmp join <G> <S>       (v4)
#         interface <seg>; ipv6 mld join <G6> <S6>    (v6)
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
#       [--ssm6-prefix ff3]
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
# --source-map lines: "<source-ip> <peer-overlay-ipv4>"  ('#' comments;
#   the source may be v4 or v6, the peer is always the v4 overlay --
#   tunnels are shared dual-stack inner).  "default <peer>" catches
#   unmatched v4 SSM sources, "default6 <peer>" the v6 ones.  A map
#   entry overrides BGP UMH discovery (O2).
#
# Managed-underlay cutover is deliberately a v2 transport concern.  Set
# DIMT_ENDPOINTS_FILE (or wrap v2 with --endpoints-file) to map overlay
# identities onto tunnelsync-managed GRE endpoints.  This daemon continues
# to record and delegate overlay identities, preserving inner addresses and
# BGP UMH resolution while v2 changes only the GRE local/remote endpoints.

set -u

MODE=""
SELF="${DIMT_SELF:-}"
SOURCE_MAP="${DIMT_SOURCE_MAP:-/etc/dimt/source-peers}"
SSM_PREFIX="${DIMT_SSM_PREFIX:-232.}"
SSM6_PREFIX="${DIMT_SSM6_PREFIX:-ff3}"
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
	--ssm6-prefix) SSM6_PREFIX="$2"; shift 2 ;;
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

# Must match dimt-reconcile.sh inner6(): fd99::<o3>:<o4>, the decimal
# octets written as literal groups, zero o3 collapsing (fd99::47).
inner6_of() {
	echo "$1" | awk -F. '{
		if ($3 == 0) printf "fd99::%s", $4
		else         printf "fd99::%s:%s", $3, $4
	}'
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
#   vtysh$ show ip pim upstream-rpf
#   Source        Group      RpfIface   RibNextHop    RpfAddress
#   69.25.95.102  232.0.0.1  dimt-0-47  10.99.0.47   10.99.0.47
# Presence alone is NOT usable: the BGP UMH route gives every
# advertised source an RPF interface, and when the BGP session rides a
# pim-passive overlay (tailscale0) pimd holds a J upstream whose joins
# are never sent -- a structural black hole that must not suppress the
# tunnel build.  Usable means the Iif is a dimt-* tunnel (pim-light,
# hello-less, so neighbor count is always 0 there) or the selected RPF
# neighbor for S is present on the selected interface.
pim_upstream_rpf() { # <show upstream-rpf command> <S> <G> -> "Iif RPF-Nbr"
	rpf=$(vtysh -c "$1 json" 2>/dev/null | tr '{},' '\n\n\n' | awk -v s="$2" -v g="$3" '
		function val(line) {
			sub(/^[ \t]*"[^"]+"[ \t]*:[ \t]*"/, "", line)
			sub(/"[ \t]*$/, "", line)
			return line
		}
		/^[ \t]*"source"[ \t]*:/       { src = val($0); next }
		/^[ \t]*"group"[ \t]*:/        { grp = val($0); next }
		/^[ \t]*"rpfInterface"[ \t]*:/ { iif = val($0); next }
		/^[ \t]*"rpfAddress"[ \t]*:/ {
			nbr = val($0)
			if (src == s && grp == g && iif != "" && iif != "Unknown" && iif != "<ifname?>" &&
			    nbr != "" && nbr != "0.0.0.0" && nbr != "::") {
				print iif, nbr
				exit
			}
		}
	')
	[ -n "$rpf" ] && { echo "$rpf"; return 0; }

	vtysh -c "$1" 2>/dev/null | awk -v s="$2" -v g="$3" '
		$1 == s && $2 == g && $3 != "Unknown" && $3 != "<ifname?>" &&
		$5 != "" && $5 != "0.0.0.0" && $5 != "::" { print $3, $5; exit }
	'
}

pim_neighbor_exact() { # <show neighbor command> <Iif> <RPF-Nbr>
	vtysh -c "$1" 2>/dev/null | awk -v i="$2" -v n="$3" '
		$1 == i && $2 == n { found = 1 }
		END { exit found ? 0 : 1 }
	'
}

upstream_usable() { # <S> <G>
	src="$1"
	grp="$2"
	rpf=$(pim_upstream_rpf 'show ip pim upstream-rpf' "$src" "$grp")
	set -- $rpf
	iif="${1:-}"
	rpf_nbr="${2:-}"
	[ -n "$iif" ] || return 1
	case "$iif" in dimt-*) return 0 ;; esac
	[ -n "$rpf_nbr" ] || return 1
	[ "$rpf_nbr" = "$src" ] && return 0
	pim_neighbor_exact 'show ip pim neighbor' "$iif" "$rpf_nbr"
}

# Resolve the source-side DIMT peer for source S.
# 1. static map (--source-map): "S peer" / "default peer" lines.  Local
#    provisioning is the draft's baseline mechanism and doubles as the
#    operator override, so an entry here always wins.
# 2. BGP UMH extended community (O2, the draft's endorsed discovery,
#    draft-zzhang-mboned-dynamic-internet-mcast-tunnel section 3):
#    the source-side PE originates S/32 with
#      set extcommunity umh <inner-addr> pim preference <p>
#    which FRR renders as "UMH:<addr>:pim:<pref>".  Only type "pim"
#    records apply here (RFC 9739 PIM-Light tunnel); "amt" records are
#    for AMT gateways.  Highest preference wins (draft section 3.2; the
#    AS_PATH-length tiebreak is irrelevant on our single-path session).
#    The UMH names the peer's INNER (data-plane) address; the tunnel
#    outer endpoint is recovered via the inverse of inner_of().
#    NOT DNS: TYPE260/DRIAD is host-oriented last-mile discovery and is
#    explicitly not the draft's router-to-router mechanism.
# stdin: `show bgp ...` output -> best pim-type UMH address on stdout.
# ECs are whitespace-delimited tokens "UMH:<addr>:pim:<pref>" (v4 or v6
# address; v6 contains colons, so anchor on the ":pim:<n>" tail rather
# than splitting).  amt-type records never match (AMT-gateway tier).
# Highest preference wins (draft section 3.2; the AS_PATH-length
# tiebreak is irrelevant on our single-path session).
umh_best() {
	awk '
		{
			for (i = 1; i <= NF; i++) {
				if ($i !~ /^UMH:/) continue
				s = substr($i, 5)
				if (s !~ /:pim:[0-9]+$/) continue
				p = s; sub(/.*:pim:/, "", p)
				a = s; sub(/:pim:[0-9]+$/, "", a)
				if (p + 0 >= best) { best = p + 0; addr = a }
			}
		}
		END { if (addr) print addr; else exit 1 }
	'
}

resolve_peer_bgp() { # <S> -> peer outer address
	umh=$(vtysh -c "show bgp ipv4 unicast $1/32" 2>/dev/null | umh_best) ||
		return 1
	outer_of "$umh"
}

resolve_peer_bgp6() { # <S6> -> peer outer address
	umh=$(vtysh -c "show bgp ipv6 unicast $1/128" 2>/dev/null | umh_best) ||
		return 1
	outer_of "$umh"
}

# Inverse of inner_of()/inner6_of(): overlay-inner -> outer 100.64.X.Y.
# A UMH outside the inner ranges is already an outer/routable endpoint
# (the non-overlay deployment shape) and passes through unchanged.
outer_of() { # <addr>
	case "$1" in
	10.99.*) echo "$1" | awk -F. '{ printf "100.64.%s.%s\n", $3, $4 }' ;;
	fd99::*:*) echo "${1#fd99::}" | awk -F: '{ printf "100.64.%s.%s\n", $1, $2 }' ;;
	fd99::*) echo "100.64.0.${1#fd99::}" ;;
	*) echo "$1" ;;
	esac
}

resolve_peer() { # <S>
	if [ -r "$SOURCE_MAP" ]; then
		awk -v s="$1" '
			/^[ \t]*#/ || NF < 2 { next }
			$1 == s        { print $2; found = 1; exit }
			$1 == "default" { dflt = $2 }
			END { if (!found && dflt) print dflt; exit (found || dflt) ? 0 : 1 }
		' "$SOURCE_MAP" && return 0
	fi
	resolve_peer_bgp "$1"
}

# v6 twin ("default6 <peer>" catches unmatched v6 sources; a v6 source
# row is just "<v6-source> <peer-overlay-v4>" -- the tunnel outer is
# always the v4 overlay address, tunnels are shared dual-stack inner).
resolve_peer6() { # <S6>
	if [ -r "$SOURCE_MAP" ]; then
		awk -v s="$1" '
			/^[ \t]*#/ || NF < 2 { next }
			$1 == s         { print $2; found = 1; exit }
			$1 == "default6" { dflt = $2 }
			END { if (!found && dflt) print dflt; exit (found || dflt) ? 0 : 1 }
		' "$SOURCE_MAP" && return 0
	fi
	resolve_peer_bgp6 "$1"
}

# Emit "S G" per active downstream MLDv2 (S,G) membership.  pim6d
# groups rows under "On interface <ifc>:" headers:
#   vtysh$ show ipv6 mld joins
#   Group      Source     State  LastSeen  NonTrkSeen  Created
#   On interface br-lan:
#   ff3e::1:1  fd69::193  JOIN   00:00:02  -           00:01:12
receiver_wants6() {
	vtysh -c 'show ipv6 mld joins' 2>/dev/null | awk -v ssm="$SSM6_PREFIX" '
		/^On interface / { ifc = $3; sub(/:$/, "", ifc); next }
		ifc ~ /^dimt-/ || ifc == "" { next }
		NF < 3 || $1 == "Group"     { next }
		$2 == "*"                   { next }
		index($1, ssm) != 1         { next }
		$3 == "JOIN" { print $2, $1 }
	' | sort -u
}

upstream_usable6() { # <S6> <G6>
	src="$1"
	grp="$2"
	rpf=$(pim_upstream_rpf 'show ipv6 pim upstream-rpf' "$src" "$grp")
	set -- $rpf
	iif="${1:-}"
	rpf_nbr="${2:-}"
	[ -n "$iif" ] || return 1
	case "$iif" in dimt-*) return 0 ;; esac
	[ -n "$rpf_nbr" ] || return 1
	[ "$rpf_nbr" = "$src" ] && return 0
	pim_neighbor_exact 'show ipv6 pim neighbor' "$iif" "$rpf_nbr"
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

# v6 RPF override.  FRR has no `ipv6 mroute`; pim6d RPF-resolves via
# the unicast RIB, so a distance-1 static /128 via the peer's inner6
# is the override -- it beats the BGP UMH route (distance 20, which
# recurses to tailscale0, NOT the tunnel).  Caveat: unlike `ip mroute`
# this also steers v6 UNICAST for S through the tunnel while a
# receiver exists; harmless for ULA source labels (fd69::/16), worth
# revisiting if a source is ever a global address something talks to.
mroute6_state() { echo "$STATE_DIR/mroute6-$1"; }

install_mroute6() { # <S6> <peer-overlay-v4>
	nh=$(inner6_of "$2")
	[ "$DRY" = 1 ] || {
		echo "peer=$2"
		echo "nexthop=$nh"
		echo "since=$(now)"
	} >"$(mroute6_state "$1")"
	sync_tunnels
	if ! vty_conf -c "ipv6 route $1/128 $nh"; then
		run rm -f "$(mroute6_state "$1")"
		sync_tunnels
		return 1
	fi
	log "installed v6 RPF override $1/128 -> $nh (peer $2)"
}

remove_mroute6() { # <S6>
	st=$(mroute6_state "$1")
	[ -f "$st" ] || return 0
	nh=$(sed -n 's/^nexthop=//p' "$st")
	vty_conf -c "no ipv6 route $1/128 $nh" || return 1
	run rm -f "$st"
	log "withdrew v6 RPF override $1/128 -> $nh"
}

# Rebuild the dynamic peers overlay and hand the union (registry file
# untouched, it stays v2's input) to v2 so tunnel ensure/GC has ONE
# owner.  With --no-v2 (dogfood over a pre-existing static tunnel) this
# is skipped and only the mroute layer is managed.
sync_tunnels() {
	[ "$DO_V2" = 1 ] || return 0
	[ -x "$V2" ] || { log "v2 reconciler $V2 not executable; --no-v2 to silence"; return 0; }
	overlay="$STATE_DIR/peers.dynamic"
	sed -n 's/^peer=//p' "$STATE_DIR"/mroute-* "$STATE_DIR"/mroute6-* 2>/dev/null | sort -u >"$overlay.tmp"
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
			log "no peer for source $s (no map entry, no BGP UMH route)"
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

	# 3/4. the v6 family, same shape (MLDv2 wants; static-/128 override)
	wants6=$(receiver_wants6)
	echo "$wants6" | while read -r s g; do
		[ -n "$s" ] || continue
		mark_seen "$STATE_DIR/seen6-$s"
		[ -f "$(mroute6_state "$s")" ] && continue
		upstream_usable6 "$s" "$g" && continue
		peer=$(resolve_peer6 "$s") || {
			log "no peer for v6 source $s (no map entry, no BGP UMH6 route)"
			continue
		}
		install_mroute6 "$s" "$peer"
	done

	for st in "$STATE_DIR"/mroute6-*; do
		[ -f "$st" ] || continue
		s=${st##*/mroute6-}
		if echo "$wants6" | grep -q "^$s "; then
			mark_seen "$STATE_DIR/seen6-$s"
			continue
		fi
		last=$(seen_at "$STATE_DIR/seen6-$s")
		if [ $((nowts - last)) -ge "$HOLDDOWN" ]; then
			remove_mroute6 "$s" && run rm -f "$STATE_DIR/seen6-$s" && sync_tunnels
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

# v6 twins: (S,G) mroutes with the segment IIF answered by an MLDv2
# membership on the segment (`ipv6 mld join`), so MLD-snooping fabrics
# deliver the v6 stream -- O1 finding 2, same physics as IGMP.
segment_pulls6() {
	vtysh -c 'show ipv6 mroute' 2>/dev/null | awk -v seg="$SEG_IFACE" '
		NF < 6 || $1 == "Source" { next }
		$5 == seg && $4 == "PIM" { print $1, $2 }
	' | sort -u
}

join6_state() { echo "$STATE_DIR/join6-$1-$2"; }

ensure_seg_join6() { # <S6> <G6>
	[ -f "$(join6_state "$1" "$2")" ] && return 0
	vty_conf -c "interface $SEG_IFACE" -c "ipv6 mld join $2 $1" || return 1
	[ "$DRY" = 1 ] || echo "since=$(now)" >"$(join6_state "$1" "$2")"
	log "joined v6 ($1, $2) on $SEG_IFACE (segment pull)"
}

remove_seg_join6() { # <S6> <G6>
	vty_conf -c "interface $SEG_IFACE" -c "no ipv6 mld join $2 $1" || return 1
	run rm -f "$(join6_state "$1" "$2")"
	log "left v6 ($1, $2) on $SEG_IFACE"
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

	# v6 family, same shape
	pulls6=$(segment_pulls6)
	echo "$pulls6" | while read -r s g; do
		[ -n "$s" ] || continue
		mark_seen "$STATE_DIR/pseen6-$s-$g"
		ensure_seg_join6 "$s" "$g"
	done

	for st in "$STATE_DIR"/join6-*; do
		[ -f "$st" ] || continue
		sg=${st##*/join6-}
		s=${sg%-*}; g=${sg##*-}
		if echo "$pulls6" | grep -q "^$s $g\$"; then
			continue
		fi
		last=$(seen_at "$STATE_DIR/pseen6-$s-$g")
		if [ $((nowts - last)) -ge "$HOLDDOWN" ]; then
			remove_seg_join6 "$s" "$g" && run rm -f "$STATE_DIR/pseen6-$s-$g"
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
		# v4: IGMPv3/v2 membership reports.  v6: MLDv2 reports are
		# ICMPv6 type 143 to ff02::16, normally behind a hop-by-hop
		# options header (router alert), so match both the HBH-shifted
		# (ip6 proto 0, ICMPv6 at offset 48) and direct (proto 58,
		# offset 40) encodings -- ip6[] cannot skip extension headers.
		receiver) TFILT="igmp[0] == 0x22 or igmp[0] == 0x16 or (ip6 proto 0 and ip6[48] == 143) or (ip6 proto 58 and ip6[40] == 143)" ;;
		# PIM Join/Prune, both families (PIMv6 is proto 103 directly
		# after the v6 header; type in the low nibble of the first byte).
		source-pe) TFILT="(pim and ip[9] == 103 and ip[20] & 0x0f == 3) or (ip6 proto 103 and ip6[40] & 0x0f == 3)" ;;
		esac
		FIFO="$STATE_DIR/.events"
		rm -f "$FIFO"; mkfifo "$FIFO" || { log "mkfifo failed; polling only"; FIFO=""; }
		if [ -n "$FIFO" ]; then
			( while :; do
				tcpdump -l -n -p -i "$TRIGGER_IFACE" "$TFILT" 2>/dev/null
				sleep 2
			  done >"$FIFO" ) &
			TCPDUMP_LOOP=$!
			trap 'pkill -P $TCPDUMP_LOOP 2>/dev/null; kill $TCPDUMP_LOOP 2>/dev/null; rm -f "$FIFO"' EXIT
			# A TERM/INT trap REPLACES default termination: without an
			# explicit exit the shell resumes the main loop after the
			# handler and the daemon becomes unkillable by SIGTERM
			# (survives procd/systemd stop; observed 2026-07-13, only
			# SIGKILL worked).  exit here fires the EXIT trap above.
			trap 'exit 143' TERM
			trap 'exit 130' INT
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
