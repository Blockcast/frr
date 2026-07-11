#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# DIMT tunnel reconciler (draft-zzhang-mboned-dynamic-internet-mcast-tunnel,
# Phase C of the PIM Light / UMH deployment).
#
# Ensures one IPIP-in-FOU tunnel netdev per peer and enrolls it with pimd
# (`ip pim` + `ip pim light`), so that adding a PE<->PoP pair needs nothing
# beyond listing the peer's overlay address.  Pure control plane: packets
# never touch this script.
#
# Peer list is REGISTRY-DRIVEN (a flat file rendered by site tooling /
# mconfig), not derived from FRR state: the UMH mapping arrives over BGP,
# and BGP must never depend on a tunnel this script creates (circular),
# so tunnels exist first and FRR state only selects among them.
#
# Addressing contract (no per-pair coordination):
#   inner(X) = 10.99.<oct3>.<oct4> of X's overlay IPv4
# Both ends derive both inner addresses from the overlay pair alone.  The
# PE's UMH extended community must advertise inner(PE).  The tunnel is
# addressed `inner(self) peer inner(peer)/32`, which is exactly what
# pimd's pim_dimt_light_iface() resolves the UMH against.
#
# Runs identically on the PE (Alpine container; `ip fou add` may be
# EPERM inside an unprivileged container -- pre-add it from the host, we
# tolerate the port already existing) and the PoP (OpenWrt ash).
#
# Safety: a missing/unreadable peers file (with no --peers inline list)
# refuses to reconcile, and an empty desired peer set skips stale-tunnel
# GC unless --allow-empty is given -- either case would otherwise be
# indistinguishable from "delete every dimt-* tunnel on the fleet".
#
# Usage:
#   dimt-reconcile.sh --self 100.64.0.40 [--peers-file /etc/dimt/peers]
#                     [--peers 100.64.0.47,...] [--mtu 1252] [--port 6636]
#                     [--no-frr] [--dry-run] [--watch SECONDS]
#                     [--allow-empty]

set -u

SELF="${DIMT_SELF:-}"
PEERS_FILE="${DIMT_PEERS_FILE:-/etc/dimt/peers}"
PEERS_INLINE=""
FOU_PORT="${DIMT_FOU_PORT:-6636}"
MTU="${DIMT_MTU:-1252}"
PREFIX="dimt-"
DO_FRR=1
DRY=0
WATCH=0
ALLOW_EMPTY="${DIMT_ALLOW_EMPTY:-0}"
VTYSH_WARNED=0

log() { echo "dimt-reconcile: $*" >&2; }

run() {
	if [ "$DRY" = 1 ]; then
		log "DRY: $*"
	else
		"$@"
	fi
}

# Print the header comment block (line 2 up to the first non-comment
# line), so the usage text tracks header edits without a fixed range.
usage() {
	awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--self) SELF="$2"; shift 2 ;;
	--peers-file) PEERS_FILE="$2"; shift 2 ;;
	--peers) PEERS_INLINE="$2"; shift 2 ;;
	--mtu) MTU="$2"; shift 2 ;;
	--port) FOU_PORT="$2"; shift 2 ;;
	--no-frr) DO_FRR=0; shift ;;
	--dry-run) DRY=1; shift ;;
	--allow-empty) ALLOW_EMPTY=1; shift ;;
	--watch)
		case "${2:-}" in
		'' | *[!0-9]*) log "--watch requires a number of seconds"; exit 1 ;;
		esac
		WATCH="$2"; shift 2 ;;
	*) usage ;;
	esac
done

[ -n "$SELF" ] || { log "--self <overlay-ipv4> is required"; exit 1; }

# 10.99.<oct3>.<oct4> of an overlay IPv4 (unique while the fleet lives in
# one overlay /16; revisit before that stops being true).
inner_of() {
	echo "$1" | awk -F. '{ printf "10.99.%s.%s", $3, $4 }'
}

# Interface name from the overlay address: dimt-<oct3>-<oct4> (fits
# IFNAMSIZ for any dotted quad).
dev_of() {
	echo "$1" | awk -F. '{ printf "dimt-%s-%s", $3, $4 }'
}

peers() {
	{
		[ -n "$PEERS_INLINE" ] && echo "$PEERS_INLINE" | tr ',' '\n'
		[ -r "$PEERS_FILE" ] && sed 's/#.*//' "$PEERS_FILE"
	} | tr -d ' \t' | grep . | sort -u
}

ensure_fou() {
	# fou/ipip may not be loaded at boot (nothing else pulls them in;
	# the legacy decap script used to).  Best-effort: inside an
	# unprivileged container this fails and the pre-added host state
	# carries us, same as the EPERM path below.
	if command -v modprobe >/dev/null 2>&1; then
		modprobe fou 2>/dev/null || true
		modprobe ipip 2>/dev/null || true
	fi
	if ip fou show 2>/dev/null | grep -q "port $FOU_PORT "; then
		return 0
	fi
	if ! run ip fou add port "$FOU_PORT" ipproto 4; then
		log "cannot add FOU port $FOU_PORT (unprivileged container?);"
		log "pre-add it from the host: ip fou add port $FOU_PORT ipproto 4"
		return 1
	fi
}

frr_iface() { # <dev> <add|del>
	[ "$DO_FRR" = 1 ] || return 0
	if ! command -v vtysh >/dev/null 2>&1; then
		if [ "$VTYSH_WARNED" = 0 ]; then
			log "vtysh not found; skipping FRR enrollment for all peers"
			VTYSH_WARNED=1
		fi
		return 0
	fi
	if [ "$2" = add ]; then
		if [ "$DRY" = 1 ]; then
			log "DRY: vtysh -c 'configure terminal' -c 'interface $1' -c 'ip pim' -c 'ip pim light'"
			return 0
		fi
		# vtysh reports some errors on stdout with exit status 0,
		# as lines prefixed '%' -- check both.
		out=$(vtysh -c 'configure terminal' -c "interface $1" \
			-c 'ip pim' -c 'ip pim light' 2>&1)
		rc=$?
		# vtysh reports errors on stdout with exit 0; match real
		# error shapes only -- mgmtd's benign "% Configuration
		# applied with notes: No changes found to be committed!"
		# (config already present, the write-saved steady state)
		# must NOT count as failure.
		if [ "$rc" -ne 0 ] ||
			printf '%s\n' "$out" |
			grep -Eq '^% (Unknown command|Command incomplete|Ambiguous|.*[Ff]ailed|ERROR)'; then
			log "vtysh failed for $1: $out"
			return 1
		fi
	else
		if [ "$DRY" = 1 ]; then
			log "DRY: vtysh -c 'configure terminal' -c 'no interface $1'"
			return 0
		fi
		# Best effort: the interface stanza may already be gone.
		vtysh -c 'configure terminal' -c "no interface $1" \
			>/dev/null 2>&1 || true
	fi
	return 0
}

ensure_peer() { # <peer-overlay>
	peer="$1"
	dev=$(dev_of "$peer")
	self_in=$(inner_of "$SELF")
	peer_in=$(inner_of "$peer")

	# Recreate on endpoint drift; `ip link change` cannot retarget
	# an ipip tunnel's local/remote reliably across kernels.
	if ip link show "$dev" >/dev/null 2>&1; then
		cur=$(ip -d link show "$dev" 2>/dev/null)
		case "$cur" in
		*"local $SELF "*"remote $peer"* | *"remote $peer "*"local $SELF"*) : ;;
		*)
			log "$dev endpoints drifted; recreating"
			frr_iface "$dev" del
			run ip link del "$dev"
			;;
		esac
	fi

	if ! ip link show "$dev" >/dev/null 2>&1; then
		run ip link add "$dev" type ipip local "$SELF" remote "$peer" \
			ttl 64 encap fou encap-sport auto encap-dport "$FOU_PORT" || return 1
		log "created $dev ($SELF -> $peer)"
	fi

	run ip link set "$dev" mtu "$MTU" multicast on up || return 1

	# An already-correct address passes the grep and is left alone;
	# only a real flush-then-add failure fails the peer.
	if ! ip -4 addr show dev "$dev" 2>/dev/null | grep -q "inet $self_in peer $peer_in/32"; then
		run ip addr flush dev "$dev" 2>/dev/null
		run ip addr add "$self_in" peer "$peer_in/32" dev "$dev" || return 1
	fi

	frr_iface "$dev" add
}

gc_stale() {
	want="$1"
	ip -o link show 2>/dev/null | awk -F': ' '{ print $2 }' |
		sed 's/@.*//' | grep "^$PREFIX" | while read -r dev; do
		case " $want " in
		*" $dev "*) : ;;
		*)
			log "removing stale $dev"
			frr_iface "$dev" del
			run ip link del "$dev"
			;;
		esac
	done
}

reconcile() {
	rc=0

	# A vanished registry must never read as "no peers desired": that
	# would GC every tunnel on the box.  Refuse instead (in --watch
	# mode the caller keeps looping and retries next cycle).
	if [ -z "$PEERS_INLINE" ] && [ -n "$PEERS_FILE" ] && [ ! -r "$PEERS_FILE" ]; then
		log "ERROR: peers file $PEERS_FILE missing/unreadable;" \
			"refusing to reconcile (would remove every tunnel)"
		return 1
	fi

	ensure_fou || rc=1

	want=""
	seen=""
	npeers=0
	for peer in $(peers); do
		[ "$peer" = "$SELF" ] && continue
		if ! echo "$peer" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
			log "ignoring invalid peer entry '$peer'"
			continue
		fi
		dev=$(dev_of "$peer")
		# Two peers in different /16s can collide on dimt-<o3>-<o4>;
		# without this check the pair fights over one netdev as an
		# endpoints-drifted recreate flip-flop every cycle.
		prev=""
		for pair in $seen; do
			case "$pair" in
			"$dev="*) prev="${pair#*=}" ;;
			esac
		done
		if [ -n "$prev" ]; then
			log "ERROR: peers $prev and $peer both derive device $dev;" \
				"skipping $peer (addressing contract needs one overlay /16)"
			rc=1
			continue
		fi
		seen="$seen $dev=$peer"
		npeers=$((npeers + 1))
		# Keep desired peers out of GC's reach even when ensure_peer
		# fails, so a transient failure cannot delete the tunnel.
		want="$want $dev"
		if ! ensure_peer "$peer"; then
			log "failed to ensure peer $peer"
			rc=1
		fi
	done

	if [ "$npeers" -eq 0 ] && [ "$ALLOW_EMPTY" != 1 ]; then
		log "WARNING: desired peer set is empty; skipping stale-tunnel GC" \
			"(pass --allow-empty to force removal of every ${PREFIX}* tunnel)"
	else
		gc_stale "$want"
	fi
	return $rc
}

if [ "$WATCH" -gt 0 ]; then
	while :; do
		reconcile
		sleep "$WATCH"
	done
else
	reconcile
fi
