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
# Usage:
#   dimt-reconcile.sh --self 100.64.0.40 [--peers-file /etc/dimt/peers]
#                     [--peers 100.64.0.47,...] [--mtu 1252] [--port 6636]
#                     [--no-frr] [--dry-run] [--watch SECONDS]

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

log() { echo "dimt-reconcile: $*" >&2; }

run() {
	if [ "$DRY" = 1 ]; then
		log "DRY: $*"
	else
		"$@"
	fi
}

usage() {
	sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
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
	--watch) WATCH="$2"; shift 2 ;;
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
		[ -f "$PEERS_FILE" ] && sed 's/#.*//' "$PEERS_FILE"
	} | tr -d ' \t' | grep . | sort -u
}

ensure_fou() {
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
	command -v vtysh >/dev/null 2>&1 || return 0
	if [ "$2" = add ]; then
		run vtysh -c 'configure terminal' -c "interface $1" \
			-c 'ip pim' -c 'ip pim light' >/dev/null
	else
		run vtysh -c 'configure terminal' -c "no interface $1" \
			>/dev/null 2>&1 || true
	fi
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
			encap fou encap-sport auto encap-dport "$FOU_PORT" || return 1
		log "created $dev ($SELF -> $peer)"
	fi

	run ip link set "$dev" mtu "$MTU" multicast on up

	if ! ip -4 addr show dev "$dev" 2>/dev/null | grep -q "inet $self_in peer $peer_in/32"; then
		run ip addr flush dev "$dev" 2>/dev/null
		run ip addr add "$self_in" peer "$peer_in/32" dev "$dev"
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
	ensure_fou || rc=1
	want=""
	for peer in $(peers); do
		[ "$peer" = "$SELF" ] && continue
		if ensure_peer "$peer"; then
			want="$want $(dev_of "$peer")"
		else
			log "failed to ensure peer $peer"
			rc=1
		fi
	done
	gc_stale "$want"
	return $rc
}

if [ "$WATCH" -gt 0 ] 2>/dev/null; then
	while :; do
		reconcile
		sleep "$WATCH"
	done
else
	reconcile
fi
