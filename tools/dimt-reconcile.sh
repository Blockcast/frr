#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# DIMT tunnel reconciler (draft-zzhang-mboned-dynamic-internet-mcast-tunnel,
# Phase C of the PIM Light / UMH deployment).
#
# Ensures one dual-stack GRE-in-FOU tunnel netdev per peer (GRE carries
# both IPv4 and IPv6 inner over the IPv4 overlay) and enrolls it with
# pimd and pim6d (`ip pim` + `ip pim light`, `ipv6 pim` + `ipv6 pim
# light`), so that adding a PE<->PoP pair needs nothing beyond listing
# the peer's overlay address.  Pure control plane: packets never touch
# this script.
#
# Peer list is REGISTRY-DRIVEN (a flat file rendered by site tooling /
# mconfig), not derived from FRR state: the UMH mapping arrives over BGP,
# and BGP must never depend on a tunnel this script creates (circular),
# so tunnels exist first and FRR state only selects among them.
#
# Addressing contract (no per-pair coordination):
#   inner4(X) = 10.99.<oct3>.<oct4> of X's overlay IPv4
#   inner6(X) = fd99::<oct3>:<oct4>  (decimal octets as literal groups,
#               RFC 5952 canonical so exists-checks match `ip` output)
# Both ends derive both inner addresses from the overlay pair alone.  The
# PE's UMH extended community must advertise inner4(PE) or inner6(PE).
# The tunnel is addressed `inner(self) peer inner(peer)/{32,128}`, which
# is exactly what pimd/pim6d's pim_dimt_light_iface() resolves the UMH
# against.  The auto link-local (fe80::) is never touched: pim6d sources
# Join/Prune from it.
#
# The FOU receive port is bound `ipproto 47` (GRE).  Pre-GRE deployments
# bound 6636 to ipproto 4 (ipip); the GRE port defaults to 6637 so both
# bindings coexist during migration -- GC the old one afterwards
# (`ip fou del port 6636`).  A dimt-* netdev of the old ipip type is
# treated as drift and recreated as GRE (brief forwarding gap; run both
# ends of a pair in the same window -- a freshly created tunnel gets a
# best-effort inner ping so a one-sided migration is loud, not a silent
# blackhole).
#
# Runs identically on the PE (Alpine container; `ip fou add` may be
# EPERM inside an unprivileged container -- pre-add it from the host, we
# tolerate the port already existing) and the PoP (OpenWrt ash).
#
# Safety: reconciliation is REFUSED outright -- before anything is
# deleted -- when (a) the peers file is missing/unreadable with no
# --peers inline list, (b) the FOU receive binding cannot be ensured (a
# GRE tunnel without FOU RX blackholes all inbound traffic), or (c) the
# kernel cannot create a GRE-in-FOU netdev at all (kmod-gre/ip_gre
# missing -- probed with a throwaway device, since the ipip->GRE
# migration deletes the working tunnel first).  An empty desired peer
# set, or a registry with malformed entries, skips stale-tunnel GC
# (--allow-empty overrides the empty case) -- each would otherwise be
# indistinguishable from "delete that tunnel on purpose".  An MTU below
# 1280 leaves the tunnels v4-only (the kernel disables IPv6 on such
# links) and is warned about loudly, as is an MTU that overflows the
# outer path to the peer.
#
# Usage:
#   dimt-reconcile.sh --self 100.64.0.40 [--peers-file /etc/dimt/peers]
#                     [--peers 100.64.0.47,...] [--mtu 1388] [--port 6637]
#                     [--no-frr] [--dry-run] [--watch SECONDS]
#                     [--allow-empty]

set -u

SELF="${DIMT_SELF:-}"
PEERS_FILE="${DIMT_PEERS_FILE:-/etc/dimt/peers}"
PEERS_INLINE=""
FOU_PORT="${DIMT_FOU_PORT:-6637}"
MTU="${DIMT_MTU:-1388}"
PREFIX="dimt-"
DO_FRR=1
DRY=0
WATCH=0
ALLOW_EMPTY="${DIMT_ALLOW_EMPTY:-0}"
VTYSH_WARNED=0
VTYSH6_WARNED=0

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

if [ "$MTU" -lt 1280 ]; then
	log "WARNING: MTU $MTU is below the IPv6 minimum of 1280;" \
		"the kernel disables IPv6 on the tunnels (v4-only)"
fi

# 10.99.<oct3>.<oct4> of an overlay IPv4 (unique while the fleet lives in
# one overlay /16; revisit before that stops being true).
inner_of() {
	echo "$1" | awk -F. '{ printf "10.99.%s.%s", $3, $4 }'
}

# fd99::<oct3>:<oct4>, the decimal octets written as literal groups
# (correlates with the device name and inner4).  Emitted in RFC 5952
# canonical form -- what `ip -6 addr show` prints back -- or the
# exists-check below would never match and every cycle would churn:
# a zero oct3 collapses (fd99::0:47 is shown as fd99::47).
inner6_of() {
	echo "$1" | awk -F. '{
		if ($3 == 0 && $4 == 0) printf "fd99::"
		else if ($3 == 0)       printf "fd99::%s", $4
		else                    printf "fd99::%s:%s", $3, $4
	}'
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
	} | tr -d ' \t\r' | grep . | sort -u
}

ensure_fou() {
	# fou/gre may not be loaded at boot (nothing else pulls them in).
	# Best-effort: inside an unprivileged container this fails and the
	# pre-added host state carries us, same as the EPERM path below.
	if command -v modprobe >/dev/null 2>&1; then
		modprobe fou 2>/dev/null || true
		modprobe gre 2>/dev/null || true
		modprobe ip_gre 2>/dev/null || true
	fi
	case "$(ip fou show 2>/dev/null)" in
	*"port $FOU_PORT ipproto 47"*) return 0 ;;
	*"port $FOU_PORT "*)
		# Rebinding would mean deleting a port something else may
		# own; a human has to resolve the collision.
		log "ERROR: FOU port $FOU_PORT exists bound to a non-GRE" \
			"ipproto; refusing (fix or pick another --port)"
		return 1 ;;
	esac
	if ! run ip fou add port "$FOU_PORT" ipproto 47; then
		log "cannot add FOU port $FOU_PORT (unprivileged container?);"
		log "pre-add it from the host: ip fou add port $FOU_PORT ipproto 47"
		return 1
	fi
}

# Prove the kernel can create a GRE-in-FOU netdev with a throwaway
# device BEFORE anything is deleted: the ipip->GRE migration removes
# the working production tunnel first, and modprobe failures above are
# deliberately suppressed -- without this probe a missing kmod-gre
# would strand the box with no tunnel at all.  (The probe device is
# dimt-prefixed, so a leaked one is swept up by the next GC.)
gre_probe() {
	probe="${PREFIX}probe0"
	ip link del "$probe" 2>/dev/null
	if ! ip link add "$probe" type gre local 127.0.0.1 remote 127.0.0.2 \
		ttl 64 encap fou encap-sport auto encap-dport "$FOU_PORT" 2>/dev/null; then
		return 1
	fi
	ip link del "$probe" 2>/dev/null
	return 0
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
			log "DRY: vtysh -c 'configure terminal' -c 'interface $1' -c 'ipv6 pim' -c 'ipv6 pim light'"
			return 0
		fi
		# vtysh reports some errors on stdout with exit status 0,
		# as lines prefixed '%' -- check both.  (frc, not rc: this
		# runs inside reconcile(), whose rc would be clobbered --
		# POSIX sh has no locals.)
		out=$(vtysh -c 'configure terminal' -c "interface $1" \
			-c 'ip pim' -c 'ip pim light' 2>&1)
		frc=$?
		# FRR not (yet) running is NOT a peer failure: at boot the
		# reconciler (S81) runs before frr (S95), and the interface
		# stanza is write-saved so the daemon picks it up on start.
		if [ "$frc" -ne 0 ] &&
			printf '%s\n' "$out" | grep -q "failed to connect"; then
			if [ "$VTYSH_WARNED" = 0 ]; then
				log "FRR not running; skipping enrollment (write-saved config covers existing peers)"
				VTYSH_WARNED=1
			fi
			return 0
		fi
		# vtysh reports errors on stdout with exit 0; match real
		# error shapes only -- mgmtd's benign "% Configuration
		# applied with notes: No changes found to be committed!"
		# (config already present, the write-saved steady state)
		# must NOT count as failure.
		if [ "$frc" -ne 0 ] ||
			printf '%s\n' "$out" |
			grep -Eq '^% (Unknown command|Command incomplete|Ambiguous|.*[Ff]ailed|ERROR)'; then
			log "vtysh failed for $1: $out"
			return 1
		fi
		# IPv6 enrollment goes in a separate call so its failure
		# cannot fail the production v4 side of the peer: with
		# pim6d not (yet) enabled, `ipv6 pim` is an unknown
		# command.  Degrade to v4-only, loudly.
		out=$(vtysh -c 'configure terminal' -c "interface $1" \
			-c 'ipv6 pim' -c 'ipv6 pim light' 2>&1)
		frc=$?
		if [ "$frc" -ne 0 ] ||
			printf '%s\n' "$out" |
			grep -Eq '^% (Unknown command|Command incomplete|Ambiguous|.*[Ff]ailed|ERROR)'; then
			if [ "$VTYSH6_WARNED" = 0 ]; then
				log "WARNING: IPv6 PIM enrollment failed (pim6d not enabled?); tunnels continue v4-only: $out"
				VTYSH6_WARNED=1
			fi
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
	self_in6=$(inner6_of "$SELF")
	peer_in6=$(inner6_of "$peer")

	# Inner MTU + outer IPv4(20) + UDP(8) + GRE(4) must fit the path
	# to the peer, or near-MTU multicast fragments/blackholes (the
	# DF-multicast trap).  Read-only, best-effort: unknown route or
	# unparsable output just skips the check.
	out_dev=$(ip route get "$peer" 2>/dev/null |
		sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1)
	if [ -n "$out_dev" ]; then
		out_mtu=$(ip link show "$out_dev" 2>/dev/null |
			sed -n 's/.* mtu \([0-9]*\).*/\1/p' | head -n 1)
		if [ -n "$out_mtu" ] && [ $((MTU + 32)) -gt "$out_mtu" ]; then
			log "WARNING: $dev: inner MTU $MTU + 32B GRE-in-FOU overhead" \
				"exceeds $out_dev MTU $out_mtu; lower --mtu to $((out_mtu - 32))"
		fi
	fi

	# Recreate on tunnel-type or endpoint drift; the kernel cannot
	# change a tunnel's type in place (ipip -> gre migration lands
	# here), and `ip link change` cannot retarget local/remote
	# reliably across kernels.  `gone` tracks a delete this run so
	# --dry-run previews the recreate coherently (the real netdev
	# still exists after a DRY delete).
	gone=0
	if ip link show "$dev" >/dev/null 2>&1; then
		cur=$(ip -d link show "$dev" 2>/dev/null)
		case "$cur" in
		*"link/gre "*) : ;;
		*)
			log "$dev is not a GRE tunnel (pre-GRE ipip?); recreating"
			frr_iface "$dev" del
			run ip link del "$dev"
			gone=1
			;;
		esac
	fi
	if [ "$gone" = 0 ] && ip link show "$dev" >/dev/null 2>&1; then
		cur=$(ip -d link show "$dev" 2>/dev/null)
		case "$cur" in
		*"local $SELF "*"remote $peer"* | *"remote $peer "*"local $SELF"*) : ;;
		*)
			log "$dev endpoints drifted; recreating"
			frr_iface "$dev" del
			run ip link del "$dev"
			gone=1
			;;
		esac
	fi

	created=0
	if [ "$gone" = 1 ] || ! ip link show "$dev" >/dev/null 2>&1; then
		run ip link add "$dev" type gre local "$SELF" remote "$peer" \
			ttl 64 encap fou encap-sport auto encap-dport "$FOU_PORT" || return 1
		log "created $dev ($SELF -> $peer)"
		created=1
	fi

	run ip link set "$dev" mtu "$MTU" multicast on up || return 1

	# An already-correct address passes the grep and is left alone;
	# only a real flush-then-add failure fails the peer.  The flush is
	# family-scoped: an unscoped flush would also remove the IPv6
	# link-local and inner.
	if [ "$created" = 1 ] ||
		! ip -4 addr show dev "$dev" 2>/dev/null | grep -q "inet $self_in peer $peer_in/32"; then
		run ip -4 addr flush dev "$dev" 2>/dev/null
		run ip addr add "$self_in" peer "$peer_in/32" dev "$dev" || return 1
	fi

	# IPv6 inner.  Never flush v6 wholesale (the fe80:: link-local
	# must survive); remove only stale fd99:: globals.  Failure here
	# degrades the peer to v4-only rather than failing it: the v4
	# plane is production and must not hinge on v6 bring-up.
	if [ "$created" = 1 ] ||
		! ip -6 addr show dev "$dev" 2>/dev/null | grep -q "inet6 $self_in6 peer $peer_in6/128"; then
		ip -6 addr show dev "$dev" scope global 2>/dev/null |
			awk '$1 == "inet6" && $2 ~ /^fd99::/ {
				if ($3 == "peer") print $2 " peer " $4
				else print $2
			}' | while read -r spec; do
			# shellcheck disable=SC2086  # spec is intentionally split
			run ip -6 addr del $spec dev "$dev"
		done
		if ! run ip -6 addr add "$self_in6" peer "$peer_in6/128" dev "$dev"; then
			log "WARNING: cannot add IPv6 inner $self_in6 on $dev" \
				"(kernel IPv6 off, or MTU < 1280?); peer continues v4-only"
		fi
	fi

	frr_iface "$dev" add || return 1

	# Data-plane probe after a (re)create: both ends of a pair must
	# migrate to GRE in the same window, and a one-sided flip is a
	# SILENT blackhole (our TX succeeds; the peer has no FOU RX for
	# it).  An inner ping crosses both directions -- make the failure
	# loud.  Best-effort: the peer may simply be down.
	if [ "$created" = 1 ] && [ "$DRY" != 1 ] &&
		command -v ping >/dev/null 2>&1; then
		if ! ping -c 1 -W 2 "$peer_in" >/dev/null 2>&1; then
			log "WARNING: $dev: peer inner $peer_in does not answer through" \
				"the new tunnel (other end not migrated to GRE yet, or down)"
		fi
	fi
	return 0
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

	# No FOU receive binding means every inbound GRE-in-FOU packet is
	# dropped -- proceeding would migrate the netdevs onto a receive
	# path that does not exist (an inbound-only blackhole that looks
	# healthy from this side).  Refuse before touching anything.
	if ! ensure_fou; then
		log "ERROR: FOU receive binding for port $FOU_PORT unavailable;" \
			"refusing to reconcile (tunnels would blackhole inbound traffic)"
		return 1
	fi

	if [ "$DRY" != 1 ] && ! gre_probe; then
		log "ERROR: kernel cannot create a GRE-in-FOU netdev" \
			"(kmod-gre/ip_gre missing?); refusing to reconcile" \
			"(the ipip->GRE migration would delete working tunnels" \
			"with no replacement)"
		return 1
	fi

	want=""
	seen=""
	npeers=0
	invalid=0
	for peer in $(peers); do
		[ "$peer" = "$SELF" ] && continue
		if ! echo "$peer" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
			log "ignoring invalid peer entry '$peer'"
			invalid=1
			rc=1
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

	# A malformed entry may be a mangled line for a DESIRED peer whose
	# device name we therefore cannot derive -- GC would delete that
	# peer's live tunnel while the run reports only a skipped entry.
	if [ "$invalid" = 1 ]; then
		log "WARNING: registry contained invalid entries; skipping" \
			"stale-tunnel GC this run"
	elif [ "$npeers" -eq 0 ] && [ "$ALLOW_EMPTY" != 1 ]; then
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
