#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# DIMT tunnel reconciler (draft-zzhang-mboned-dynamic-internet-mcast-tunnel,
# Phase C of the PIM Light / UMH deployment).
#
# Ensures one dual-stack GRE tunnel netdev per peer (GRE carries
# both IPv4 and IPv6 inner over the IPv4 overlay) and enrolls it with
# pimd and pim6d (`ip pim` + `ip pim light`, `ipv6 pim` + `ipv6 pim
# light`), so that adding a PE<->PoP pair needs nothing beyond listing
# the peer's overlay address.  Pure control plane: packets never touch
# this script.  Overlay identity and transport endpoints are separate:
# by default the outer endpoint remains the overlay address, while an
# endpoints file can retarget GRE onto a managed interconnect without
# changing device names, inner addresses, or BGP UMH values.
#
# Peer list is REGISTRY-DRIVEN (a flat file rendered by site tooling /
# mconfig), not derived from FRR state: the UMH mapping arrives over BGP,
# and BGP must never depend on a tunnel this script creates (circular),
# so tunnels exist first and FRR state only selects among them.
#
# Addressing contract (no per-pair coordination):
#   dev(X)    = dimt-<oct3>-<oct4> of X's overlay IPv4
#   inner4(X) = 10.99.<oct3>.<oct4> of X's overlay IPv4
#   inner6(X) = fd99::<oct3>:<oct4>  (decimal octets as literal groups,
#               RFC 5952 canonical so exists-checks match `ip` output)
# All three values share one derivation; changing any one requires changing
# all three.  The peer-collision guard protects inner-address and UMH
# uniqueness, not merely the netdev name.  Overlay addresses therefore come
# from one Blockcast-allocated /16; do not hash dev(X) to admit a collision.
# Both ends derive both inner addresses from the overlay pair alone.  The
# PE's UMH extended community must advertise inner4(PE) or inner6(PE).
# The tunnel is addressed `inner(self) peer inner(peer)/{32,128}`, which
# is exactly what pimd/pim6d's pim_dimt_light_iface() resolves the UMH
# against.  The auto link-local (fe80::) is never touched: pim6d sources
# Join/Prune from it.
#
# Peer registry format:
#   One peer per line, "<overlay-ipv4> [gre|gre-in-fou]".  The second
#   column is the ENCAP MODE and defaults to gre-in-fou, so a
#   single-column registry keeps the pre-existing behavior verbatim.
#   Vendor PEs that terminate plain GRE with no FOU take `gre`; the
#   names match pimd's native `encap <gre|gre-in-fou>` (pim_cmd.c).
#   --peers spells the same thing inline as "<overlay-ipv4>[=<mode>]".
#   A peer's encap mode is part of its drift identity: flipping it
#   recreates the netdev, because the kernel cannot add or remove FOU
#   encapsulation on an existing tunnel in place.
#
# The FOU receive port is bound `ipproto 47` (GRE).  Pre-GRE deployments
# bound 6636 to ipproto 4 (ipip); the GRE port defaults to 6637 so both
# bindings coexist during migration -- GC the old one afterwards
# (`ip fou del port 6636`).  A dimt-* netdev of the old ipip type is
# treated as drift and recreated as GRE (brief forwarding gap; run both
# ends of a pair in the same window -- a freshly created tunnel gets a
# best-effort inner ping so a one-sided migration is loud, not a silent
# blackhole).  The FOU binding and its capability probe are scoped to
# gre-in-fou peers: a box whose registry is all plain GRE never needs
# FOU, and a FOU failure must not take its plain-GRE peers down with it.
#
# Runs identically on the PE (Alpine container; `ip fou add` may be
# EPERM inside an unprivileged container -- pre-add it from the host, we
# tolerate the port already existing) and the PoP (OpenWrt ash).
#
# Safety: reconciliation is REFUSED outright -- before anything is
# deleted -- when (a) the peers file is missing/unreadable with no
# --peers inline list, or (b) the managed-underlay endpoint map is
# incomplete.  Two further capability failures are refused per ENCAP
# MODE rather than per run, so one mode's breakage cannot take the
# other's peers down: (c) the FOU receive binding cannot be ensured (a
# GRE-in-FOU tunnel without FOU RX blackholes all inbound traffic), and
# (d) the kernel cannot create a netdev of that mode at all
# (kmod-gre/ip_gre missing -- probed with a throwaway device, since the
# ipip->GRE migration deletes the working tunnel first).  Peers of a
# failed mode are skipped with their tunnels left intact and held out of
# GC's reach, and the run still exits nonzero.  An empty desired peer
# set, or a registry with malformed entries, skips stale-tunnel GC
# (--allow-empty overrides the empty case) -- each would otherwise be
# indistinguishable from "delete that tunnel on purpose".  Note that with
# --allow-empty and an empty registry no mode is wanted, so no capability
# gate runs and GC reaps every tunnel this script owns; the old
# unconditional ensure_fou() used to refuse first whenever FOU was
# unavailable, which was incidental protection rather than a contract.
# An MTU below 1280 leaves the tunnels v4-only (the kernel disables IPv6
# on such links) and is warned about loudly, as is an MTU that overflows
# the outer path to the peer.
#
# Managed-underlay cutover:
#   --endpoints-file (or DIMT_ENDPOINTS_FILE) names a rendered file with
#   "<overlay-ipv4> <underlay-ipv4>" rows for self and every desired peer.
#   The mapping is all-or-nothing and validated before tunnel state is
#   touched.  UCI/mconfig should render the file, then run both ends in the
#   same cutover window.  Omitting the knob preserves the tailnet/overlay
#   endpoint behavior for rollback.
#
# Usage:
#   dimt-reconcile.sh --self 100.64.0.40 [--peers-file /etc/dimt/peers]
#                     [--peers 100.64.0.47,...] [--mtu 1388] [--port 6637]
#                     [--endpoints-file /etc/dimt/underlay-endpoints]
#                     [--no-frr] [--dry-run] [--watch SECONDS]
#                     [--allow-empty]

set -u

SELF="${DIMT_SELF:-}"
PEERS_FILE="${DIMT_PEERS_FILE:-/etc/dimt/peers}"
PEERS_INLINE=""
ENDPOINTS_FILE="${DIMT_ENDPOINTS_FILE:-}"
FOU_PORT="${DIMT_FOU_PORT:-6637}"
MTU="${DIMT_MTU:-1388}"
# `dimt-` is a SHARED namespace, not ours: zebra/pimd name their own
# on-demand tunnels dimt-%08x.  PREFIX selects the namespace; gc_stale()
# matches the narrower set of names this script actually creates.  Adding
# another script-owned dimt-* device means widening that pattern too, or
# the device leaks forever.
PREFIX="dimt-"
DO_FRR=1
DRY=0
WATCH=0
ALLOW_EMPTY="${DIMT_ALLOW_EMPTY:-0}"
VTYSH_WARNED=0
VTYSH6_WARNED=0

log() { printf '%s\n' "dimt-reconcile: $*" >&2; }

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
	--endpoints-file) ENDPOINTS_FILE="$2"; shift 2 ;;
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
	printf '%s\n' "$1" | awk -F. '{ printf "10.99.%s.%s", $3, $4 }'
}

# fd99::<oct3>:<oct4>, the decimal octets written as literal groups
# (correlates with the device name and inner4).  Emitted in RFC 5952
# canonical form -- what `ip -6 addr show` prints back -- or the
# exists-check below would never match and every cycle would churn:
# a zero oct3 collapses (fd99::0:47 is shown as fd99::47).
inner6_of() {
	printf '%s\n' "$1" | awk -F. '{
		if ($3 == 0 && $4 == 0) printf "fd99::"
		else if ($3 == 0)       printf "fd99::%s", $4
		else                    printf "fd99::%s:%s", $3, $4
	}'
}

# Interface name from the overlay address: dimt-<oct3>-<oct4> (fits
# IFNAMSIZ for any dotted quad).
dev_of() {
	printf '%s\n' "$1" | awk -F. '{ printf "dimt-%s-%s", $3, $4 }'
}

# Emits one whitespace-free "<overlay>[=<mode>]" spec per desired peer,
# so the registry's two-column form and --peers' inline form collapse to
# a single token the callers below split with overlay_of/encap_of.
# Interior whitespace is NOT deleted any more (it used to be, which
# silently repaired "100.64. 0.47" into a different valid address);
# a mangled entry now fails the dotted-quad check loudly instead.
# EVERY field is joined, not just the first two: a third column used to
# be dropped on the floor, so "100.64.0.47 gre extra" parsed as a valid
# gre peer.  Joining it makes the mode "gre=extra", which the build loop
# rejects loudly.  One silent drop remains by design: the self line is
# skipped before the mode check, so a third column on it is ignored with
# no diagnostic -- nothing is built for self either way.
peers() {
	{
		[ -n "$PEERS_INLINE" ] && printf '%s\n' "$PEERS_INLINE" | tr ',' '\n'
		[ -r "$PEERS_FILE" ] && sed 's/#.*//' "$PEERS_FILE"
	} | tr -d '\r' |
		awk 'NF { spec = $1
			for (i = 2; i <= NF; i++) spec = spec "=" $i
			print spec }' | sort -u
}

overlay_of() { printf '%s\n' "${1%%=*}"; }

# The build loop's dotted-quad gate, shared with the capability pre-scan
# in reconcile() AND with validate_endpoints() so the three can never
# disagree about which addresses are buildable.
#
# A real dotted quad, not just the shape: this used to be
# '([0-9]{1,3}\.){3}[0-9]{1,3}', which passed 999.999.999.999 through to
# dev dimt-999-999 and inner addresses 10.99.999.999/32 -- rejected by
# `ip`, so it failed loudly downstream rather than silently.  Two reasons
# the shape check is not enough:
#   - an octet > 255 is a mangled line, and dev_of() reads octets 3-4, so
#     the device we derive is not the device the operator meant;
#   - a leading zero ALIASES: 10.99.010.20 and 10.99.10.20 are the same
#     address but derive dimt-010-20 and dimt-10-20, i.e. two netdevs
#     fighting over one peer (and 010 is octal to inet_aton besides).
# [1-9]?[0-9] is what forbids the leading zero while still admitting 0.
is_quad() {
	printf '%s\n' "$1" | grep -Eq \
		'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
}

# --self is the fourth address consumer and was the one left outside the
# gate: it was only checked non-empty, then flowed into inner_of/inner6_of
# ("10.99.<o3>.<o4>") and the local endpoint.  It also decides the
# self-skip, which is a TEXTUAL compare against each peer, so an
# unvalidated --self 100.64.010.40 would not match a peers-file
# 100.64.10.40 and the box would build a tunnel to itself.
#
# Deliberately NOT next to the `-n "$SELF"` check above: that runs during
# argument parsing, ~70 lines before is_quad() is defined, so the call
# would be a `command not found` -> rc 127 -> the `||` fires and EVERY
# --self is rejected, valid ones included.  It has to follow the
# definition it uses.
is_quad "$SELF" || { log "--self must be a dotted quad: '$SELF'"; exit 1; }

# Absent second column means gre-in-fou: every registry written before
# this knob existed describes GRE-in-FOU peers.
encap_of() {
	case "$1" in
	*=*) printf '%s\n' "${1#*=}" ;;
	*) printf '%s\n' "gre-in-fou" ;;
	esac
}

# Resolve an overlay identity to its GRE transport endpoint.  Keeping this
# separate from inner_of()/inner6_of()/dev_of() is the core cutover invariant:
# transport changes must not alter the UMH resolution key.
endpoint_of() {
	if [ -z "$ENDPOINTS_FILE" ]; then
		printf '%s\n' "$1"
		return 0
	fi
	awk -v overlay="$1" '
		/^[ \t]*#/ || NF < 2 { next }
		$1 == overlay { print $2; found = 1; exit }
		END { exit found ? 0 : 1 }
	' "$ENDPOINTS_FILE"
}

# An endpoint-map cutover must be atomic.  Refuse before ensure_fou(), the GRE
# capability probe, endpoint-drift deletion, or GC if any desired identity is
# absent or malformed.
#
# Takes the registry snapshot as an argument rather than calling peers()
# itself: every consumer in one reconcile() pass must see the same registry
# (see the snapshot comment in reconcile()).
# shellcheck disable=SC2086  # $1 is a peer-spec list, split on purpose
validate_endpoints() { # <peer-spec-list>
	[ -n "$ENDPOINTS_FILE" ] || return 0
	[ -r "$ENDPOINTS_FILE" ] || {
		log "ERROR: endpoints file $ENDPOINTS_FILE missing/unreadable; refusing cutover"
		return 1
	}
	for spec in "$SELF" ${1:-}; do
		overlay=$(overlay_of "$spec")
		endpoint=$(endpoint_of "$overlay") || {
			log "ERROR: no managed underlay endpoint for overlay $overlay; refusing cutover"
			return 1
		}
		if ! is_quad "$endpoint"; then
			log "ERROR: invalid managed underlay endpoint '$endpoint' for overlay $overlay; refusing cutover"
			return 1
		fi
	done
}

# fou/gre may not be loaded at boot (nothing else pulls them in).
# Best-effort: inside an unprivileged container this fails and the
# pre-added host state carries us, same as the EPERM path below.
#
# Hoisted out of ensure_fou(), which now runs only when the registry asks
# for gre-in-fou: an all-plain-GRE box would otherwise never modprobe at
# all and would depend solely on the kernel's rtnl-link-gre autoload.
load_tunnel_modules() {
	command -v modprobe >/dev/null 2>&1 || return 0
	modprobe fou 2>/dev/null || true
	modprobe gre 2>/dev/null || true
	modprobe ip_gre 2>/dev/null || true
}

ensure_fou() {
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

# Prove the kernel can create a netdev of <encap-mode> with a throwaway
# device BEFORE anything is deleted: the ipip->GRE migration removes
# the working production tunnel first, and modprobe failures above are
# deliberately suppressed -- without this probe a missing kmod-gre
# would strand the box with no tunnel at all.  (The probe device is
# dimt-prefixed, so a leaked one is swept up by the next GC.)  Probed
# per mode actually desired: gre-in-fou needs the fou module on top of
# ip_gre, so a plain-GRE-only box must not be gated on FOU support.
gre_probe() { # <encap-mode>
	probe="${PREFIX}probe0"
	probe_encap=""
	[ "$1" = gre-in-fou ] &&
		probe_encap="encap fou encap-sport auto encap-dport $FOU_PORT"
	ip link del "$probe" 2>/dev/null
	# shellcheck disable=SC2086  # probe_encap is intentionally split
	if ! ip link add "$probe" type gre local 127.0.0.1 remote 127.0.0.2 \
		ttl 64 $probe_encap 2>/dev/null; then
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

ensure_peer() { # <peer-overlay> <encap-mode>
	peer="$1"
	mode="$2"
	self_endpoint=$(endpoint_of "$SELF") || return 1
	peer_endpoint=$(endpoint_of "$peer") || return 1
	dev=$(dev_of "$peer")
	self_in=$(inner_of "$SELF")
	peer_in=$(inner_of "$peer")
	self_in6=$(inner6_of "$SELF")
	peer_in6=$(inner6_of "$peer")
	if [ "$mode" = gre-in-fou ]; then
		encap_args="encap fou encap-sport auto encap-dport $FOU_PORT"
		overhead=32
		overhead_label="GRE-in-FOU"
	else
		encap_args=""
		overhead=24
		overhead_label="GRE"
	fi

	# Inner MTU + outer IPv4(20) + GRE(4), plus UDP(8) when FOU-encapped,
	# must fit the path to the peer, or near-MTU multicast
	# fragments/blackholes (the DF-multicast trap).  Read-only,
	# best-effort: unknown route or unparsable output just skips the check.
	out_dev=$(ip route get "$peer_endpoint" 2>/dev/null |
		sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1)
	if [ -n "$out_dev" ]; then
		out_mtu=$(ip link show "$out_dev" 2>/dev/null |
			sed -n 's/.* mtu \([0-9]*\).*/\1/p' | head -n 1)
		if [ -n "$out_mtu" ] && [ $((MTU + overhead)) -gt "$out_mtu" ]; then
			log "WARNING: $dev: inner MTU $MTU + ${overhead}B $overhead_label overhead" \
				"exceeds $out_dev MTU $out_mtu; lower --mtu to $((out_mtu - overhead))"
		fi
	fi

	# Recreate on tunnel-type, encap-mode or endpoint drift; the kernel
	# cannot change a tunnel's type in place (ipip -> gre migration lands
	# here), cannot add/remove FOU encapsulation on a live tunnel, and
	# `ip link change` cannot retarget local/remote reliably across
	# kernels.  `gone` tracks a delete this run so --dry-run previews the
	# recreate coherently (the real netdev still exists after a DRY delete).
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
	# Test for the presence of `encap fou` rather than for a literal
	# `encap none`: iproute2 versions differ on whether they print
	# anything at all for an unencapsulated tunnel.
	#
	# Three outcomes, not two.  `ip link add type gre` also accepts gue
	# and mpls, and iproute2 prints those as `encap gue`/`encap mpls`.
	# Folding them into `gre` would compare equal against a plain-GRE
	# registry entry and leave a wrongly-encapsulated tunnel in place --
	# exactly the silent drift this check exists to catch.  `other`
	# matches neither validated mode, so it always recreates.
	if [ "$gone" = 0 ] && ip link show "$dev" >/dev/null 2>&1; then
		cur=$(ip -d link show "$dev" 2>/dev/null)
		case "$cur" in
		*"encap fou"*) cur_mode=gre-in-fou ;;
		*"encap "*) cur_mode=other ;;
		*) cur_mode=gre ;;
		esac
		if [ "$cur_mode" != "$mode" ]; then
			log "$dev encap mode drifted ($cur_mode -> $mode); recreating"
			frr_iface "$dev" del
			run ip link del "$dev"
			gone=1
		fi
	fi
	if [ "$gone" = 0 ] && ip link show "$dev" >/dev/null 2>&1; then
		cur=$(ip -d link show "$dev" 2>/dev/null)
		case "$cur" in
		*"local $self_endpoint "*"remote $peer_endpoint"* | *"remote $peer_endpoint "*"local $self_endpoint"*) : ;;
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
		# shellcheck disable=SC2086  # encap_args is intentionally split
		run ip link add "$dev" type gre local "$self_endpoint" remote "$peer_endpoint" \
			ttl 64 $encap_args || return 1
		log "created $dev ($mode; $self_endpoint -> $peer_endpoint; overlay $SELF -> $peer)"
		created=1
	fi

	run ip link set "$dev" mtu "$MTU" multicast on up || return 1

	# OpenWrt defaults rx-gro-list (fraglist GRO) ON for every netdev.
	# It coalesces same-outer-tuple UDP and each stage on this path
	# then eats the aggregate: on the underlay device the FOU/GRE
	# decap processes only the head segment, and on the tunnel itself
	# the inner aggregate is mangled in bridge/DSA TX segmentation.
	# Measured 2/3 silent loss at 26-52 Mbps with every drop counter
	# clean; 99.97% delivery with the flag off (2026-07-13).  Direct
	# (not via run): best-effort on both real and DRY passes would
	# pollute the DRY trace; ethtool may be absent and non-OpenWrt
	# kernels default the flag off, so failures are ignored.
	if [ "$DRY" != 1 ] && command -v ethtool >/dev/null 2>&1; then
		ethtool -K "$dev" rx-gro-list off 2>/dev/null
		[ -n "$out_dev" ] &&
			ethtool -K "$out_dev" rx-gro-list off 2>/dev/null
	fi

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
	# Scope GC to the names THIS script derives.  `dimt-` is a shared
	# namespace: zebra/pimd build their own on-demand tunnels as
	# dimt-%08x of the tunnel id (pim_dimt.c, zebra_dimt.c), and they
	# are not in our peer list by construction.  Sweeping every dimt-*
	# deleted them every cycle while zebra rebuilt them -- two owners
	# fighting forever on any host running both.  Ours are dev_of()'s
	# dimt-<o3>-<o4> plus a leaked gre_probe device; the two shapes
	# cannot collide (hex ids carry no '-').  Anything else under the
	# prefix belongs to someone else: leave it alone.
	ip -o link show 2>/dev/null | awk -F': ' '{ print $2 }' |
		sed 's/@.*//' |
		grep -E "^$PREFIX([0-9]{1,3}-[0-9]{1,3}|probe0)$" |
		while read -r dev; do
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

	# Read the registry EXACTLY ONCE per pass and iterate that snapshot
	# everywhere below.  Re-reading would let the capability pre-scan and
	# the build loop disagree if config management rewrites the file
	# between them: a peer seen as plain-GRE by the pre-scan and as
	# gre-in-fou by the build loop would keep fou_ok=1 by default, so
	# ensure_fou would never have run for it and the netdev would be
	# created with `encap fou` against an unbound port -- the inbound
	# blackhole the gate below exists to prevent.
	all_peers=$(peers)

	validate_endpoints "$all_peers" || return 1

	# Loading the tunnel modules is unconditional: both modes need
	# ip_gre, and only the FOU path used to pull it in.
	load_tunnel_modules

	# Which encap modes does the registry actually ask for?  Decided
	# before the peer loop, because every capability gate below must run
	# before the first delete.  Three classes are skipped here because the
	# build loop rejects them too, and nothing should be probed or bound
	# on their behalf: self, a malformed overlay, and an unrecognised
	# mode.  The overlay check is what keeps a bare junk line ("garbage")
	# from breaking the all-plain-GRE-needs-no-FOU contract in the header:
	# encap_of() defaults its absent mode to gre-in-fou, and want_fou runs
	# ensure_fou(), which BINDS the FOU port (`ip fou add`) rather than
	# merely probing.
	#
	# Known residual -- this is NOT "only entries the loop could build".
	# The device-collision check runs inside the build loop, i.e. after
	# this scan, so a collision-losing peer still arms its mode's gate and
	# is then never built: two peers deriving one dimt-N-M can bind the
	# FOU port on an otherwise all-plain-GRE box.  Pre-existing (base
	# 77c3bb30 behaves identically) and bounded -- but NOT by the GC
	# suppression the other reject paths get: the collision branch sets
	# rc=1 WITHOUT invalid=1, and GC is gated on invalid alone, so
	# gc_stale still runs.  What bounds it is that the winning peer puts
	# the contested device in want before the loser is rejected, so GC
	# cannot delete it.  Hoisting the dedupe ahead of this scan would
	# close it.
	want_fou=0
	want_plain=0
	for spec in $all_peers; do
		peer=$(overlay_of "$spec")
		[ "$peer" = "$SELF" ] && continue
		is_quad "$peer" || continue
		case "$(encap_of "$spec")" in
		gre-in-fou) want_fou=1 ;;
		gre) want_plain=1 ;;
		esac
	done

	# No FOU receive binding means every inbound GRE-in-FOU packet is
	# dropped -- proceeding would migrate the netdevs onto a receive
	# path that does not exist (an inbound-only blackhole that looks
	# healthy from this side).  Scoped to gre-in-fou peers, and fatal
	# only to them: plain-GRE peers never touch the FOU port.
	fou_ok=1
	plain_ok=1
	if [ "$want_fou" = 1 ]; then
		if ! ensure_fou; then
			log "ERROR: FOU receive binding for port $FOU_PORT unavailable;" \
				"refusing to reconcile gre-in-fou peers" \
				"(tunnels would blackhole inbound traffic)"
			fou_ok=0
			rc=1
		elif [ "$DRY" != 1 ] && ! gre_probe gre-in-fou; then
			log "ERROR: kernel cannot create a GRE-in-FOU netdev" \
				"(kmod-gre/ip_gre missing?); refusing to reconcile" \
				"gre-in-fou peers (the ipip->GRE migration would" \
				"delete working tunnels with no replacement)"
			fou_ok=0
			rc=1
		fi
	fi
	if [ "$want_plain" = 1 ] && [ "$DRY" != 1 ] && ! gre_probe gre; then
		log "ERROR: kernel cannot create a plain GRE netdev" \
			"(kmod-gre/ip_gre missing?); refusing to reconcile" \
			"gre peers (a type migration would delete working" \
			"tunnels with no replacement)"
		plain_ok=0
		rc=1
	fi

	want=""
	seen=""
	npeers=0
	invalid=0
	for spec in $all_peers; do
		peer=$(overlay_of "$spec")
		mode=$(encap_of "$spec")
		[ "$peer" = "$SELF" ] && continue
		# DISPOSITION, decided rather than fallen into: an out-of-range
		# or leading-zero octet is a MALFORMED ENTRY (invalid=1, GC
		# suppressed run-wide), not a skip-with-rc=1 like the device
		# collision below.  The two look alike and are not:
		#   - the collision branch can leave GC running because the
		#     WINNING peer has already put the contested device in
		#     want, so gc_stale cannot reap it (pinned by h6e);
		#   - here there is no winner.  A mangled octet is most often a
		#     typo of a real peer, and dev_of() reads octets 3-4, so the
		#     device we would derive is not the one the operator meant.
		#     The peer's real device is in nobody's want and GC would
		#     delete a live tunnel.  Same reasoning as the GC gate's own
		#     comment below -- kept identical on purpose.
		if ! is_quad "$peer"; then
			log "ignoring invalid peer entry '$peer'"
			invalid=1
			rc=1
			continue
		fi
		case "$mode" in
		gre | gre-in-fou) : ;;
		*=*)
			# peers() joins every field, so a surviving "=" means the
			# entry had a third column.  Echo it back with the "="
			# turned back into spaces -- normalized to single spaces,
			# NOT the entry's original spacing, so an operator grepping
			# their peers file for this string may not match the line.
			log "ignoring peer $peer: trailing field(s) after encap mode" \
				"in '$peer $(printf '%s\n' "$mode" | tr '=' ' ')'" \
				"(expected '<overlay> <gre|gre-in-fou>')"
			invalid=1
			rc=1
			continue
			;;
		*)
			log "ignoring peer $peer: unknown encap mode '$mode'" \
				"(expected gre or gre-in-fou)"
			invalid=1
			rc=1
			continue
			;;
		esac
		dev=$(dev_of "$peer")
		# Two peers in different /16s can collide on dimt-<o3>-<o4>;
		# without this check the pair fights over one netdev as an
		# endpoints-drifted recreate flip-flop every cycle.  The same
		# guard catches one overlay listed twice under different encap
		# modes, where the flip-flop would be over encap instead.
		prev=""
		for pair in $seen; do
			case "$pair" in
			"$dev="*) prev="${pair#*=}" ;;
			esac
		done
		if [ -n "$prev" ]; then
			if [ "$prev" = "$peer" ]; then
				log "ERROR: peer $peer is listed twice with conflicting" \
					"encap modes; skipping the later entry"
			else
				log "ERROR: peers $prev and $peer both derive device $dev;" \
					"skipping $peer (addressing contract needs one overlay /16)"
			fi
			rc=1
			continue
		fi
		seen="$seen $dev=$peer"
		npeers=$((npeers + 1))
		# Keep desired peers out of GC's reach even when ensure_peer
		# fails or its mode is unavailable, so a transient failure
		# cannot delete the tunnel.
		want="$want $dev"
		if { [ "$mode" = gre-in-fou ] && [ "$fou_ok" != 1 ]; } ||
			{ [ "$mode" = gre ] && [ "$plain_ok" != 1 ]; }; then
			log "skipping peer $peer: $mode is unavailable on this box" \
				"(existing $dev left untouched)"
			continue
		fi
		if ! ensure_peer "$peer" "$mode"; then
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
			"(pass --allow-empty to force removal of every tunnel this script owns)"
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
