#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Self-contained test for tools/dimt-reconcile.sh.  Needs no root and no
# network: fake `ip` and `ping` on PATH keep link/addr/fou state in flat
# files under a temp dir and log every invocation; a fake `vtysh` logs
# and succeeds.  Run as: sh tools/dimt-reconcile-test.sh
# (set DIMT_TEST_SH=dash/busybox-ash to exercise another interpreter).
#
# Failure injection (create the marker file in $FAKEIP_DIR):
#   fail-gre-add     -- every `ip link add ... type gre` fails (no kmod-gre)
#   fail-fou-gre-add -- only GRE-in-FOU adds fail (ip_gre present, fou not)
#   fail-fou-add     -- `ip fou add` fails (EPERM in unprivileged container)
#   ping-fail        -- the inner-address ping probe fails (one-sided flip)

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RECONCILE="$SCRIPT_DIR/dimt-reconcile.sh"
RUN_SH="${DIMT_TEST_SH:-sh}"

TESTDIR=$(mktemp -d "${TMPDIR:-/tmp}/dimt-test.XXXXXX") || exit 1
trap 'rm -rf "$TESTDIR"' EXIT INT TERM

BIN="$TESTDIR/bin"
mkdir -p "$BIN"

# ---------------------------------------------------------------------
# fake ip(8): state lives in $FAKEIP_DIR
#   links  -- one line per netdev: "<dev> <local> <remote> [<type>] [<encap>]"
#             (type defaults to ipip so pre-GRE state can be seeded;
#              encap defaults to fou, the only mode that existed before
#              the per-peer encap column -- set it to "none" to seed a
#              plain-GRE tunnel)
#   addrs  -- one line per address: "<dev> <inet|inet6> <a> peer <p>/NN"
#   fou    -- verbatim `ip fou show` output
#   route-dev -- if present, `ip route get X` says "X dev $(cat route-dev)"
#   ip.log -- every invocation, verbatim
# ---------------------------------------------------------------------
cat > "$BIN/ip" <<'FAKEIP'
#!/bin/sh
set -u
: "${FAKEIP_DIR:?FAKEIP_DIR not set}"
LINKS="$FAKEIP_DIR/links"
ADDRS="$FAKEIP_DIR/addrs"
echo "ip $*" >> "$FAKEIP_DIR/ip.log"

detail=0
family=""
while [ $# -gt 0 ]; do
	case "$1" in
	-d) detail=1; shift ;;
	-4) family=inet; shift ;;
	-6) family=inet6; shift ;;
	-*) shift ;;
	*) break ;;
	esac
done

obj="${1:-}"
[ $# -gt 0 ] && shift
sub="${1:-}"
[ $# -gt 0 ] && shift

case "$obj/$sub" in
fou/show)
	cat "$FAKEIP_DIR/fou" 2>/dev/null
	exit 0
	;;
fou/add)
	[ -f "$FAKEIP_DIR/fail-fou-add" ] && exit 2
	echo "$* " >> "$FAKEIP_DIR/fou"
	exit 0
	;;
route/get)
	if [ -f "$FAKEIP_DIR/route-dev" ]; then
		echo "${1:-} dev $(cat "$FAKEIP_DIR/route-dev") src 100.64.0.40 uid 0"
	fi
	exit 0
	;;
link/show)
	dev="${1:-}"
	if [ -z "$dev" ]; then
		i=1
		[ -f "$LINKS" ] || exit 0
		while read -r d rest; do
			: "$rest"
			echo "$i: $d: <POINTOPOINT,MULTICAST,UP> mtu 1388 qdisc noqueue state UNKNOWN"
			i=$((i + 1))
		done < "$LINKS"
		exit 0
	fi
	line=$(grep "^$dev " "$LINKS" 2>/dev/null | head -n 1)
	[ -n "$line" ] || exit 1
	set -- $line
	typ="${4:-ipip}"
	enc="${5:-fou}"
	echo "7: $dev: <POINTOPOINT,MULTICAST,UP> mtu 1388 qdisc noqueue state UNKNOWN"
	if [ "$detail" = 1 ]; then
		echo "    link/$typ $2 peer $3"
		if [ "$enc" = fou ]; then
			echo "    $typ remote $3 local $2 ttl 64 encap fou encap-sport auto encap-dport 6637"
		elif [ "$enc" = none ]; then
			echo "    $typ remote $3 local $2 ttl 64"
		else
			# gue/mpls: same `ip link add type gre` syntax, different
			# encap keyword -- seeds the third-encap drift case.
			echo "    $typ remote $3 local $2 ttl 64 encap $enc encap-sport auto encap-dport 6637"
		fi
	fi
	exit 0
	;;
link/add)
	dev="$1"; shift
	loc=""; rem=""; typ=""; enc=none
	while [ $# -gt 0 ]; do
		case "$1" in
		type) typ="$2"; shift 2 ;;
		local) loc="$2"; shift 2 ;;
		remote) rem="$2"; shift 2 ;;
		encap) [ "$2" = fou ] && enc=fou; shift 2 ;;
		*) shift ;;
		esac
	done
	if [ "$typ" = gre ] && [ -f "$FAKEIP_DIR/fail-gre-add" ]; then
		exit 2
	fi
	if [ "$enc" = fou ] && [ -f "$FAKEIP_DIR/fail-fou-gre-add" ]; then
		exit 2
	fi
	echo "$dev $loc $rem ${typ:-ipip} $enc" >> "$LINKS"
	exit 0
	;;
link/del)
	dev="$1"
	grep -v "^$dev " "$LINKS" > "$LINKS.tmp" 2>/dev/null || true
	mv "$LINKS.tmp" "$LINKS"
	grep -v "^$dev " "$ADDRS" > "$ADDRS.tmp" 2>/dev/null || true
	mv "$ADDRS.tmp" "$ADDRS"
	exit 0
	;;
link/set)
	dev="$1"
	grep -q "^$dev " "$LINKS" 2>/dev/null || exit 1
	exit 0
	;;
addr/show)
	dev=""
	while [ $# -gt 0 ]; do
		case "$1" in
		dev) dev="$2"; shift 2 ;;
		scope) shift 2 ;;
		*) shift ;;
		esac
	done
	grep "^$dev " "$ADDRS" 2>/dev/null | {
		if [ -n "$family" ]; then grep " $family "; else cat; fi
	} | sed "s/^$dev /    /"
	exit 0
	;;
addr/flush)
	dev=""
	while [ $# -gt 0 ]; do
		case "$1" in
		dev) dev="$2"; shift 2 ;;
		*) shift ;;
		esac
	done
	if [ -n "$family" ]; then
		grep -v "^$dev $family " "$ADDRS" > "$ADDRS.tmp" 2>/dev/null || true
	else
		grep -v "^$dev " "$ADDRS" > "$ADDRS.tmp" 2>/dev/null || true
	fi
	mv "$ADDRS.tmp" "$ADDRS"
	exit 0
	;;
addr/add)
	a="$1"; shift
	peer=""; dev=""
	while [ $# -gt 0 ]; do
		case "$1" in
		peer) peer="$2"; shift 2 ;;
		dev) dev="$2"; shift 2 ;;
		*) shift ;;
		esac
	done
	case "$a" in
	*:*) fam=inet6 ;;
	*) fam=inet ;;
	esac
	echo "$dev $fam $a peer $peer" >> "$ADDRS"
	exit 0
	;;
addr/del)
	a="$1"; shift
	peer=""; dev=""
	while [ $# -gt 0 ]; do
		case "$1" in
		peer) peer="$2"; shift 2 ;;
		dev) dev="$2"; shift 2 ;;
		*) shift ;;
		esac
	done
	case "$a" in
	*:*) fam=inet6 ;;
	*) fam=inet ;;
	esac
	grep -v "^$dev $fam $a peer $peer$" "$ADDRS" > "$ADDRS.tmp" 2>/dev/null || true
	mv "$ADDRS.tmp" "$ADDRS"
	exit 0
	;;
esac
exit 0
FAKEIP
chmod +x "$BIN/ip"

cat > "$BIN/vtysh" <<'FAKEVTYSH'
#!/bin/sh
echo "vtysh $*" >> "${FAKEIP_DIR:?}/vtysh.log"
exit 0
FAKEVTYSH
chmod +x "$BIN/vtysh"

cat > "$BIN/ping" <<'FAKEPING'
#!/bin/sh
echo "ping $*" >> "${FAKEIP_DIR:?}/ping.log"
[ -f "$FAKEIP_DIR/ping-fail" ] && exit 1
exit 0
FAKEPING
chmod +x "$BIN/ping"

PATH="$BIN:$PATH"
export PATH

FAILS=0
ok() { echo "ok $*"; }
fail() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }
check() { # <desc> <cmd...>
	desc="$1"; shift
	if "$@"; then ok "$desc"; else fail "$desc"; fi
}

new_state() {
	FAKEIP_DIR="$TESTDIR/state-$1"
	rm -rf "$FAKEIP_DIR"
	mkdir -p "$FAKEIP_DIR"
	# Pre-GRE deployments left the old ipip binding behind; the GRE
	# port must be added alongside it, never instead of it.
	echo "port 6636 ipproto 4" > "$FAKEIP_DIR/fou"
	: > "$FAKEIP_DIR/links"
	: > "$FAKEIP_DIR/addrs"
	: > "$FAKEIP_DIR/ip.log"
	: > "$FAKEIP_DIR/vtysh.log"
	: > "$FAKEIP_DIR/ping.log"
	export FAKEIP_DIR
}

# Assertion helpers.  All are invoked indirectly through check(), an
# indirection shellcheck cannot see -- hence the SC2329 directives.
# shellcheck disable=SC2329
log_has() { grep -q -- "$1" "$FAKEIP_DIR/ip.log"; }
# shellcheck disable=SC2329
log_lacks() { ! grep -q -- "$1" "$FAKEIP_DIR/ip.log"; }
# shellcheck disable=SC2329
log_count() { [ "$(grep -c -- "$1" "$FAKEIP_DIR/ip.log")" -eq "$2" ]; }
# err_has matches against $err, the captured stderr of the last run.
# shellcheck disable=SC2329
err_has() { printf '%s\n' "$err" | grep -q -- "$1"; }
# shellcheck disable=SC2329
err_lacks() { ! printf '%s\n' "$err" | grep -q -- "$1"; }
# shellcheck disable=SC2329
vtysh_lacks() { ! grep -q -- "$1" "$FAKEIP_DIR/vtysh.log"; }

# --- (a) inner derivation, dual-stack create ---------------------------
new_state a
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "a: exit 0" [ "$rc" -eq 0 ]
check "a: adds the GRE FOU port" log_has \
	"^ip fou add port 6637 ipproto 47$"
check "a: probes GRE capability with a throwaway device" log_has \
	"^ip link add dimt-probe0 type gre local 127.0.0.1 remote 127.0.0.2 "
check "a: probe device is cleaned up" \
	awk '/^ip link add dimt-probe0 /{a=NR} /^ip link del dimt-probe0$/{if (NR>a) d=NR}
	     END { exit !(a && d) }' "$FAKEIP_DIR/ip.log"
check "a: creates dimt-0-47 as GRE with correct endpoints" log_has \
	"^ip link add dimt-0-47 type gre local 100.64.0.40 remote 100.64.0.47 "
check "a: addresses inner4(self) peer inner4(peer)" log_has \
	"^ip addr add 10.99.0.40 peer 10.99.0.47/32 dev dimt-0-47$"
check "a: addresses inner6(self) peer inner6(peer)" log_has \
	"^ip -6 addr add fd99::40 peer fd99::47/128 dev dimt-0-47$"
check "a: v4 flush is family-scoped" log_has \
	"^ip -4 addr flush dev dimt-0-47"
check "a: never flushes unscoped (would kill the v6 link-local)" \
	log_lacks "^ip addr flush"
check "a: enrolls dimt-0-47 with FRR" \
	grep -q "interface dimt-0-47" "$FAKEIP_DIR/vtysh.log"
check "a: enrolls IPv4 PIM Light" \
	grep -q "ip pim light" "$FAKEIP_DIR/vtysh.log"
check "a: enrolls IPv6 PIM Light" \
	grep -q "ipv6 pim light" "$FAKEIP_DIR/vtysh.log"
check "a: probes the peer inner address after creation" \
	grep -q -- "-c 1 -W 2 10.99.0.47" "$FAKEIP_DIR/ping.log"
check "a: reachable peer produces no warning" \
	err_lacks "does not answer"
[ "$rc" -ne 0 ] && printf '%s\n' "$err"

# --- (a2) managed underlay endpoints preserve overlay identity ----------
new_state a2
cat > "$TESTDIR/underlay-endpoints" <<'EOF'
100.64.0.40 192.0.2.1
100.64.0.47 192.0.2.2
EOF
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" \
	--endpoints-file "$TESTDIR/underlay-endpoints" 2>&1)
rc=$?
check "a2: managed-underlay reconcile exits 0" [ "$rc" -eq 0 ]
check "a2: GRE uses managed underlay endpoints" log_has \
	"^ip link add dimt-0-47 type gre local 192.0.2.1 remote 192.0.2.2 "
check "a2: PMTU lookup follows the managed endpoint" log_has \
	"^ip route get 192.0.2.2$"
check "a2: device and inner4 remain overlay-derived" log_has \
	"^ip addr add 10.99.0.40 peer 10.99.0.47/32 dev dimt-0-47$"
check "a2: inner6 remains overlay-derived" log_has \
	"^ip -6 addr add fd99::40 peer fd99::47/128 dev dimt-0-47$"

# Missing mappings fail before endpoint-drift deletion or any other mutation.
new_state a3
echo "100.64.0.40 192.0.2.1" > "$TESTDIR/underlay-incomplete"
echo "dimt-0-47 100.64.0.40 100.64.0.47 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" \
	--endpoints-file "$TESTDIR/underlay-incomplete" 2>&1)
rc=$?
check "a3: incomplete endpoint map exits nonzero" [ "$rc" -ne 0 ]
check "a3: missing peer mapping is explicit" err_has \
	"no managed underlay endpoint for overlay 100.64.0.47"
check "a3: incomplete map cannot delete the live tunnel" \
	log_lacks "^ip link del dimt-0-47$"
check "a3: incomplete map fails before FOU or GRE probes" \
	log_lacks "^ip fou add"

# Out-of-range mappings are malformed even when they look like dotted quads.
new_state a4
cat > "$TESTDIR/underlay-out-of-range" <<'EOF'
100.64.0.40 192.0.2.1
100.64.0.47 999.999.999.999
EOF
echo "dimt-0-47 192.0.2.1 192.0.2.2 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" \
	--endpoints-file "$TESTDIR/underlay-out-of-range" 2>&1)
rc=$?
check "a4: out-of-range endpoint exits nonzero" [ "$rc" -ne 0 ]
check "a4: invalid endpoint is explicit" err_has \
	"invalid managed underlay endpoint '999.999.999.999'"
check "a4: invalid endpoint cannot delete the live tunnel" \
	log_lacks "^ip link del dimt-0-47$"
check "a4: invalid endpoint fails before FOU or GRE probes" \
	log_lacks "^ip fou add"
check "a4: invalid endpoint cannot mutate FRR" \
	vtysh_lacks "interface dimt-0-47"

# a4b: validate_endpoints() now shares is_quad() with the peer gate
# instead of carrying its own shape+range pair, so it inherits the
# leading-zero rejection.  Refusing here is strictly the safe direction:
# validate_endpoints returns before any delete, and `ip` would reject
# 010.0.2.47 downstream anyway (inet_pton has no octal).
new_state a4b
cat > "$TESTDIR/underlay-leading-zero" <<'EOF'
100.64.0.40 192.0.2.1
100.64.0.47 010.0.2.47
EOF
echo "dimt-0-47 192.0.2.1 192.0.2.2 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" \
	--endpoints-file "$TESTDIR/underlay-leading-zero" 2>&1)
rc=$?
check "a4b: leading-zero endpoint exits nonzero" [ "$rc" -ne 0 ]
check "a4b: leading-zero endpoint is named" err_has \
	"invalid managed underlay endpoint '010.0.2.47'"
check "a4b: it refuses before touching the live tunnel" \
	log_lacks "^ip link del dimt-0-47$"

# --- (b) missing peers file refuses ----------------------------------
new_state b
echo "dimt-9-9 100.64.0.40 100.64.9.9" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "b: missing peers file exits nonzero" [ "$rc" -ne 0 ]
check "b: refusal is logged" err_has "refusing to reconcile"
check "b: no ip link del issued" log_lacks "^ip link del"

# --- (c) empty peers file: GC gated on --allow-empty ------------------
new_state c
: > "$TESTDIR/peers-empty"
echo "dimt-9-9 100.64.0.40 100.64.9.9" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-empty" 2>&1)
rc=$?
check "c: empty set without --allow-empty exits 0" [ "$rc" -eq 0 ]
check "c: GC-skip warning is logged" err_has "skipping stale-tunnel GC"
check "c: no GC delete without --allow-empty" log_lacks "^ip link del dimt-9-9"

new_state c2
echo "dimt-9-9 100.64.0.40 100.64.9.9" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-empty" --allow-empty 2>&1)
rc=$?
check "c: --allow-empty exits 0" [ "$rc" -eq 0 ]
check "c: --allow-empty GCs the stale tunnel" log_has "^ip link del dimt-9-9$"

# --- (c3) coexistence: GC only touches this script's own names ---------
# zebra/pimd name their on-demand DIMT tunnels dimt-%08x (pim_dimt.c:1027,
# zebra_dimt.c:345).  A GC that swept every dimt-* deleted those on every
# cycle and zebra rebuilt them, so the two owners fought forever on any
# host running both.  GC is scoped to the names this script derives:
# dimt-<o3>-<o4> peers, plus its own leaked dimt-probe0.
new_state c3
echo "dimt-0a000001 100.64.0.40 100.64.0.99 gre" >> "$FAKEIP_DIR/links"
echo "dimt-9-9 100.64.0.40 100.64.9.9 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "c3: exits 0" [ "$rc" -eq 0 ]
check "c3: zebra dimt-%08x tunnel survives reconcile" \
	log_lacks "^ip link del dimt-0a000001"
check "c3: zebra tunnel still present afterwards" \
	grep -q "^dimt-0a000001 " "$FAKEIP_DIR/links"
check "c3: own stale dimt-<o3>-<o4> still GC'd" \
	log_has "^ip link del dimt-9-9$"

# Leaked own probe stays in GC's reach.  Asserted under --dry-run: in a
# real run gre_probe deletes dimt-probe0 itself before GC ever sees it.
new_state c4
echo "dimt-probe0 127.0.0.1 127.0.0.2 gre" >> "$FAKEIP_DIR/links"
echo "dimt-0a000001 100.64.0.40 100.64.0.99 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" --dry-run 2>&1)
check "c3: leaked own dimt-probe0 still GC'd" \
	err_has "DRY: ip link del dimt-probe0"
check "c3: --dry-run also spares dimt-%08x" \
	err_lacks "ip link del dimt-0a000001"

# --- (d) invalid peer entry: skipped, loud, GC suppressed --------------
new_state d
printf 'notanip\n100.64.0.47\n' > "$TESTDIR/peers-invalid"
echo "dimt-9-9 100.64.0.40 100.64.9.9" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-invalid" 2>&1)
rc=$?
check "d: invalid entry exits nonzero" [ "$rc" -ne 0 ]
check "d: invalid entry logged" err_has "ignoring invalid peer entry 'notanip'"
check "d: valid peer still processed" log_has "^ip link add dimt-0-47 "
check "d: GC suppressed (mangled entry may be a desired peer)" \
	log_lacks "^ip link del dimt-9-9"
check "d: GC suppression is logged" err_has "registry contained invalid entries"

# --- (d2) device-name collision: second peer skipped ------------------
new_state d2
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers 10.1.0.47,100.64.0.47 --peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "d2: collision exits nonzero" [ "$rc" -ne 0 ]
check "d2: collision names both peers" err_has \
	"peers 10.1.0.47 and 100.64.0.47 both derive device dimt-0-47"
check "d2: only one dimt-0-47 created" log_count "^ip link add dimt-0-47 " 1

# --- (d3) CRLF-mangled registry entry is sanitized ---------------------
new_state d3
printf '100.64.0.47\r\n' > "$TESTDIR/peers-crlf"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-crlf" 2>&1)
rc=$?
check "d3: CRLF entry exits 0" [ "$rc" -eq 0 ]
check "d3: CRLF entry is not treated as invalid" \
	err_lacks "invalid peer entry"
check "d3: CRLF entry is processed" log_has "^ip link add dimt-0-47 "

# --- (e) endpoint drift -> delete + recreate --------------------------
new_state e
echo "dimt-0-47 100.64.0.99 100.64.0.47 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "e: exit 0" [ "$rc" -eq 0 ]
check "e: drift is logged" err_has "endpoints drifted"
check "e: delete precedes recreate" \
	awk '/^ip link del dimt-0-47$/ { d = NR } /^ip link add dimt-0-47 / { a = NR }
	     END { exit !(d && a && d < a) }' "$FAKEIP_DIR/ip.log"
check "e: recreated with corrected endpoints" log_has \
	"^ip link add dimt-0-47 type gre local 100.64.0.40 remote 100.64.0.47 "

# --- (e2) pre-GRE ipip tunnel -> type migration recreate ---------------
new_state e2
echo "dimt-0-47 100.64.0.40 100.64.0.47 ipip" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "e2: exit 0" [ "$rc" -eq 0 ]
check "e2: type migration is logged" err_has "not a GRE tunnel"
check "e2: capability probe precedes the production delete" \
	awk '/^ip link add dimt-probe0 /{p=NR} /^ip link del dimt-0-47$/{d=NR}
	     END { exit !(p && d && p < d) }' "$FAKEIP_DIR/ip.log"
check "e2: delete precedes recreate" \
	awk '/^ip link del dimt-0-47$/ { d = NR } /^ip link add dimt-0-47 / { a = NR }
	     END { exit !(d && a && d < a) }' "$FAKEIP_DIR/ip.log"
check "e2: recreated as GRE with same endpoints" log_has \
	"^ip link add dimt-0-47 type gre local 100.64.0.40 remote 100.64.0.47 "
check "e2: dual-stack after migration" log_has \
	"^ip -6 addr add fd99::40 peer fd99::47/128 dev dimt-0-47$"

# --- (e3) stale fd99:: inner replaced, link-local untouched ------------
new_state e3
echo "dimt-0-47 100.64.0.40 100.64.0.47 gre" >> "$FAKEIP_DIR/links"
echo "dimt-0-47 inet 10.99.0.40 peer 10.99.0.47/32" >> "$FAKEIP_DIR/addrs"
echo "dimt-0-47 inet6 fd99::99 peer fd99::98/128" >> "$FAKEIP_DIR/addrs"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "e3: exit 0" [ "$rc" -eq 0 ]
check "e3: stale fd99 inner deleted" log_has \
	"^ip -6 addr del fd99::99 peer fd99::98/128 dev dimt-0-47$"
check "e3: correct v6 inner added" log_has \
	"^ip -6 addr add fd99::40 peer fd99::47/128 dev dimt-0-47$"
check "e3: correct v4 inner left alone" log_lacks "^ip -4 addr flush"
check "e3: v6 is never flushed wholesale" log_lacks "^ip -6 addr flush"

# --- (e4) FOU port taken by a non-GRE ipproto -> refuse before damage --
new_state e4
echo "port 6637 ipproto 4" > "$FAKEIP_DIR/fou"
echo "dimt-0-47 100.64.0.40 100.64.0.47 ipip" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "e4: wrong-proto binding exits nonzero" [ "$rc" -ne 0 ]
check "e4: collision is logged" err_has "bound to a non-GRE"
check "e4: no fou add issued" log_lacks "^ip fou add"
check "e4: production tunnel is NOT deleted" log_lacks "^ip link del dimt-0-47"
check "e4: no replacement tunnel created" log_lacks "^ip link add dimt-0-47"

# --- (e5) sub-1280 MTU warns (kernel disables IPv6) --------------------
new_state e5
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" --mtu 1200 2>&1)
rc=$?
check "e5: exit 0" [ "$rc" -eq 0 ]
check "e5: sub-1280 MTU is warned about" err_has "below the IPv6 minimum"

# --- (e6) kernel cannot create GRE -> refuse BEFORE deleting -----------
new_state e6
touch "$FAKEIP_DIR/fail-gre-add"
echo "dimt-0-47 100.64.0.40 100.64.0.47 ipip" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "e6: GRE-incapable kernel exits nonzero" [ "$rc" -ne 0 ]
check "e6: refusal is logged" err_has "cannot create a GRE-in-FOU netdev"
check "e6: production ipip tunnel survives" log_lacks "^ip link del dimt-0-47"
check "e6: FRR stanza is not removed" \
	vtysh_lacks "no interface dimt-0-47"

# --- (e7) FOU add fails (EPERM) -> refuse BEFORE deleting --------------
new_state e7
touch "$FAKEIP_DIR/fail-fou-add"
echo "dimt-0-47 100.64.0.40 100.64.0.47 ipip" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "e7: FOU EPERM exits nonzero" [ "$rc" -ne 0 ]
check "e7: pre-add hint is logged" err_has "pre-add it from the host"
check "e7: refusal is logged" err_has "blackhole inbound traffic"
check "e7: production ipip tunnel survives" log_lacks "^ip link del dimt-0-47"
check "e7: no GRE tunnel created" log_lacks "^ip link add dimt-0-47"

# --- (e8) one-sided migration: unreachable peer inner warns ------------
new_state e8
touch "$FAKEIP_DIR/ping-fail"
echo "dimt-0-47 100.64.0.40 100.64.0.47 ipip" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "e8: exit 0 (peer may just be down)" [ "$rc" -eq 0 ]
check "e8: silent-blackhole warning is loud" err_has "does not answer through"

# --- (e9) inner MTU + overhead vs outer path MTU ------------------------
new_state e9
echo "tailscale0 0.0.0.0 0.0.0.0 dummy" >> "$FAKEIP_DIR/links"
echo "tailscale0" > "$FAKEIP_DIR/route-dev"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" --mtu 1388 2>&1)
rc=$?
check "e9: oversized inner MTU warns (1388+32 > outer 1388)" \
	err_has "exceeds tailscale0 MTU 1388"

new_state e9b
echo "tailscale0 0.0.0.0 0.0.0.0 dummy" >> "$FAKEIP_DIR/links"
echo "tailscale0" > "$FAKEIP_DIR/route-dev"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" --mtu 1356 2>&1)
rc=$?
check "e9: fitting inner MTU does not warn (1356+32 = outer 1388)" \
	err_lacks "exceeds tailscale0"

# --- (e10) --dry-run previews the full migration, mutates nothing ------
new_state e10
echo "dimt-0-47 100.64.0.40 100.64.0.47 ipip" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" --dry-run 2>&1)
rc=$?
check "e10: exit 0" [ "$rc" -eq 0 ]
check "e10: previews the delete" err_has \
	"DRY: ip link del dimt-0-47"
check "e10: previews the recreate (netdev still exists after DRY del)" err_has \
	"DRY: ip link add dimt-0-47 type gre"
check "e10: previews the v6 inner add" err_has \
	"DRY: ip -6 addr add fd99::40 peer fd99::47/128 dev dimt-0-47"
check "e10: nothing is mutated" \
	grep -q "^dimt-0-47 100.64.0.40 100.64.0.47 ipip$" "$FAKEIP_DIR/links"
check "e10: no real delete issued" log_lacks "^ip link del dimt-0-47"

# --- (h) plain-GRE peer: no FOU anywhere on its path -------------------
# Vendor PEs terminate plain GRE.  A box whose registry is entirely
# plain GRE must not bind a FOU port, probe FOU capability, or put
# `encap fou` on the netdev.
new_state h
printf '100.64.0.47 gre\n' > "$TESTDIR/peers-plain"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-plain" 2>&1)
rc=$?
check "h: plain-GRE reconcile exits 0" [ "$rc" -eq 0 ]
check "h: creates the tunnel without encap fou" \
	awk '/^ip link add dimt-0-47 type gre local 100.64.0.40 remote 100.64.0.47 /
	     { if ($0 !~ /encap/) ok = 1 } END { exit !ok }' "$FAKEIP_DIR/ip.log"
check "h: no FOU port is bound for a plain-GRE-only registry" \
	log_lacks "^ip fou add"
check "h: no GRE-in-FOU capability probe" \
	log_lacks "^ip link add dimt-probe0 .* encap fou"
check "h: still probes plain GRE capability before touching anything" log_has \
	"^ip link add dimt-probe0 type gre local 127.0.0.1 remote 127.0.0.2 ttl 64 *$"
check "h: dual-stack inner addressing is unchanged" log_has \
	"^ip -6 addr add fd99::40 peer fd99::47/128 dev dimt-0-47$"
check "h: enrolled with FRR like any other peer" \
	grep -q "interface dimt-0-47" "$FAKEIP_DIR/vtysh.log"

new_state h0
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47=gre \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "h0: inline overlay=mode exits 0" [ "$rc" -eq 0 ]
check "h0: inline mode reaches the netdev" \
	awk '/^ip link add dimt-0-47 type gre / { if ($0 !~ /encap/) ok = 1 }
	     END { exit !ok }' "$FAKEIP_DIR/ip.log"

# --- (h2) encap flip gre-in-fou -> gre is drift ------------------------
new_state h2
echo "dimt-0-47 100.64.0.40 100.64.0.47 gre fou" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-plain" 2>&1)
rc=$?
check "h2: exit 0" [ "$rc" -eq 0 ]
check "h2: encap drift is logged" err_has \
	"encap mode drifted (gre-in-fou -> gre)"
check "h2: delete precedes recreate" \
	awk '/^ip link del dimt-0-47$/ { d = NR } /^ip link add dimt-0-47 / { a = NR }
	     END { exit !(d && a && d < a) }' "$FAKEIP_DIR/ip.log"
check "h2: recreated without FOU encapsulation" \
	awk '/^ip link add dimt-0-47 type gre / { if ($0 !~ /encap/) ok = 1 }
	     END { exit !ok }' "$FAKEIP_DIR/ip.log"
check "h2: FRR stanza is rebuilt after the recreate" \
	grep -q "no interface dimt-0-47" "$FAKEIP_DIR/vtysh.log"

# --- (h3) encap flip gre -> gre-in-fou is drift ------------------------
new_state h3
echo "dimt-0-47 100.64.0.40 100.64.0.47 gre none" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "h3: exit 0" [ "$rc" -eq 0 ]
check "h3: reverse encap drift is logged" err_has \
	"encap mode drifted (gre -> gre-in-fou)"
check "h3: recreated with FOU encapsulation" log_has \
	"^ip link add dimt-0-47 type gre local 100.64.0.40 remote 100.64.0.47 ttl 64 encap fou "

# --- (h4) a matching encap mode is NOT drift (no churn every cycle) ----
new_state h4
echo "dimt-0-47 100.64.0.40 100.64.0.47 gre none" >> "$FAKEIP_DIR/links"
echo "dimt-0-47 inet 10.99.0.40 peer 10.99.0.47/32" >> "$FAKEIP_DIR/addrs"
echo "dimt-0-47 inet6 fd99::40 peer fd99::47/128" >> "$FAKEIP_DIR/addrs"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-plain" 2>&1)
rc=$?
check "h4: exit 0" [ "$rc" -eq 0 ]
check "h4: steady-state plain-GRE peer is not recreated" \
	log_lacks "^ip link del dimt-0-47"
check "h4: no encap-drift log on a matching mode" err_lacks "encap mode drifted"

# --- (h5) FOU failure must not take plain-GRE peers down ---------------
# Mixed registry, FOU binding unavailable (EPERM).  The gre-in-fou peer
# is skipped with its tunnel intact; the plain-GRE peer reconciles.
new_state h5
touch "$FAKEIP_DIR/fail-fou-add"
printf '100.64.0.47 gre\n100.64.0.48 gre-in-fou\n' > "$TESTDIR/peers-mixed"
echo "dimt-0-48 100.64.0.40 100.64.0.48 gre fou" >> "$FAKEIP_DIR/links"
echo "dimt-9-9 100.64.0.40 100.64.9.9 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-mixed" 2>&1)
rc=$?
check "h5: run still exits nonzero (the FOU peer did not reconcile)" \
	[ "$rc" -ne 0 ]
check "h5: FOU refusal names the scope" err_has \
	"refusing to reconcile gre-in-fou peers"
check "h5: the plain-GRE peer is still created" \
	awk '/^ip link add dimt-0-47 type gre / { if ($0 !~ /encap/) ok = 1 }
	     END { exit !ok }' "$FAKEIP_DIR/ip.log"
check "h5: the plain-GRE peer is still enrolled with FRR" \
	grep -q "interface dimt-0-47" "$FAKEIP_DIR/vtysh.log"
check "h5: the FOU peer is skipped, not reconciled" err_has \
	"skipping peer 100.64.0.48"
check "h5: the FOU peer's live tunnel is left untouched" \
	log_lacks "^ip link del dimt-0-48"
check "h5: the FOU peer is still held out of GC's reach" \
	grep -q "^dimt-0-48 " "$FAKEIP_DIR/links"
check "h5: genuinely stale tunnels are still GC'd" \
	log_has "^ip link del dimt-9-9$"

# The mirror case: ip_gre present but FOU encap unsupported.  Plain-GRE
# peers reconcile; the FOU peer fails its own probe only.
new_state h5b
touch "$FAKEIP_DIR/fail-fou-gre-add"
echo "dimt-0-48 100.64.0.40 100.64.0.48 gre fou" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-mixed" 2>&1)
rc=$?
check "h5b: exits nonzero" [ "$rc" -ne 0 ]
check "h5b: GRE-in-FOU probe failure is scoped" err_has \
	"refusing to reconcile gre-in-fou peers"
check "h5b: plain-GRE peer still reconciles" log_has "^ip link add dimt-0-47 "
check "h5b: FOU peer's tunnel survives" log_lacks "^ip link del dimt-0-48"

# --- (h6) unknown encap mode: loud, skipped, GC suppressed -------------
new_state h6
printf '100.64.0.47 wireguard\n' > "$TESTDIR/peers-badmode"
echo "dimt-9-9 100.64.0.40 100.64.9.9 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-badmode" 2>&1)
rc=$?
check "h6: unknown mode exits nonzero" [ "$rc" -ne 0 ]
check "h6: unknown mode is named" err_has "unknown encap mode 'wireguard'"
check "h6: no tunnel created for it" log_lacks "^ip link add dimt-0-47"
check "h6: GC suppressed (the entry may be a desired peer)" \
	log_lacks "^ip link del dimt-9-9"

# --- (h6b) a THIRD column is loud, not silently dropped ----------------
# The parser used to keep $1/$2 and discard the rest, so this parsed as a
# perfectly valid plain-GRE peer.  It is the last silent repair that was
# left after "100.64. 0.47" was made to fail the dotted-quad check.
new_state h6b
printf '100.64.0.47 gre extra\n' > "$TESTDIR/peers-junk"
echo "dimt-9-9 100.64.0.40 100.64.9.9 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-junk" 2>&1)
rc=$?
check "h6b: a trailing field exits nonzero" [ "$rc" -ne 0 ]
check "h6b: the offending mode is echoed back" err_has \
	"invalid encap mode 'gre=extra'"
check "h6b: not mistaken for a valid gre peer" log_lacks "^ip link add dimt-0-47"
check "h6b: GC suppressed (the entry may be a desired peer)" \
	log_lacks "^ip link del dimt-9-9"
# Same line from --peers, where the field separator is a comma.
new_state h6b2
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers '100.64.0.47 gre extra' \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "h6b2: inline trailing field exits nonzero" [ "$rc" -ne 0 ]
check "h6b2: inline trailing field is named" err_has \
	"invalid encap mode"

# --- (h6b3) a two-column entry whose mode contains "=" -----------------
# peers() joins fields with "=", so this reaches the same arm as a third
# column with the field count already gone.  The arm must not assert a
# trailing field that does not exist, and must echo the mode verbatim:
# rewriting the operator's literal "=" back to a space produced a string
# that does not occur anywhere in their peers file.
new_state h6b3
printf '100.64.0.47 gre=x\n' > "$TESTDIR/peers-eq"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-eq" 2>&1)
rc=$?
check "h6b3: a mode containing = exits nonzero" [ "$rc" -ne 0 ]
check "h6b3: the mode is echoed verbatim, = intact" err_has \
	"invalid encap mode 'gre=x'"
check "h6b3: no trailing field is asserted" err_lacks "trailing field"
check "h6b3: the echoed mode still matches the peers file" \
	grep -q "gre=x" "$TESTDIR/peers-eq"
check "h6b3: not mistaken for a valid gre peer" log_lacks "^ip link add dimt-0-47"

# --- (h6d) a malformed overlay arms no capability gate ----------------
# encap_of() defaults an absent mode to gre-in-fou, so a bare junk line
# used to set want_fou and run ensure_fou() -- a real `ip fou add` bind,
# not a probe -- on a box whose registry is otherwise all plain GRE, and
# only then be rejected by the dotted-quad check.  h6/h6b cannot see
# this: their junk yields modes ("0.47", "gre=extra") that arm nothing.
new_state h6d
printf '100.64.0.47 gre\ngarbage\n' > "$TESTDIR/peers-garbage"
echo "dimt-9-9 100.64.0.40 100.64.9.9 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-garbage" 2>&1)
rc=$?
check "h6d: a bare junk line exits nonzero" [ "$rc" -ne 0 ]
check "h6d: the junk line is rejected by name" err_has \
	"ignoring invalid peer entry 'garbage'"
check "h6d: no FOU port is bound on its behalf" log_lacks "^ip fou add"
check "h6d: no GRE-in-FOU probe on its behalf" \
	log_lacks "^ip link add dimt-probe0 .* encap fou"
check "h6d: the valid plain-GRE peer still builds" \
	awk '/^ip link add dimt-0-47 type gre / { if ($0 !~ /encap/) ok = 1 }
	     END { exit !ok }' "$FAKEIP_DIR/ip.log"
check "h6d: GC suppressed (the entry may be a desired peer)" \
	log_lacks "^ip link del dimt-9-9"
# The explicit-mode twin: "garbage=gre" must not run the plain-GRE probe.
new_state h6d2
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers garbage=gre \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "h6d2: a malformed explicit-mode overlay exits nonzero" [ "$rc" -ne 0 ]
check "h6d2: no capability probe runs on its behalf" \
	log_lacks "^ip link add dimt-probe0"

# --- (h6e) the documented collision residual, pinned -------------------
# The comment above want_fou admits this hole rather than asserting it
# away: the dedupe runs inside the build loop, so a collision-losing
# peer arms its mode's gate first and binds the FOU port on a box that
# builds only plain GRE.  Pinned here so the deferred dedupe-hoist has
# a failing assertion to flip instead of a paragraph to re-derive.
# The BOUND is pinned by two assertions, named here rather than
# numbered because an ordinal breaks the moment one is inserted:
#   "GC is NOT suppressed on the collision path"
#   "the contested device survives GC"
# It is not what it looks like: the collision branch sets rc=1 without
# invalid=1, so GC is NOT suppressed the way it is for a malformed
# entry (contrast h6d).  What keeps the contested device safe is the
# winning peer having already put it in want.  By contrast
#   "the residual FOU bind happens anyway"
# is the HOLE this block exists to disclose -- not the safety property.
new_state h6e
echo "dimt-9-9 100.64.0.40 100.64.9.9 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers 100.64.0.47=gre,100.65.0.47=gre-in-fou \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "h6e: a colliding pair exits nonzero" [ "$rc" -ne 0 ]
check "h6e: the collision is named" err_has "both derive device dimt-0-47"
check "h6e: the residual FOU bind happens anyway (documented hole)" \
	log_has "^ip fou add port 6637 ipproto 47"
check "h6e: GC is NOT suppressed on the collision path" \
	log_has "^ip link del dimt-9-9"
check "h6e: the contested device survives GC (winner put it in want)" \
	log_lacks "^ip link del dimt-0-47"

# --- (h6c) both valid grammars still build a plain-GRE tunnel ----------
# Positive control for h6b: the field-joining that makes a third column
# loud must not break the two documented forms.  The file's two-column
# form is exercised throughout (peers-plain); this pins the inline form,
# where the mode arrives already glued on with "=".
new_state h6c
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47=gre \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "h6c: inline <overlay>=<mode> exits zero" [ "$rc" -eq 0 ]
check "h6c: inline form creates an unencapsulated GRE tunnel" \
	awk '/^ip link add dimt-0-47 type gre / { if ($0 !~ /encap/) ok = 1 }
	     END { exit !ok }' "$FAKEIP_DIR/ip.log"
new_state h6c2
printf '100.64.0.47 gre\n100.64.0.48\n' > "$TESTDIR/peers-mixed"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-mixed" 2>&1)
rc=$?
check "h6c2: mixed explicit/absent modes exit zero" [ "$rc" -eq 0 ]
check "h6c2: the explicit gre peer is unencapsulated" \
	awk '/^ip link add dimt-0-47 type gre / { if ($0 !~ /encap/) ok = 1 }
	     END { exit !ok }' "$FAKEIP_DIR/ip.log"
check "h6c2: the absent-mode peer defaults to gre-in-fou" log_has \
	"^ip link add dimt-0-48 type gre local 100.64.0.40 remote 100.64.0.48 ttl 64 encap fou "

# --- (h6f) an out-of-range octet is MALFORMED, not a collision --------
# is_quad() used to check only the shape, so 100.64.999.20 reached the
# build loop and derived dimt-999-20 plus nonsense inner addresses.
# The disposition is pinned here, not just the rejection: this takes the
# invalid=1 path (GC suppressed run-wide), NOT the collision path's
# rc=1-and-carry-on (h6e).  The difference is that a collision has a
# WINNER holding the contested device in want; a mangled octet has none,
# and dev_of() reads octets 3-4, so the device the operator meant is in
# nobody's want and GC would reap it.
new_state h6f
printf '100.64.0.47 gre\n100.64.999.20 gre\n' > "$TESTDIR/peers-oor"
echo "dimt-9-9 100.64.0.40 100.64.9.9 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-oor" 2>&1)
rc=$?
check "h6f: an out-of-range octet exits nonzero" [ "$rc" -ne 0 ]
check "h6f: the offending entry is named" err_has \
	"ignoring invalid peer entry '100.64.999.20'"
check "h6f: no tunnel is derived from the bad octet" \
	log_lacks "^ip link add dimt-999-20"
check "h6f: GC suppressed (invalid=1, not the collision path)" \
	log_lacks "^ip link del dimt-9-9"
check "h6f: the valid peer alongside it still builds" \
	awk '/^ip link add dimt-0-47 type gre / { if ($0 !~ /encap/) ok = 1 }
	     END { exit !ok }' "$FAKEIP_DIR/ip.log"

# --- (h6f2) a leading zero ALIASES, so it is malformed too ------------
# 100.64.010.20 and 100.64.10.20 are one address written two ways, but
# dev_of() is textual: they derive dimt-010-20 and dimt-10-20, i.e. two
# netdevs for one peer.  (010 is also octal to inet_aton.)
new_state h6f2
printf '100.64.0.47 gre\n100.64.010.20 gre\n' > "$TESTDIR/peers-lz"
echo "dimt-9-9 100.64.0.40 100.64.9.9 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-lz" 2>&1)
rc=$?
check "h6f2: a leading-zero octet exits nonzero" [ "$rc" -ne 0 ]
check "h6f2: the leading-zero entry is named" err_has \
	"ignoring invalid peer entry '100.64.010.20'"
check "h6f2: no aliased device is created" log_lacks "^ip link add dimt-010-20"
check "h6f2: GC suppressed (invalid=1)" log_lacks "^ip link del dimt-9-9"

# --- (h6f3) an out-of-range overlay arms no capability gate -----------
# The :is_quad pre-scan twin of h6d, and the only assertion that covers
# the OTHER is_quad() caller.  encap_of() defaults the absent mode to
# gre-in-fou, so while is_quad checked shape only, this line set want_fou
# and ran ensure_fou() -- a real `ip fou add` bind -- on a box whose
# registry is otherwise all plain GRE, and only then got rejected.
new_state h6f3
printf '100.64.0.47 gre\n100.64.999.20\n' > "$TESTDIR/peers-oor-bare"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-oor-bare" 2>&1)
rc=$?
check "h6f3: a bare out-of-range overlay exits nonzero" [ "$rc" -ne 0 ]
check "h6f3: no FOU port is bound on its behalf" log_lacks "^ip fou add"
check "h6f3: no GRE-in-FOU probe on its behalf" \
	log_lacks "^ip link add dimt-probe0 .* encap fou"
check "h6f3: the valid plain-GRE peer still builds" \
	awk '/^ip link add dimt-0-47 type gre / { if ($0 !~ /encap/) ok = 1 }
	     END { exit !ok }' "$FAKEIP_DIR/ip.log"

# --- (h6f4) positive control: the range boundaries still build --------
# Guards the other direction.  A tightened quad regex that fumbles the
# 200-255 alternation, or that forbids a bare 0, would silently stop
# building real peers -- a far worse failure than the one h6f fixes.
new_state h6f4
printf '100.64.255.255 gre\n100.64.0.0 gre\n' > "$TESTDIR/peers-bounds"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-bounds" 2>&1)
rc=$?
check "h6f4: boundary octets exit zero" [ "$rc" -eq 0 ]
check "h6f4: 255.255 builds" log_has \
	"^ip link add dimt-255-255 type gre local 100.64.0.40 remote 100.64.255.255 "
check "h6f4: a bare 0 octet builds" log_has \
	"^ip link add dimt-0-0 type gre local 100.64.0.40 remote 100.64.0.0 "
check "h6f4: nothing was called invalid" err_lacks "ignoring invalid peer entry"

# --- (h6f5) --self is the FOURTH address consumer --------------------
# It was only checked non-empty, then flowed into inner_of/inner6_of and
# the local endpoint.  It also decides the self-skip, which is a TEXTUAL
# compare (`[ "$peer" = "$SELF" ]`), so an unvalidated --self would not
# match an equivalent-but-differently-written peer and the box would
# build a tunnel to itself.
new_state h6f5
echo "dimt-9-9 100.64.0.40 100.64.9.9 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.999.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "h6f5: an out-of-range --self exits nonzero" [ "$rc" -ne 0 ]
check "h6f5: --self is named in the refusal" err_has \
	"--self must be a dotted quad: '100.64.999.40'"
check "h6f5: it refuses before touching the live tunnel" \
	log_lacks "^ip link del dimt-9-9"
check "h6f5: no tunnel is derived from the bad --self" \
	log_lacks "^ip link add dimt-0-47"

# h6f5b: the self-skip aliasing case.  --self 100.64.010.40 is the same
# address as the peers file's 100.64.0.40-equivalent written with a
# leading zero; textual self-skip would miss it and dimt-0-47 would be
# built against a self that inner_of() renders as 10.99.010.40.
new_state h6f5b
err=$($RUN_SH "$RECONCILE" --self 100.64.010.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "h6f5b: a leading-zero --self exits nonzero" [ "$rc" -ne 0 ]
check "h6f5b: the aliased --self is named" err_has \
	"--self must be a dotted quad: '100.64.010.40'"
check "h6f5b: no aliased inner address is configured" \
	log_lacks "10.99.010.40"

# h6f5c: positive control for the gate's PLACEMENT, not its regex.  The
# gate sits next to the `-n "$SELF"` test, which only works because
# is_quad() is defined up by log().  Move that definition back down
# among the other address helpers and the call becomes `command not
# found` -> rc 127 -> the `||` fires and EVERY --self is rejected, valid
# ones included.  Every other test here passes a valid --self and so is
# also a control for that; this one just says so out loud.
new_state h6f5c
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "h6f5c: a valid --self still exits zero" [ "$rc" -eq 0 ]
check "h6f5c: a valid --self still builds its peer" log_has \
	"^ip link add dimt-0-47 "
check "h6f5c: a valid --self is never called malformed" err_lacks \
	"--self must be a dotted quad"

# h6f5d: is_quad's grep is LINE-oriented, so '^...$' alone accepts an
# embedded newline -- the anchors match the first line and grep -q
# succeeds on any matching line, so "1.2.3.4\n9.9.9.9" built a device.
# Only reachable via --self: peers() splits on whitespace ($1) and
# endpoint_of() prints one field, so neither file path can carry one.
new_state h6f5d
err=$($RUN_SH "$RECONCILE" --self "$(printf '100.64.0.40\n9.9.9.9')" \
	--peers 100.64.0.47 --peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "h6f5d: a multi-line --self exits nonzero" [ "$rc" -ne 0 ]
check "h6f5d: the multi-line --self is named" err_has \
	"--self must be a dotted quad"
check "h6f5d: no device is derived from it" log_lacks "ip link add "

# --- (h6f6) the gate is escape-proof under a POSIX echo --------------
# `echo "$1" | grep -Eq` is escape-sensitive: under dash (advertised at
# the top of this file as a supported interpreter) `echo "1.2.3.4\c"`
# emits "1.2.3.4" and swallows the rest, so is_quad returned TRUE for a
# token that still carried the backslash -- and dev_of() then derived a
# device name from it.  printf '%s\n' has no such behaviour, which is
# why every address helper and log() now use it.
# NOTE: this only fails pre-fix under an interpreter whose echo expands
# backslashes (dash/ash, not bash), so run the suite under both.
# The assertions below are deliberately NOT ^-anchored: \c suppresses the
# newline on the fake ip's own log writes too, so pre-fix the log reads
# "...get 100.64.0.4ip link show dimt-0-4ip link add dimt-0-4ip link set..."
# as ONE line and every anchored pattern silently misses.  The blast
# radius is bigger than a bad return value: a dimt-0-4 netdev is really
# created, and the reconciler's own log framing is corrupted.
new_state h6f6
printf '100.64.0.47 gre\n100.64.0.4\\c gre\n' > "$TESTDIR/peers-esc"
echo "dimt-9-9 100.64.0.40 100.64.9.9 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-esc" 2>&1)
rc=$?
check "h6f6: a backslash-bearing token exits nonzero" [ "$rc" -ne 0 ]
check "h6f6: the escaped entry is named" err_has \
	"ignoring invalid peer entry"
check "h6f6: no device is derived from the escaped token" \
	log_lacks "ip link add dimt-0-4[^7]"
check "h6f6: GC suppressed (invalid=1)" log_lacks "^ip link del dimt-9-9"
check "h6f6: the valid peer alongside it still builds" log_has \
	"^ip link add dimt-0-47 "

# --- (h6f7) the MODE field is escape-proof under a POSIX echo ---------
# h6f6 pins the peer token; the mode field reaches the same hazard by a
# different route.  encap_of() and log() both use printf for this reason,
# and neither had a failing mutation until now (Ally, frr#117 review at
# c5533c16).  Reverting encap_of() to `echo "${1#*=}"` under dash turns
# the spec "100.64.0.48=gre\c" into mode "gre", which matches the valid
# `gre` arm -- a malformed mode is ACCEPTED and a netdev really built,
# with the suite otherwise green.  Reverting log() instead leaves the
# mode intact, but dash's echo eats the backslash AND the newline it
# would have printed: the tail of the message vanishes and the next
# diagnostic -- the GC-suppression WARNING -- is swallowed onto the same
# line.
#
# Which assertion pins which guard, measured one revert per run:
#   encap_of  -> 1 2 3 5 6 fail
#   log       -> 3 and 4 fail, and nothing else
# 4 is log's alone: encap_of's failure mode ACCEPTS the mode, so nothing is
# ever malformed, no second diagnostic follows, and no newline is lost.
# 3 and 4 are NOT a redundant pair: 3 dies when the message tail is lost,
# 4 when the newline is.  4 asserts the MECHANISM rather than a neighbour
# -- a lost newline concatenates whatever is emitted next onto the
# truncated line, so that line carries two "dimt-reconcile: " prefixes --
# and so it dies regardless of 3's wording AND regardless of what follows.
# It was previously anchored on the WARNING being the next emission, which
# made it go INERT (silently pass) if any diagnostic was inserted between
# the two, while the newline loss was still happening.  Ally caught that at
# frr#117 review 5360486212; don't re-introduce an adjacency assumption.
# Keep both.  Assertion 2 belongs to encap_of -- trimming it "because 2
# and 3 both assert the diagnostic" would leave log() pinned by 3 alone.
#
# These fail only when the SCRIPT UNDER TEST runs under an interpreter
# whose echo expands backslashes -- that is $RUN_SH, not the shell
# running this harness.  The CI job sets DIMT_TEST_SH explicitly per step
# for exactly that reason: with /bin/sh -> bash and DIMT_TEST_SH unset,
# this whole class goes inert while the suite still prints green.
new_state h6f7
printf '100.64.0.47 gre\n100.64.0.48 gre\\c\n' > "$TESTDIR/peers-mode-esc"
echo "dimt-9-9 100.64.0.40 100.64.9.9 gre" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-mode-esc" 2>&1)
rc=$?
check "h6f7: a backslash-bearing mode exits nonzero" [ "$rc" -ne 0 ]
check "h6f7: the mode is rejected, not silently accepted as gre" err_has \
	"unknown encap mode"
check "h6f7: the message survives the backslash intact" err_has \
	"(expected gre or gre-in-fou)"
check "h6f7: no diagnostic loses its newline" err_lacks \
	"dimt-reconcile: .*dimt-reconcile: "
check "h6f7: no device is derived from the escaped mode" \
	log_lacks "ip link add dimt-0-48"
check "h6f7: GC suppressed (invalid=1)" log_lacks "^ip link del dimt-9-9"
check "h6f7: the valid peer alongside it still builds" log_has \
	"^ip link add dimt-0-47 "

# --- (h7) one overlay listed twice under conflicting modes -------------
new_state h7
printf '100.64.0.47 gre\n100.64.0.47 gre-in-fou\n' > "$TESTDIR/peers-conflict"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-conflict" 2>&1)
rc=$?
check "h7: conflicting modes exit nonzero" [ "$rc" -ne 0 ]
check "h7: the conflict is diagnosed as a duplicate, not a /16 collision" \
	err_has "listed twice with conflicting encap modes"
check "h7: only one dimt-0-47 created (no per-cycle flip-flop)" \
	log_count "^ip link add dimt-0-47 " 1

# --- (h8) plain GRE overhead is 24B, not GRE-in-FOU's 32B --------------
new_state h8
echo "tailscale0 0.0.0.0 0.0.0.0 dummy" >> "$FAKEIP_DIR/links"
echo "tailscale0" > "$FAKEIP_DIR/route-dev"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-plain" --mtu 1364 2>&1)
check "h8: plain GRE fits where GRE-in-FOU would not (1364+24 = 1388)" \
	err_lacks "exceeds tailscale0"
new_state h8b
echo "tailscale0 0.0.0.0 0.0.0.0 dummy" >> "$FAKEIP_DIR/links"
echo "tailscale0" > "$FAKEIP_DIR/route-dev"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 --mtu 1364 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
check "h8b: the same MTU overflows under GRE-in-FOU (1364+32 > 1388)" \
	err_has "1364 + 32B GRE-in-FOU overhead"

# --- (h9) a single-column registry keeps the pre-existing behavior -----
new_state h9
printf '  100.64.0.47  \n' > "$TESTDIR/peers-padded"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-padded" 2>&1)
rc=$?
check "h9: padded single-column entry exits 0" [ "$rc" -eq 0 ]
check "h9: defaults to gre-in-fou" log_has \
	"^ip link add dimt-0-47 type gre local 100.64.0.40 remote 100.64.0.47 ttl 64 encap fou "

# --- (h10) a THIRD encap type is drift, not "plain GRE" ---------------
# `ip link add type gre` also takes gue/mpls.  Classifying anything that
# is not `encap fou` as plain GRE made an `encap gue` tunnel compare equal
# to a `gre` registry row, so the wrongly-encapsulated netdev survived.
new_state h10
echo "dimt-0-47 100.64.0.40 100.64.0.47 gre gue" >> "$FAKEIP_DIR/links"
echo "dimt-0-47 inet 10.99.0.40 peer 10.99.0.47/32" >> "$FAKEIP_DIR/addrs"
echo "dimt-0-47 inet6 fd99::40 peer fd99::47/128" >> "$FAKEIP_DIR/addrs"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-plain" 2>&1)
rc=$?
check "h10: exit 0" [ "$rc" -eq 0 ]
check "h10: a non-FOU encap is not mistaken for plain GRE" err_has \
	"encap mode drifted (other -> gre)"
check "h10: the gue tunnel is deleted" log_has "^ip link del dimt-0-47$"
check "h10: delete precedes recreate" \
	awk '/^ip link del dimt-0-47$/ { d = NR } /^ip link add dimt-0-47 / { a = NR }
	     END { exit !(d && a && d < a) }' "$FAKEIP_DIR/ip.log"
check "h10: recreated as unencapsulated GRE" \
	awk '/^ip link add dimt-0-47 type gre / { if ($0 !~ /encap/) ok = 1 }
	     END { exit !ok }' "$FAKEIP_DIR/ip.log"

# --- (h11) the registry is read exactly once per reconcile ------------
# The capability pre-scan and the build loop must see the same snapshot.
# If they re-read $PEERS_FILE independently, a rewrite between them lets a
# peer be plain-GRE for the FOU gate and gre-in-fou for the netdev create,
# so `encap fou` is configured against a port ensure_fou never bound.
# That race has no deterministic behavioural fixture -- it needs the file
# to change mid-run -- so this pins the structural property instead: no
# peers() call survives anywhere except the single snapshot assignment.
check "h11: reconcile snapshots the registry once" \
	[ "$(grep -c '\$(peers)' "$RECONCILE")" -eq 1 ]
check "h11: the one call is the snapshot assignment" \
	grep -q '^	all_peers=\$(peers)$' "$RECONCILE"
check "h11: validate_endpoints consumes the snapshot" \
	grep -q 'validate_endpoints "\$all_peers"' "$RECONCILE"

# --- (h12) both registry grammars parse on both paths -----------------
# `overlay=mode` and `overlay mode` are one grammar accepted on both the
# file and the inline path; that was load-bearing and untested.
new_state h12
printf '100.64.0.47=gre\n' > "$TESTDIR/peers-eq"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-eq" 2>&1)
rc=$?
check "h12: file path accepts overlay=mode" [ "$rc" -eq 0 ]
check "h12: file overlay=mode yields plain GRE" \
	awk '/^ip link add dimt-0-47 type gre / { if ($0 !~ /encap/) ok = 1 }
	     END { exit !ok }' "$FAKEIP_DIR/ip.log"
new_state h12b
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers "100.64.0.60 gre" \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "h12b: inline path accepts space-separated mode" [ "$rc" -eq 0 ]
check "h12b: inline space form yields plain GRE" \
	awk '/^ip link add dimt-0-60 type gre / { if ($0 !~ /encap/) ok = 1 }
	     END { exit !ok }' "$FAKEIP_DIR/ip.log"

# --- (f) --watch rejects non-numeric ----------------------------------
new_state f
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --watch abc 2>&1)
rc=$?
check "f: --watch abc exits nonzero" [ "$rc" -ne 0 ]
check "f: --watch abc error message" err_has "watch requires a number of seconds"

# --- (g) usage prints the whole header incl. --allow-empty ------------
new_state g
err=$($RUN_SH "$RECONCILE" --bogus 2>&1)
rc=$?
check "g: unknown flag exits nonzero" [ "$rc" -ne 0 ]
check "g: usage mentions the refuse-outright safety" err_has "REFUSED outright"
check "g: usage prints the last header line" err_has "\[--allow-empty\]"
# usage() prints the header block verbatim, so a reflow artifact in the
# comment is user-visible in `-h`.  Pins the sentence that was stranded
# as a three-word line mid-paragraph.
check "g: the MTU sentence is not broken mid-clause" err_has \
	"An MTU below 1280 leaves the tunnels v4-only"

echo
if [ "$FAILS" -gt 0 ]; then
	echo "$FAILS test(s) FAILED"
	exit 1
fi
echo "all tests passed"
exit 0
