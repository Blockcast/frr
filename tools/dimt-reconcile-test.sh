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
#   fail-gre-add -- every `ip link add ... type gre` fails (no kmod-gre)
#   fail-fou-add -- `ip fou add` fails (EPERM in unprivileged container)
#   ping-fail    -- the inner-address ping probe fails (one-sided flip)

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
#   links  -- one line per netdev: "<dev> <local> <remote> [<type>]"
#             (type defaults to ipip so pre-GRE state can be seeded)
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
	echo "7: $dev: <POINTOPOINT,MULTICAST,UP> mtu 1388 qdisc noqueue state UNKNOWN"
	if [ "$detail" = 1 ]; then
		echo "    link/$typ $2 peer $3"
		echo "    $typ remote $3 local $2 ttl 64 encap fou encap-sport auto encap-dport 6637"
	fi
	exit 0
	;;
link/add)
	dev="$1"; shift
	loc=""; rem=""; typ=""
	while [ $# -gt 0 ]; do
		case "$1" in
		type) typ="$2"; shift 2 ;;
		local) loc="$2"; shift 2 ;;
		remote) rem="$2"; shift 2 ;;
		*) shift ;;
		esac
	done
	if [ "$typ" = gre ] && [ -f "$FAKEIP_DIR/fail-gre-add" ]; then
		exit 2
	fi
	echo "$dev $loc $rem ${typ:-ipip}" >> "$LINKS"
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

echo
if [ "$FAILS" -gt 0 ]; then
	echo "$FAILS test(s) FAILED"
	exit 1
fi
echo "all tests passed"
exit 0
