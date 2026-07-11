#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Self-contained test for tools/dimt-reconcile.sh.  Needs no root and no
# network: a fake `ip` on PATH keeps link/addr/fou state in flat files
# under a temp dir and logs every invocation; a fake `vtysh` logs and
# succeeds.  Run as: sh tools/dimt-reconcile-test.sh
# (set DIMT_TEST_SH=dash/busybox-ash to exercise another interpreter).

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
#   links  -- one line per netdev: "<dev> <local> <remote>"
#   addrs  -- one line per address: "<dev> inet <a> peer <p>/32"
#   fou    -- verbatim `ip fou show` output
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
while [ $# -gt 0 ]; do
	case "$1" in
	-d) detail=1; shift ;;
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
	echo "$* " >> "$FAKEIP_DIR/fou"
	exit 0
	;;
link/show)
	dev="${1:-}"
	if [ -z "$dev" ]; then
		i=1
		[ -f "$LINKS" ] || exit 0
		while read -r d loc rem; do
			: "$loc" "$rem"
			echo "$i: $d: <POINTOPOINT,MULTICAST,UP> mtu 1252 qdisc noqueue state UNKNOWN"
			i=$((i + 1))
		done < "$LINKS"
		exit 0
	fi
	line=$(grep "^$dev " "$LINKS" 2>/dev/null | head -n 1)
	[ -n "$line" ] || exit 1
	set -- $line
	echo "7: $dev: <POINTOPOINT,MULTICAST,UP> mtu 1252 qdisc noqueue state UNKNOWN"
	if [ "$detail" = 1 ]; then
		echo "    ipip remote $3 local $2 ttl 64 encap fou encap-sport auto encap-dport 6636"
	fi
	exit 0
	;;
link/add)
	dev="$1"; shift
	loc=""; rem=""
	while [ $# -gt 0 ]; do
		case "$1" in
		local) loc="$2"; shift 2 ;;
		remote) rem="$2"; shift 2 ;;
		*) shift ;;
		esac
	done
	echo "$dev $loc $rem" >> "$LINKS"
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
		*) shift ;;
		esac
	done
	grep "^$dev " "$ADDRS" 2>/dev/null | sed "s/^$dev /    /"
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
	grep -v "^$dev " "$ADDRS" > "$ADDRS.tmp" 2>/dev/null || true
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
	echo "$dev inet $a peer $peer" >> "$ADDRS"
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
	echo "port 6636 ipproto 4" > "$FAKEIP_DIR/fou"
	: > "$FAKEIP_DIR/links"
	: > "$FAKEIP_DIR/addrs"
	: > "$FAKEIP_DIR/ip.log"
	: > "$FAKEIP_DIR/vtysh.log"
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

# --- (a) inner_of/dev_of derivation ----------------------------------
new_state a
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "a: exit 0" [ "$rc" -eq 0 ]
check "a: creates dimt-0-47 with correct endpoints" log_has \
	"^ip link add dimt-0-47 type ipip local 100.64.0.40 remote 100.64.0.47 "
check "a: addresses inner(self) peer inner(peer)" log_has \
	"^ip addr add 10.99.0.40 peer 10.99.0.47/32 dev dimt-0-47$"
check "a: enrolls dimt-0-47 with FRR" \
	grep -q "interface dimt-0-47" "$FAKEIP_DIR/vtysh.log"
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
check "c: no GC delete without --allow-empty" log_lacks "^ip link del"

new_state c2
echo "dimt-9-9 100.64.0.40 100.64.9.9" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-empty" --allow-empty 2>&1)
rc=$?
check "c: --allow-empty exits 0" [ "$rc" -eq 0 ]
check "c: --allow-empty GCs the stale tunnel" log_has "^ip link del dimt-9-9$"

# --- (d) invalid peer entry skipped, valid one processed --------------
new_state d
printf 'notanip\n100.64.0.47\n' > "$TESTDIR/peers-invalid"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers-file "$TESTDIR/peers-invalid" 2>&1)
rc=$?
check "d: exit 0" [ "$rc" -eq 0 ]
check "d: invalid entry logged" err_has "ignoring invalid peer entry 'notanip'"
check "d: valid peer still processed" log_has "^ip link add dimt-0-47 "

# --- (d2) device-name collision: second peer skipped ------------------
new_state d2
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 \
	--peers 10.1.0.47,100.64.0.47 --peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "d2: collision exits nonzero" [ "$rc" -ne 0 ]
check "d2: collision names both peers" err_has \
	"peers 10.1.0.47 and 100.64.0.47 both derive device dimt-0-47"
check "d2: only one dimt-0-47 created" log_count "^ip link add dimt-0-47 " 1

# --- (e) endpoint drift -> delete + recreate --------------------------
new_state e
echo "dimt-0-47 100.64.0.99 100.64.0.47" >> "$FAKEIP_DIR/links"
err=$($RUN_SH "$RECONCILE" --self 100.64.0.40 --peers 100.64.0.47 \
	--peers-file "$TESTDIR/no-such-file" 2>&1)
rc=$?
check "e: exit 0" [ "$rc" -eq 0 ]
check "e: drift is logged" err_has "endpoints drifted"
check "e: delete precedes recreate" \
	awk '/^ip link del dimt-0-47$/ { d = NR } /^ip link add dimt-0-47 / { a = NR }
	     END { exit !(d && a && d < a) }' "$FAKEIP_DIR/ip.log"
check "e: recreated with corrected endpoints" log_has \
	"^ip link add dimt-0-47 type ipip local 100.64.0.40 remote 100.64.0.47 "

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
check "g: usage mentions --allow-empty safety" err_has "empty desired peer set skips"
check "g: usage prints the last header line" err_has "\[--allow-empty\]"

echo
if [ "$FAILS" -gt 0 ]; then
	echo "$FAILS test(s) FAILED"
	exit 1
fi
echo "all tests passed"
exit 0
