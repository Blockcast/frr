#!/usr/bin/env bash
#
# BLO-15579 -- Junos GTM-SSM MVPN interoperability matrix, one command, one artifact.
#
#   ./mvpn-gtm-interop.sh              # the real run (needs lab L3 + docker)
#   ./mvpn-gtm-interop.sh --dry-run    # agent-side self-check, no lab, no docker
#
# Design constraints this script exists to satisfy (CTO ruling, BLO-15579
# 2026-10-09):
#   * non-interactive and idempotent -- the operator runs it once and gets back
#     a tarball, not a shell session per matrix cell;
#   * fail-fast step 0, so a licensing / TCP-179 / v6-codec problem surfaces in
#     gate 1 of 6 rather than in cell 30 of 40;
#   * the Junos is left byte-identical to how it was found, and the artifact
#     carries the proof rather than the claim;
#   * the FRR build is pinned to an explicit Blockcast/frr SHA, recorded in the
#     artifact.
#
# FRR runs in its OWN network namespace (plain `docker run`, no --network host).
# The container initiates the iBGP session outbound and docker NATs it, so Junos
# peers with the lab host's address.  That is deliberate: it needs no new network
# grant, and -- more importantly -- IGMP/MLD joins and the dummy receiver stub
# stay inside the container instead of mutating a hypervisor's forwarding state.
# iBGP (not eBGP) because it is NAT- and multihop-tolerant by default.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------- parameters
DRY_RUN=0; DRY_WRAPPER=0
case "${1:-}" in
  --dry-run)       DRY_RUN=1; DRY_WRAPPER=1 ;;   # self-check: runs itself twice, asserts
  --dry-run-inner) DRY_RUN=1 ;;                  # one stubbed pass, invoked by the wrapper
esac

# Lab-specific values are REQUIRED from the environment and have no literal
# defaults here on purpose: the endpoint, the jump host and the key path are lab
# facts that belong in the ticket, not baked into a git object -- git objects are
# content-addressed, so unlike a comment they cannot be redacted afterwards.
# See BLO-15630 for the current values; they are checked below, once `die` exists.
JUNOS_USER="${JUNOS_USER:-root}"
JUNOS_JUMP="${JUNOS_JUMP:-}"          # set when this host is not the jump host itself

# Pin the FRR build.  FRR_IMAGE is produced by .github/workflows/gtm-image-build.yml
# (workflow_dispatch with ref=<sha>), which tags harbor.blockcast.net/blockcast/frr:gtm-<shortsha>.
FRR_SHA="${FRR_SHA:-$(git -C "$HERE" rev-parse HEAD 2>/dev/null || echo unknown)}"
FRR_IMAGE="${FRR_IMAGE:-harbor.blockcast.net/blockcast/frr:gtm-${FRR_SHA:0:7}}"

# Protocol parameters.  These are RFC 5737 / RFC 3849 documentation ranges and the
# SSM ranges; they are not lab facts and are safe to carry in the repo.
AS="${AS:-65001}"
FRR_RID="${FRR_RID:-10.255.0.1}"
V4_SRC="${V4_SRC:-10.199.99.1}"; V4_GRP="${V4_GRP:-232.1.1.10}"
V6_SRC="${V6_SRC:-2001:db8:1557::1}"; V6_GRP="${V6_GRP:-ff3e::1}"
RX_V4="${RX_V4:-10.199.0.1/24}"; RX_V6="${RX_V6:-2001:db8:1557:9::1/64}"

HOLD_SECONDS="${HOLD_SECONDS:-600}"   # step-0 soak; the CTO asked for ~10 min
SETTLE="${SETTLE:-20}"                # per-cell convergence wait
CONFIRM_MIN="${CONFIRM_MIN:-10}"      # `commit confirmed` window: crash => auto-revert
CNAME="${CNAME:-blo15579-frr}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$PWD/blo15579-artifact-$TS}"
mkdir -p "$OUT/cells"

# Junos commits we have made; the exit trap rolls back exactly this many.
JUNOS_COMMITS=0
RESULTS=()   # "VERDICT<TAB>cell<TAB>note"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
die() { log "FATAL: $*"; exit 1; }

# The lab endpoint and key path are required from the environment for a real run.
# --dry-run substitutes RFC 5737 documentation addresses so the self-check needs
# no lab, no credentials and no prior setup.
if (( DRY_RUN )); then
  JUNOS_HOST="${JUNOS_HOST:-198.51.100.120}"
  JUNOS_KEY="${JUNOS_KEY:-/dev/null}"
  JUNOS_LAN_IFL="${JUNOS_LAN_IFL:-ge-0/0/1.0}"
else
  [[ -n "${JUNOS_HOST:-}" ]] || die "set JUNOS_HOST (the vJunos address -- see BLO-15630)"
  [[ -n "${JUNOS_KEY:-}"  ]] || die "set JUNOS_KEY (path to the lab SSH key -- see BLO-15630)"
  [[ -n "${JUNOS_LAN_IFL:-}" ]] || die "set JUNOS_LAN_IFL (Junos receiver-stub ifl, e.g. ge-0/0/1.0)"
  [[ -r "$JUNOS_KEY" ]] || die "JUNOS_KEY is not readable: $JUNOS_KEY"
fi
JUNOS_RID="${JUNOS_RID:-$JUNOS_HOST}"

# ------------------------------------------------------------------ sanitize
# Applied to every captured byte before it reaches the artifact.  Built from the
# values actually in use, so it cannot drift from the parameters above.
sanitize() {
  # Every pattern must be non-empty: an empty sed regex silently means "reuse the
  # previous one", which turns a missing optional value into a wrong substitution.
  local jump="${JUNOS_JUMP#*@}"; : "${jump:=__nojump__}"
  sed -e "s#$JUNOS_HOST#<JUNOS-ADDR>#g" \
      -e "s#$jump#<JUMP-ADDR>#g" \
      -e "s#$JUNOS_KEY#<JUNOS-KEY>#g" \
      -e "s#$JUNOS_USER@#<JUNOS-USER>@#g" \
      -e "s#${LOCAL_ADDR:-__nolocal__}#<LAB-HOST-ADDR>#g" \
      -e 's#\b\([0-9a-fA-F]\{2\}:\)\{5\}[0-9a-fA-F]\{2\}\b#<MAC>#g' \
      -e 's#\(ssh-rsa\|ssh-ed25519\) [A-Za-z0-9+/=]\{20,\}#\1 <PUBKEY>#g'
}

# ----------------------------------------------------------------- transport
ssh_opts=(-o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new
          -o ConnectTimeout=15 -o BatchMode=yes -i "$JUNOS_KEY")
[[ -n "$JUNOS_JUMP" ]] && ssh_opts+=(-J "$JUNOS_JUMP")

if (( DRY_RUN )); then
  FIXTURES="$HERE/fixtures/${FIXTURE_MODE:-good}"
  CURRENT_CELL=""
  # Per-cell override, falling back to the generic bundle.  The withdraw cells
  # assert ABSENCE, so they need a capture in which the route is genuinely gone;
  # one static fixture cannot represent both halves of a withdraw.
  fx() { local s="$FIXTURES/$1-$CURRENT_CELL.txt"; [[ -r "$s" ]] && cat "$s" || cat "$FIXTURES/$1.txt"; }
  jcmd()  { fx junos; }
  jload() { cat >/dev/null; echo "configuration check succeeds"; }
  jcommit() { JUNOS_COMMITS=$((JUNOS_COMMITS + 1)); echo "commit complete"; }
  frrcmd() { fx frr; }
  frr_up() { echo "dry-run: FRR container not started"; }
  frr_restart_bgpd() { echo "dry-run: bgpd restart"; }
  cleanup_junos() { :; }
  sleep() { :; }
else
  jcmd() { ssh "${ssh_opts[@]}" "$JUNOS_USER@$JUNOS_HOST" "$@" 2>&1; }
  # stdin = `set` lines; loads them into a private candidate and reports.
  jload() {
    local f="$OUT/.junos-load.set"; cat >"$f"
    scp "${ssh_opts[@]}" "$f" "$JUNOS_USER@$JUNOS_HOST:/var/tmp/blo15579.set" >/dev/null
    printf 'configure exclusive\nload set /var/tmp/blo15579.set\ncommit check\nrollback\nexit\n' \
      | jcmd
  }
  jcommit() {
    local f="$OUT/.junos-load.set"
    scp "${ssh_opts[@]}" "$f" "$JUNOS_USER@$JUNOS_HOST:/var/tmp/blo15579.set" >/dev/null
    local o
    o=$(printf 'configure exclusive\nload set /var/tmp/blo15579.set\ncommit confirmed %s\nexit\n' \
          "$CONFIRM_MIN" | jcmd)
    grep -qi 'commit complete' <<<"$o" || { echo "$o"; return 1; }
    JUNOS_COMMITS=$((JUNOS_COMMITS + 1))
    echo "$o"
  }
  frrcmd() { docker exec "$CNAME" vtysh -c "$1" 2>&1; }
  frr_up() {
    docker rm -f "$CNAME" >/dev/null 2>&1 || true
    docker run -d --name "$CNAME" --privileged \
      -v "$OUT/frr.conf:/etc/frr/frr.conf:ro" \
      -v "$OUT/daemons:/etc/frr/daemons:ro" "$FRR_IMAGE" >/dev/null
    # rx0 is the receiver stub the IGMP/MLD joins land on.  Inside the
    # container's netns, so it cannot touch the lab host.
    docker exec "$CNAME" ip link add rx0 type dummy
    docker exec "$CNAME" ip link set rx0 up
  }
  frr_restart_bgpd() { docker exec "$CNAME" sh -c 'pkill -x bgpd'; sleep 15; }
  cleanup_junos() {
    (( JUNOS_COMMITS == 0 )) && return 0
    printf 'configure exclusive\nrollback %s\ncommit\nexit\n' "$JUNOS_COMMITS" | jcmd
  }
fi

cleanup() {
  local rc=$?
  log "cleanup: rolling back $JUNOS_COMMITS Junos commit(s), removing container"
  cleanup_junos 2>&1 | sanitize >"$OUT/junos-cleanup.txt" || true
  (( DRY_RUN )) || docker rm -f "$CNAME" >/dev/null 2>&1 || true
  return $rc
}
trap cleanup EXIT

# -------------------------------------------------------- rendered configs
LOCAL_ADDR="${LOCAL_ADDR:-}"
if (( ! DRY_RUN )) && [[ -z "$LOCAL_ADDR" ]]; then
  LOCAL_ADDR=$(ip route get "$JUNOS_HOST" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
fi
: "${LOCAL_ADDR:=203.0.113.9}"   # dry-run placeholder only
GW_V4="${GW_V4:-172.17.0.1}"     # container default gw (docker0)

render() {   # render <file>
  sed -e "s#@@AS@@#$AS#g" -e "s#@@FRR_RID@@#$FRR_RID#g" \
      -e "s#@@JUNOS_RID@@#$JUNOS_RID#g" -e "s#@@JUNOS_RID_HOST@@#vjunos-router#g" \
      -e "s#@@FRR_PEER@@#$LOCAL_ADDR#g" -e "s#@@GW_V4@@#$GW_V4#g" \
      -e "s#@@V4_SRC@@#$V4_SRC#g" -e "s#@@V4_GRP@@#$V4_GRP#g" \
      -e "s#@@V6_SRC@@#$V6_SRC#g" -e "s#@@V6_GRP@@#$V6_GRP#g" \
      -e "s#@@RX_V4@@#$RX_V4#g" -e "s#@@RX_V6@@#$RX_V6#g" \
      -e "s#@@LAN_IFL@@#$JUNOS_LAN_IFL#g" "$1"
}
render "$HERE/frr-base.conf"  >"$OUT/frr.conf"
render "$HERE/junos-base.set" >"$OUT/junos-rendered.set"
for d in zebra bgpd pimd pim6d staticd; do echo "$d=yes"; done >"$OUT/daemons"
sanitize <"$OUT/junos-rendered.set" >"$OUT/junos-config.set"

# ------------------------------------------------------------- evidence
# Every cell captures the same bundle, so cells are comparable and a cell only
# has to declare what it *changed* and what it expects.
FRR_SHOWS=(
  "show bgp summary"
  "show bgp ipv4 mvpn"
  "show bgp ipv6 mvpn"
  "show bgp mvpn events"
  "show ip mroute"
  "show bgp neighbor $JUNOS_RID"
)
JUNOS_SHOWS=(
  "show bgp summary"
  "show bgp neighbor $LOCAL_ADDR"
  "show route table bgp.mvpn.0 detail"
  "show route table bgp.mvpn6.0 detail"
  "show mvpn c-multicast"
  "show multicast route"
)

capture() {  # capture <cell>; writes $OUT/cells/<cell>.txt, echoes nothing
  local cl="$1" s f
  f="$OUT/cells/$cl.txt"
  CURRENT_CELL="$cl"
  { echo "######## CELL $cl @ $(date -u +%FT%TZ)"
    echo "######## FRR (Blockcast/frr $FRR_SHA)"
    for s in "${FRR_SHOWS[@]}"; do echo "===== frr# $s"; frrcmd "$s"; done
    echo "######## JUNOS"
    for s in "${JUNOS_SHOWS[@]}"; do echo "===== junos> $s"; jcmd "$s"; done
  } 2>&1 | sanitize >"$f"
}

# Established-session counter, read from the FRR side.  Used to prove "zero
# unexpected session resets": it may only move in the two restart cells.
established_count() {
  local n
  n=$(frrcmd "show bgp neighbor $JUNOS_RID json" \
        | sed -n 's/.*"connectionsEstablished": *\([0-9]*\).*/\1/p' | head -1)
  echo "${n:-0}"
}
BASE_ESTAB=0

record() { RESULTS+=("$1	$2	$3"); log "$1 $2 ${3:+-- $3}"; }

# cell <name> <frr-config-or-empty> <junos-set-mutation-or-empty> <expect-frr> <expect-junos>
# An expectation starting with '!' asserts ABSENCE -- that is how the withdrawal
# cells are expressed, and it is the only way a withdraw can actually be proven.
cell() {
  local name="$1" frr_do="$2" junos_do="$3" exp_frr="$4" exp_junos="$5"
  [[ -n "$frr_do" ]] && frrcmd "configure terminal
$frr_do" >/dev/null
  if [[ -n "$junos_do" ]]; then
    { cat "$OUT/junos-rendered.set"; echo "$junos_do"; } >"$OUT/.junos-load.set"
    if ! jcommit >>"$OUT/run.log" 2>&1; then record FAIL "$name" "junos commit rejected"; return; fi
  fi
  sleep "$SETTLE"
  capture "$name"
  local body; body="$(cat "$OUT/cells/$name.txt")"
  local why=""
  # Every arm ends `return 0` on purpose.  A bare `grep ... && why=...` whose grep
  # misses leaves the function's status at 1, and under `set -e` that aborts the
  # whole run -- silently, and *only* on the withdraw cells, whose entire job is
  # for that grep to miss.  A harness that dies on its own success path reports
  # fewer cells rather than a failure, which is the worst direction.
  check() {  # check <expect> <label>
    local e="$1" label="$2"
    if [[ -n "$e" ]]; then
      if [[ "${e:0:1}" == "!" ]]; then
        if grep -qE -- "${e:1}" <<<"$body"; then why="$why $label:unexpectedly-present(${e:1})"; fi
      else
        if ! grep -qE -- "$e" <<<"$body"; then why="$why $label:missing($e)"; fi
      fi
    fi
    return 0
  }
  check "$exp_frr" frr
  check "$exp_junos" junos
  # Session-reset accounting, on every cell except the two that restart on purpose.
  local n; n="$(established_count)"
  if [[ "$name" == restart-* ]]; then
    BASE_ESTAB="$n"
  elif [[ "$n" != "$BASE_ESTAB" ]]; then
    why="$why session-reset($BASE_ESTAB->$n)"
  fi
  if [[ -n "$why" ]]; then record FAIL "$name" "$why"; else record PASS "$name" ""; fi
  return 0
}

###############################################################################
# STEP 0 -- fail-fast gates.  If any of these fails we stop: everything after it
# would be measuring the wrong thing, and an operator round-trip is the scarcest
# input here.
###############################################################################
gate() { log "GATE $1: $2"; }

step0() {
  local o

  gate G1 "lab host can reach the Junos on TCP/179 (TCP/22 reachability does not imply it)"
  if (( ! DRY_RUN )); then
    (exec 3<>"/dev/tcp/$JUNOS_HOST/179") 2>/dev/null \
      || { record FAIL step0-G1-tcp179 "no TCP/179 to Junos from this host"; return 1; }
  fi
  record PASS step0-G1-tcp179 ""

  gate G2 "baseline Junos config captured, so 'we changed nothing' is provable, not asserted"
  jcmd "show configuration | display set" 2>&1 | sanitize >"$OUT/junos-baseline.set"
  { jcmd "show system commit"; jcmd "show system license"; jcmd "show version"; } 2>&1 \
    | sanitize >"$OUT/junos-baseline-state.txt"
  record PASS step0-G2-baseline ""

  gate G3 "the Junos config in junos-base.set is syntactically accepted (commit check only)"
  o="$(jload <"$OUT/junos-rendered.set" 2>&1 | sanitize)"
  echo "$o" >"$OUT/junos-commit-check.txt"
  grep -qi 'configuration check succeeds' <<<"$o" \
    || { record FAIL step0-G3-commit-check "Junos rejected the config; see junos-commit-check.txt"; return 1; }
  record PASS step0-G3-commit-check ""

  gate G4 "iBGP comes up and BOTH MCAST-VPN AFs are negotiated (not merely configured)"
  cp "$OUT/junos-rendered.set" "$OUT/.junos-load.set"
  jcommit >>"$OUT/run.log" 2>&1 || { record FAIL step0-G4-session "Junos commit failed"; return 1; }
  frr_up
  sleep "$SETTLE"
  capture step0-G4-session
  local b; b="$(cat "$OUT/cells/step0-G4-session.txt")"
  local why=""
  grep -qE 'Established|established' <<<"$b"       || why="$why no-established"
  grep -qE 'IPv4 MCAST-VPN|ipv4Mvpn|inet-mvpn'  <<<"$b" || why="$why v4-mvpn-af-not-negotiated"
  grep -qE 'IPv6 MCAST-VPN|ipv6Mvpn|inet6-mvpn' <<<"$b" || why="$why v6-mvpn-af-not-negotiated"
  if [[ -n "$why" ]]; then
    # v6-only failure is survivable: bank the v4 matrix rather than hold everything.
    if [[ "$why" == " v6-mvpn-af-not-negotiated" ]]; then
      record FAIL step0-G4-v6-af "IPv6 MCAST-VPN AF did not negotiate; v4 matrix continues, split the v6 half to its own row"
      SKIP_V6=1
    else
      record FAIL step0-G4-session "$why"; return 1
    fi
  else
    record PASS step0-G4-session ""
  fi
  BASE_ESTAB="$(established_count)"

  gate G5 "hold the session ${HOLD_SECONDS}s -- commit check is not a sustained session, and the box reports no installed licenses"
  sleep "$HOLD_SECONDS"
  capture step0-G5-soak
  local n; n="$(established_count)"
  if [[ "$n" != "$BASE_ESTAB" ]]; then
    record FAIL step0-G5-soak "session reset during soak ($BASE_ESTAB->$n) -- suspect the license/filter entitlement"
    return 1
  fi
  record PASS step0-G5-soak ""
  return 0
}

###############################################################################
# THE MATRIX
###############################################################################
matrix() {
  # FRR prints MVPN routes as ` [<type>] source <S> group <G> ...` /
  # ` [1] originator <X> ...` (bgp_mvpn_show_routes), so anchor on `[N]` rather
  # than on a bare "5:" -- an unanchored "5:" also matches an uptime timestamp,
  # which is exactly how a harness reports a route it never saw.
  cell type1-ipmsi-bidir "" "" \
    "\\[1\\] originator" "^1:|Intra-AS"

  cell type1-pmsi-ir-label "router bgp $AS
 bgp mvpn ipmsi-label 1000" "" \
    "" "PMSI|Ingress Replication|label 1000"

  cell type5-v4-frr-to-junos "router bgp $AS
 address-family ipv4 mvpn
  bgp mvpn source-active $V4_SRC group $V4_GRP" "" \
    "\\[5\\] source $V4_SRC group $V4_GRP" "^5:.*$V4_SRC"

  cell type5-v4-junos-to-frr "" \
    "set protocols mvpn source-active-advertisement" \
    "\\[5\\] source" ""

  cell type7-v4-frr-to-junos "interface rx0
 ip igmp join-group $V4_GRP $V4_SRC" "" \
    "\\[7\\] source $V4_SRC group $V4_GRP" "^7:.*$V4_SRC"

  cell type7-v4-junos-to-frr "" \
    "set protocols igmp interface $JUNOS_LAN_IFL static group $V4_GRP source $V4_SRC" \
    "\\[7\\] source $V4_SRC group $V4_GRP" ""

  cell withdraw-type7-v4-leave "interface rx0
 no ip igmp join-group $V4_GRP $V4_SRC" "" \
    "" "!^7:.*$V4_SRC.*$V4_GRP"

  cell withdraw-type5-v4 "router bgp $AS
 address-family ipv4 mvpn
  no bgp mvpn source-active $V4_SRC group $V4_GRP" "" \
    "" "!^5:.*$V4_SRC.*$V4_GRP"

  if [[ "${SKIP_V6:-0}" == "0" ]]; then
    cell type5-v6-frr-to-junos "router bgp $AS
 address-family ipv6 mvpn
  bgp mvpn source-active $V6_SRC group $V6_GRP" "" \
      "\\[5\\] source $V6_SRC group $V6_GRP" "^5:.*$V6_SRC"

    cell type7-v6-frr-to-junos "interface rx0
 ipv6 mld join-group $V6_GRP $V6_SRC" "" \
      "\\[7\\] source $V6_SRC group $V6_GRP" "^7:.*$V6_SRC"

    cell type7-v6-junos-to-frr "" \
      "set protocols mld interface $JUNOS_LAN_IFL static group $V6_GRP source $V6_SRC" \
      "\\[7\\] source $V6_SRC group $V6_GRP" ""

    cell withdraw-type7-v6-leave "interface rx0
 no ipv6 mld join-group $V6_GRP $V6_SRC" "" \
      "" "!^7:.*$V6_SRC.*$V6_GRP"
  else
    record SKIP type5-v6-frr-to-junos "IPv6 MCAST-VPN AF did not negotiate (step0-G4-v6-af)"
    record SKIP type7-v6-frr-to-junos "ditto"
    record SKIP type7-v6-junos-to-frr "ditto"
    record SKIP withdraw-type7-v6-leave "ditto"
  fi

  # Re-arm one of each so the restart cells have something that must come back.
  frrcmd "configure terminal
router bgp $AS
 address-family ipv4 mvpn
  bgp mvpn source-active $V4_SRC group $V4_GRP" >/dev/null
  sleep "$SETTLE"

  log "restart cells: bgpd restart, then a deliberate session clear"
  frr_restart_bgpd
  cell restart-bgpd "" "" "\\[5\\] source $V4_SRC" "^5:.*$V4_SRC"

  frrcmd "clear bgp $JUNOS_RID" >/dev/null || true
  cell restart-session "" "" "\\[5\\] source $V4_SRC" "^5:.*$V4_SRC"
}

###############################################################################
summarize() {
  local pass=0 fail=0 skip=0 r v n w
  {
    echo "# BLO-15579 Junos GTM-SSM MVPN interop matrix"
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| run | \`$TS\` |"
    echo "| FRR commit | \`$FRR_SHA\` |"
    echo "| FRR image | \`$FRR_IMAGE\` |"
    echo "| Junos | see \`junos-baseline-state.txt\` |"
    echo "| Junos commits made / rolled back | $JUNOS_COMMITS |"
    echo
    echo "| verdict | cell | note |"
    echo "|---|---|---|"
    for r in "${RESULTS[@]}"; do
      IFS=$'\t' read -r v n w <<<"$r"
      case "$v" in PASS) pass=$((pass+1));; FAIL) fail=$((fail+1));; SKIP) skip=$((skip+1));; esac
      echo "| $v | \`$n\` | ${w:-} |"
    done
    echo
    echo "**$pass passed, $fail failed, $skip skipped.**"
    echo
    echo "Per-cell verbatim FRR + Junos CLI transcripts are in \`cells/\`, sanitized."
    echo "\`junos-baseline.set\` vs \`junos-final.set\` is the did-we-change-anything proof."
  } >"$OUT/summary.md"
  cat "$OUT/summary.md"
  return $(( fail > 0 ))
}

###############################################################################
main() {
  log "BLO-15579 interop matrix; artifact -> $OUT"
  log "FRR $FRR_SHA via $FRR_IMAGE; Junos $JUNOS_HOST; local $LOCAL_ADDR"

  if step0; then
    matrix
  else
    log "step 0 gate failed -- matrix not run (this is the intended fail-fast)"
  fi

  # The proof, not the claim: pull the config back down after cleanup and diff.
  cleanup_junos >/dev/null 2>&1 || true
  JUNOS_COMMITS=0
  jcmd "show configuration | display set" 2>&1 | sanitize >"$OUT/junos-final.set"
  if diff -u "$OUT/junos-baseline.set" "$OUT/junos-final.set" >"$OUT/junos-config.diff"; then
    record PASS junos-left-unchanged ""
  else
    record FAIL junos-left-unchanged "config differs from baseline; see junos-config.diff"
  fi

  local rc=0; summarize || rc=1
  tar czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")"
  log "artifact: $OUT.tar.gz"
  return $rc
}

###############################################################################
# --dry-run: exercise the real cell loop, verdict logic, sanitizer and packaging
# against fixtures, in both directions.  A harness whose PASS path is tested but
# whose FAIL path is not will happily report green on an empty capture.
###############################################################################
if (( DRY_WRAPPER )); then
  fails=0
  assert() { if eval "$2"; then echo "  ok   $1"; else echo "  FAIL $1"; fails=$((fails+1)); fi; }
  # grep -c exits 1 on zero matches, which under `set -e` turns a legitimate
  # "no failures" into a skipped assertion.  awk always exits 0.
  countfail() { awk '/^\| FAIL \|/{n++} END{print n+0}' "$1" 2>/dev/null || echo 99; }

  echo "== dry-run A: good fixtures, expect the matrix to pass"
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-good" \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-good.log" 2>&1 || true
  good_fail=$(countfail "$OUT/dryrun-good/summary.md")

  echo "== dry-run B: empty fixtures, expect the matrix to fail (negative control)"
  FIXTURE_MODE=empty HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-empty" \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-empty.log" 2>&1 || true
  empty_fail=$(countfail "$OUT/dryrun-empty/summary.md")

  echo "== assertions"
  assert "good fixtures produce zero FAIL cells (got $good_fail)"  "[ '$good_fail' -eq 0 ]"
  assert "empty fixtures produce FAIL cells (got $empty_fail)"     "[ '$empty_fail' -gt 5 ]"
  assert "summary.md was written"             "[ -s '$OUT/dryrun-good/summary.md' ]"
  assert "every cell produced a transcript"   "[ \$(ls '$OUT/dryrun-good/cells' 2>/dev/null | wc -l) -ge 14 ]"
  # The `-d` half is not padding: a grep over a directory that does not exist
  # also reports "clean", so without it a crashed run scores as sanitized.
  assert "sanitizer removed the Junos address" \
    "[ -d '$OUT/dryrun-good/cells' ] && ! grep -rqF '$JUNOS_HOST' '$OUT/dryrun-good/cells'"
  assert "sanitizer removed the lab host address" \
    "[ -d '$OUT/dryrun-good/cells' ] && ! grep -rqF '$LOCAL_ADDR' '$OUT/dryrun-good/cells'"
  assert "sanitizer actually fired (placeholders present)" \
    "grep -rqF '<JUNOS-ADDR>' '$OUT/dryrun-good/cells' 2>/dev/null"
  assert "artifact tarball was produced"      "[ -s '$OUT/dryrun-good.tar.gz' ]"
  echo
  if (( fails )); then echo "DRY-RUN FAILED ($fails assertion(s))"; exit 1; fi
  echo "DRY-RUN OK -- harness logic, verdicts (both directions), sanitizer and packaging all exercised."
  exit 0
fi

main
