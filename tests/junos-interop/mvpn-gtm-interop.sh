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
# `commit confirmed` window, minutes: crash => auto-revert.  It has to outlive the
# longest stretch with no Junos commit, or the box reverts mid-run: G4's commit is
# followed by the HOLD_SECONDS soak plus four SETTLE waits, and the tail after the
# last commit by up to six.  A revert mid-soak makes G5 blame the license for our
# own timer.  Hence derived, with 10 min for captures, ssh and the bgpd restart;
# an override is honoured only if it clears the same floor.
CONFIRM_FLOOR_S=$(( HOLD_SECONDS + 6 * SETTLE + 600 ))
CONFIRM_MIN="${CONFIRM_MIN:-$(( (CONFIRM_FLOOR_S + 59) / 60 ))}"
CNAME="${CNAME:-blo15579-frr}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$PWD/blo15579-artifact-$TS}"
mkdir -p "$OUT/cells"

# Junos commits we have made; nonzero means cleanup must restore the box.
JUNOS_COMMITS=0
# G2 saves the running config here; cleanup puts it back with `load override`.
# Absolute, not `rollback $JUNOS_COMMITS`: `configure exclusive` lasts one ssh
# call, so another session's commit (or a confirmed-commit expiry) can land
# between ours, and a count would then name the wrong revision.
JUNOS_RESTORE="/var/tmp/blo15579-baseline-$TS.conf"
JUNOS_RESTORE_GLOB='/var/tmp/blo15579-baseline-*.conf'
RESULTS=()   # "VERDICT<TAB>cell<TAB>note"
JUNOS_RESTORED=0   # set by main() once the restore is VERIFIED, never assumed

# ------------------------------------------------------------------ sanitize
# Applied to every captured byte before it reaches the artifact.  Built from the
# values actually in use, so it cannot drift from the parameters.  run.log goes
# through it too (log() below), so it must cope with values not yet set.
sanitize() {
  # Every pattern must be non-empty: an empty sed regex silently means "reuse the
  # previous one", which turns a missing optional value into a wrong substitution.
  local jump="${JUNOS_JUMP#*@}"; : "${jump:=__nojump__}"
  sed -e "s#${JUNOS_HOST:-__nohost__}#<JUNOS-ADDR>#g" \
      -e "s#$jump#<JUMP-ADDR>#g" \
      -e "s#${JUNOS_KEY:-__nokey__}#<JUNOS-KEY>#g" \
      -e "s#$JUNOS_USER@#<JUNOS-USER>@#g" \
      -e "s#${LOCAL_ADDR:-__nolocal__}#<LAB-HOST-ADDR>#g" \
      -e "s#${JUNOS_LAN_IFL:-__noifl__}#<JUNOS-IFL>#g" \
      -e "s#${JUNOS_RID:-__norid__}#<JUNOS-RID>#g" \
      -e 's#\b\([0-9a-fA-F]\{2\}:\)\{5\}[0-9a-fA-F]\{2\}\b#<MAC>#g' \
      -e 's#\(ssh-rsa\|ssh-ed25519\) [A-Za-z0-9+/=]\{20,\}#\1 <PUBKEY>#g'
}

# The console stays verbatim for the operator; run.log is packaged, so it is sanitized.
log() { local l; l="[$(date -u +%H:%M:%S)] $*"; printf '%s\n' "$l"; sanitize <<<"$l" >>"$OUT/run.log"; }
die() { log "FATAL: $*"; exit 1; }

if ! { [[ "$CONFIRM_MIN" =~ ^[1-9][0-9]*$ ]] && (( CONFIRM_MIN * 60 >= CONFIRM_FLOOR_S )); }; then
  die "CONFIRM_MIN=$CONFIRM_MIN is shorter than the longest commit-free stretch; need >= $(( (CONFIRM_FLOOR_S + 59) / 60 )) min (HOLD_SECONDS=$HOLD_SECONDS SETTLE=$SETTLE)"
fi

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
  # Mutation hook for the abort self-checks (dry-run D/E/G/H): a stubbed command whose
  # "<cell> <command>" matches DRY_FAIL_CMD prints an error and exits 1, as a
  # rejected vtysh line or a dropped ssh would.
  stub_ok() { [[ -n "${DRY_FAIL_CMD:-}" && "$CURRENT_CELL $1" =~ $DRY_FAIL_CMD ]] || return 0; echo "% dry-run: forced failure"; return 1; }
  # `load set` MERGES into the committed config: a line one cell sets survives
  # until a later cell deletes it.  Model that, and give the stubbed bgp.mvpn
  # tables the Type-7 each committed static join originates, so a join that is
  # never deleted (or sits in junos-base.set) shows up in the withdraw cells.
  joins() {  # joins igmp|mld: "<S> <G>" per static join committed on the box
    sed -n "s#^set protocols $1 interface [^ ]* static group \([^ ]*\) source \([^ ]*\)\$#\2 \1#p" \
      "$PRIV/.junos-live.set" 2>/dev/null || true
  }
  live7() {  # live7 <table>
    local af=igmp s g; [[ "$1" == bgp.mvpn6.0 ]] && af=mld
    joins "$af" | while read -r s g; do echo "7:dry-run-model:$s:$g *[MVPN/70] committed static join"; done
  }
  # FRR's view: paths received from Junos, which bgp_mvpn_show_routes prints
  # without the "(local)" tag FRR's own routes carry.  A Type-7 per committed
  # static join, and a Type-5 once source-active-advertisement is committed.
  # This assumes Junos sends them; README "Known limits" says why it may not.
  # The empty fixtures model a session that carries no MVPN route, so not there.
  rx() {  # rx igmp|mld
    local s g; [[ "${FIXTURE_MODE:-good}" == empty ]] && return 0
    joins "$1" | while read -r s g; do echo " [7] source $s group $g  RT:dry-run-model"; done
    if [[ "$1" == igmp ]] && grep -qx 'set protocols mvpn source-active-advertisement' "$PRIV/.junos-live.set"; then
      echo " [5] source $V4_SRC group $V4_GRP  RT:dry-run-model"
    fi
  }
  # The config commands read and write that model, so G2's baseline, the restore
  # point and the final read-back are all real; the box starts with a config of
  # its own (seeded below), so a restore has to bring it back, not just empty it.
  jcmd()  {
    stub_ok "$*" || return
    case "$*" in
      "")                 jcli ;;
      *"| display set")   sort -u "$PRIV/.junos-live.set" ;;
      *"| save $JUNOS_RESTORE")
        cp "$PRIV/.junos-live.set" "$PRIV/.junos-saved.set"
        echo "Wrote $(wc -l <"$PRIV/.junos-live.set") lines of configuration to '$JUNOS_RESTORE'" ;;
      # Checked before the generic arm below: at G2 this asks "is ANOTHER run's
      # restore point here?", which must answer no on a clean box even though this
      # run's own file is about to exist.  DRY_STALE_RESTORE models a collision.
      *"file list $JUNOS_RESTORE_GLOB")
        if [[ -n "${DRY_STALE_RESTORE:-}" ]]
        then echo "/var/tmp/blo15579-baseline-20260101T000000Z.conf"
        else echo "$JUNOS_RESTORE_GLOB: No such file or directory"; fi ;;
      # Junos prints the path either way; the error text is the only discriminator,
      # which is why cleanup_junos tests for both.  DRY_NO_RESTORE models the
      # restore point having been reaped out from under us.
      *"file list "*)
        if [[ -e "$PRIV/.junos-saved.set" && -z "${DRY_NO_RESTORE:-}" ]]
        then echo "$JUNOS_RESTORE"
        else echo "$JUNOS_RESTORE: No such file or directory"; fi ;;
      *" hidden "*)       fx junos-hidden ;;
      *) fx junos
         if [[ "$*" =~ table\ (bgp\.mvpn6?\.0)\ detail ]]; then live7 "${BASH_REMATCH[1]}"; fi ;;
    esac
  }
  # stdin = the configure-mode script cleanup_junos sends.  Only `load override`
  # is modelled: a rollback count is right only if no other session committed in
  # between, which nothing here can promise, so the model does not offer one.
  # `commit` reports success unconditionally ON PURPOSE -- on a real box a commit
  # of an unchanged candidate also succeeds, and *confirms* the pending
  # `commit confirmed`.  So the transcript check alone cannot save us; the
  # refusal in cleanup_junos, before anything is sent, is what does.
  jcli() {
    local l
    while read -r l; do
      case "$l" in
        "load override $JUNOS_RESTORE") cp "$PRIV/.junos-saved.set" "$PRIV/.junos-live.set" ;;
        commit) echo "commit complete" ;;
      esac
    done
  }
  jload() { cat >/dev/null; echo "configuration check succeeds"; }
  # DRY_DROP_JUNOS (dry-run F): `set` lines matching it never reach the box, as
  # if the cell had not set them.
  jcommit() {
    local l live="$PRIV/.junos-live.set"
    JUNOS_COMMITS=$((JUNOS_COMMITS + 1))
    while IFS= read -r l; do
      case "$l" in
        "set "*)    [[ -n "${DRY_DROP_JUNOS:-}" && "$l" =~ $DRY_DROP_JUNOS ]] || echo "$l" >>"$live" ;;
        "delete "*) { grep -vF -- "set ${l#delete }" "$live" || true; } >"$live.t"; mv "$live.t" "$live" ;;
      esac
    done <"$PRIV/.junos-load.set"
    echo "commit complete"
  }
  # The session counter has to MOVE when something restarts, or the restart cells'
  # "did anything actually restart?" check has nothing to read and a static fixture
  # would let "nothing restarted" pass.  DRY_NO_RESTART freezes it: that is the
  # mutation test for the check.
  DRY_ESTAB=1
  frrcmd() {
    stub_ok "$1" || return
    case "$1" in
      *"neighbor $JUNOS_RID json") echo "  \"connectionsEstablished\": $DRY_ESTAB,"; return 0 ;;
      "clear bgp "*) [[ -n "${DRY_NO_RESTART:-}" ]] || DRY_ESTAB=$((DRY_ESTAB + 1)); return 0 ;;
      # Only the rx0 stanza matters to G6, and running-config is FRR's own view of
      # gm_enable (pim_vty.c only emits these two when it is set), not an echo of
      # frr-base.conf.  DRY_NO_GM drops them: the mutation test for that gate.
      "show running-config")
        echo "interface rx0"; echo " ip pim"; echo " ipv6 pim"
        [[ -n "${DRY_NO_GM:-}" ]] || { echo " ip igmp"; echo " ipv6 mld"; }
        echo "!"; return 0 ;;
    esac
    fx frr
    case "$1" in "show bgp ipv4 mvpn") rx igmp ;; "show bgp ipv6 mvpn") rx mld ;; esac
  }
  frr_up() { echo "dry-run: FRR container not started"; }
  frr_restart_bgpd() {
    echo "dry-run: bgpd restart"
    [[ -n "${DRY_NO_RESTART:-}" ]] || DRY_ESTAB=$((DRY_ESTAB + 1))
  }
  sleep() { :; }
else
  jcmd() { ssh "${ssh_opts[@]}" "$JUNOS_USER@$JUNOS_HOST" "$@" 2>&1; }
  # stdin = `set` lines; loads them into a private candidate and reports.
  jload() {
    local f="$PRIV/.junos-load.set"; cat >"$f"
    scp "${ssh_opts[@]}" "$f" "$JUNOS_USER@$JUNOS_HOST:/var/tmp/blo15579.set" >/dev/null
    printf 'configure exclusive\nload set /var/tmp/blo15579.set\ncommit check\nrollback\nexit\n' \
      | jcmd
  }
  # Callers append this to run.log, so everything it emits -- scp/ssh errors
  # included -- goes through sanitize.
  jcommit() {
    local f="$PRIV/.junos-load.set" o
    o=$( { scp "${ssh_opts[@]}" "$f" "$JUNOS_USER@$JUNOS_HOST:/var/tmp/blo15579.set" >/dev/null
           printf 'configure exclusive\nload set /var/tmp/blo15579.set\ncommit confirmed %s\nexit\n' \
             "$CONFIRM_MIN" | jcmd; } 2>&1 | sanitize)
    grep -qi 'commit complete' <<<"$o" || { echo "$o"; return 1; }
    JUNOS_COMMITS=$((JUNOS_COMMITS + 1))
    echo "$o"
  }
  frrcmd() { docker exec "$CNAME" vtysh -c "$1" 2>&1; }
  frr_up() {
    docker rm -f "$CNAME" >/dev/null 2>&1 || true
    docker run -d --name "$CNAME" --privileged \
      -v "$PRIV/frr.conf:/etc/frr/frr.conf:ro" \
      -v "$OUT/daemons:/etc/frr/daemons:ro" "$FRR_IMAGE" >/dev/null
    # rx0 is the receiver stub the IGMP/MLD joins land on.  Inside the
    # container's netns, so it cannot touch the lab host.
    docker exec "$CNAME" ip link add rx0 type dummy
    docker exec "$CNAME" ip link set rx0 up
  }
  # pkill exits 1 when no bgpd matched; the restart-bgpd cell judges the effect.
  frr_restart_bgpd() { docker exec "$CNAME" sh -c 'pkill -x bgpd' || log "bgpd restart: pkill exited $?"; sleep 15; }
fi

# Shared by the real run and the dry-run, so the self-check exercises it.
# Returns 0 only when the box is VERIFIABLY back on the G2 restore point.
#
# The bare `commit` is the hazard.  jcommit() arms `commit confirmed`, and the
# Junos CLI does not abort a stdin script when a line errors -- so if
# `load override` fails (restore point reaped, /var/tmp cleared, the G2 save
# having landed elsewhere) the candidate is still the harness config and the
# next line's `commit` CONFIRMS the pending auto-revert, turning the safety net
# into the thing that makes the mutation permanent.  A commit of an unchanged
# candidate succeeds, so no transcript check can catch that after the fact:
# the only defence is to not send `commit` at all unless the restore point is
# known to be there.  Letting the timer fire is strictly better than confirming.
cleanup_junos() {
  (( JUNOS_COMMITS == 0 )) && return 0
  local o
  o="$(jcmd "file list $JUNOS_RESTORE" 2>&1 || true)"
  if ! grep -qF "$JUNOS_RESTORE" <<<"$o" || grep -qi 'no such file' <<<"$o"; then
    echo "!!!!! restore point $JUNOS_RESTORE is not on the box -- NOT committing."
    echo "!!!!! Sending a bare commit now would confirm the pending 'commit confirmed'"
    echo "!!!!! and make the harness config permanent.  Leaving the ${CONFIRM_MIN}-minute"
    echo "!!!!! timer to auto-revert instead.  file list said: $o"
    return 1
  fi
  o="$(printf 'configure exclusive\nload override %s\ncommit\nexit\n' "$JUNOS_RESTORE" | jcmd 2>&1 || true)"
  echo "$o"
  grep -q 'commit complete' <<<"$o"
}

cleanup() {
  local rc=$?
  log "cleanup: restoring Junos from $JUNOS_RESTORE ($JUNOS_COMMITS commit(s) made), removing container"
  if cleanup_junos 2>&1 | sanitize >>"$OUT/junos-cleanup.txt"; then
    (( JUNOS_COMMITS == 0 )) || log "cleanup: Junos restore verified"
  else
    log "cleanup: JUNOS NOT RESTORED -- 'load override $JUNOS_RESTORE' by hand; see junos-cleanup.txt"
  fi
  (( DRY_RUN )) || docker rm -f "$CNAME" >/dev/null 2>&1 || true
  rm -rf "$PRIV"
  return $rc
}
# The rendered configs carry the real lab addresses because they are what gets
# loaded; they live here, outside $OUT, so the tarball cannot pick them up.
PRIV="$(mktemp -d)"
trap cleanup EXIT
if (( DRY_RUN )); then echo "set system host-name dry-run-box" >"$PRIV/.junos-live.set"; fi

# -------------------------------------------------------- rendered configs
LOCAL_ADDR="${LOCAL_ADDR:-}"
if (( ! DRY_RUN )) && [[ -z "$LOCAL_ADDR" ]]; then
  LOCAL_ADDR=$(ip route get "$JUNOS_HOST" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
fi
: "${LOCAL_ADDR:=203.0.113.9}"   # dry-run placeholder only
GW_V4="${GW_V4:-172.17.0.1}"     # container default gw (docker0)

render() {   # render <file>
  sed -e "s#@@AS@@#$AS#g" -e "s#@@FRR_RID@@#$FRR_RID#g" \
      -e "s#@@JUNOS_RID@@#$JUNOS_RID#g" \
      -e "s#@@FRR_PEER@@#$LOCAL_ADDR#g" -e "s#@@GW_V4@@#$GW_V4#g" \
      -e "s#@@V4_SRC@@#$V4_SRC#g" -e "s#@@V4_GRP@@#$V4_GRP#g" \
      -e "s#@@V6_SRC@@#$V6_SRC#g" -e "s#@@V6_GRP@@#$V6_GRP#g" \
      -e "s#@@RX_V4@@#$RX_V4#g" -e "s#@@RX_V6@@#$RX_V6#g" \
      -e "s#@@LAN_IFL@@#$JUNOS_LAN_IFL#g" "$1"
}
render "$HERE/frr-base.conf"  >"$PRIV/frr.conf"
render "$HERE/junos-base.set" >"$PRIV/junos-rendered.set"
for d in zebra bgpd pimd pim6d staticd; do echo "$d=yes"; done >"$OUT/daemons"
sanitize <"$PRIV/junos-rendered.set" >"$OUT/junos-config.set"
sanitize <"$PRIV/frr.conf" >"$OUT/frr.conf"

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
# `hidden`: a route Junos received but did not import (no matching route-target,
# say) is invisible to plain `detail`, so without these "arrived but hidden" reads
# exactly like "never arrived".  cell() keeps them out of presence checks.
JUNOS_SHOWS=(
  "show bgp summary"
  "show bgp neighbor $LOCAL_ADDR"
  "show route table bgp.mvpn.0 detail"
  "show route table bgp.mvpn.0 hidden detail"
  "show route table bgp.mvpn6.0 detail"
  "show route table bgp.mvpn6.0 hidden detail"
  "show mvpn c-multicast"
  "show multicast route"
)

# A failing show is marked, not fatal: under set -e it would abort the run and
# truncate the transcript; cell() turns the marker into a FAIL.
capture() {  # capture <cell>; writes $OUT/cells/<cell>.txt, echoes nothing
  local cl="$1" s f
  f="$OUT/cells/$cl.txt"
  CURRENT_CELL="$cl"
  { echo "######## CELL $cl @ $(date -u +%FT%TZ)"
    echo "######## FRR (Blockcast/frr $FRR_SHA)"
    for s in "${FRR_SHOWS[@]}"; do echo "===== frr# $s"; frrcmd "$s" || echo "!!!!! show failed, exit $?"; done
    echo "######## JUNOS"
    for s in "${JUNOS_SHOWS[@]}"; do echo "===== junos> $s"; jcmd "$s" || echo "!!!!! show failed, exit $?"; done
  } 2>&1 | sanitize >"$f"
}

# Established-session counter, read from the FRR side.  Used to prove "zero
# unexpected session resets": it may only move in the two restart cells.
# Prints nothing if the counter cannot be read, and callers FAIL on that: a
# failed read turned into 0 matches a 0 baseline and passes every reset check.
# sed quits on the first match itself; a `| head -1` could SIGPIPE it.
established_count() {
  local j
  j="$(frrcmd "show bgp neighbor $JUNOS_RID json")" || return 0
  sed -n '/"connectionsEstablished"/{s/.*"connectionsEstablished": *\([0-9]*\).*/\1/p;q;}' <<<"$j"
}
BASE_ESTAB=0

record() { RESULTS+=("$1	$2	$3"); log "$1 $2 ${3:+-- $3}"; }

# cell <name> <frr-config-or-empty> <junos-set-mutation-or-empty> <expect-frr> <expect-junos>
# An expectation starting with '!' asserts ABSENCE -- that is how the withdrawal
# cells are expressed, and it is the only way a withdraw can actually be proven.
cell() {
  local name="$1" frr_do="$2" junos_do="$3" exp_frr="$4" exp_junos="$5"
  # DRY_MISSCOPE (dry-run L): point one Junos expectation at a heading only the FRR
  # section emits.  Per-box scoping must FAIL it; without scoping it is satisfied
  # off the wrong box and PASSes.  That is the mutation test for sect().
  [[ -n "${DRY_MISSCOPE:-}" && "$name" == type1-ipmsi-bidir ]] && exp_junos='MCAST-VPN routes for IPv4'
  if [[ -n "$frr_do" ]] && ! frrcmd "configure terminal
$frr_do" >/dev/null; then record FAIL "$name" "frr config rejected"; return; fi
  if [[ -n "$junos_do" ]]; then
    { cat "$PRIV/junos-rendered.set"; echo "$junos_do"; } >"$PRIV/.junos-load.set"
    if ! jcommit >>"$OUT/run.log" 2>&1; then record FAIL "$name" "junos commit rejected"; return; fi
  fi
  sleep "$SETTLE"
  capture "$name"
  local body; body="$(cat "$OUT/cells/$name.txt")"
  # A hidden route must not satisfy a presence check, but is named when it would
  # have, since its fix differs.  Absence reads both views: withdrawn means gone.
  # Sections are also scoped to the box that produced them, so `frr:` / `junos:`
  # is a scope rather than a naming convention: both views are greppable from one
  # string, so an expectation that is not format-distinctive (a bare group
  # address, say) would otherwise be satisfiable from the wrong box.
  sect() {  # sect <frr#|junos>> <0 active | 1 hidden | 2 either>
    awk -v p="===== $1" -v want="$2" \
      '/^=====/{ s = (substr($0, 1, length(p)) == p); h = (/ hidden / ? 1 : 0) }
       s && (want == 2 || h == want)' <<<"$body"
  }
  local why=""
  # Every arm ends `return 0` on purpose.  A bare `grep ... && why=...` whose grep
  # misses leaves the function's status at 1, and under `set -e` that aborts the
  # whole run -- silently, and *only* on the withdraw cells, whose entire job is
  # for that grep to miss.  A harness that dies on its own success path reports
  # fewer cells rather than a failure, which is the worst direction.
  check() {  # check <expect> <label> <section-prefix>
    local e="$1" label="$2" p="$3"
    if [[ -n "$e" ]]; then
      if [[ "${e:0:1}" == "!" ]]; then
        if grep -qE -- "${e:1}" <<<"$(sect "$p" 2)"; then why="$why $label:unexpectedly-present(${e:1})"; fi
      else
        if grep -qE -- "$e" <<<"$(sect "$p" 0)"; then :
        elif grep -qE -- "$e" <<<"$(sect "$p" 1)"; then why="$why $label:hidden($e)"
        else why="$why $label:missing($e)"; fi
      fi
    fi
    return 0
  }
  check "$exp_frr" frr 'frr#'
  check "$exp_junos" junos 'junos>'
  # A failed show leaves a hole that a '!' (absence) expectation reads as proof.
  if grep -q '^!!!!! show failed' <<<"$body"; then why="$why show-failed"; fi
  # Session-reset accounting, on every cell except the two that restart on purpose.
  local n; n="$(established_count)"
  if [[ -z "$n" ]]; then
    why="$why session-counter-unreadable"
  elif [[ "$name" == restart-* ]]; then
    # Both restart triggers are deliberately non-fatal (pkill matching no bgpd,
    # a rejected `clear bgp`), so a run in which nothing actually restarted would
    # leave the counter unmoved and re-baseline onto it -- and these two cells are
    # the only evidence the session recovers.  connectionsEstablished only ever
    # increases, so requiring it to move is what stops "never disturbed" passing.
    if (( n > BASE_ESTAB )); then BASE_ESTAB="$n"
    else why="$why no-restart-observed($BASE_ESTAB->$n)"; fi
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

  gate G2 "baseline Junos config captured and saved on the box as the restore point, so 'we changed nothing' is provable, not asserted"
  jcmd "show configuration | display set" 2>&1 | sanitize >"$OUT/junos-baseline.set" \
    || { record FAIL step0-G2-baseline "could not read the Junos config; see junos-baseline.set"; return 1; }
  # junos-baseline.set is sanitized, so it cannot be loaded back; save a raw copy on
  # the box itself.  No restore point, no commits.
  #
  # The path carries $TS because a fixed one lets two runs against the same box
  # collide: the second run's G2 would capture the FIRST run's harness config as
  # its baseline, restore the box to that, and report junos-left-unchanged PASS
  # over a box that is still mutated.  Timestamping stops the clobber; refusing to
  # start while another run's restore point is present stops the false baseline,
  # which timestamping alone does not.
  o="$(jcmd "file list $JUNOS_RESTORE_GLOB" 2>&1 || true)"
  if grep -qF '/var/tmp/blo15579-baseline-' <<<"$o" && ! grep -qi 'no such file' <<<"$o"; then
    log "$o"
    record FAIL step0-G2-baseline "another blo15579 run's restore point is on the box; its baseline would be this run's mutations. Finish or clean up that run first (see run.log)"
    return 1
  fi
  o="$(jcmd "show configuration | save $JUNOS_RESTORE" 2>&1 | sanitize)"
  grep -qi '^wrote' <<<"$o" \
    || { log "$o"; record FAIL step0-G2-baseline "could not save the restore point $JUNOS_RESTORE; see run.log"; return 1; }
  { jcmd "show system commit"; jcmd "show system license"; jcmd "show version"; } 2>&1 \
    | sanitize >"$OUT/junos-baseline-state.txt"
  record PASS step0-G2-baseline ""

  gate G3 "the Junos config in junos-base.set is syntactically accepted (commit check only)"
  o="$(jload <"$PRIV/junos-rendered.set" 2>&1 | sanitize)"
  echo "$o" >"$OUT/junos-commit-check.txt"
  grep -qi 'configuration check succeeds' <<<"$o" \
    || { record FAIL step0-G3-commit-check "Junos rejected the config; see junos-commit-check.txt"; return 1; }
  record PASS step0-G3-commit-check ""

  gate G4 "iBGP comes up and BOTH MCAST-VPN AFs are negotiated (not merely configured)"
  cp "$PRIV/junos-rendered.set" "$PRIV/.junos-load.set"
  jcommit >>"$OUT/run.log" 2>&1 || { record FAIL step0-G4-session "Junos commit failed"; return 1; }
  frr_up
  sleep "$SETTLE"
  capture step0-G4-session
  local b; b="$(cat "$OUT/cells/step0-G4-session.txt")"
  local why=""
  grep -qE 'Established|established' <<<"$b"       || why="$why no-established"
  grep -qE 'IPv4 MCAST-VPN|ipv4Mvpn|inet-mvpn'  <<<"$b" || why="$why v4-mvpn-af-not-negotiated"
  grep -qE 'IPv6 MCAST-VPN|ipv6Mvpn|inet6-mvpn' <<<"$b" || why="$why v6-mvpn-af-not-negotiated"
  # The baseline every reset check compares against; no baseline, no matrix.
  BASE_ESTAB="$(established_count)"
  [[ -n "$BASE_ESTAB" ]] || why="$why session-counter-unreadable"
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

  gate G4b "the rx0 receiver stub is GM-enabled, so join-group becomes local membership rather than a silent no-op"
  # `ip pim` alone leaves gm_enable false.  join-group only needs pim_ifp, so it is
  # ACCEPTED and even issues a socket join, but pim_if_membership_refresh() returns
  # early on !gm_enable: FRR never reaches JOINED, originates no Type-7, and six of
  # the fourteen cells fail for a reason that is not interop.  The dry-run cannot
  # see this (no FRR, no container), which is exactly what a step-0 gate is for --
  # an operator round-trip is the scarcest input here.
  # running-config emits these two only when gm_enable is set (pim_vty.c
  # gm_config_write), so this reads FRR's state, not an echo of frr-base.conf.
  local rx0; rx0="$(frrcmd "show running-config" 2>/dev/null \
    | awk '/^interface rx0$/{f=1;next} /^interface |^router /{f=0} f')"
  why=""
  grep -qx ' ip igmp'  <<<"$rx0" || why="$why rx0-igmp-not-enabled"
  grep -qx ' ipv6 mld' <<<"$rx0" || why="$why rx0-mld-not-enabled"
  if [[ -n "$why" ]]; then
    record FAIL step0-G4b-receiver-stub "$why -- join-group would be accepted but never become membership; see frr-base.conf"
    return 1
  fi
  record PASS step0-G4b-receiver-stub ""

  gate G5 "hold the session ${HOLD_SECONDS}s -- commit check is not a sustained session, and the box reports no installed licenses"
  sleep "$HOLD_SECONDS"
  capture step0-G5-soak
  local n; n="$(established_count)"
  if [[ -z "$n" ]]; then
    record FAIL step0-G5-soak "session counter unreadable after the soak"
    return 1
  elif [[ "$n" != "$BASE_ESTAB" ]]; then
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

  # Received, not "(local)": FRR's own Type-5 from the cell above is up until
  # withdraw-type5-v4 and would satisfy a bare `[5] source`.  As for Type-7 below.
  cell type5-v4-junos-to-frr "" \
    "set protocols mvpn source-active-advertisement" \
    "\\[5\\] source [^ ]+ group [^ ]+ ( |\$)" ""

  cell type7-v4-frr-to-junos "interface rx0
 ip igmp join-group $V4_GRP $V4_SRC" "" \
    "\\[7\\] source $V4_SRC group $V4_GRP" "^7:.*$V4_SRC"

  # Junos->FRR needs a Type-7 that FRR RECEIVED.  FRR's own Type-7 for this
  # (S,G), from the cell above and up until the withdraw cell, also prints
  # `[7] source S group G`, so that alone passes with no Junos join at all.
  # bgp_mvpn_show_routes tags FRR's own path "(local)" right after the group; a
  # received one has a space or nothing there.  Topology caveat (README "Known
  # limits"): C-S sits behind Junos here, so Junos is its own upstream for this
  # join and may send no Type-7 at all.  This cell then FAILs, which is the
  # honest answer, not a harness bug.
  cell type7-v4-junos-to-frr "" \
    "set protocols igmp interface $JUNOS_LAN_IFL version 3
set protocols igmp interface $JUNOS_LAN_IFL static group $V4_GRP source $V4_SRC" \
    "\\[7\\] source $V4_SRC group $V4_GRP ( |\$)" ""

  # Both joins leave: Junos keeps its own Type-7 for as long as its static join
  # is committed, so an FRR-only leave could never empty bgp.mvpn.0.
  cell withdraw-type7-v4-leave "interface rx0
 no ip igmp join-group $V4_GRP $V4_SRC" \
    "delete protocols igmp interface $JUNOS_LAN_IFL static group $V4_GRP" \
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
      "set protocols mld interface $JUNOS_LAN_IFL version 2
set protocols mld interface $JUNOS_LAN_IFL static group $V6_GRP source $V6_SRC" \
      "\\[7\\] source $V6_SRC group $V6_GRP ( |\$)" ""

    cell withdraw-type7-v6-leave "interface rx0
 no ipv6 mld join-group $V6_GRP $V6_SRC" \
      "delete protocols mld interface $JUNOS_LAN_IFL static group $V6_GRP" \
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
  bgp mvpn source-active $V4_SRC group $V4_GRP" >/dev/null \
    || log "re-arm of the v4 type-5 rejected; the restart cells will show it"
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
    echo "| Junos commits made | ${JUNOS_MADE:-0} |"
    # Reported from the verified restore, never assumed: an operator holding only
    # the tarball has to be able to tell a restored box from a mutated one, and
    # which file to load override by hand if it is the latter.
    if (( ${JUNOS_MADE:-0} == 0 )) || (( JUNOS_RESTORED )); then
      echo "| Junos restore | restored |"
    else
      echo "| Junos restore | **NOT RESTORED** -- \`load override $JUNOS_RESTORE\` by hand; see \`junos-cleanup.txt\` |"
    fi
    echo "| Junos restore point | \`$JUNOS_RESTORE\` |"
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
  # Only a VERIFIED restore disarms the EXIT trap.  Zeroing unconditionally spent
  # the one automatic retry on a path that could not report failure, and the
  # summary then asserted "restored" over a box left fully mutated.
  JUNOS_MADE=$JUNOS_COMMITS
  if cleanup_junos 2>&1 | sanitize >"$OUT/junos-cleanup.txt"; then
    JUNOS_RESTORED=1
    JUNOS_COMMITS=0            # verified: the exit trap must not restore twice
  else
    JUNOS_RESTORED=0           # unverified: leave the trap armed for one more go
    log "Junos NOT restored -- EXIT trap stays armed; 'load override $JUNOS_RESTORE' by hand if it also fails"
  fi
  if ! jcmd "show configuration | display set" 2>&1 | sanitize >"$OUT/junos-final.set"; then
    record FAIL junos-left-unchanged "could not read the Junos config back; see junos-final.set"
  elif diff -u "$OUT/junos-baseline.set" "$OUT/junos-final.set" >"$OUT/junos-config.diff"; then
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
  #
  # The -f guard makes the missing-file answer independent of the awk in $PATH.
  # Whether awk runs END after failing to open a file is implementation-defined:
  # if it does, the old form emitted `0` from END *and* `99` from the `||` arm, and
  # the two-line result made `[ '$good_fail' -eq 0 ]` die with "integer expression
  # expected" instead of reporting the missing summary.  Not reproduced on the awks
  # here -- mawk 1.3.4 and busybox both treat it as fatal and skip END, so both
  # forms print a bare 99 -- so the assertion below does not discriminate on this
  # host.  One line to stop depending on which awk is installed.
  countfail() { [ -f "$1" ] || { echo 99; return 0; }; awk '/^\| FAIL \|/{n++} END{print n+0}' "$1"; }

  echo "== dry-run A: good fixtures, expect the matrix to pass"
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-good" \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-good.log" 2>&1 || true
  good_fail=$(countfail "$OUT/dryrun-good/summary.md")

  echo "== dry-run B: empty fixtures, expect the matrix to fail (negative control)"
  FIXTURE_MODE=empty HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-empty" \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-empty.log" 2>&1 || true
  empty_fail=$(countfail "$OUT/dryrun-empty/summary.md")

  echo "== dry-run C: CONFIRM_MIN shorter than the soak, expect a refusal before step 0"
  confirm_rc=0
  CONFIRM_MIN=10 HOLD_SECONDS=600 SETTLE=20 OUT="$OUT/dryrun-confirm" \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-confirm.log" 2>&1 || confirm_rc=$?

  echo "== dry-run D: a show, an FRR config or one cell's session counter fails, expect FAIL cells, not an abort"
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-showfail" \
    DRY_FAIL_CMD='ipmsi-label|source-active|^type1-ipmsi-bidir .*json|^withdraw-type7-v4-leave show route table bgp\.mvpn\.0' \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-showfail.log" 2>&1 || true

  echo "== dry-run E: the Junos config cannot be read, expect G2 and the read-back to FAIL"
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-noconfig" DRY_FAIL_CMD='display set' \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-noconfig.log" 2>&1 || true

  echo "== dry-run F: mutation, the junos-to-frr cells' Junos lines never committed, expect those cells to FAIL"
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-nojoin" DRY_DROP_JUNOS='static group|source-active-advertisement' \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-nojoin.log" 2>&1 || true

  echo "== dry-run G/H: the session counter cannot be read at G4 / after the soak, expect step 0 to FAIL"
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-nocount" DRY_FAIL_CMD='json' \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-nocount.log" 2>&1 || true
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-nocount-g5" DRY_FAIL_CMD='^step0-G5-soak .*json' \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-nocount-g5.log" 2>&1 || true

  echo "== dry-run I: the restore point is gone, expect a REFUSAL to commit, not a confirm"
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-norestore" DRY_NO_RESTORE=1 \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-norestore.log" 2>&1 || true

  echo "== dry-run J: nothing actually restarts, expect the restart cells to FAIL"
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-norestart" DRY_NO_RESTART=1 \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-norestart.log" 2>&1 || true

  echo "== dry-run K: rx0 is not GM-enabled, expect step 0 to FAIL before the matrix"
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-nogm" DRY_NO_GM=1 \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-nogm.log" 2>&1 || true

  echo "== dry-run L: a Junos expectation that only FRR satisfies, expect that cell to FAIL"
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-misscope" DRY_MISSCOPE=1 \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-misscope.log" 2>&1 || true

  echo "== dry-run M: another run's restore point is on the box, expect G2 to refuse"
  FIXTURE_MODE=good HOLD_SECONDS=0 SETTLE=0 OUT="$OUT/dryrun-stale" DRY_STALE_RESTORE=1 \
    bash "${BASH_SOURCE[0]}" --dry-run-inner >"$OUT/dryrun-stale.log" 2>&1 || true

  echo "== assertions"
  assert "good fixtures produce zero FAIL cells (got $good_fail)"  "[ '$good_fail' -eq 0 ]"
  assert "empty fixtures produce FAIL cells (got $empty_fail)"     "[ '$empty_fail' -gt 5 ]"
  assert "summary.md was written"             "[ -s '$OUT/dryrun-good/summary.md' ]"
  # CONFIRM_MIN=10 is the old hardcoded value: the box would revert inside G5's soak.
  assert "commit-confirmed window shorter than the soak is refused (rc $confirm_rc)" \
    "[ $confirm_rc -ne 0 ] && grep -qF 'FATAL: CONFIRM_MIN=10' '$OUT/dryrun-confirm.log' && [ ! -e '$OUT/dryrun-confirm/summary.md' ]"
  assert "every cell produced a transcript"   "[ \$(ls '$OUT/dryrun-good/cells' 2>/dev/null | wc -l) -ge 14 ]"
  # The `-d` half is not padding: a grep over a directory that does not exist
  # also reports "clean", so without it a crashed run scores as sanitized.
  assert "sanitizer removed the Junos address" \
    "[ -d '$OUT/dryrun-good/cells' ] && ! grep -rqF '$JUNOS_HOST' '$OUT/dryrun-good'"
  assert "sanitizer removed the lab host address" \
    "[ -d '$OUT/dryrun-good/cells' ] && ! grep -rqF '$LOCAL_ADDR' '$OUT/dryrun-good'"
  assert "sanitizer actually fired (placeholders present)" \
    "grep -rqF '<JUNOS-ADDR>' '$OUT/dryrun-good/cells' 2>/dev/null"
  assert "artifact tarball was produced"      "[ -s '$OUT/dryrun-good.tar.gz' ]"
  # The tarball is what leaves the lab, so check it, not just the directory.
  # grep -c, not `! ... | grep -q`: an early grep exit can SIGPIPE tar, and under
  # pipefail the negation would then read a match as clean.
  assert "tarball carries neither lab address" \
    "[ -s '$OUT/dryrun-good.tar.gz' ] && [ \$(tar -xzOf '$OUT/dryrun-good.tar.gz' | grep -caF -e '$JUNOS_HOST' -e '$LOCAL_ADDR') -eq 0 ]"
  # Each of these used to abort under set -e before tar, so no artifact at all.
  # BRE on purpose: '|' is literal, '.' stands in for the backticks.
  assert "failing show / rejected config still yields summary.md and a tarball" \
    "[ -s '$OUT/dryrun-showfail/summary.md' ] && [ -s '$OUT/dryrun-showfail.tar.gz' ]"
  assert "rejected FRR config fails its cell" \
    "grep -q '^| FAIL | .type1-pmsi-ir-label. | frr config rejected' '$OUT/dryrun-showfail/summary.md'"
  # A failed show leaves a hole that an absence check would read as proof.
  assert "withdraw cell whose show failed is FAIL, not proven-absent" \
    "grep -q '^| FAIL | .withdraw-type7-v4-leave. |.*show-failed' '$OUT/dryrun-showfail/summary.md'"
  # Absent at G4: a join in junos-base.set makes the join cells no-ops.  Present
  # in the join cells: otherwise the withdraw absence checks pass on a dead model.
  assert "Junos static joins are committed by their cells, not by junos-base.set" \
    "[ -s '$OUT/dryrun-good/cells/step0-G4-session.txt' ] && ! grep -q '^7:dry-run-model' '$OUT/dryrun-good/cells/step0-G4-session.txt' && grep -q '^7:dry-run-model:$V4_SRC:$V4_GRP ' '$OUT/dryrun-good/cells/type7-v4-junos-to-frr.txt' && grep -q '^7:dry-run-model:$V6_SRC:$V6_GRP ' '$OUT/dryrun-good/cells/type7-v6-junos-to-frr.txt'"
  # The model has no `rollback`, and the seeded host-name must come back: a count
  # restores nothing, and a restore that empties the box fails the diff too.
  assert "cleanup restores the G2 restore point, not a commit count" \
    "grep -q '^| PASS | .junos-left-unchanged.' '$OUT/dryrun-good/summary.md' && grep -q 'dry-run-box' '$OUT/dryrun-good/junos-final.set' && grep -q '^commit complete' '$OUT/dryrun-good/junos-cleanup.txt'"
  assert "a route Junos holds hidden fails its cell as hidden, not as present" \
    "grep -q '^| FAIL | .type5-v4-frr-to-junos. |.*junos:hidden(' '$OUT/dryrun-empty/summary.md'"
  assert "junos-base.set sets no system statement and no v6 prefix in the v4 ssm-groups" \
    "[ -s '$OUT/dryrun-good/junos-config.set' ] && ! grep -qE '^set system |^set routing-options multicast ssm-groups [^ ]*:' '$OUT/dryrun-good/junos-config.set'"
  assert "unreadable Junos config fails G2 and the read-back, still packaged" \
    "[ -s '$OUT/dryrun-noconfig.tar.gz' ] && grep -q '^| FAIL | .step0-G2-baseline.' '$OUT/dryrun-noconfig/summary.md' && grep -q '^| FAIL | .junos-left-unchanged.' '$OUT/dryrun-noconfig/summary.md'"
  # FRR's own "(local)" Type-5/Type-7 are in the fixture throughout, so this fails
  # if a cell accepts those paths instead of ones received from Junos.
  assert "without their Junos lines, the three junos-to-frr cells FAIL" \
    "grep -q '^| FAIL | .type5-v4-junos-to-frr. |.*frr:missing(' '$OUT/dryrun-nojoin/summary.md' && grep -q '^| FAIL | .type7-v4-junos-to-frr. |.*frr:missing(' '$OUT/dryrun-nojoin/summary.md' && grep -q '^| FAIL | .type7-v6-junos-to-frr. |.*frr:missing(' '$OUT/dryrun-nojoin/summary.md'"
  # Read as 0, a failed counter matches a 0 baseline and passes every reset check.
  assert "unreadable session counter fails G4, G5 and the cell, not 0 == 0" \
    "grep -q '^| FAIL | .step0-G4-session. |.*session-counter-unreadable' '$OUT/dryrun-nocount/summary.md' && grep -q '^| FAIL | .step0-G5-soak. | session counter unreadable' '$OUT/dryrun-nocount-g5/summary.md' && grep -q '^| FAIL | .type1-ipmsi-bidir. |.*session-counter-unreadable' '$OUT/dryrun-showfail/summary.md'"
  # C2: a bare `commit` after a failed `load override` CONFIRMS the pending
  # `commit confirmed` and makes the mutation permanent.  The refusal has to
  # happen before anything is sent, so the box must be left mutated and SAID to be.
  assert "a missing restore point refuses to commit rather than confirming" \
    "grep -q 'NOT committing' '$OUT/dryrun-norestore/junos-cleanup.txt' && ! grep -q 'commit complete' '$OUT/dryrun-norestore/junos-cleanup.txt'"
  assert "an unrestored box is reported as NOT RESTORED, not as restored" \
    "grep -q 'NOT RESTORED' '$OUT/dryrun-norestore/summary.md' && grep -q '^| FAIL | .junos-left-unchanged.' '$OUT/dryrun-norestore/summary.md' && grep -qF '| Junos restore point |' '$OUT/dryrun-norestore/summary.md'"
  assert "a restored box still reports restored (positive control)" \
    "grep -q '^| Junos restore | restored |' '$OUT/dryrun-good/summary.md'"
  # I1: both restart triggers are non-fatal, so "nothing restarted" must not pass.
  assert "restart cells FAIL when nothing actually restarted" \
    "grep -q '^| FAIL | .restart-bgpd. |.*no-restart-observed' '$OUT/dryrun-norestart/summary.md' && grep -q '^| FAIL | .restart-session. |.*no-restart-observed' '$OUT/dryrun-norestart/summary.md'"
  # C1: join-group without `ip igmp` is accepted and never becomes membership.
  assert "a receiver stub that is not GM-enabled fails step 0, before the matrix" \
    "grep -q '^| FAIL | .step0-G4b-receiver-stub. |.*rx0-igmp-not-enabled' '$OUT/dryrun-nogm/summary.md' && [ \$(ls '$OUT/dryrun-nogm/cells' | wc -l) -lt 10 ]"
  assert "frr-base.conf enables igmp and mld on the receiver stub" \
    "grep -qx ' ip igmp' '$HERE/frr-base.conf' && grep -qx ' ipv6 mld' '$HERE/frr-base.conf'"
  # S3: the ifl and an overridden router-id are parameters like any other.
  assert "sanitizer removed the Junos receiver ifl" \
    "[ -d '$OUT/dryrun-good/cells' ] && ! grep -rqF '$JUNOS_LAN_IFL' '$OUT/dryrun-good'"
  # Contract check, not a mutation test: it fires only on an awk that runs END
  # after a failed open.  mawk and busybox do not, so this passes either way here.
  assert "countfail reports a missing summary as a single 99" \
    "[ \$(countfail /nonexistent/summary.md) -eq 99 ]"
  # S2: `frr:` / `junos:` must be a scope, not a naming convention.
  assert "a Junos expectation is not satisfiable from the FRR section" \
    "grep -q '^| FAIL | .type1-ipmsi-bidir. |.*junos:missing(' '$OUT/dryrun-misscope/summary.md'"
  # S4: a fixed restore path let a second run adopt the first run's mutations as
  # its baseline and then report junos-left-unchanged PASS over a mutated box.
  assert "a second run refuses to start while another run's restore point is present" \
    "grep -q '^| FAIL | .step0-G2-baseline. |.*another blo15579 run' '$OUT/dryrun-stale/summary.md'"
  assert "the restore point is per-run, not a fixed path two runs would share" \
    "grep -qE 'blo15579-baseline-[0-9]{8}T[0-9]{6}Z\.conf' '$OUT/dryrun-good/summary.md'"
  echo
  if (( fails )); then echo "DRY-RUN FAILED ($fails assertion(s))"; exit 1; fi
  echo "DRY-RUN OK -- harness logic, verdicts (both directions), sanitizer and packaging all exercised."
  exit 0
fi

main
