#!/usr/bin/env bash
# Build the nbg6817 PoP's OpenWrt FRR .ipk set from a pinned Blockcast/frr tag.
#
# Runs INSIDE the official OpenWrt SDK container for the router's exact firmware
# point release (openwrt/sdk:ipq806x-generic-<release>). Driven by
# .github/workflows/nbg6817-openwrt-ipk.yml.
#
# WHY A CONTAINER: the SDK point release must match the router's installed
# firmware exactly — an ABI-skewed .ipk installs and then crashes at runtime
# (onprem-k8s pop-fleet/nbg6817/frr-openwrt-build.md, "Toolchain"). Pinning the
# image tag to the firmware release makes that match a property of the build
# definition rather than of whoever ran it. The image also ships OpenWrt's full
# host prereq set and a non-root `buildbot` user, which OpenWrt requires — it
# refuses to build as root.
#
# WHY file:// AND NOT https://github.com/Blockcast/frr.git: the fork is private,
# so an https clone from inside the container would need a token passed in, and
# this build runs with `V=s` — which echoes command lines, so a credentialed URL
# could land in a retained CI log. The workflow instead checks the tag out on
# the runner (where actions/checkout already holds a scoped token) and hands the
# repo to the container as a plain local git repo. No secret ever enters the
# container, and PKG_SOURCE_VERSION still pins to the tag.
set -euo pipefail

: "${FRR_REF:?FRR_REF (Blockcast/frr tag) is required}"
: "${FRR_SHA:?FRR_SHA (full commit SHA the tag resolves to) is required}"
: "${ROUTER_OPENWRT_RELEASE:?ROUTER_OPENWRT_RELEASE (nbg6817 firmware point release) is required}"
: "${ROUTER_OPENWRT_TARGET:=ipq806x/generic}"
: "${SDK_IMAGE:=unknown}"
: "${SDK_DIGEST:=unknown}"
: "${PKG_RELEASE:=4}"
: "${FRR_SRC:=/src}"
: "${FRR_PKG_VERSION:=10.8.0}"

# The daemon set the nbg6817 `daemons` file and the frr-gtm DaemonSet enable.
#
# NOTE: there is deliberately no `frr-vtysh` here. vtysh is NOT a separate
# OpenWrt package — it is installed by the base `frr` package (see the feed
# Makefile's Package/frr/install) and enabled by --enable-vtysh, already present
# in the feed's CONFIGURE_ARGS. Asserted at the end of this script rather than
# assumed. `frr-watchfrr` is included because it is the supervisor the init
# script drives (the feed marks it DEFAULT:=y if PACKAGE_frr).
FRR_PKGS=(frr frr-bgpd frr-pimd frr-pim6d frr-zebra frr-staticd frr-watchfrr)

# The source repo is copied in by `docker cp`, so it arrives owned by a uid that
# is not `buildbot`. Without this git refuses to read it ("dubious ownership").
git config --global --add safe.directory '*'

cd /builder

echo "=== SDK container layout ==="
ls -la /builder | head -40

if [ ! -x ./scripts/feeds ]; then
  echo "scripts/feeds not present; running the image's setup path"
  [ -x ./setup.sh ] && ./setup.sh || true
fi
if [ ! -x ./scripts/feeds ]; then
  echo "FATAL: no OpenWrt SDK in /builder — cannot build" >&2
  ls -la /builder >&2
  exit 1
fi

echo "=== SDK identity (must match the router's firmware) ==="
# This block used to be `cat ./version || true` + `grep .config || true`. Both
# are best-effort no-ops here: the SDK image ships no ./version, and .config
# does not exist until `make defconfig` runs much later. So the block printed
# NOTHING and asserted NOTHING, while its header claimed a firmware match --
# and that is why every manifest so far recorded `sdk_version: unknown`, the
# exact "not recorded at build time" pattern BLO-31631 exists to eliminate.
#
# Read the identity the SDK image actually carries. VERSION_PATH and TARGET are
# set in the image's own Config.Env by OpenWrt's SDK build, so they describe the
# toolchain that will compile these bytes rather than the tag someone typed.
# The workflow asserts the same pair on the runner before `docker create`; this
# re-asserts it where the compile happens, for the same reason the FRR_SHA check
# below is duplicated in here.
SDK_RELEASE="${VERSION_PATH#releases/}"
SDK_TARGET="${TARGET:-}"
echo "sdk_release=${SDK_RELEASE:-<unset>} sdk_target=${SDK_TARGET:-<unset>}"
if [ -z "${SDK_RELEASE:-}" ] || [ -z "${SDK_TARGET:-}" ]; then
  echo "FATAL: SDK image carries no VERSION_PATH/TARGET -- cannot establish toolchain identity" >&2
  exit 1
fi
# An ABI-skewed .ipk installs cleanly and then crashes at runtime, on a router
# only a human standing next to it can recover. Fail the build, not the router.
if [ "$SDK_RELEASE" != "$ROUTER_OPENWRT_RELEASE" ]; then
  echo "FATAL: SDK release '$SDK_RELEASE' != router firmware '$ROUTER_OPENWRT_RELEASE' -- ABI skew" >&2
  exit 1
fi
if [ "$SDK_TARGET" != "$ROUTER_OPENWRT_TARGET" ]; then
  echo "FATAL: SDK target '$SDK_TARGET' != router target '$ROUTER_OPENWRT_TARGET'" >&2
  exit 1
fi
echo "OK: SDK $SDK_RELEASE / $SDK_TARGET matches the nbg6817 firmware"

echo "=== source repo handed in by the workflow ==="
git -C "$FRR_SRC" log -1 --format='%H %ci %s' || {
  echo "FATAL: $FRR_SRC is not a git repo" >&2; exit 1; }
# Re-assert inside the container what the workflow asserted on the runner. The
# container is where the bytes actually get compiled, so this is the check that
# matters: a mismatch here means the wrong tree was handed in.
SRC_SHA=$(git -C "$FRR_SRC" rev-parse "${FRR_REF}^{commit}")
if [ "$SRC_SHA" != "$FRR_SHA" ]; then
  echo "FATAL: $FRR_SRC has $FRR_REF -> $SRC_SHA, expected $FRR_SHA" >&2
  exit 1
fi
echo "OK: $FRR_REF -> $SRC_SHA in the handed-in repo"

echo "=== feeds update ==="
./scripts/feeds update -a

MK=feeds/packages/net/frr/Makefile
[ -f "$MK" ] || { echo "FATAL: $MK missing after feeds update" >&2; exit 1; }
cp "$MK" "$MK.orig"

# Repoint the feed's frr package (upstream FRR release tarball) at the Blockcast
# fork, pinned to an immutable reviewed TAG rather than a moving branch.
FRR_REF="$FRR_REF" PKG_RELEASE="$PKG_RELEASE" FRR_SRC="$FRR_SRC" \
FRR_PKG_VERSION="$FRR_PKG_VERSION" python3 - "$MK" <<'PY'
import os, re, sys

path = sys.argv[1]
src = open(path).read()
ref = os.environ["FRR_REF"]
rel = os.environ["PKG_RELEASE"]
url = "file://" + os.environ["FRR_SRC"]
ver = os.environ["FRR_PKG_VERSION"]

subs = [
    (r"(?m)^PKG_VERSION:=.*$",        f"PKG_VERSION:={ver}"),
    (r"(?m)^PKG_RELEASE:=.*$",        f"PKG_RELEASE:={rel}"),
    # Only present when the feed pins a dated snapshot; harmless if absent.
    (r"(?m)^PKG_SOURCE_DATE:=.*\n",   "", True),
    (r"(?m)^PKG_SOURCE:=.*$",         "PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz"),
    (r"(?m)^PKG_SOURCE_VERSION:=.*$", f"PKG_SOURCE_VERSION:={ref}"),
    (r"(?m)^PKG_SOURCE_URL:=.*$",     f"PKG_SOURCE_URL:={url}"),
    # Swap the release-tarball hash for the git-proto trio.
    (r"(?m)^PKG_HASH:=.*$",
     "PKG_SOURCE_PROTO:=git\n"
     "PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)\n"
     "PKG_MIRROR_HASH:=skip"),
    # The feed keys these off PKG_SOURCE_VERSION (a bare SHA upstream). With a
    # tag they must instead match PKG_SOURCE_SUBDIR, which is what the git
    # download actually extracts to.
    (r"(?m)^PKG_BUILD_DIR:=.*$",  "PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)"),
    (r"(?m)^HOST_BUILD_DIR:=.*$", "HOST_BUILD_DIR:=$(BUILD_DIR_HOST)/$(PKG_NAME)-$(PKG_VERSION)"),
    # Ship libmlag_pb.so alongside the other FRR shared libs in the base
    # package. The feed does not, and on FRR >= 10.3 that breaks the build:
    #
    #   Package frr-zebra is missing dependencies for the following libraries:
    #   libmlag_pb.so.0
    #
    # mlag/subdir.am has always had `if HAVE_PROTOBUF3: lib_LTLIBRARIES +=
    # mlag/libmlag_pb.la`, but in FRR 10.2.1 (the version this feed pins)
    # PROTO3 was only ever set true under `if test "$enable_protobuf3" = yes`
    # -- and no AC_ARG_ENABLE ever defined --enable-protobuf3, so the flag was
    # unsettable and HAVE_PROTOBUF3 was permanently false. libmlag_pb was
    # therefore never built as a shared library, zebra never linked it, and the
    # feed had no reason to install it. FRR later fixed that dead flag: this
    # tag's configure.ac sets PROTO3=true whenever protobuf is not disabled and
    # libprotobuf-c >= 1.3.0 is present, which it is here (the feed itself
    # depends on +libprotobuf-c). So the library is now built shared, installed
    # to PKG_INSTALL_DIR, and linked by zebra -- while the feed's install list
    # still reflects the 10.2.1 world. Upstream's master feed (10.6.1) has not
    # caught up either, so this is not something to wait for.
    #
    # Shipping it is preferred over building with --disable-protobuf: it keeps
    # this .ipk configured identically to the PE container image built from the
    # same tag, which is the whole point of the version-parity contract.
    #
    # Copied UNCONDITIONALLY, exactly as the feed copies libfrr.so* and
    # libmgmt_be_nb.so* on the two lines above. An earlier revision guarded this
    # with $(if $(wildcard $(PKG_INSTALL_DIR)/usr/lib/libmlag_pb.so*),...) and
    # that silently expanded to NOTHING -- run 33891736212 installed the library
    # into PKG_INSTALL_DIR at 16:42:20.85 and then ran this very recipe at
    # 16:42:25.64 emitting copies for libfrr and libmgmt_be_nb and none for
    # libmlag_pb, failing frr-zebra packaging 3s later on the same missing
    # libmlag_pb.so.0. GNU make caches its directory globs, so a $(wildcard) on
    # a path that Build/Install populates LATER in the same make invocation keeps
    # returning the stale empty listing. The feed's own $(if $(CONFIG_FRR_SNMP),...)
    # idiom this was modelled on is keyed off a Kconfig symbol, which is fixed at
    # parse time; a filesystem glob is not, and that is the difference.
    #
    # Unconditional is also the safer failure mode: at this tag the library is
    # always built shared (configure sets PROTO3 whenever protobuf is enabled),
    # and if some future build does disable protobuf the cp fails loudly at build
    # time instead of quietly shipping a zebra that cannot start on a router only
    # a human can reach.
    (r"(?m)^(\t\$\(CP\) \$\(PKG_INSTALL_DIR\)/usr/lib/libmgmt_be_nb\.so\* \$\(1\)/usr/lib/)$",
     "\\1\n\t$(CP) $(PKG_INSTALL_DIR)/usr/lib/libmlag_pb.so* $(1)/usr/lib/"),
]
for entry in subs:
    pat, repl = entry[0], entry[1]
    optional = len(entry) > 2 and entry[2]
    src, n = re.subn(pat, repl, src, count=1)
    if n != 1 and not optional:
        sys.exit(f"FATAL: pattern did not match exactly once in {path}: {pat!r}")

open(path, "w").write(src)
print("rewrote", path)
PY

echo "=== frr package source pin (diff vs feed) ==="
diff -u "$MK.orig" "$MK" || true

echo "=== feeds install ==="
./scripts/feeds install -a

echo "=== package selection ==="
for p in "${FRR_PKGS[@]}"; do
  echo "CONFIG_PACKAGE_${p}=y" >> .config
done
make defconfig >/dev/null

echo "--- resolved frr config ---"
grep -E '^(CONFIG_PACKAGE_frr|# CONFIG_PACKAGE_frr)' .config | sort

# AC gate: frr-pim6d is not optional. BLO-22372's probe drives
# `ipv6 mld static-group`, which lives in pim6d; a build without it yields a
# probe that silently originates no Type-7 and a validation run that looks
# clean while proving nothing. Fail loudly rather than ship that.
if ! grep -qx 'CONFIG_PACKAGE_frr-pim6d=y' .config; then
  echo "FATAL: CONFIG_PACKAGE_frr-pim6d=y not selected after defconfig" >&2
  exit 1
fi
echo "OK: CONFIG_PACKAGE_frr-pim6d=y is selected"

echo "=== make package/frr/clean ==="
make package/frr/clean V=s

echo "=== make package/frr/compile ==="
make package/frr/compile -j"$(nproc)" V=s

echo "=== configure flags actually used (pim6d/vtysh evidence from the build) ==="
CFGLOG=$(find build_dir -maxdepth 4 -name config.log -path '*frr*' 2>/dev/null | head -1)
if [ -n "${CFGLOG:-}" ]; then
  grep -ohE '\-\-(enable|disable)-(pim6d|pimd|bgpd|vtysh)' "$CFGLOG" | sort -u || true
else
  echo "(no config.log found)"
fi

echo "=== produced packages ==="
mkdir -p /builder/artifacts
# Copy ONLY the daemon set this PoP runs -- deliberately not `find -name 'frr*.ipk'`.
#
# `make defconfig` marks every other FRR daemon =m (the SDK's default for package
# symbols), so the build also produces frr-ospfd, frr-isisd, frr-ldpd, frr-nhrpd,
# frr-pythontools and a dozen more. Shipping those to the operator is actively
# harmful, not merely untidy: the retrieval instructions say
# `opkg install ./frr*.ipk` (one transaction, so opkg resolves the inter-package
# deps together), and frr-pythontools DEPENDS on +python3-base +python3-light
# +python3-logging. A home router has none of those and no configured network
# feed to fetch them from, so opkg fails the WHOLE transaction on an unsatisfied
# dependency -- inside a one-shot operator window, on a device only a human can
# reach. Filtering here is what keeps the glob in those instructions safe.
#
# It also honours frr-openwrt-build.md's standing rule: "do not let the SDK's
# default package selection silently add daemons this fork doesn't ship config
# for."
# OpenWrt 24.10 still ships opkg/.ipk; apk arrives after 24.10.
for p in "${FRR_PKGS[@]}"; do
  found=$(find bin/packages -name "${p}_*.ipk" | head -1)
  if [ -n "$found" ]; then cp "$found" /builder/artifacts/; fi
done
ls -la /builder/artifacts

echo "=== built but deliberately NOT shipped ==="
find bin/packages -name 'frr*.ipk' -printf '%f\n' | sort > /tmp/all_built.txt
find /builder/artifacts -name '*.ipk' -printf '%f\n' | sort > /tmp/shipped.txt
comm -23 /tmp/all_built.txt /tmp/shipped.txt | sed 's/^/  excluded: /' || true

if [ -z "$(ls -A /builder/artifacts 2>/dev/null)" ]; then
  echo "FATAL: no frr .ipk produced" >&2
  exit 1
fi
missing=0
for p in "${FRR_PKGS[@]}"; do
  if ! ls /builder/artifacts | grep -q "^${p}_"; then
    echo "FATAL: expected package ${p} not produced" >&2
    missing=1
  fi
done
[ "$missing" -eq 0 ] || exit 1
echo "OK: all ${#FRR_PKGS[@]} expected packages produced"

# The delivered set must be EXACTLY the daemon set -- no extras. This is the
# check that keeps the operator's `opkg install ./frr*.ipk` a safe instruction.
shipped_count=$(find /builder/artifacts -name '*.ipk' | wc -l)
if [ "$shipped_count" -ne "${#FRR_PKGS[@]}" ]; then
  echo "FATAL: artifacts hold ${shipped_count} .ipk but the daemon set is ${#FRR_PKGS[@]}" >&2
  ls -1 /builder/artifacts >&2
  exit 1
fi
echo "OK: artifacts hold exactly ${#FRR_PKGS[@]} .ipk, matching the daemon set"

# vtysh ships inside the base frr package rather than a frr-vtysh package.
# Prove it from the artifact instead of asserting it in prose.
echo "=== vtysh presence in base frr package ==="
BASE=$(find /builder/artifacts -name 'frr_*.ipk' | head -1)

# .ipk payload members may be listed with or without a leading "./" depending on
# how the archive was rolled, so every match below is anchored on (^|/) rather
# than assuming one form.
#
# Read the payload member list ONCE per archive, into a variable, and match
# against that text. Do not re-derive it per check by piping tar into a
# consumer, which is what this file used to do.
#
# Why: listing an .ipk means unwrapping two nested archives, and any consumer
# that stops reading early -- `grep -q` on its first match, `head -1` on its
# first line -- SIGPIPEs the upstream tar. Under this script's `set -o pipefail`
# that turns a SUCCESSFUL match into a non-zero pipeline, so the status
# inverts the answer.
#
# Run 33900460174 (head 5b414a13) failed exactly that way. It reported
#   "FATAL: libmlag_pb.so missing from frr_10.8.0-r4_..."
# against an .ipk whose payload provably contains usr/lib/libmlag_pb.so,
# libmlag_pb.so.0 and libmlag_pb.so.0.0.0 -- verified by extracting the very
# artifact that run uploaded, and corroborated by the build log, which shows
# both the `cp` into the package dir and rstrip.sh processing the library.
# The vtysh and pim6d checks passed in that same run only by accident: they
# wrapped the pipeline in $( ) and tested the resulting STRING, so they never
# looked at the status that was lying.
#
# Capture a payload listing once, and assert the archive was read COMPLETELY.
#
# An unreadable archive and an archive missing one member are different faults
# with different owners, and only this assertion can tell them apart. Without
# it, a bad archive surfaces at whichever member check runs first and reports
# that member as missing -- diagnosing the wrong problem, which is how a
# corrupt package would read as "zebra will not start".
#
# Non-empty alone is NOT sufficient: a truncated .ipk yields a PARTIAL member
# list, which is worse than an empty one because it looks plausible while
# silently lacking members. So the status of the read is checked too -- and
# here, uniquely, that status is trustworthy, because the command substitution
# consumes the stream to EOF, so nothing exits early and nothing is SIGPIPEd.
# `pipefail` is re-stated inside to mark this as the one construction in this
# file whose pipeline status means what it says.
ipk_list() {
  local list
  if ! list=$(set -o pipefail; tar -xzOf "$1" ./data.tar.gz 2>/dev/null | tar -tzf - 2>/dev/null); then
    echo "FATAL: cannot read the payload of $(basename "$1") -- truncated, corrupt," >&2
    echo "       or not an .ipk. This is an ARCHIVE fault, not a missing file." >&2
    return 1
  fi
  if [ -z "$list" ]; then
    echo "FATAL: payload of $(basename "$1") lists no members. ARCHIVE fault, not" >&2
    echo "       a missing file." >&2
    return 1
  fi
  printf '%s\n' "$list"
}

# Stream one payload member out of an .ipk to stdout. The caller checks the
# extracted bytes (`[ -s ]`), not this status, for the same reason as above.
ipk_extract() { tar -xzOf "$1" ./data.tar.gz 2>/dev/null | tar -xzOf - "$2" 2>/dev/null; }

# Listed once here and reused by every base-package check below, so the
# archive is opened one time and each check is a pure string match.
BASE_FILES=$(ipk_list "$BASE") || exit 1

if grep -qE '(^|/)usr/bin/vtysh$' <<<"$BASE_FILES"; then
  echo "OK: usr/bin/vtysh present in $(basename "$BASE")"
else
  echo "WARN: could not confirm vtysh inside $(basename "$BASE")"
  head -30 <<<"$BASE_FILES"
fi

# --- Artifact-level acceptance checks -------------------------------------
#
# Everything above proves things about the build INPUTS (the tag, its ancestry,
# the SDK release). These three prove things about the OUTPUT bytes the operator
# will actually install, which is what the acceptance criteria ask for.

fail=0

# 1. libmlag_pb.so must be in the base package. zebra has a NEEDED entry for
#    libmlag_pb.so.0 (see the feed patch above); without the library present
#    zebra does not start -- it dies at load time with "cannot open shared
#    object file", which on a remote router looks like a bad flash rather than
#    a missing file. OpenWrt's own dependency check catches this at package
#    time, but assert it against the artifact too so the guarantee survives any
#    future change to that check.
echo "=== libmlag_pb.so in base frr package ==="
if grep -qE '(^|/)usr/lib/libmlag_pb\.so' <<<"$BASE_FILES"; then
  echo "OK: libmlag_pb.so* present in $(basename "$BASE")"
  grep -E '(^|/)usr/lib/' <<<"$BASE_FILES" | sort || true
else
  echo "FATAL: libmlag_pb.so missing from $(basename "$BASE") -- zebra will not start" >&2
  echo "       (the archive read completely, so this is a genuine absence)" >&2
  fail=1
fi

# 2. frr-pim6d must contain a real pim6d binary. AC2 asks for the daemon to be
#    evidenced from the produced packages rather than asserted, and a selected
#    CONFIG_PACKAGE_frr-pim6d=y alone does not prove a binary came out the far
#    end. BLO-22372's probe drives `ipv6 mld static-group`, which lives here.
echo "=== pim6d binary in frr-pim6d package ==="
P6=$(find /builder/artifacts -name 'frr-pim6d_*.ipk' | head -1)
if [ -z "${P6:-}" ]; then
  echo "FATAL: no frr-pim6d_*.ipk in the artifact set at all" >&2
  fail=1
elif ! P6_FILES=$(ipk_list "$P6"); then
  # ipk_list already named the archive fault. Do not let it read as a missing
  # daemon: "no pim6d" and "cannot read the package" need different fixes.
  fail=1
elif grep -qE '(^|/)usr/sbin/pim6d$' <<<"$P6_FILES"; then
  echo "OK: usr/sbin/pim6d present in $(basename "$P6")"
else
  echo "FATAL: no usr/sbin/pim6d in frr-pim6d package -- the probe would originate no Type-7" >&2
  fail=1
fi

# 3. The compiled bgpd must actually carry d3cfdeb8. Ancestry proves the SOURCE
#    contained the fix; this proves the BYTES do, which is the claim the PoP
#    deploy actually rests on.
#
#    The sentinel is the flog_err format string the fix introduces:
#      bgpd/bgp_mvpn.c: "%s [Error] MVPN Type-%u body does not match advertised
#                        length %u"
#    Occurrences in bgp_mvpn.c: 0 at d3cfdeb8^, 1 at this tag. As a string
#    literal it lands in .rodata and survives rstrip/sstrip.
#
#    Do NOT use BGP_MVPN_TYPE3_V6_V4_SPEC_LEN as the sentinel even though the
#    fix introduces it. It is a #define used in an integer comparison
#    (bgp_mvpn.c:197 `length == BGP_MVPN_TYPE3_V6_V4_SPEC_LEN`), so it compiles
#    to a number and never appears in the binary -- grepping for it returns 0 on
#    pre-fix AND post-fix builds, i.e. a silent false negative.
SENTINEL='body does not match advertised length'
echo "=== d3cfdeb8 sentinel in the compiled bgpd ==="
BGPD_IPK=$(find /builder/artifacts -name 'frr-bgpd_*.ipk' | head -1)
if [ -z "${BGPD_IPK:-}" ]; then
  echo "FATAL: no frr-bgpd_*.ipk in the artifact set at all" >&2
  fail=1
elif ! BGPD_FILES=$(ipk_list "$BGPD_IPK"); then
  # Archive fault already named. Critically, do NOT let it fall through to the
  # sentinel branch: "cannot read the package" must never be reported as
  # "the bytes do not carry the fix", which would read as a PRE-FIX verdict on
  # the one check the PoP deploy decision actually rests on.
  fail=1
else
  BGPD_MEMBER=$(grep -m1 -E '(^|/)usr/sbin/bgpd$' <<<"$BGPD_FILES" || true)
  if [ -z "${BGPD_MEMBER:-}" ]; then
    echo "FATAL: no usr/sbin/bgpd member in $(basename "$BGPD_IPK")" >&2
    head -20 <<<"$BGPD_FILES"
    fail=1
  else
    ipk_extract "$BGPD_IPK" "$BGPD_MEMBER" > /tmp/bgpd.bin || true
    if [ ! -s /tmp/bgpd.bin ]; then
      echo "FATAL: could not extract ${BGPD_MEMBER} from $(basename "$BGPD_IPK")" >&2
      fail=1
    elif grep -aqF "$SENTINEL" /tmp/bgpd.bin; then
      echo "OK: post-fix sentinel present in bgpd -- the built binary contains d3cfdeb8"
      echo "    ($(stat -c%s /tmp/bgpd.bin) bytes, member ${BGPD_MEMBER} of $(basename "$BGPD_IPK"))"
    else
      echo "FATAL: sentinel '$SENTINEL' NOT found in the compiled bgpd." >&2
      echo "       The tag's ancestry contains d3cfdeb8 but the bytes do not carry it." >&2
      fail=1
    fi
  fi
fi

[ "$fail" -eq 0 ] || { echo "FATAL: artifact acceptance checks failed" >&2; exit 1; }
echo "OK: all artifact acceptance checks passed"

# Read one field out of an .ipk's control file. Best-effort by construction:
# the manifest is a record, not a gate, and it is written AFTER the acceptance
# checks have already passed, so nothing here may fail a two-hour build. Every
# failure path yields the literal "unknown" instead.
ipk_control_field() {
  local v
  v=$(tar -xzOf "$1" ./control.tar.gz 2>/dev/null \
      | tar -xzOf - ./control 2>/dev/null \
      | sed -n "s/^${2}: *//p" | head -1) || true
  [ -n "$v" ] && printf '%s\n' "$v" || printf 'unknown\n'
}

# The durable record that closes frr-openwrt-build.md's version-parity contract.
{
  echo "# nbg6817 OpenWrt FRR .ipk build manifest"
  echo
  echo "frr_tag:             $FRR_REF"
  echo "frr_commit_sha:      $FRR_SHA"
  echo "frr_source:          ${FRR_SRC} (tag checked out on the runner from Blockcast/frr)"
  echo "openwrt_pkg_version: ${FRR_PKG_VERSION}-r${PKG_RELEASE}"
  echo "sdk_version:         ${SDK_RELEASE}"
  echo "sdk_target:          ${SDK_TARGET}"
  echo "sdk_image:           ${SDK_IMAGE}"
  echo "sdk_digest:          ${SDK_DIGEST}"
  echo "router_firmware:     ${ROUTER_OPENWRT_RELEASE} (asserted equal to sdk_version)"
  echo "target:              $(grep -E '^CONFIG_TARGET_BOARD=' .config | cut -d'"' -f2)/$(grep -E '^CONFIG_TARGET_SUBTARGET=' .config | cut -d'"' -f2)"
  echo "arch_packages:       $(grep -E '^CONFIG_TARGET_ARCH_PACKAGES=' .config | cut -d'"' -f2)"
  echo "built_at:            $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "## selected frr config"
  grep -E '^CONFIG_PACKAGE_frr' .config | sort
  echo
  echo "## packages (sha256)"
  (cd /builder/artifacts && sha256sum ./*.ipk)
  echo
  # Each package's declared Depends, so the operator can diff the required set
  # against `opkg list-installed` BEFORE opening the one-shot install window.
  # This is the one thing about the artifact that cannot be derived on the
  # router without committing to the install, and nbg6817 is reachable only by
  # a human standing next to it -- so a failed dependency resolution there
  # costs another physical visit, not a retry.
  echo "## declared dependencies (verify against \`opkg list-installed\` first)"
  for f in /builder/artifacts/*.ipk; do
    echo "$(basename "$f"): $(ipk_control_field "$f" Depends)"
  done
} > /builder/artifacts/MANIFEST.txt

echo "=== MANIFEST ==="
cat /builder/artifacts/MANIFEST.txt
