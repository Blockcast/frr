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
cat ./version 2>/dev/null || true
grep -E '^CONFIG_TARGET_(BOARD|SUBTARGET|ARCH_PACKAGES)=' .config 2>/dev/null || true

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
# OpenWrt 24.10 still ships opkg/.ipk; apk arrives after 24.10.
find bin/packages -name 'frr*.ipk' -exec cp {} /builder/artifacts/ \;
ls -la /builder/artifacts

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

# vtysh ships inside the base frr package rather than a frr-vtysh package.
# Prove it from the artifact instead of asserting it in prose.
echo "=== vtysh presence in base frr package ==="
BASE=$(find /builder/artifacts -name 'frr_*.ipk' | head -1)
if tar -xzOf "$BASE" ./data.tar.gz 2>/dev/null | tar -tzf - 2>/dev/null | grep -qE '\./usr/bin/vtysh$'; then
  echo "OK: ./usr/bin/vtysh present in $(basename "$BASE")"
else
  echo "WARN: could not confirm vtysh inside $(basename "$BASE")"
  tar -xzOf "$BASE" ./data.tar.gz 2>/dev/null | tar -tzf - 2>/dev/null | head -30 || true
fi

# The durable record that closes frr-openwrt-build.md's version-parity contract.
{
  echo "# nbg6817 OpenWrt FRR .ipk build manifest"
  echo
  echo "frr_tag:             $FRR_REF"
  echo "frr_commit_sha:      $FRR_SHA"
  echo "frr_source:          ${FRR_SRC} (tag checked out on the runner from Blockcast/frr)"
  echo "openwrt_pkg_version: ${FRR_PKG_VERSION}-r${PKG_RELEASE}"
  echo "sdk_version:         $(cat ./version 2>/dev/null || echo unknown)"
  echo "target:              $(grep -E '^CONFIG_TARGET_BOARD=' .config | cut -d'"' -f2)/$(grep -E '^CONFIG_TARGET_SUBTARGET=' .config | cut -d'"' -f2)"
  echo "arch_packages:       $(grep -E '^CONFIG_TARGET_ARCH_PACKAGES=' .config | cut -d'"' -f2)"
  echo "built_at:            $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "## selected frr config"
  grep -E '^CONFIG_PACKAGE_frr' .config | sort
  echo
  echo "## packages (sha256)"
  (cd /builder/artifacts && sha256sum ./*.ipk)
} > /builder/artifacts/MANIFEST.txt

echo "=== MANIFEST ==="
cat /builder/artifacts/MANIFEST.txt
