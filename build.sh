#!/bin/sh
# Build the wireguard sysext for ZimaOS.
#   sh build.sh [amd64|arm64]      (default: amd64)
# Output in dist/: wireguard-<arch>.raw (+ .sha256), for amd64 also wireguard.raw.
set -eu
cd "$(dirname "$0")"
ARCH="${1:-amd64}"
MODKIT="${LINTUX_MODKIT:-../lintux-modkit}"
[ -f "$MODKIT/sysext/unit-watchdog.sh" ] || { echo "lintux-modkit with sysext/unit-watchdog.sh not found at $MODKIT (set LINTUX_MODKIT)" >&2; exit 1; }
VERSION=$(cat VERSION)
go vet ./...
go test ./...

# wireguard-tools from upstream source, pinned by tag AND commit (Debian 13 ships 1.0.20210914).
WG_TAG=v1.0.20260223
WG_COMMIT=49ce333da02056ae7b22ee2aeb6afe8aaed79b19
IMAGE="debian:trixie@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308"
# Compiler and libc headers from the Debian snapshot the image names, not the live mirror,
# so a later rebuild of a release gives the same wg binary (lintux-modkit bundle-debian.sh does the same).
DEBIAN_SNAPSHOT="${DEBIAN_SNAPSHOT:-20261020T213255Z}"
# The fixed snapshot also keeps security updates out: every build checks the build packages against
# the live mirror and stops when one is newer — raise DEBIAN_SNAPSHOT then. DEBIAN_SNAPSHOT_ALLOW_OLD=1
# only to rebuild an old release.
DEBIAN_SNAPSHOT_ALLOW_OLD="${DEBIAN_SNAPSHOT_ALLOW_OLD:-0}"

rm -rf build/root
mkdir -p build/root
cp -a files/. build/root/
mkdir -p build/root/usr/libexec/wireguard build/root/usr/share/doc/wireguard build/root/usr/share/casaos/modules
cp "$MODKIT/sysext/unit-watchdog.sh" build/root/usr/libexec/wireguard/unit-watchdog.sh

docker run --rm --platform "linux/$ARCH" -e WG_TAG="$WG_TAG" -e WG_COMMIT="$WG_COMMIT" -e DEBIAN_SNAPSHOT="$DEBIAN_SNAPSHOT" -e DEBIAN_SNAPSHOT_ALLOW_OLD="$DEBIAN_SNAPSHOT_ALLOW_OLD" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" -v "$PWD/build/root:/out" "$IMAGE" sh -euc '
  S=/etc/apt/sources.list.d/debian.sources
  sed -i -E "s#^URIs: http://deb\.debian\.org/(debian(-security)?)\$#URIs: http://snapshot.debian.org/archive/\\1/$DEBIAN_SNAPSHOT#" "$S"
  [ "$(grep -c "^URIs: http://snapshot.debian.org/archive/.*/$DEBIAN_SNAPSHOT\$" "$S")" -eq 2 ] || { echo "snapshot not set in $S" >&2; exit 1; }
  apt-get -o Acquire::Check-Valid-Until=false update -qq >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends git ca-certificates gcc make libc6-dev binutils >/dev/null
  git clone -q --depth 1 --branch "$WG_TAG" https://git.zx2c4.com/wireguard-tools /src
  got=$(git -C /src rev-parse HEAD)
  [ "$got" = "$WG_COMMIT" ] || { echo "tag $WG_TAG is $got, expected $WG_COMMIT" >&2; exit 1; }
  make -s -C /src/src wg >/dev/null
  sed -i -E "s#^URIs: http://snapshot\.debian\.org/archive/(debian(-security)?)/$DEBIAN_SNAPSHOT\$#URIs: http://deb.debian.org/\\1#" "$S"
  [ "$(grep -c "^URIs: http://deb.debian.org/" "$S")" -eq 2 ] || { echo "live mirror not set in $S" >&2; exit 1; }
  apt-get update -qq >/dev/null
  behind=""
  for pk in git gcc make libc6-dev binutils libc6; do
    ver=$(dpkg-query -W -f "\${Version}" "$pk"); cand=$(apt-cache policy "$pk" | awk "/Candidate:/{print \$2}")
    if dpkg --compare-versions "$cand" gt "$ver"; then behind="$behind $pk:$ver->$cand"; fi
  done
  if [ -n "$behind" ]; then
    echo "Debian snapshot $DEBIAN_SNAPSHOT is outdated, newer in the mirror:$behind" >&2
    [ "$DEBIAN_SNAPSHOT_ALLOW_OLD" = 1 ] || { echo "raise DEBIAN_SNAPSHOT (security updates), or DEBIAN_SNAPSHOT_ALLOW_OLD=1 only to rebuild an old release" >&2; exit 3; }
  else
    echo "Debian snapshot $DEBIAN_SNAPSHOT current: 6 build packages checked against the mirror, none newer"
  fi
  install -m 755 /src/src/wg /out/usr/bin/wg
  install -m 755 /src/src/wg-quick/linux.bash /out/usr/bin/wg-quick
  cp /src/COPYING /out/usr/share/doc/wireguard/COPYING
  echo "wireguard-tools $WG_TAG ($WG_COMMIT)" > /out/usr/share/doc/wireguard/packages.txt
  objdump -T /out/usr/bin/wg | grep -o "GLIBC_2\.[0-9]*" | sort -t. -k2 -n -u | tail -n 1
  readelf -d /out/usr/bin/wg | sed -n "s/.*(NEEDED).*\[\(.*\)\]/needs \1/p"
  chown -R "$HOST_UID:$HOST_GID" /out'

# The tile: module JSON (its "services" make zpkg enable and start wireguard-web; without the
# JSON zpkg answers "module not installed", rc=1 — measured 1.8.0), UI files and the backend.
sh "$MODKIT/sysext/add-web.sh" wireguard build/root "$VERSION"
# -buildvcs=false: without it Go stamps the nearest tag and "dirty" (any untracked file) into the binary,
# so a rebuild from the release tag differed from the release (measured 2026-10-23, restic-web).
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$VERSION" \
  -o build/root/usr/bin/wireguard-web ./cmd/wireguard-web
sh "$MODKIT/sysext/build-sysext.sh" wireguard build/root "$ARCH" dist "$VERSION"
cat "dist/wireguard-$ARCH.raw.sha256"
