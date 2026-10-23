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

rm -rf build/root
mkdir -p build/root
cp -a files/. build/root/
mkdir -p build/root/usr/libexec/wireguard build/root/usr/share/doc/wireguard build/root/usr/share/casaos/modules
cp "$MODKIT/sysext/unit-watchdog.sh" build/root/usr/libexec/wireguard/unit-watchdog.sh

docker run --rm --platform "linux/$ARCH" -e WG_TAG="$WG_TAG" -e WG_COMMIT="$WG_COMMIT" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" -v "$PWD/build/root:/out" "$IMAGE" sh -euc '
  apt-get update -qq >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends git ca-certificates gcc make libc6-dev binutils >/dev/null
  git clone -q --depth 1 --branch "$WG_TAG" https://git.zx2c4.com/wireguard-tools /src
  got=$(git -C /src rev-parse HEAD)
  [ "$got" = "$WG_COMMIT" ] || { echo "tag $WG_TAG is $got, expected $WG_COMMIT" >&2; exit 1; }
  make -s -C /src/src wg >/dev/null
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
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags="-s -w -X main.version=$VERSION" \
  -o build/root/usr/bin/wireguard-web ./cmd/wireguard-web
sh "$MODKIT/sysext/build-sysext.sh" wireguard build/root "$ARCH" dist "$VERSION"
cat "dist/wireguard-$ARCH.raw.sha256"
