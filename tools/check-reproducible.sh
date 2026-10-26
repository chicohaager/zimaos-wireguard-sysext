#!/usr/bin/env bash
# Builds the image three times and compares the bytes: once with umask 022 and no group write bit
# on the checked-out files (as in a CI checkout), once with umask 002 and group-writable files
# (a desktop checkout), once with umask 077 (a root shell of the sudo helper on ZimaOS). Different bytes mean a release image depends on the machine that
# built it (measured 2026-10-26: file modes; lintux-modkit build-sysext.sh fixed in 8d03211).
#   tools/check-reproducible.sh [amd64|arm64]
set -euo pipefail
cd "$(dirname "$0")/.."
ARCH="${1:-amd64}"
NAME=wireguard
OUT="dist/$NAME-$ARCH.raw"
build() { sh build.sh "$ARCH" > /dev/null; }
modes=$(mktemp); trap 'rm -f "$modes"' EXIT
git ls-files -z | xargs -0 stat -c '%a %n' > "$modes"
git ls-files -z | xargs -0 chmod g-w
(umask 022 && build)
a=$(sha256sum "$OUT" | cut -d' ' -f1)
git ls-files -z | xargs -0 chmod g+w
(umask 002 && build)
b=$(sha256sum "$OUT" | cut -d' ' -f1)
git ls-files -z | xargs -0 chmod go-rwx
(umask 077 && build)
c=$(sha256sum "$OUT" | cut -d' ' -f1)
# the checked-out files get their modes back
while read -r mode f; do chmod "$mode" "$f"; done < "$modes"
if [ "$a" != "$b" ] || [ "$a" != "$c" ]; then
  echo "not reproducible: $OUT is $a with umask 022, $b with umask 002 and group-writable files, $c with umask 077" >&2
  exit 1
fi
echo "reproducible: $OUT $a (umask 022, 002 and 077)"
