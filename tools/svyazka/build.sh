#!/usr/bin/env bash
# Builds Связка for Linux and fills the installer with the checksums.
#   tools/svyazka/build.sh 0.1.0 /tmp/svz/dist
set -euo pipefail
VERSION=${1:?version}
OUT=${2:?output dir}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUT"
for arch in amd64 arm64; do
	(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -buildvcs=false \
		-ldflags "-s -w -X main.version=$VERSION" -o "$OUT/svyazka-linux-$arch" ./cmd/svyazka)
done
SHA_AMD64=$(sha256sum "$OUT/svyazka-linux-amd64" | cut -d' ' -f1)
SHA_ARM64=$(sha256sum "$OUT/svyazka-linux-arm64" | cut -d' ' -f1)
sed -e "s/__VERSION__/$VERSION/" -e "s/__SHA_AMD64__/$SHA_AMD64/" -e "s/__SHA_ARM64__/$SHA_ARM64/" \
	"$ROOT/tools/svyazka/install.sh" >"$OUT/install.sh"
chmod 0755 "$OUT/install.sh"
(cd "$OUT" && sha256sum svyazka-linux-amd64 svyazka-linux-arm64 install.sh >SHA256SUMS)
cat "$OUT/SHA256SUMS"
