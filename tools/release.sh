#!/usr/bin/env bash
# Builds Lazeyka.exe and lays out the "release" branch of the GitHub
# repository that Лазейка updates itself from: latest.json and the zipped exe.
#
#   tools/release.sh OUT_DIR "что нового, одной-двумя строками"
#
# OUT_DIR gets Lazeyka-<version>.zip, latest.json and README.md; commit them
# as the only files of the "release" branch. Run from the repository root.
set -euo pipefail
cd "$(dirname "$0")/.."

out=${1:?OUT_DIR}
notes=${2:-}
ver=$(sed -n 's/^var Version = "\(.*\)"$/\1/p' internal/app/app.go)
[[ $ver =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version not found" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
./tools/make_syso.sh >/dev/null
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui" -o "$work/Lazeyka.exe" .

mkdir -p "$out"
zipname="Lazeyka-$ver.zip"
python3 -I - "$work/Lazeyka.exe" "$out/$zipname" <<'EOF'
import sys, zipfile
src, dst = sys.argv[1], sys.argv[2]
info = zipfile.ZipInfo("Lazeyka.exe", date_time=(2026, 1, 1, 0, 0, 0))
info.compress_type = zipfile.ZIP_DEFLATED
info.external_attr = 0o644 << 16
with zipfile.ZipFile(dst, "w") as z, open(src, "rb") as f:
    z.writestr(info, f.read())
EOF

exe_sha=$(sha256sum "$work/Lazeyka.exe" | cut -d' ' -f1)
zip_sha=$(sha256sum "$out/$zipname" | cut -d' ' -f1)
size=$(stat -c %s "$out/$zipname")
python3 -I - "$out/latest.json" "$ver" "$zipname" "$size" "$zip_sha" "$exe_sha" "$notes" <<'EOF'
import json, sys, datetime
path, ver, name, size, zsha, esha, notes = sys.argv[1:]
json.dump({
    "version": ver, "file": name, "size": int(size), "sha256": zsha, "exe_sha256": esha,
    "notes": notes, "published": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}, open(path, "w"), ensure_ascii=False, indent=2)
EOF

cat >"$out/README.md" <<EOF
# Лазейка: обновления

Эту ветку читает сама Лазейка: \`latest.json\` — последняя версия и
контрольные суммы SHA-256, рядом архив с \`Lazeyka.exe\`. Лазейка скачивает
архив в свою папку, сверяет суммы и ставит новую версию.

Версия $ver, Lazeyka.exe SHA-256 \`$exe_sha\`.
EOF
echo "$ver $exe_sha"
