#!/usr/bin/env bash
# Builds Lazeyka for Android on GitHub Actions (ubuntu-latest has the Android
# SDK and NDK). Everything goes to build.log; the APK comes out unsigned and
# is signed outside GitHub (tools/android/sign.py), so the key never lands here.
set -euo pipefail
cd "$(dirname "$0")/../.."
V=$(cat android/VERSION)
MIHOMO=${MIHOMO:-v1.19.34}
BYEDPI=${BYEDPI:-v0.17.3}
NDK=${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_HOME:-}}
JNI=android/app/src/main/jniLibs
WORK=$(mktemp -d)
echo "== Лазейка для Android $V: mihomo $MIHOMO, ByeDPI $BYEDPI, NDK $NDK"

# --- mihomo: official Linux builds, checked against GitHub's SHA-256 ---------
gh api "repos/MetaCubeX/mihomo/releases/tags/$MIHOMO" > "$WORK/rel.json"
fetch_mihomo() { # regex dst
  python3 - "$WORK/rel.json" "$1" > "$WORK/asset.txt" <<'PY'
import json, re, sys
rel = json.load(open(sys.argv[1]))
for a in rel["assets"]:
    if re.fullmatch(sys.argv[2], a["name"]):
        d = a.get("digest") or ""
        if not d.startswith("sha256:"):
            sys.exit("no sha256 digest for " + a["name"])
        print(a["browser_download_url"], d[7:], a["name"])
        break
else:
    sys.exit("no asset " + sys.argv[2])
PY
  read -r url sum name < "$WORK/asset.txt"
  curl -fsSL --retry 3 -o "$WORK/$name" "$url"
  echo "$sum  $WORK/$name" | sha256sum -c -
  mkdir -p "$(dirname "$2")"
  gunzip -c "$WORK/$name" > "$2"
  chmod 755 "$2"
  echo "mihomo: $name -> $2"
}
fetch_mihomo "mihomo-linux-arm64-${MIHOMO}\.gz" "$JNI/arm64-v8a/libmihomo.so"
fetch_mihomo "mihomo-linux-armv7-${MIHOMO}\.gz" "$JNI/armeabi-v7a/libmihomo.so"
fetch_mihomo "mihomo-linux-amd64-(compatible-|v1-)?${MIHOMO}\.gz" "$WORK/mihomo-host"
"$WORK/mihomo-host" -v

# --- ByeDPI: built from the tagged source with the NDK ------------------------
git clone -q --depth 1 -b "$BYEDPI" https://github.com/hufrea/byedpi "$WORK/byedpi"
SRC="packets.c main.c conev.c proxy.c desync.c mpool.c extend.c"
TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
build_byedpi() { # cc dst
  (cd "$WORK/byedpi" && "$1" -O2 -std=c99 -D_DEFAULT_SOURCE -I. -fPIE -pie -s -o "$OLDPWD/$2" $SRC)
  echo "ByeDPI -> $2"
}
build_byedpi "$TC/aarch64-linux-android26-clang" "$JNI/arm64-v8a/libbyedpi.so"
build_byedpi "$TC/armv7a-linux-androideabi26-clang" "$JNI/armeabi-v7a/libbyedpi.so"
(cd "$WORK/byedpi" && make -s CC=gcc >/dev/null 2>&1 && cp ciadpi "$WORK/byedpi-host")

# --- the core: tests (configs checked by the real mihomo), then the builds ----
MIHOMO_BIN="$WORK/mihomo-host" go test ./...
LDF="-s -w -X lazeyka/internal/app.Version=$V"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags lzandroid -trimpath -ldflags "$LDF" -o "$JNI/arm64-v8a/liblazeyka.so" .
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -tags lzandroid -trimpath -ldflags "$LDF" -o "$JNI/armeabi-v7a/liblazeyka.so" .
CGO_ENABLED=0 go build -tags lzandroid -trimpath -ldflags "$LDF" -o "$WORK/lazeyka-host" .

# --- end to end on the runner: a real TUN descriptor, the real mihomo ---------
sudo -E python3 tools/android/e2e.py "$WORK/lazeyka-host" "$WORK/mihomo-host" "$WORK/byedpi-host"

# --- the APK ------------------------------------------------------------------
gradle -p android --no-daemon -q assembleRelease -PlzVersion="$V"
ls -la android/app/build/outputs/apk/release/
