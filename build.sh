#!/usr/bin/env bash
set -euo pipefail

GAME_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
JAVA_EXE="${JAVA_EXE:-java}"
PYTHON_EXE="${PYTHON_EXE:-python}"
APKTOOL_JAR="${APKTOOL_JAR:?Set APKTOOL_JAR to your apktool jar}"
ANDROID_BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-${ANDROID_SDK_ROOT:?Set ANDROID_SDK_ROOT or ANDROID_BUILD_TOOLS}/build-tools/37.0.0}"
SIGNING_KEY="${SIGNING_KEY:?Set SIGNING_KEY to your PKCS#8 signing key}"
SIGNING_CERT="${SIGNING_CERT:?Set SIGNING_CERT to your X.509 certificate}"
SIGNING_CERT_SHA256="${SIGNING_CERT_SHA256:?Set SIGNING_CERT_SHA256 to the expected certificate digest}"
SIGNING_CERT_SHA256="${SIGNING_CERT_SHA256,,}"
[[ "$SIGNING_CERT_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  printf '%s\n' 'SIGNING_CERT_SHA256 must contain 64 hexadecimal digits' >&2; exit 1;
}
EXE_SUFFIX=''
case "${OSTYPE:-}" in msys*|cygwin*|win32*) EXE_SUFFIX='.exe'; export MSYS_NO_PATHCONV=1 ;; esac
for REQUIRED in "$APKTOOL_JAR" "$ANDROID_BUILD_TOOLS/zipalign$EXE_SUFFIX" \
    "$ANDROID_BUILD_TOOLS/aapt2$EXE_SUFFIX" "$ANDROID_BUILD_TOOLS/lib/apksigner.jar" \
    "$SIGNING_KEY" "$SIGNING_CERT"; do
  test -f "$REQUIRED" || { printf 'Missing build dependency: %s\n' "$REQUIRED" >&2; exit 1; }
done
tool_apktool() { "$JAVA_EXE" -jar "$APKTOOL_JAR" "$@"; }
tool_zipalign() { "$ANDROID_BUILD_TOOLS/zipalign$EXE_SUFFIX" "$@"; }
tool_aapt2() { "$ANDROID_BUILD_TOOLS/aapt2$EXE_SUFFIX" "$@"; }
tool_apksigner() { "$JAVA_EXE" -jar "$ANDROID_BUILD_TOOLS/lib/apksigner.jar" "$@"; }

test -f "$GAME_ROOT/app/apktool.yml" || { printf '%s\n' 'Missing app/apktool.yml' >&2; exit 1; }
if grep -aqF 'diagnostic source selection: embedded OBB deliberately skipped' \
    "$GAME_ROOT/app/lib/arm64-v8a/libParsons.so" &&
    [ "${ALLOW_BRIDGE_DIAGNOSTIC_OBB:-0}" != '1' ]; then
  printf '%s\n' 'Refusing to package force-external OBB diagnostic bridge as a production APK' >&2
  exit 1
fi
mkdir -p "$GAME_ROOT/out"

UNSIGNED="$GAME_ROOT/out/Carmageddon-unsigned.apk"
ALIGNED="$GAME_ROOT/out/Carmageddon-aligned.apk"
SIGNED="$GAME_ROOT/out/Carmageddon.apk"

tool_apktool b "$GAME_ROOT/app" -o "$UNSIGNED"
tool_zipalign -P 16 -f 4 "$UNSIGNED" "$ALIGNED"
tool_apksigner sign \
  --key "$SIGNING_KEY" \
  --cert "$SIGNING_CERT" \
  --out "$SIGNED" \
  "$ALIGNED"

VERIFY_OUTPUT="$(tool_apksigner verify --verbose --print-certs "$SIGNED" 2>&1)"
printf '%s\n' "$VERIFY_OUTPUT"
CERT_DIGEST=''
while IFS= read -r line; do
  case "$line" in
    *'certificate SHA-256 digest:'*) CERT_DIGEST="${line##*: }"; break ;;
  esac
done <<< "$VERIFY_OUTPUT"
CERT_DIGEST="${CERT_DIGEST//$'\r'/}"
CERT_DIGEST="${CERT_DIGEST,,}"
test "$CERT_DIGEST" = "$SIGNING_CERT_SHA256" || {
  printf 'Unexpected signing certificate: %s\n' "$CERT_DIGEST" >&2
  exit 1
}
tool_zipalign -c -P 16 4 "$SIGNED"
BADGING_OUTPUT="$(tool_aapt2 dump badging "$SIGNED")"
printf '%s\n' "$BADGING_OUTPUT" | tee "$GAME_ROOT/out/Carmageddon.badging.txt"
printf '%s\n' "$BADGING_OUTPUT" | grep -F "native-code: 'arm64-v8a'"
if printf '%s\n' "$BADGING_OUTPUT" | grep -Eq "native-code: '.*(armeabi|x86|mips)"; then
  printf '%s\n' 'Unexpected non-arm64 native ABI in APK' >&2
  exit 1
fi
"$PYTHON_EXE" - "$SIGNED" "$GAME_ROOT/main.507.com.stainlessgames.carmageddon.obb" <<'PY'
import hashlib
import sys
import zipfile

apk = sys.argv[1]
original_obb = sys.argv[2]
obb_entry = "assets/main.507.com.stainlessgames.carmageddon.obb"
obb_sha256 = "f35bed98ef82c7c5b316437a3bb5cb89d2c0f917f06a9e07e4718024dc4a59e3"
expected = {
    "assets/guest_libs/libfmodevent.so",
    "assets/guest_libs/libfmodeventL.so",
    "assets/guest_libs/libfmodex.so",
    "assets/guest_libs/libfmodexL.so",
    "assets/guest_libs/libParsons.so",
}
with zipfile.ZipFile(apk) as archive:
    names = set(archive.namelist())
    assert obb_entry in names and "assets/DATA_ANDROID.WAD" not in names
    obb_info = archive.getinfo(obb_entry)
    assert obb_info.compress_type == zipfile.ZIP_STORED and obb_info.file_size == 78692000
    with open(original_obb, "rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == obb_sha256
    with archive.open(obb_entry) as packaged:
        assert hashlib.file_digest(packaged, "sha256").hexdigest() == obb_sha256
    guest = {name for name in names if name.startswith("assets/guest_libs/")}
    assert guest == expected, (guest, expected)
    assert not any(name.startswith("lib/armeabi-v7a/") for name in names)
    assert {name for name in names if name.startswith("lib/") and not name.endswith("/")} == {"lib/arm64-v8a/libParsons.so"}
    for name in expected:
        assert archive.getinfo(name).compress_type == zipfile.ZIP_STORED, name
PY
printf 'size_bytes=%s\n' "$(stat -c '%s' "$SIGNED")"
printf 'sha256='; sha256sum "$SIGNED"
printf '%s\n' 'BUILD_OK'
