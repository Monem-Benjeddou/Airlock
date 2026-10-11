#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: 2026 Airlock contributors
#
# Builds the small fixture APKs used by the AirlockArchive and AirlockSafety tests.
#
#   scripts/make-test-apks.sh
#
# Needs the Android SDK build-tools (aapt2, d8, zipalign, apksigner), an android.jar platform and a JDK
# (javac, keytool). Paths can be overridden with ANDROID_HOME, BUILD_TOOLS and PLATFORM.
#
# Everything is built from the stub sources below; no third-party code is involved. The keystores in
# Fixtures/apk/keys are TEST-ONLY keys: they are generated once and then reused so the outputs stay
# stable. RSA PKCS#1 signatures are deterministic; ECDSA signatures are randomised by design, so the
# EC-signed fixtures change on every run (they still verify).
set -euo pipefail
export TZ=UTC LC_ALL=C

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/Tests/AirlockTestSupport/Fixtures/apk"
KEYS="$OUT/keys"
RAW="$OUT/raw"
ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BUILD_TOOLS="${BUILD_TOOLS:-$ANDROID_HOME/build-tools/35.0.0}"
PLATFORM="${PLATFORM:-$ANDROID_HOME/platforms/android-36/android.jar}"
AAPT2="$BUILD_TOOLS/aapt2"
D8="$BUILD_TOOLS/d8"
ZIPALIGN="$BUILD_TOOLS/zipalign"
APKSIGNER="$BUILD_TOOLS/apksigner"
PASS="airlock-test"
STAMP="202601010000"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT" "$KEYS" "$RAW"
rm -f "$OUT"/*.apk "$OUT"/*.idsig "$RAW"/*

# --- Test-only keystores ----------------------------------------------------------------------------
if [[ ! -f "$KEYS/rsa.p12" ]]; then
  keytool -genkeypair -keystore "$KEYS/rsa.p12" -storetype PKCS12 -storepass "$PASS" -alias rsa \
    -keyalg RSA -keysize 2048 -validity 9000 -startdate "2026/01/01 00:00:00" \
    -dname "CN=Airlock Test RSA, OU=Fixtures, O=Airlock, C=US"
fi
if [[ ! -f "$KEYS/ec.p12" ]]; then
  keytool -genkeypair -keystore "$KEYS/ec.p12" -storetype PKCS12 -storepass "$PASS" -alias ec \
    -keyalg EC -groupname secp256r1 -validity 9000 -startdate "2026/01/01 00:00:00" \
    -dname "CN=Airlock Test EC, O=Airlock, C=DE"
fi

# --- Stub Java sources under tracker-like packages ----------------------------------------------------
SRC="$WORK/src"
mkdir -p "$SRC/com/facebook/ads" "$SRC/com/google/firebase/analytics" "$SRC/org/airlock/fixture/deep/inner"
cat > "$SRC/com/facebook/ads/AdView.java" <<'JAVA'
package com.facebook.ads;
/** Stub with a tracker-like name; contains no third-party code. */
public final class AdView {
    public String describe() { return "stub"; }
}
JAVA
cat > "$SRC/com/google/firebase/analytics/FirebaseAnalytics.java" <<'JAVA'
package com.google.firebase.analytics;
/** Stub with a tracker-like name; contains no third-party code. */
public final class FirebaseAnalytics {
    public static int count() { return 1; }
}
JAVA
cat > "$SRC/org/airlock/fixture/deep/inner/Leaf.java" <<'JAVA'
package org.airlock.fixture.deep.inner;
import com.facebook.ads.AdView;
import com.google.firebase.analytics.FirebaseAnalytics;
/** Five package levels deep, to exercise the depth cap of the prefix scan. */
public final class Leaf {
    public String run() { return new AdView().describe() + FirebaseAnalytics.count(); }
}
JAVA
mkdir -p "$WORK/classes" "$WORK/dex"
javac --release 8 -nowarn -d "$WORK/classes" $(find "$SRC" -name '*.java' | sort)
"$D8" --release --min-api 24 --lib "$PLATFORM" --output "$WORK/dex" $(find "$WORK/classes" -name '*.class' | sort)

# --- Manifests ----------------------------------------------------------------------------------------
cat > "$WORK/app.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.airlock.fixture" android:versionCode="42" android:versionName="1.2.3">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-feature android:name="android.hardware.camera" />
    <application android:label="Airlock Fixture" />
</manifest>
XML
cat > "$WORK/flags.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.airlock.flags" android:versionCode="7" android:versionCodeMajor="2"
    android:isSplitRequired="true" android:requiredSplitTypes="base__abi">
    <uses-sdk android:minSdkVersion="26" />
    <uses-permission-sdk-23 android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" android:maxSdkVersion="33" />
    <uses-feature android:name="android.hardware.microphone" android:required="true" />
    <uses-feature android:name="android.hardware.bluetooth" android:required="false" />
    <uses-feature android:glEsVersion="0x00020000" />
    <application android:label="@string/app_name" android:debuggable="true" android:testOnly="true">
        <activity android:name=".Main" android:exported="false" />
    </application>
</manifest>
XML
cat > "$WORK/split.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.airlock.fixture" android:versionCode="42" split="config.arm64_v8a">
    <application android:hasCode="false" />
</manifest>
XML
mkdir -p "$WORK/res/values"
cat > "$WORK/res/values/strings.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<resources><string name="app_name">Airlock Flags</string></resources>
XML
"$AAPT2" compile -o "$WORK/res.zip" --dir "$WORK/res"

link() { # link <manifest> <out> [extra aapt2 args...]
  local manifest="$1" out="$2"; shift 2
  "$AAPT2" link --manifest "$manifest" -I "$PLATFORM" -o "$out" "$@"
}
aligned() { # aligned <in> <out>
  "$ZIPALIGN" -f -p 4 "$1" "$2"
}

link "$WORK/app.xml" "$WORK/app-linked.apk"
cp "$WORK/dex/classes.dex" "$WORK/classes.dex"
touch -t "$STAMP" "$WORK/classes.dex"
(cd "$WORK" && zip -q -X -D app-linked.apk classes.dex)
aligned "$WORK/app-linked.apk" "$OUT/app-unsigned.apk"

link "$WORK/flags.xml" "$WORK/flags-linked.apk" -R "$WORK/res.zip" --auto-add-overlay
aligned "$WORK/flags-linked.apk" "$OUT/flags-unsigned.apk"

link "$WORK/split.xml" "$WORK/split-linked.apk"
aligned "$WORK/split-linked.apk" "$WORK/split-aligned.apk"

# --- Signing ----------------------------------------------------------------------------------------
sign() { # sign <key: rsa|ec> <in> <out> <v1> <v2> <v3> [extra apksigner args...]
  local key="$1" in="$2" out="$3" v1="$4" v2="$5" v3="$6"; shift 6
  "$APKSIGNER" sign --ks "$KEYS/$key.p12" --ks-pass "pass:$PASS" --ks-key-alias "$key" \
    --v1-signing-enabled "$v1" --v2-signing-enabled "$v2" --v3-signing-enabled "$v3" \
    --v4-signing-enabled false --out "$out" "$@" "$in"
}
U="$OUT/app-unsigned.apk"
sign rsa "$U" "$OUT/app-v1-rsa.apk"   true  false false --min-sdk-version 24
sign rsa "$U" "$OUT/app-v2-rsa.apk"   false true  false
sign rsa "$U" "$OUT/app-v3-rsa.apk"   false false true
sign rsa "$U" "$OUT/app-v123-rsa.apk" true  true  true  --min-sdk-version 24
sign ec  "$U" "$OUT/app-v1-ec.apk"    true  false false --min-sdk-version 24
sign ec  "$U" "$OUT/app-v2-ec.apk"    false true  false
sign ec  "$U" "$OUT/app-v123-ec.apk"  true  true  true  --min-sdk-version 24
sign rsa "$WORK/split-aligned.apk" "$OUT/split-arm64-v2-rsa.apk" false true false

# v4 writes a detached <apk>.idsig next to the APK.
"$APKSIGNER" sign --ks "$KEYS/rsa.p12" --ks-pass "pass:$PASS" --ks-key-alias rsa \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled false \
  --v4-signing-enabled true --out "$OUT/app-v24-rsa.apk" "$U"

# Key rotation RSA -> EC: the v3 block keeps the old signer, the v3.1 block carries the new one.
"$APKSIGNER" rotate --out "$WORK/lineage" \
  --old-signer --ks "$KEYS/rsa.p12" --ks-pass "pass:$PASS" --ks-key-alias rsa \
  --new-signer --ks "$KEYS/ec.p12" --ks-pass "pass:$PASS" --ks-key-alias ec
"$APKSIGNER" sign --ks "$KEYS/rsa.p12" --ks-pass "pass:$PASS" --ks-key-alias rsa \
  --next-signer --ks "$KEYS/ec.p12" --ks-pass "pass:$PASS" --ks-key-alias ec \
  --lineage "$WORK/lineage" --rotation-min-sdk-version 33 \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true \
  --v4-signing-enabled false --out "$OUT/app-rotated.apk" "$U"

# Tampered: flip one byte of the first stored file's data (the manifest) after signing.
cp "$OUT/app-v123-rsa.apk" "$OUT/app-tampered.apk"
python3 -I - "$OUT/app-tampered.apk" <<'PY'
import struct, sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
assert data[:4] == b"PK\x03\x04"
name_len, extra_len = struct.unpack_from("<HH", data, 26)
target = 30 + name_len + extra_len + 8
data[target] ^= 0x01
open(path, "wb").write(bytes(data))
PY

# --- Raw entries for parser tests (no zip reader needed in those tests) -------------------------------
unzip -p "$OUT/app-unsigned.apk" AndroidManifest.xml > "$RAW/app.AndroidManifest.xml"
unzip -p "$OUT/flags-unsigned.apk" AndroidManifest.xml > "$RAW/flags.AndroidManifest.xml"
unzip -p "$OUT/split-arm64-v2-rsa.apk" AndroidManifest.xml > "$RAW/split.AndroidManifest.xml"
cp "$WORK/dex/classes.dex" "$RAW/classes.dex"
unzip -Z1 "$OUT/app-v1-rsa.apk" > "$RAW/app-v1-rsa.entries.txt"
unzip -p "$OUT/app-v1-rsa.apk" META-INF/RSA.RSA > "$RAW/app-v1-rsa.RSA"
unzip -Z1 "$OUT/app-v1-ec.apk" > "$RAW/app-v1-ec.entries.txt"
unzip -p "$OUT/app-v1-ec.apk" META-INF/EC.EC > "$RAW/app-v1-ec.EC"

# Sanity: apksigner must agree with the expectations encoded in the tests.
for f in app-v2-rsa app-v3-rsa app-v123-rsa app-v2-ec app-v123-ec app-rotated split-arm64-v2-rsa app-v24-rsa; do
  "$APKSIGNER" verify --min-sdk-version 24 "$OUT/$f.apk" >/dev/null
done
# v1-only APKs targeting SDK 34 are refused on Android 11+, so check them against older platforms only.
for f in app-v1-rsa app-v1-ec; do
  "$APKSIGNER" verify --min-sdk-version 24 --max-sdk-version 29 "$OUT/$f.apk" >/dev/null
done
if "$APKSIGNER" verify "$OUT/app-tampered.apk" >/dev/null 2>&1; then
  echo "tampered fixture unexpectedly verifies" >&2; exit 1
fi
du -sh "$OUT"
