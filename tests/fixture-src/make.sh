#!/bin/sh
set -eu
output=$1
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cp /fixture/base.xml "$scratch/AndroidManifest.xml"
aapt package -f -M "$scratch/AndroidManifest.xml" -I /usr/share/android-framework-res/framework-res.apk -F "$scratch/unsigned.apk"
for identity in original rotated; do
  keytool -genkeypair -storetype PKCS12 -keystore "$scratch/$identity.p12" -storepass fixtureonly \
    -keypass fixtureonly -alias fixture -keyalg RSA -keysize 2048 -dname "CN=Sentinel Test $identity" -validity 3650
  apksigner sign --ks "$scratch/$identity.p12" --ks-pass pass:fixtureonly --v4-signing-enabled false \
    --out "$output/$identity.apk" "$scratch/unsigned.apk"
  apksigner verify --print-certs "$output/$identity.apk"
done
cp "$scratch/unsigned.apk" "$output/unsigned.apk"
