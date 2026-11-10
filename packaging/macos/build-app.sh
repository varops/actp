#!/usr/bin/env bash
# Builds actp.app: a menu bar app (no Dock icon) with a universal binary.
#
#   packaging/macos/build-app.sh [version]
#
# Output: dist/actp.app and dist/actp_<version>_macos.zip
#
# Signing: ad-hoc by default, which is enough to run it on your own Mac.
# Set CODESIGN_IDENTITY (for example "Developer ID Application: Name (TEAMID)")
# to sign for distribution, and NOTARY_PROFILE (a profile saved with
# `xcrun notarytool store-credentials`) to notarize as well.
set -euo pipefail

cd "$(dirname "$0")/../.."
version="${1:-$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev)}"
app="dist/actp.app"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "Building actp $version"
for arch in arm64 amd64; do
  CGO_ENABLED=1 GOOS=darwin GOARCH="$arch" go build -tags tray -trimpath \
    -ldflags "-s -w -X main.version=$version" -o "$work/actp-$arch" ./cmd/actp
done

rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
lipo -create -output "$app/Contents/MacOS/actp" "$work/actp-arm64" "$work/actp-amd64"

# Icon: every size macOS asks for, from one 1024 px PNG.
iconset="$work/actp.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" packaging/macos/icon.png --out "$iconset/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  sips -z "$double" "$double" packaging/macos/icon.png --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/actp.icns"

sed "s/__VERSION__/$version/g" packaging/macos/Info.plist > "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" >/dev/null

if [[ -n "${CODESIGN_IDENTITY:-}" ]]; then
  codesign --force --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$app"
else
  codesign --force --sign - "$app"
fi
codesign --verify --strict "$app"

zip="dist/actp_${version}_macos.zip"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"

if [[ -n "${CODESIGN_IDENTITY:-}" && -n "${NOTARY_PROFILE:-}" ]]; then
  xcrun notarytool submit "$zip" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$app"
  rm -f "$zip"
  ditto -c -k --keepParent "$app" "$zip"
fi

echo "Built $app and $zip"
