#!/bin/sh
# Builds the universal (arm64 + amd64) MKConnect.app and the CLI into dist/.
# Needs Go 1.26 and the Xcode Command Line Tools. Usage: scripts/build-macos.sh [version]
set -eu

cd "$(dirname "$0")/.."
version=${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
tags=with_gvisor,with_quic,with_utls
ldflags="-s -w -X github.com/khaliilii/MKConnect/internal/version.Version=$version"
out=dist/macos
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

for arch in arm64 amd64; do
	echo "building $arch..."
	GOOS=darwin GOARCH=$arch CGO_ENABLED=1 \
		CGO_CFLAGS="-arch $(test $arch = amd64 && echo x86_64 || echo arm64)" \
		CGO_LDFLAGS="-arch $(test $arch = amd64 && echo x86_64 || echo arm64)" \
		go build -trimpath -tags "$tags" -ldflags "$ldflags" -o "$work/gui-$arch" ./cmd/mkconnect-gui
	GOOS=darwin GOARCH=$arch CGO_ENABLED=0 \
		go build -trimpath -tags "$tags" -ldflags "$ldflags" -o "$work/cli-$arch" .
done

app=$out/MKConnect.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
lipo -create -output "$app/Contents/MacOS/MKConnect" "$work/gui-arm64" "$work/gui-amd64"
lipo -create -output "$out/mkconnect" "$work/cli-arm64" "$work/cli-amd64"

iconset=$work/MKConnect.iconset
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
	sips -z $size $size cmd/mkconnect-gui/Icon.png --out "$iconset/icon_${size}x${size}.png" >/dev/null
	sips -z $((size * 2)) $((size * 2)) cmd/mkconnect-gui/Icon.png --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/MKConnect.icns"

plist_version=$(echo "$version" | sed -e 's/^v//' -e 's/-.*//')
cat >"$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>MKConnect</string>
  <key>CFBundleDisplayName</key><string>MKConnect</string>
  <key>CFBundleIdentifier</key><string>com.khaliilii.mkconnect</string>
  <key>CFBundleExecutable</key><string>MKConnect</string>
  <key>CFBundleIconFile</key><string>MKConnect.icns</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$plist_version</string>
  <key>CFBundleVersion</key><string>$plist_version</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST

codesign --force --deep --sign - "$app"
(cd "$out" && rm -f MKConnect-macos-universal.zip && ditto -c -k --keepParent MKConnect.app MKConnect-macos-universal.zip)
echo "done: $app, $out/mkconnect ($version)"
