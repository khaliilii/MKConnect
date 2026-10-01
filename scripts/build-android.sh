#!/bin/sh
# Builds the Android APKs into dist/android with fyne-cross (Docker).
# Usage: scripts/build-android.sh [version] [arch...]   (default arches: arm64 arm amd64 386)
#
# Works offline once the fyne-cross Android image is pulled: dependencies come
# from vendor/ (created here) and the container's Go toolchain from the
# fyne-cross cache (pre-fetched here when the network allows).
set -eu

cd "$(dirname "$0")/.."
version=${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
[ $# -gt 0 ] && shift
arches=${*:-arm64 arm amd64 386}

go_version=$(go env GOVERSION)
case "$(uname)" in Darwin) cache=$HOME/Library/Caches/fyne-cross ;; *) cache=${XDG_CACHE_HOME:-$HOME/.cache}/fyne-cross ;; esac

# The container runs linux/amd64; give it this Go so it doesn't download one mid-build.
# Run outside the module: the bootstrap Go may be older than go.mod requires.
(cd / && GOTOOLCHAIN=local GOFLAGS=-modcacherw GOMODCACHE="$cache/pkg/mod" \
	go mod download "golang.org/toolchain@v0.0.1-$go_version.linux-amd64")

go mod vendor
trap 'rm -rf vendor' EXIT

app_version=$(echo "$version" | sed -e 's/^v//' -e 's/-.*//')
echo "$app_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || app_version=0.0.0

mkdir -p dist/android
for arch in $arches; do
	echo "building android/$arch..."
	# fyne-cross forwards the host GOFLAGS into the container, which would
	# override the vendor/ directory; build from vendor with no network.
	env -u GOFLAGS fyne-cross android -arch="$arch" \
		-tags with_gvisor,with_quic,with_utls \
		-env GOTOOLCHAIN="$go_version" -env GOPROXY=off \
		-app-id com.khaliilii.mkconnect -name MKConnect \
		-app-version "$app_version" \
		-icon cmd/mkconnect-gui/Icon.png \
		./cmd/mkconnect-gui
	cp fyne-cross/dist/android-"$arch"/*.apk "dist/android/MKConnect-android-$arch.apk"
done
ls -lh dist/android
