#!/bin/sh
# FreeBSD builds into dist/freebsd: the CLI for amd64/arm64/386/armv7 (pure Go)
# and the desktop app for amd64/arm64 (fyne-cross; Fyne has no FreeBSD 386/arm).
# Usage: [FYNE_CROSS=/path/to/fyne-cross] scripts/build-freebsd.sh [version] [gui-arch...]
set -eu

cd "$(dirname "$0")/.."
version=${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
[ $# -gt 0 ] && shift
gui_arches=${*:-amd64 arm64}
fyne_cross=${FYNE_CROSS:-fyne-cross}
tags=with_gvisor,with_quic,with_utls
mkdir -p dist/freebsd

for a in amd64 arm64 386 arm; do
	echo "building freebsd/$a CLI..."
	GOOS=freebsd GOARCH=$a GOARM=7 CGO_ENABLED=0 go build -trimpath -tags "$tags" \
		-ldflags "-s -w -X github.com/khaliilii/MKConnect/internal/version.Version=$version" \
		-o "dist/freebsd/mkconnect-cli-freebsd-$a" .
done

# The fyne-cross container is linux/<host arch>; give it this Go up front.
go_version=$(go env GOVERSION)
host_arch=$(docker info --format '{{.Architecture}}' | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
case "$(uname)" in Darwin) cache=$HOME/Library/Caches/fyne-cross ;; *) cache=${XDG_CACHE_HOME:-$HOME/.cache}/fyne-cross ;; esac
(cd / && GOTOOLCHAIN=local GOFLAGS=-modcacherw GOMODCACHE="$cache/pkg/mod" \
	go mod download "golang.org/toolchain@v0.0.1-$go_version.linux-$host_arch")

go mod vendor
trap 'rm -rf vendor' EXIT
app_version=$(echo "$version" | sed -e 's/^v//' -e 's/-.*//')
echo "$app_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || app_version=0.0.0

for a in $gui_arches; do
	echo "building freebsd/$a GUI..."
	# fyne-cross forwards the host GOFLAGS into the container, which would
	# override the vendor/ directory; build from vendor with no network.
	# x11: go-gl/glfw only compiles X11 on the BSDs by default but still references
	# its Wayland helpers unless the x11 tag picks the X11-only code paths.
	env -u GOFLAGS "$fyne_cross" freebsd -arch="$a" -tags "$tags,x11" \
		-env GOTOOLCHAIN="$go_version" -env GOPROXY=off \
		-app-id com.khaliilii.mkconnect -name MKConnect -app-version "$app_version" \
		-icon cmd/mkconnect-gui/Icon.png ./cmd/mkconnect-gui
	cp fyne-cross/dist/freebsd-"$a"/*.tar.xz "dist/freebsd/MKConnect-freebsd-$a.tar.xz"
done
git checkout -- cmd/mkconnect-gui/FyneApp.toml 2>/dev/null || true
ls -lh dist/freebsd
