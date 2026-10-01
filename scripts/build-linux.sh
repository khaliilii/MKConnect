#!/bin/sh
# Builds the Linux desktop app and CLI for amd64, 386, arm64 and armv7 into
# dist/linux, inside a Debian container with multiarch cross toolchains.
# Go and all modules come from the host (no Go downloads in the container).
# Usage: scripts/build-linux.sh [version] [arch...]   (default: amd64 386 arm64 arm)
set -eu

cd "$(dirname "$0")/.."
version=${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
[ $# -gt 0 ] && shift
arches=${*:-amd64 386 arm64 arm}

host_arch=$(docker info --format '{{.Architecture}}' | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
go_version=$(go env GOVERSION)
toolchain_cache=${FYNE_CROSS_CACHE:-$HOME/Library/Caches/fyne-cross}/pkg/mod
# Run outside the module: the bootstrap Go may be older than go.mod requires.
(cd / && GOTOOLCHAIN=local GOFLAGS=-modcacherw GOMODCACHE="$toolchain_cache" \
	go mod download "golang.org/toolchain@v0.0.1-$go_version.linux-$host_arch")
goroot=$toolchain_cache/golang.org/toolchain@v0.0.1-$go_version.linux-$host_arch
# Module zips don't keep the executable bit (the go command restores it when it
# switches toolchains itself).
chmod +x "$goroot"/bin/* "$goroot"/pkg/tool/*/*

build_cache=${LINUX_BUILD_CACHE:-$(go env GOCACHE)-linux}
mkdir -p dist/linux "$build_cache"

apt_cache=${LINUX_APT_CACHE:-$build_cache/apt}
mkdir -p "$apt_cache"

# One container per architecture: the -dev packages of different
# architectures can't all be installed side by side.
for arch in $arches; do
	docker run --rm --platform "linux/$host_arch" \
		-v "$PWD":/src -w /src \
		-v "$goroot":/usr/local/go:ro \
		-v "$(go env GOMODCACHE)":/gomod:ro \
		-v "$build_cache":/gocache \
		-v "$apt_cache":/var/cache/apt/archives \
		-e GOMODCACHE=/gomod -e GOCACHE=/gocache -e GOPROXY=off -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=local \
		-e VERSION="$version" -e ARCH="$arch" \
		debian:bookworm-slim sh -eu -c '
export PATH=/usr/local/go/bin:$PATH DEBIAN_FRONTEND=noninteractive
native=$(dpkg --print-architecture)
case $ARCH in
amd64) triplet=x86_64-linux-gnu deb=amd64 cc=x86_64-linux-gnu-gcc ;;
386) triplet=i386-linux-gnu deb=i386 cc=i686-linux-gnu-gcc ;;
arm64) triplet=aarch64-linux-gnu deb=arm64 cc=aarch64-linux-gnu-gcc ;;
arm) triplet=arm-linux-gnueabihf deb=armhf cc=arm-linux-gnueabihf-gcc ;;
*) echo "unsupported arch $ARCH" >&2; exit 1 ;;
esac
pkgs="gcc libc6-dev pkg-config wayland-protocols"
# crossbuild-essential-<arch> = cross gcc + libc6-dev:<arch> (the target headers).
if [ $deb = $native ]; then cc=gcc; else dpkg --add-architecture $deb; pkgs="$pkgs crossbuild-essential-$deb libc6-dev:$deb"; fi
for p in libgl1-mesa-dev libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev libxxf86vm-dev libxkbcommon-dev libwayland-dev; do
	pkgs="$pkgs $p:$deb"
done
apt-get update -qq -o Acquire::Retries=8
apt-get install -y -qq -o Acquire::Retries=8 --no-install-recommends $pkgs >/dev/null

tags=with_gvisor,with_quic,with_utls
ldflags="-s -w -X github.com/khaliilii/MKConnect/internal/version.Version=$VERSION"
echo "building linux/$ARCH with $cc..."
export PKG_CONFIG_PATH= PKG_CONFIG_LIBDIR=/usr/lib/$triplet/pkgconfig:/usr/share/pkgconfig
GOOS=linux GOARCH=$ARCH GOARM=7 CGO_ENABLED=1 CC=$cc \
	go build -trimpath -buildvcs=false -tags $tags -ldflags "$ldflags" -o dist/linux/MKConnect-linux-$ARCH ./cmd/mkconnect-gui
GOOS=linux GOARCH=$ARCH GOARM=7 CGO_ENABLED=0 \
	go build -trimpath -buildvcs=false -tags $tags -ldflags "$ldflags" -o dist/linux/mkconnect-cli-linux-$ARCH .
'
done

# Package each GUI build with a desktop entry and icon.
for a in $arches; do
	d=$(mktemp -d)
	mkdir -p "$d/MKConnect"
	cp "dist/linux/MKConnect-linux-$a" "$d/MKConnect/mkconnect"
	cp cmd/mkconnect-gui/Icon.png "$d/MKConnect/mkconnect.png"
	cat >"$d/MKConnect/mkconnect.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=MKConnect
Exec=mkconnect
Icon=mkconnect
Categories=Network;
EOF
	tar -C "$d" -czf "dist/linux/MKConnect-linux-$a.tar.gz" MKConnect
	rm -rf "$d" "dist/linux/MKConnect-linux-$a"
done
ls -lh dist/linux
