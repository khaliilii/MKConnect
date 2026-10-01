#!/bin/sh
# Cross-compiles the Windows desktop app and CLI into dist/windows from macOS or
# Linux, using zig as the C compiler (it ships the MinGW headers and libraries).
# Usage: ZIG=/path/to/zig scripts/build-windows.sh [version] [arch...]   (default: amd64 386 arm64)
set -eu

cd "$(dirname "$0")/.."
version=${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
[ $# -gt 0 ] && shift
arches=${*:-amd64 386 arm64}
zig=${ZIG:-zig}
tags=with_gvisor,with_quic,with_utls
ldflags="-s -w -X github.com/khaliilii/MKConnect/internal/version.Version=$version"

mkdir -p dist/windows
for arch in $arches; do
	case $arch in
	amd64) target=x86_64-windows-gnu ;;
	386) target=x86-windows-gnu ;;
	arm64) target=aarch64-windows-gnu ;;
	*) echo "unsupported arch $arch" >&2; exit 1 ;;
	esac
	echo "building windows/$arch..."
	# With an external linker, -H=windowsgui alone still yields a console app; tell the linker too.
	GOOS=windows GOARCH=$arch CGO_ENABLED=1 \
		CC="$zig cc -target $target -Wl,--subsystem,windows" CXX="$zig c++ -target $target" \
		go build -trimpath -tags "$tags" -ldflags "$ldflags -H=windowsgui" \
		-o "dist/windows/MKConnect-windows-$arch.exe" ./cmd/mkconnect-gui
	GOOS=windows GOARCH=$arch CGO_ENABLED=0 \
		go build -trimpath -tags "$tags" -ldflags "$ldflags" \
		-o "dist/windows/mkconnect-cli-windows-$arch.exe" .
done
ls -lh dist/windows
