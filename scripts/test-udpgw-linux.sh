#!/bin/sh
# Checks the SSH UDP relay against the real badvpn-udpgw, in a Docker
# container: builds udpgw from source, runs it on 127.0.0.1:7300 with the
# container's resolver pointed at the test's own DNS responder, and runs the
# engine's udpgw test against it (MKCONNECT_UDPGW_ADDR).
set -eu

cd "$(dirname "$0")/.."
host_arch=$(docker info --format '{{.Architecture}}' | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
# LINUX_GO_VERSION picks another (e.g. already downloaded) toolchain, such as go1.26.8.
go_version=${LINUX_GO_VERSION:-$(go env GOVERSION)}
toolchain_cache=${FYNE_CROSS_CACHE:-$HOME/Library/Caches/fyne-cross}/pkg/mod
(cd / && GOTOOLCHAIN=local GOFLAGS=-modcacherw GOMODCACHE="$toolchain_cache" \
	GOPROXY="${GOPROXY:-https://proxy.golang.org|https://goproxy.io|https://goproxy.cn|direct}" \
	go mod download "golang.org/toolchain@v0.0.1-$go_version.linux-$host_arch")
goroot=$toolchain_cache/golang.org/toolchain@v0.0.1-$go_version.linux-$host_arch
chmod +x "$goroot"/bin/* "$goroot"/pkg/tool/*/*
build_cache=${LINUX_BUILD_CACHE:-$(go env GOCACHE)-linux}
mkdir -p "$build_cache/apt"

docker run --rm --platform "linux/$host_arch" \
	-v "$PWD":/src -w /src \
	-v "$goroot":/usr/local/go:ro \
	-v "$(go env GOMODCACHE)":/gomod:ro \
	-v "$build_cache":/gocache \
	-v "$build_cache/apt":/var/cache/apt/archives \
	-e GOMODCACHE=/gomod -e GOCACHE=/gocache -e GOPROXY=off -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=local \
	-e MIRROR="${DEBIAN_MIRROR:-http://ftp.nl.debian.org}" \
	debian:bookworm-slim sh -eu -c '
export PATH=/usr/local/go/bin:$PATH DEBIAN_FRONTEND=noninteractive
cur=http://deb.debian.org
for m in $MIRROR http://ftp.de.debian.org http://ftp.nl.debian.org http://deb.debian.org; do
	sed -i "s#$cur#$m#g" /etc/apt/sources.list.d/debian.sources; cur=$m
	apt-get update -qq -o Acquire::Retries=8 >/dev/null 2>&1 && break
done
for try in 1 2 3 4 5 6; do
	apt-get install -y -qq -o Acquire::Retries=8 --no-install-recommends cmake make gcc libc6-dev git ca-certificates >/dev/null && break
	[ $try = 6 ] && exit 1; sleep 5
done

echo "== build badvpn-udpgw"
git clone -q --depth 1 https://github.com/ambrop72/badvpn.git /tmp/badvpn
mkdir -p /tmp/badvpn/build && cd /tmp/badvpn/build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null
make -s udpgw/badvpn-udpgw 2>&1 | grep -v warning || true
ls -l udpgw/badvpn-udpgw
cd /src

echo "== run udpgw; the resolver is the test DNS responder on 127.0.0.1:53"
echo "nameserver 127.0.0.1" > /etc/resolv.conf
/tmp/badvpn/build/udpgw/badvpn-udpgw --listen-addr 127.0.0.1:7300 --loglevel warning >/tmp/udpgw.log 2>&1 &
sleep 1

echo "== engine test against the real udpgw"
MKCONNECT_UDPGW_ADDR=127.0.0.1:7300 go test -buildvcs=false -count=1 -tags with_gvisor,with_quic,with_utls -run TestSSHUDPThroughUDPGW -v ./internal/engine 2>&1 | grep -E "^(=== RUN|--- |ok|FAIL|PASS)|_test.go:" || { cat /tmp/udpgw.log; exit 1; }
echo "udpgw log:"; cat /tmp/udpgw.log
'
