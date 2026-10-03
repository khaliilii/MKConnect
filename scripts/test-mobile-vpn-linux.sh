#!/bin/sh
# Tests the Android VPN bridge (mobile/) as root in a privileged container: a
# fake VpnService creates the TUN and protects the core's sockets, and the
# test process - like any app on the phone - reaches a site (and DNS) that
# only exists behind the Shadowsocks server.
set -eu

cd "$(dirname "$0")/.."
host_arch=$(docker info --format '{{.Architecture}}' | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
go_version=$(go env GOVERSION)
toolchain_cache=${FYNE_CROSS_CACHE:-$HOME/Library/Caches/fyne-cross}/pkg/mod
(cd / && GOTOOLCHAIN=local GOFLAGS=-modcacherw GOMODCACHE="$toolchain_cache" \
	go mod download "golang.org/toolchain@v0.0.1-$go_version.linux-$host_arch")
goroot=$toolchain_cache/golang.org/toolchain@v0.0.1-$go_version.linux-$host_arch
chmod +x "$goroot"/bin/* "$goroot"/pkg/tool/*/*
build_cache=${LINUX_BUILD_CACHE:-$(go env GOCACHE)-linux}
mkdir -p "$build_cache/apt"

docker run --rm --privileged --platform "linux/$host_arch" \
	-v "$PWD":/src -w /src \
	-v "$goroot":/usr/local/go:ro \
	-v "$(go env GOMODCACHE)":/gomod:ro \
	-v "$build_cache":/gocache \
	-v "$build_cache/apt":/var/cache/apt/archives \
	-e GOMODCACHE=/gomod -e GOCACHE=/gocache -e GOPROXY=off -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=local \
	-e MIRROR="${DEBIAN_MIRROR:-http://ftp.nl.debian.org}" \
	debian:bookworm-slim sh -eu -c '
export PATH=/usr/local/go/bin:$PATH DEBIAN_FRONTEND=noninteractive
# Try the preferred mirror first, then others: some drop connections on some networks.
cur=http://deb.debian.org
for m in $MIRROR http://ftp.de.debian.org http://ftp.nl.debian.org http://deb.debian.org; do
	sed -i "s#$cur#$m#g" /etc/apt/sources.list.d/debian.sources; cur=$m
	apt-get update -qq -o Acquire::Retries=8 >/dev/null 2>&1 && break
	echo "mirror $m unreachable, trying the next one"
done
for try in 1 2 3 4 5 6; do
	apt-get install -y -qq -o Acquire::Retries=8 --no-install-recommends iproute2 nftables >/dev/null && break
	[ $try = 6 ] && exit 1; sleep 5
done
CGO_ENABLED=0 go build -buildvcs=false -o /tmp/ssserver ./internal/testtools/ssserver

ip netns add remote
ip link add wan0 type veth peer name wan1 netns remote
ip addr add 10.200.0.1/24 dev wan0; ip link set wan0 up
ip -n remote addr add 10.200.0.2/24 dev wan1; ip -n remote link set wan1 up; ip -n remote link set lo up
ip -n remote addr add 203.0.113.10/32 dev lo
ip -n remote addr add 1.1.1.1/32 dev lo
ip route del default || true
ip route add default via 10.200.0.2 dev wan0
# The website and DNS only answer through the Shadowsocks server.
ip netns exec remote nft -f - <<NFT
table inet only_via_proxy {
	chain input {
		type filter hook input priority 0;
		iifname "wan1" ip daddr { 203.0.113.10, 1.1.1.1 } drop
	}
}
NFT
ip netns exec remote /tmp/ssserver -ss 10.200.0.2:8388 -http 203.0.113.10:8080 -dns 1.1.1.1:53 >/tmp/ssserver.log 2>&1 &
sleep 1
# Without the VPN the site is unreachable (no route back from "the internet").
if timeout 3 bash -c "exec 3<>/dev/tcp/203.0.113.10/8080" 2>/dev/null; then echo "FAIL: reachable without the VPN"; exit 1; fi
CGO_ENABLED=0 go test -count=1 -tags "roottest with_gvisor with_quic with_utls" -run TestVPNThroughFakeVpnService -v ./mobile/
'
