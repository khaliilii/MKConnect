#!/bin/sh
# End-to-end test of gateway mode on Linux, in a privileged Docker container:
#
#   [lan ns] 10.50.0.2 --lan0-- [gateway: MKConnect TUN --share lan0] --wan0-- [remote ns]
#                                                                              shadowsocks 10.200.0.2:8388
#                                                                              website 203.0.113.10:8080
#
# The website is only reachable through the Shadowsocks server (the remote
# namespace has no route back to the LAN), so a device on lan0 can only load it
# if MKConnect really routes its traffic through the tunnel.
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
	debian:bookworm-slim sh -eu -c '
export PATH=/usr/local/go/bin:$PATH DEBIAN_FRONTEND=noninteractive
apt-get update -qq -o Acquire::Retries=8
apt-get install -y -qq -o Acquire::Retries=8 --no-install-recommends iproute2 curl nftables procps >/dev/null

echo "== build"
CGO_ENABLED=0 go build -buildvcs=false -tags with_gvisor,with_quic,with_utls -o /tmp/mkconnect .
CGO_ENABLED=0 go build -buildvcs=false -o /tmp/ssserver ./internal/testtools/ssserver

echo "== network"
ip netns add remote; ip netns add lan
ip link add wan0 type veth peer name wan1 netns remote
ip link add lan0 type veth peer name lan1 netns lan
ip addr add 10.200.0.1/24 dev wan0; ip link set wan0 up
ip addr add 10.50.0.1/24 dev lan0; ip link set lan0 up
ip -n remote addr add 10.200.0.2/24 dev wan1; ip -n remote link set wan1 up; ip -n remote link set lo up
ip -n remote addr add 203.0.113.10/32 dev lo
ip -n remote addr add 1.1.1.1/32 dev lo # the public DNS server lives in "the internet" too
ip -n lan addr add 10.50.0.2/24 dev lan1; ip -n lan link set lan1 up; ip -n lan link set lo up
ip -n lan route add default via 10.50.0.1
# "The internet" is behind wan0 now.
ip route del default || true
ip route add default via 10.200.0.2 dev wan0
sysctl -qw net.ipv4.ip_forward=0

ip netns exec remote /tmp/ssserver -ss 10.200.0.2:8388 -http 203.0.113.10:8080 -dns 1.1.1.1:53 >/tmp/ssserver.log 2>&1 &
mkdir -p /etc/netns/lan && echo "nameserver 1.1.1.1" >/etc/netns/lan/resolv.conf
sleep 1

echo "== before: the LAN device must NOT reach the website"
if ip netns exec lan curl -s -m 3 http://203.0.113.10:8080/; then echo "FAIL: reachable without the tunnel"; exit 1; fi
echo "ok: unreachable"

cfg=/tmp/mk.json
/tmp/mkconnect --config $cfg profile add shadowsocks --name remote --server 10.200.0.2 --port 8388 --method aes-256-gcm --password pw >/dev/null
/tmp/mkconnect --config $cfg run --mode tun --share lan0 >/tmp/mk.log 2>&1 &
mk=$!
for i in $(seq 1 30); do grep -q "running on" /tmp/mk.log && break; sleep 0.5; done
grep -E "running on|sharing|inbound|outbound|Devices on" /tmp/mk.log || { cat /tmp/mk.log; exit 1; }
echo "ip_forward while sharing: $(sysctl -n net.ipv4.ip_forward)"

echo "== during: the LAN device reaches the website through the tunnel"
body=$(ip netns exec lan curl -s -m 10 http://203.0.113.10:8080/) || { echo "FAIL: request failed"; tail -20 /tmp/mk.log; exit 1; }
echo "$body"
echo "== during: DNS from the LAN device (to 1.1.1.1) is answered through the tunnel"
body=$(ip netns exec lan curl -s -m 10 http://website.test:8080/) || { echo "FAIL: name lookup or request failed"; tail -20 /tmp/mk.log; exit 1; }
echo "website.test -> $body"

echo "== after: disconnect restores the system"
kill -INT $mk; wait $mk || true
echo "ip_forward after disconnect: $(sysctl -n net.ipv4.ip_forward)"
[ "$(sysctl -n net.ipv4.ip_forward)" = 0 ] || { echo "FAIL: ip_forward not restored"; exit 1; }
if nft list ruleset | grep -q sing-box; then echo "FAIL: nftables rules left behind"; nft list ruleset; exit 1; fi
echo "ok: forwarding off, no nftables rules left"
if ip netns exec lan curl -s -m 3 http://203.0.113.10:8080/; then echo "FAIL: still reachable after disconnect"; exit 1; fi
echo "PASS: gateway mode works"
'
