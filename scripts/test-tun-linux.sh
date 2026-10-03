#!/bin/sh
# End-to-end TUN test on Linux, in a privileged Docker container:
#   1. the system's own traffic (curl with no proxy settings) and DNS go
#      through the tunnel while connected;
#   2. after disconnecting, the network configuration is exactly as before
#      (interfaces, addresses, routes, policy rules, nftables, ip_forward, DNS);
#   3. the same with gateway sharing (--share);
#   4. what a crash (kill -9) leaves behind, and that the next run cleans it up.
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
	debian:bookworm-slim bash -eu -c '
export PATH=/usr/local/go/bin:$PATH DEBIAN_FRONTEND=noninteractive
cur=http://deb.debian.org
for m in $MIRROR http://ftp.de.debian.org http://ftp.nl.debian.org http://deb.debian.org; do
	sed -i "s#$cur#$m#g" /etc/apt/sources.list.d/debian.sources; cur=$m
	apt-get update -qq -o Acquire::Retries=8 >/dev/null 2>&1 && break
done
for try in 1 2 3 4 5 6; do
	apt-get install -y -qq -o Acquire::Retries=8 --no-install-recommends iproute2 curl nftables procps >/dev/null && break
	[ $try = 6 ] && exit 1; sleep 5
done

echo "== build"
CGO_ENABLED=0 go build -buildvcs=false -tags with_gvisor,with_quic,with_utls -o /tmp/mkconnect .
CGO_ENABLED=0 go build -buildvcs=false -o /tmp/ssserver ./internal/testtools/ssserver

echo "== network: \"the internet\" is behind wan0"
ip netns add remote; ip netns add lan
ip link add wan0 type veth peer name wan1 netns remote
ip link add lan0 type veth peer name lan1 netns lan
ip addr add 10.200.0.1/24 dev wan0; ip link set wan0 up
ip addr add 10.50.0.1/24 dev lan0; ip link set lan0 up
ip -n remote addr add 10.200.0.2/24 dev wan1; ip -n remote link set wan1 up; ip -n remote link set lo up
ip -n remote addr add 203.0.113.10/32 dev lo
ip -n remote addr add 1.1.1.1/32 dev lo
ip -n lan addr add 10.50.0.2/24 dev lan1; ip -n lan link set lan1 up; ip -n lan link set lo up
ip -n lan route add default via 10.50.0.1
ip route del default || true
ip route add default via 10.200.0.2 dev wan0
# The website and DNS server only answer through the Shadowsocks server:
# direct packets from this machine are dropped.
ip netns exec remote nft -f - <<NFT
table inet only_via_proxy {
	chain input {
		type filter hook input priority 0;
		iifname "wan1" ip daddr { 203.0.113.10, 1.1.1.1 } drop
	}
}
NFT
ip netns exec remote /tmp/ssserver -ss 10.200.0.2:8388 -http 203.0.113.10:8080 -dns 1.1.1.1:53 >/tmp/ssserver.log 2>&1 &
echo "nameserver 1.1.1.1" > /etc/resolv.conf
mkdir -p /etc/netns/lan && echo "nameserver 1.1.1.1" > /etc/netns/lan/resolv.conf
sysctl -qw net.ipv4.ip_forward=0
sleep 1

cfg=/tmp/mk.json
/tmp/mkconnect --config $cfg profile add shadowsocks --name remote --server 10.200.0.2 --port 8388 --method aes-256-gcm --password pw >/dev/null

snapshot() {
	{
		echo "## links";      ip -br link | awk "{print \$1, \$2}" | sort
		echo "## addresses";  ip -br addr | sort
		echo "## routes v4";  ip -4 route show table all | sort
		echo "## routes v6";  ip -6 route show table all | sort
		echo "## rules v4";   ip -4 rule | sort
		echo "## rules v6";   ip -6 rule | sort
		echo "## nftables";   nft list ruleset
		echo "## ip_forward"; sysctl -n net.ipv4.ip_forward
		echo "## resolv.conf"; cat /etc/resolv.conf
	} > "$1"
}
fail() { echo "FAIL: $*"; tail -20 /tmp/mk.log 2>/dev/null; exit 1; }
start() {
	/tmp/mkconnect --config $cfg run --mode tun "$@" > /tmp/mk.log 2>&1 &
	mk=$!
	for i in $(seq 1 40); do grep -q "running on" /tmp/mk.log && return; sleep 0.25; done
	fail "did not start"
}
stop() { kill -INT $mk; wait $mk || true; }
compare() {
	snapshot /tmp/after.txt
	if diff -u /tmp/before.txt /tmp/after.txt >/tmp/diff.txt; then
		echo "ok: network configuration identical to before ($1)"
	else
		echo "FAIL: leftovers after $1:"; cat /tmp/diff.txt; exit 1
	fi
}

echo
echo "== 1. the system traffic goes through the tunnel"
if curl -s -m 3 http://203.0.113.10:8080/ >/dev/null; then fail "website reachable without the tunnel"; fi
echo "ok: without the tunnel the website is unreachable"
snapshot /tmp/before.txt
start
snapshot /tmp/during.txt
echo "while connected the system has: $(diff /tmp/before.txt /tmp/during.txt | grep -c "^>") new and $(diff /tmp/before.txt /tmp/during.txt | grep -c "^<") changed lines of network configuration, e.g.:"
diff /tmp/before.txt /tmp/during.txt | grep "^>" | grep -E "tun|lookup|table sing-box" | head -6 | sed "s/^/   /"
body=$(curl -s -m 10 http://203.0.113.10:8080/) || fail "curl with no proxy settings failed while connected"
echo "curl (no proxy settings): $body"
case "$body" in *"you are 203.0.113.10"*) echo "ok: request left through the Shadowsocks server";; *) fail "request did not go through the tunnel";; esac
ip=$(getent hosts website.test | awk "{print \$1}") || true
[ "$ip" = 203.0.113.10 ] || fail "system DNS lookup through the tunnel gave \"$ip\""
echo "ok: system DNS (getent) resolved website.test -> $ip through the tunnel"
body=$(curl -s -m 10 http://website.test:8080/) || fail "request by name failed"
echo "ok: curl http://website.test:8080/ -> $body"

echo
echo "== 2. disconnect restores everything"
stop
compare "disconnect"
if curl -s -m 3 http://203.0.113.10:8080/ >/dev/null; then fail "website still reachable after disconnect"; fi
echo "ok: after disconnecting the website is unreachable again"

echo
echo "== 3. gateway sharing (--share lan0), then disconnect"
start --share lan0
[ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || fail "ip_forward not enabled while sharing"
body=$(ip netns exec lan curl -s -m 10 http://website.test:8080/) || fail "LAN device could not reach the website"
echo "ok: LAN device via the gateway: $body"
stop
compare "disconnecting gateway mode"

echo
echo "== 4. crash (kill -9) while connected with gateway sharing, then \"mkconnect cleanup\""
crash() {
	start --share lan0
	kill -9 $mk; wait $mk 2>/dev/null || true
	sleep 1
	snapshot /tmp/crash.txt
	echo "a crash left $(diff /tmp/before.txt /tmp/crash.txt | grep -c "^>") new lines of network configuration behind"
}
crash
/tmp/mkconnect cleanup | sed "s/^/   /"
compare "mkconnect cleanup"

echo
echo "== 5. crash again, then just connect and disconnect (automatic recovery)"
crash
start
grep "cleaned up after an earlier crash" /tmp/mk.log | sed "s/^.*🧹/   🧹/" || true
stop
compare "reconnecting after a crash"
echo
echo "PASS"
'
