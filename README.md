# MKConnect

A multi-account client for **SSH, VMess, VLESS, Trojan, Shadowsocks, Hysteria2 and TUIC**, with a local proxy, LAN sharing and a TUN (virtual network interface) mode.

## Features

- Any number of accounts, added by hand or imported in bulk from `vmess://`, `vless://`, `trojan://`, `ss://`, `ssh://`,
  `hysteria2://` (`hy2://`) and `tuic://` links: one click on **Clipboard** imports every link found in the copied
  text (one or many, in a chat message, space- or line-separated, or base64), detects each protocol and skips duplicates
- Groups, and subscriptions (like Hiddify): a URL whose accounts are refreshed automatically, with the data
  used / remaining and expiry date reported by the provider (`subscription-userinfo`)
- Choice of core:
  - **sing-box** (built in): all protocols including SSH, native TUN
  - **xray** (built in): VMess / VLESS / Trojan / Shadowsocks, incl. `xhttp` (Hysteria2 and TUIC need sing-box)
  - **external**: run your own `sing-box` or `xray` binary with the generated config
  - SSH accounts on the xray core use the built-in SSH client (auto-reconnect, keepalive)
- **proxy** mode: SOCKS5 + HTTP on `127.0.0.1:1080` (SOCKS5 only for xray / built-in SSH)
- **LAN sharing**: listen on all interfaces, optionally with a username/password, so other devices can use the proxy
- **tun** mode: a virtual network interface that routes the whole system through the tunnel (needs root / Administrator)
- **gateway** (TUN mode, "Share with"): devices on other network interfaces (Ethernet, a second Wi-Fi, a hotspot)
  reach the internet through the tunnel without any proxy settings. TUN interfaces can't be bridged with Ethernet,
  so MKConnect acts as a router instead: Linux uses sing-box `auto_redirect` + IP forwarding, macOS IP forwarding,
  Windows Internet Connection Sharing (devices get 192.168.137.x automatically). Everything is undone on disconnect.
  `scripts/test-gateway-linux.sh` checks it end to end with network namespaces.
- SSH host keys are pinned on first connect (trust on first use), and a changed key is refused
- Profiles are stored in `<user config dir>/mkconnect/profiles.json` with owner-only permissions

## Desktop app

`MKConnect` (from the `MKConnect-GUI-*` release files) is the desktop app for Linux, Windows and macOS:

- account list with **Add** (form per protocol), **Import** (links in bulk, optionally into a group, or a subscription URL), edit, copy share link and delete
- group picker; subscriptions show a usage card (used / total, upload / download, expiry) and refresh automatically
- share links copied to the clipboard are added automatically when you switch to the app (can be turned off)
- core, mode (Proxy / TUN), local port, LAN sharing and proxy password, all saved as you change them
- one-click connect / disconnect; selecting another account while connected switches to it
- live connection info: inbound, outbound, core, upload / download speed and totals
- live logs, a tray icon that keeps the connection running when the window is closed, and an About page

For TUN mode start the app with administrator rights (`sudo` on Linux/macOS, "Run as administrator" on Windows).
The macOS app is not notarized; after unzipping run `xattr -dr com.apple.quarantine MKConnect.app` once.

The desktop app and the CLI share the same profiles file. Set `MKCONNECT_CONFIG` to use a different one.

## Command line

```sh
# add accounts
mkconnect profile add ssh --name home --server 1.2.3.4 --user root --ask-password
mkconnect profile import 'vless://...' 'vmess://...'
mkconnect profile import --clipboard
mkconnect profile import --group work 'vless://...' 'trojan://...'
mkconnect sub add https://example.com/subscription
mkconnect sub ls                                    # usage and expiry per subscription
mkconnect sub update --all
mkconnect profile import --legacy config.json      # migrate a v1 config

# manage them
mkconnect profile ls
mkconnect profile edit home --port 2222
mkconnect profile show germany --link
mkconnect profile use germany
mkconnect profile rm home

# settings
mkconnect settings                                  # show
mkconnect settings set core xray                    # singbox | xray | external
mkconnect settings set mode tun                     # proxy | tun
mkconnect settings set lan true
mkconnect settings set proxy-user me
mkconnect settings set proxy-pass secret

# external core
mkconnect settings set external-path /usr/local/bin/sing-box
mkconnect settings set external-kind singbox        # or xray
mkconnect settings set core external

# connect (active profile, or name it); flags override settings for this run
mkconnect
mkconnect run germany --mode tun
sudo mkconnect run germany --mode tun --lan
mkconnect interfaces                                # interfaces that can share the tunnel
sudo mkconnect run germany --mode tun --share eth1  # gateway for devices on eth1
```

## Build

Requires Go 1.26.

```sh
# command line (pure Go, cross-compiles anywhere)
go build -trimpath -tags with_gvisor,with_quic,with_utls -ldflags "-s -w" .

# desktop app (needs a C compiler; on Linux also: libgl1-mesa-dev xorg-dev libxkbcommon-dev)
go build -trimpath -tags with_gvisor,with_quic,with_utls -ldflags "-s -w" ./cmd/mkconnect-gui
```

Local packages into `dist/` (both scripts also run offline once their dependencies are cached):

```sh
scripts/build-macos.sh v2.0.0      # universal MKConnect.app + CLI (needs Xcode command line tools)
scripts/build-android.sh v2.0.0    # APKs for arm64/armv7/x86_64/x86 via fyne-cross (needs Docker)
scripts/build-windows.sh v2.0.0    # Windows amd64/x86/arm64, cross-compiled with zig (ZIG=/path/to/zig)
scripts/build-linux.sh v2.0.0      # Linux amd64/x86/arm64/armv7 in Debian containers (needs Docker)
```

Add `-tags no_xray` or `-tags no_singbox` to leave a core out and get a smaller binary. TUN mode needs the sing-box core.

GitHub Actions builds these on every push and attaches them to a release for `v*.*.*` tags:

| | amd64 | 386 (x86) | arm64 | armv7 |
|---|---|---|---|---|
| Desktop app, Linux | ✅ | ✅ | ✅ | ✅ |
| Desktop app, Windows | ✅ | ✅ | ✅ | – |
| Desktop app, macOS | ✅ universal | – | ✅ universal | – |
| Android app (APK) | ✅ | ✅ | ✅ | ✅ |
| CLI, Linux / Windows / macOS / Android | ✅ | ✅ | ✅ | ✅ (Linux) |

On Android the app currently runs the proxy mode (local SOCKS/HTTP proxy, shareable over a hotspot);
a system-wide VPN (TUN) on Android needs a VPN service and is on the roadmap.

## Roadmap

- Hotspot helpers
- Android app with a background VPN service
