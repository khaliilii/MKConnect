# MKConnect

A multi-account client for **SSH, VMess, VLESS, Trojan and Shadowsocks**, with a local proxy, LAN sharing and a TUN (virtual network interface) mode.

## Features

- Any number of accounts, added by hand or imported from `vmess://`, `vless://`, `trojan://`, `ss://`, `ssh://` links or a subscription URL
- Choice of core:
  - **sing-box** (built in): all protocols including SSH, native TUN
  - **xray** (built in): VMess / VLESS / Trojan / Shadowsocks, incl. `xhttp`
  - **external**: run your own `sing-box` or `xray` binary with the generated config
  - SSH accounts on the xray core use the built-in SSH client (auto-reconnect, keepalive)
- **proxy** mode: SOCKS5 + HTTP on `127.0.0.1:1080` (SOCKS5 only for xray / built-in SSH)
- **LAN sharing**: listen on all interfaces, optionally with a username/password, so other devices can use the proxy
- **tun** mode: a virtual network interface that routes the whole system through the tunnel (needs root / Administrator)
- SSH host keys are pinned on first connect (trust on first use), and a changed key is refused
- Profiles are stored in `<user config dir>/mkconnect/profiles.json` with owner-only permissions

## Desktop app

`MKConnect` (from the `MKConnect-GUI-*` release files) is the desktop app for Linux, Windows and macOS:

- account list with **Add** (form per protocol), **Import** (links, clipboard or subscription URL), edit, copy share link and delete
- core, mode (Proxy / TUN), local port, LAN sharing and proxy password, all saved as you change them
- one-click connect / disconnect; selecting another account while connected switches to it
- live logs from the cores, and a tray icon that keeps the connection running when the window is closed

For TUN mode start the app with administrator rights (`sudo` on Linux/macOS, "Run as administrator" on Windows).
The macOS app is not notarized; after unzipping run `xattr -dr com.apple.quarantine MKConnect.app` once.

The desktop app and the CLI share the same profiles file. Set `MKCONNECT_CONFIG` to use a different one.

## Command line

```sh
# add accounts
mkconnect profile add ssh --name home --server 1.2.3.4 --user root --ask-password
mkconnect profile import 'vless://...' 'vmess://...'
mkconnect profile import --url https://example.com/subscription
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
```

## Build

Requires Go 1.26.

```sh
# command line (pure Go, cross-compiles anywhere)
go build -trimpath -tags with_gvisor,with_quic,with_utls -ldflags "-s -w" .

# desktop app (needs a C compiler; on Linux also: libgl1-mesa-dev xorg-dev libxkbcommon-dev)
go build -trimpath -tags with_gvisor,with_quic,with_utls -ldflags "-s -w" ./cmd/mkconnect-gui
```

Add `-tags no_xray` or `-tags no_singbox` to leave a core out and get a smaller binary. TUN mode needs the sing-box core.

Releases for Linux, Windows, macOS and Android (CLI) on amd64 / arm64 / 386 / armv7 are built by GitHub Actions when a `v*.*.*` tag is pushed.

## Roadmap

- Gateway mode (share the TUN with other devices) and hotspot helpers
- Android app with a background VPN service
