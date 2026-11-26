<div align="center">

```text
                       _   _
             _ __   ___| |_| |_
            | '_ \ / _ \ __| __|
            | | | |  __/ |_| |_
            |_| |_|\___|\__|\__|

          [ tunnel terminal / windows x64 ]
```

![build](https://img.shields.io/badge/build-1.0.0-9cff44?style=flat-square&labelColor=141d18)
![Rust](https://img.shields.io/badge/client-Rust-9cff44?style=flat-square&labelColor=141d18&logo=rust)
![Windows](https://img.shields.io/badge/platform-Windows_x64-9cff44?style=flat-square&labelColor=141d18)
![WG + AWG](https://img.shields.io/badge/tunnels-WireGuard_%2B_AmneziaWG-9cff44?style=flat-square&labelColor=141d18)

**Green phosphor. Encrypted profiles. Your routing rules.**

[download release](https://github.com/yorishu/nett-vpn/releases/latest) · [boot sequence](#01--b00t) · [routing](#03--r0ut3) · [build](#05--d3v)

</div>

![nett terminal interface](docs/terminal.png)

## 00 // wh4t is this

`nett` is a Windows VPN client with a Rust interface styled after an old terminal: pixel-letter **k**, phosphor glow, scanlines, a vignette, a moving raster and short chromatic glitches.

Underneath: WireGuard and AmneziaWG, a DPAPI-encrypted profile library, site/app split tunneling and a tray that keeps the tunnel alive when the window is closed.

No browser shell. No Go installation needed to run it. VPN engines live beside the executable, not inside a pretend single-file bundle.

## 01 // b00t

```text
> download  nett-v1.0.0-windows-x64.zip
> extract   the whole archive
> launch    nett.exe
> import    your .conf
> connect   approve Windows UAC
```

Keep the extracted layout intact:

```text
nett.exe
engines/
  AmneziaWG/    official AWG engine + Wintun
  AmneziaBox/   Nett split core + Wintun + source + licenses
README.md
```

Normal AmneziaWG connections use the bundled official Windows engine. Normal WireGuard connections require [WireGuard for Windows](https://www.wireguard.com/install/). Enabling split tunneling selects the bundled Nett split core for either protocol.

Before upgrading, exit the previous copy through `qu1t`. Do not run two Nett instances against the same profile library.

## 02 // c0ntr0ls

| Input | Action |
| :--- | :--- |
| `SETTINGS` | Open the control deck above `IMPORT .CONF` |
| `PROFILES` | Import, select, rename or delete saved profiles |
| `SITES` / `APPS` | Configure global user routing rules shared by all VPN profiles |
| `DISPLAY` | Change CRT effects and animation, even with VPN active |
| `SAVE & APPLY` | Save the current section; VPN profiles and user config save independently |
| `BACK` | Return; confirm before discarding unsaved changes |
| `F8` | Toggle CRT effects immediately |
| `kill switch [X]` | Protect VPN traffic while respecting DIRECTLY; disconnect before changing |
| `HIDE` / `CLOSE` | Hide the window; keep the tunnel running |
| Tray → `s33` | Restore the window |
| Tray → `qu1t` | Stop the tunnel, then exit |

Profile and routing edits are locked while connected. Display preferences are saved independently and do not restart the VPN. Importing a VPN profile saves VPN-profile edits while preserving any pending user-config draft. Saving one config does not commit or discard unsaved edits in the other. Split lists are saved independently of engine validation; a connection error never clears saved rules. Successful saves retain the current settings tab. AWG boolean fields support on/off, yes/no, true/false and 1/0; empty optional fields are treated as unset. AWG PersistentKeepalive ranges such as 25-35 are preserved by the bundled split core; off disables keepalive.

The tray **k** turns green and the title reports `wired` only after a TCP connection succeeds through the VPN. A running engine with a failed probe remains unverified; DISCONNECT stays available. Probes repeat in the background approximately every three seconds, with bounded timeouts. The probe tries `1.1.1.1:443` and `1.0.0.1:443`; profiles that cannot reach either destination remain unverified even if a private-network tunnel works. A failed disconnect or cancelled UAC leaves Nett open with an error instead of silently exiting.

Split tunnels use an authenticated, loopback-only probe listener pinned to the VPN outbound before user routing rules. Native tunnels bind the probe to their Windows interface. Neither probe falls back to direct internet.

The red kill switch is off by default. Enable it before CONNECT. Persistent Windows Filtering Platform filters arm before engine startup. With split tunneling, only the bundled split core may open physical connections for DIRECTLY rules and any other traffic your routing policy assigns to direct. Ordinary applications cannot bypass the firewall themselves; the core's VPN outbound has no direct fallback. No shared website IPs are globally whitelisted. Without split tunneling, protection stays strict. VPN transport endpoints, localhost, DHCP and link-local IPv6 discovery remain available.

DIRECTLY domain DNS rules remain direct; VPN domain DNS rules remain VPN. When protection is enabled, direct DNS is sent by the allowed core to the first usable non-loopback IPv4 resolver from Windows (fallback: `1.1.1.1`). This avoids relying on the blocked shared Windows DNS process. Application-owned encrypted DNS follows application routing; shared system DNS still cannot be isolated per application, so an app using the default VPN resolver can lose uncached name resolution during a VPN outage.

If the VPN peer stops responding while the split core remains alive, DIRECTLY routes can continue; VPN routes fail closed. If the core itself crashes, filtering persists and blocks traffic until recovery or an explicit disconnect. Manual DISCONNECT and tray `qu1t` stop the tunnel and release filtering. HIDE/CLOSE keep the connection and protection active.

After a crash, reopen Nett and use DISCONNECT or turn off the red switch to release protection. If the UI cannot open, run PowerShell from the application directory: `Start-Process .\nett.exe -ArgumentList '--nett-network clear _global' -Verb RunAs -Wait -WindowStyle Hidden`. This explicitly removes Nett's filters; it does not remove other firewall rules.

## 03 // r0ut3

User config has one site list and one application list shared by every VPN profile. You can edit and save these lists before importing a VPN config. Importing, switching, renaming or deleting a VPN profile never replaces them.

| Mode | Listed destinations | Everything else |
| :--- | :--- | :--- |
| `VIA VPN` | VPN | Direct |
| `DIRECTLY` | Direct | VPN |

With both lists enabled, explicit direct exceptions win. If either list is in `VIA VPN` mode, unmatched traffic defaults to direct; the VPN inclusions form a union.

```text
[sites]  example.com
         192.168.10.0/24
         host.ts.net:8766

[apps]   C:\Apps\Discord.exe
         C:\Apps\qbittorrent.exe
```

Domains include subdomains. App rules match full executable paths without case sensitivity. Add helper executables separately and restart apps after reconnecting.

Routing limits:

- Peer `AllowedIPs` still apply. A local rule cannot grant access beyond the peer configuration.
- Domain matching uses intercepted DNS or protocol sniffing. App-owned encrypted DNS and ECH can hide the domain; use IP/CIDR rules or adjust secure DNS in that app.
- VPN DNS uses the first IP in the profile DNS list, or `1.1.1.1` when none exists. Direct DNS uses Windows. Shared Windows DNS services are not isolated per app.
- The split AWG server endpoint needs an IPv4 address or hostname with an IPv4 DNS record. Nett resolves hostnames through Windows DNS before each connection, in the background. Unsupported config fields fail explicitly.

## 04 // l0cal vault

```text
%LOCALAPPDATA%\nett-vpn\profiles.dpapi
%LOCALAPPDATA%\nett-vpn\user-config.dpapi
```

Both stores are encrypted with Windows DPAPI for the current account. `profiles.dpapi` contains only VPN profiles and the selected profile. `user-config.dpapi` contains global site/app rules, display preferences and kill-switch preference. Saving either store does not rewrite the other. Original import files are no longer needed; startup does not automatically connect.

On upgrade, the selected VPN profile's old routing rules become the global user rules (the first profile is used if none was selected). Existing user config always wins and is never replaced by migration. The complete original encrypted vault, including other profiles' old rule sets, is preserved as `profiles.before-user-config.dpapi`. The older single-profile format is also migrated automatically.

Exit the old client through `qu1t` before upgrading. Older clients do not read the new user-config store; avoid running them against the migrated data directory.

Engines also need working `.conf` / `.json` files. These files and logs can contain keys or network metadata; their directory ACL permits the current user, SYSTEM and administrators. Do not publish this directory or copy it into an issue.

CRT overlays do not capture clicks or keyboard focus. The phosphor glow runs at half its original opacity, with a gently curved raster and one sweep at the original speed. A short burst of large red pixels marks a successful kill-switch toggle. DISPLAY preferences and Windows reduced-motion settings control animations. Ordinary labels cannot be selected; input fields retain normal editing.

## 05 // d3v

Requirements: a current Rust Windows GNU toolchain with edition 2024 support, GCC and `windres` on PATH (included in WinLibs). `build.rs` embeds `nett.ico` and Windows file properties in the EXE. Clone, then:

```powershell
cargo build --release --locked
cargo test --release --locked
```

For local use, extract `engines/` from a release beside `target/release/nett-vpn.exe`. Binaries, local profiles and build caches are excluded from Git.

The split core is a Nett derivative of [Amnezia Box](https://github.com/amnezia-vpn/amnezia-box), pinned to `v1.260910.0`. To rebuild it, put Go **1.25.5** and Python on PATH:

```powershell
./scripts/build_split_engine.ps1
cargo test --release --locked -- --include-ignored
```

The script verifies the upstream archive checksum and applies the small lifecycle patch. Engine readiness includes PID and process creation time. A stop request calls the engine's normal cleanup path instead of abruptly killing it. Go is a build dependency for this sidecar only; Nett's UI stays Rust.

The test suite covers encrypted persistence, routing config generation, UI clicks and layout, display changes during an active connection, tray lifecycle, failed verification and probe interface binding. Optional engine tests validate generated WG/AWG configs and start/stop a route-free instance. The two optional WFP tests require an elevated PowerShell: one aborts the complete filter transaction, the other blocks only a temporary localhost port and removes its rules automatically. Live VPN traffic and a complete real-server outage are not covered by these tests.

Isolated screenshot mode never opens the real vault or creates a tray:

```powershell
$env:NETT_PREVIEW_SCREEN = 'home' # profiles / sites / apps / display / glitch / wired / unverified / blocked
$env:EFRAME_SCREENSHOT_TO = "$PWD/preview.png"
cargo run --release --features ui-preview
```

Screenshot builds exit automatically. **Do not distribute a `ui-preview` build**; build the release again without that feature.

## 06 // credits & source

- [AmneziaWG for Windows](https://github.com/amnezia-vpn/amneziawg-windows-client/releases/tag/3.1.0): signed engine and Wintun in the portable release.
- [Amnezia Box](https://github.com/amnezia-vpn/amnezia-box/tree/v1.260910.0): split-core base. Nett's modified engine source is included in the release under `engines/AmneziaBox/source.zip`.
- [egui / eframe](https://github.com/emilk/egui): native Rust interface.

Third-party licenses remain in `engines/`. See [split-core source notes](engines/AmneziaBox/SOURCE.md) for the pinned toolchain, build tags and changes. Nett split core is a derivative, not an official Amnezia Box binary.

```text
> end of transmission_
```
