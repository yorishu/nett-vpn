# Nett split core

This is a Nett derivative, not an official Amnezia Box or sing-box binary.

- Source: https://github.com/amnezia-vpn/amnezia-box, tag `v1.260910.0`.
- Runtime version: `1.260910.0-nett.1`.
- Toolchain: Go `1.25.5`, Windows amd64, `CGO_ENABLED=0`.
- Tags: `with_gvisor,with_awg,with_wireguard,with_conntrack`.
- Upstream licensing: GPL-3.0-or-later and the additional naming condition reproduced in `LICENSE.txt`.

Nett adds `--nett-ready-file` and `--nett-stop-file` to `run`, and renames the derivative command/version display. Readiness is published after startup with PID and Windows process creation time. Stop requests invoke normal engine `Close()` rather than killing it and leaving tunnel routes behind.

`source.zip` includes the exact modified source, lifecycle extension, Go module manifests and upstream licenses. Dependencies are identified by `go.mod` and `go.sum` and downloaded by Go with checksum verification. It contains no VPN credentials or local profiles.

To rebuild from that source archive, extract it, enter its root, and run with Go 1.25.5 on PATH:

```powershell
$env:GOTOOLCHAIN='local'
$env:GOWORK='off'
$env:CGO_ENABLED='0'
go build -trimpath -tags with_gvisor,with_awg,with_wireguard,with_conntrack -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.260910.0-nett.1' -o nett-split-core.exe ./cmd/sing-box
```

The Nett workspace also has `scripts/patch_split_engine.py` and `scripts/build_split_engine.ps1` for rebuilding from the fresh upstream tag. Users do not need Go to run Nett.

`wintun.dll` is the signed amd64 library from the official AmneziaWG Windows 3.1.0 package: https://github.com/amnezia-vpn/amneziawg-windows-client/releases/tag/3.1.0. Its upstream licensing is included in `WINTUN-LICENSE.txt`.
