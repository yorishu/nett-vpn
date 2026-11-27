$ErrorActionPreference = 'Stop'
$nettWorkspace = Split-Path $PSScriptRoot -Parent
Set-Location $nettWorkspace
$nettGo = Get-Command go -ErrorAction Stop
if ((& $nettGo.Source version) -notmatch '^go version go1\.27\.4 ') {
    throw 'Use Go 1.27.4, the toolchain pinned for the Nett security update.'
}
$nettSource = Join-Path $nettWorkspace 'vendor\amnezia-box-1.260910.0'
if (-not (Test-Path -LiteralPath $nettSource)) {
    New-Item -ItemType Directory -Force vendor | Out-Null
    $nettArchive = Join-Path $nettWorkspace 'vendor\amnezia-box-source.zip'
    Invoke-WebRequest 'https://codeload.github.com/amnezia-vpn/amnezia-box/zip/refs/tags/v1.260910.0' -OutFile $nettArchive
    if ((Get-FileHash -LiteralPath $nettArchive -Algorithm SHA256).Hash -ne '2C7563405AA61CD973A7BD43AEF0E22E1ED3EE74E6724A18244A641B8BBFE152') {
        throw 'Upstream source checksum mismatch.'
    }
    Expand-Archive -LiteralPath $nettArchive -DestinationPath vendor
}
python scripts\patch_split_engine.py $nettSource
if ($LASTEXITCODE -ne 0) { throw 'Source patch failed' }
New-Item -ItemType Directory -Force engines\AmneziaBox | Out-Null
$nettOutput = Join-Path $nettWorkspace 'engines\AmneziaBox\nett-split-core.exe'
$env:GOTOOLCHAIN = 'local'
$env:GOWORK = 'off'
$env:CGO_ENABLED = '0'
Set-Location $nettSource
# shortcut: http2legacy preserves upstream's private HTTP/2 pool layout; remove when upstream uses public connection cleanup APIs.
& $nettGo.Source build -mod=mod -trimpath -buildvcs=false -tags with_gvisor,with_awg,with_wireguard,with_conntrack,http2legacy -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.260910.0-nett.3' -o $nettOutput ./cmd/sing-box
if ($LASTEXITCODE -ne 0) { throw 'Split core build failed' }
