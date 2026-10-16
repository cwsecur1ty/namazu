[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [string]$Python = "",
    [switch]$InstallDependencies,
    [switch]$SkipArchive
)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $OutputPath) { $OutputPath = Join-Path $projectRoot 'dist/Namazu Desktop' }
$releaseRoot = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $releaseRoot) { throw "Output already exists. Choose a fresh -OutputPath; existing releases are preserved." }
if (-not $Python) { $Python = Join-Path $projectRoot '.venv/Scripts/python.exe' }
if (-not (Test-Path -LiteralPath $Python)) { throw 'Choose a Python 3.14 x64 virtual environment with -Python.' }
$sdkVersion = '10.0.402'
$sdkChecksum = 'ae4fd528cb7e9f6af6aaf7de36715a69f761f183744f1bb3025d19f5a92447090ec561410e46266c1d10a63781ed6f3de771760bc76c876d87daabc367b898cd'
$toolRoot = Join-Path $projectRoot 'desktop/.tools'
$dotnet = Join-Path $toolRoot 'dotnet/dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet)) {
    New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null
    $sdkArchive = Join-Path $toolRoot "dotnet-sdk-$sdkVersion-win-x64.zip"
    if (-not (Test-Path -LiteralPath $sdkArchive)) {
        Invoke-WebRequest -UseBasicParsing -Uri "https://builds.dotnet.microsoft.com/dotnet/Sdk/$sdkVersion/dotnet-sdk-$sdkVersion-win-x64.zip" -OutFile $sdkArchive
    }
    if ((Get-FileHash -LiteralPath $sdkArchive -Algorithm SHA512).Hash -ne $sdkChecksum) { throw 'Official .NET SDK checksum mismatch.' }
    Expand-Archive -LiteralPath $sdkArchive -DestinationPath (Join-Path $toolRoot 'dotnet') -Force
}
$actualSdk = & $dotnet --version
if ($actualSdk -ne $sdkVersion) { throw "Expected .NET SDK $sdkVersion; found $actualSdk" }
if ($InstallDependencies) {
    & $Python -m pip install --requirement (Join-Path $projectRoot 'desktop/requirements-build.lock.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Pinned Python dependency installation failed.' }
}
$node = (Get-Command node.exe -ErrorAction Stop).Source
if ((& $node --version) -ne 'v25.2.1') { throw 'This release pins Node.js v25.2.1. Install that build before packaging.' }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$buildRoot = Join-Path $projectRoot "build/desktop-$stamp"
New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null
New-Item -ItemType Directory -Force -Path $releaseRoot | Out-Null
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$env:DOTNET_CLI_HOME = Join-Path $toolRoot 'cli-home'
$env:NUGET_PACKAGES = Join-Path $toolRoot 'nuget'
Push-Location $projectRoot
try {
    & $Python desktop/release_manifest.py inputs (Join-Path $buildRoot 'source-inputs.json')
    if ($LASTEXITCODE -ne 0) { throw 'Pinned build input validation failed.' }
    $buildId = (Get-Content -LiteralPath (Join-Path $buildRoot 'source-inputs.json') -Raw | ConvertFrom-Json).build_id
    $identityRoot = Join-Path $buildRoot 'identity'
    & $Python desktop/release_manifest.py stage $identityRoot (Join-Path $buildRoot 'source-inputs.json')
    if ($LASTEXITCODE -ne 0) { throw 'Build identity/resource staging failed.' }
    $env:NAMAZU_BUILD_IDENTITY_DIR = $identityRoot
    & $dotnet publish desktop/Namazu.Desktop/Namazu.Desktop.csproj -c Release -r win-x64 --self-contained true -o $releaseRoot -p:DebugType=None -p:DebugSymbols=false -p:RestoreLockedMode=true "-p:NamazuBuildId=$buildId"
    if ($LASTEXITCODE -ne 0) { throw 'Native Windows shell build failed.' }
    & $Python -m PyInstaller --noconfirm --distpath $buildRoot --workpath (Join-Path $buildRoot 'pyinstaller') desktop/backend.spec
    if ($LASTEXITCODE -ne 0) { throw 'Python backend packaging failed.' }
    Copy-Item -LiteralPath (Join-Path $buildRoot 'backend') -Destination $releaseRoot -Recurse
    $runtime = Join-Path $releaseRoot 'runtime'
    New-Item -ItemType Directory -Force -Path $runtime | Out-Null
    Copy-Item -LiteralPath $node -Destination (Join-Path $runtime 'node.exe')
    $licenses = Join-Path $releaseRoot 'licenses'
    & $Python desktop/collect_notices.py $licenses
    if ($LASTEXITCODE -ne 0) { throw 'Python license collection failed.' }
    New-Item -ItemType Directory -Force -Path (Join-Path $licenses 'node'), (Join-Path $licenses 'python'), (Join-Path $licenses 'bruno'), (Join-Path $licenses 'webview2'), (Join-Path $licenses 'dotnet') | Out-Null
    $nodeLicense = Join-Path $projectRoot 'desktop/licenses/Node-25.2.1-LICENSE.txt'
    if ((Get-FileHash -LiteralPath $nodeLicense -Algorithm SHA256).Hash -ne '537308465103a306d0e3eecf42632b4ff1b48aaaec044e9fc10a78c81fd00b34') { throw 'Pinned Node.js license checksum mismatch.' }
    Copy-Item -LiteralPath $nodeLicense -Destination (Join-Path $licenses 'node/LICENSE')
    Copy-Item -LiteralPath (Join-Path $toolRoot 'dotnet/LICENSE.txt'), (Join-Path $toolRoot 'dotnet/ThirdPartyNotices.txt') -Destination (Join-Path $licenses 'dotnet')
    $pythonBase = & $Python -c 'import sys; print(sys.base_prefix)'
    Copy-Item -LiteralPath (Join-Path $pythonBase 'LICENSE.txt') -Destination (Join-Path $licenses 'python/LICENSE.txt')
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'namazu/bruno_node') -File | Where-Object { $_.Name -match '(?i)license|notice' } | Copy-Item -Destination (Join-Path $licenses 'bruno')
    Get-ChildItem -LiteralPath (Join-Path $env:NUGET_PACKAGES 'microsoft.web.webview2/1.0.4258.31') -File | Where-Object { $_.Name -match '(?i)license|notice' } | Copy-Item -Destination (Join-Path $licenses 'webview2')
    Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination $releaseRoot
    Copy-Item -LiteralPath (Join-Path $projectRoot 'desktop/THIRD-PARTY-NOTICES.md') -Destination $releaseRoot
    Copy-Item -LiteralPath (Join-Path $projectRoot 'desktop/requirements-build.lock.txt') -Destination $releaseRoot
    $manifest = @{ application='Namazu'; version='0.1.0'; build_id=$buildId; platform='win-x64'; sdk=$sdkVersion; webview2_sdk='1.0.4258.31'; node='25.2.1'; pyinstaller='6.19.0'; source_revision=(& git rev-parse HEAD); created_at=(Get-Date).ToUniversalTime().ToString('o') }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $releaseRoot 'build-manifest.json') -Encoding UTF8
    & $Python desktop/release_manifest.py artifact $releaseRoot (Join-Path $buildRoot 'source-inputs.json')
    if ($LASTEXITCODE -ne 0) { throw 'Release content validation failed.' }
    if (-not $SkipArchive) { Compress-Archive -LiteralPath $releaseRoot -DestinationPath ($releaseRoot + '.zip') -CompressionLevel Optimal }
    @{ folder=$releaseRoot; executable=(Join-Path $releaseRoot 'Namazu.exe'); archive=($releaseRoot + '.zip') } | ConvertTo-Json
} finally { Pop-Location }
