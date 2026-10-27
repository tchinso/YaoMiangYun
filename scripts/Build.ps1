param([string]$Dotnet = 'dotnet', [switch]$SkipFetch)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (!$SkipFetch) { & (Join-Path $PSScriptRoot 'Fetch-Core.ps1') }
& $Dotnet build (Join-Path $root 'tests/YaoVpn.Tests/YaoVpn.Tests.csproj') -c Release
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
& $Dotnet run --project (Join-Path $root 'tests/YaoVpn.Tests/YaoVpn.Tests.csproj') -c Release --no-build
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
& $Dotnet publish (Join-Path $root 'src/YaoVpn.App/YaoVpn.App.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o (Join-Path $root 'artifacts/YaoVPN')
if ($LASTEXITCODE -ne 0) { throw 'Publish failed' }
Copy-Item -LiteralPath (Join-Path $root 'README.md'),(Join-Path $root 'SECURITY.md'),(Join-Path $root 'THIRD-PARTY-NOTICES.md'),(Join-Path $root 'LICENSE') -Destination (Join-Path $root 'artifacts/YaoVPN')
Write-Output 'Ready: artifacts/YaoVPN/YaoVPN.exe'
