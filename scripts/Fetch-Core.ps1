#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Update these pins together only after checking the official release checksums.
$CoreVersion = '1.14.4'
$ArchiveUri = [uri]'https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip'
$ArchiveSha256 = '99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df'
$LicenseUri = [uri]'https://raw.githubusercontent.com/SagerNet/sing-box/v1.14.4/LICENSE'
$LicenseSha256 = '650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c'
$ExpectedEntry = 'sing-box-1.14.4-windows-amd64/sing-box.exe'
$RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$RuntimeDirectory = Join-Path $RepositoryRoot 'runtime'
$Destination = Join-Path $RuntimeDirectory 'sing-box.exe'
$LicenseDestination = Join-Path $RuntimeDirectory 'LICENSE.sing-box.txt'

function Assert-NotReparsePoint([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        if (((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing reparse point: $Path"
        }
    }
}

function Assert-Sha256([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if (-not [string]::Equals($actual, $Expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "SHA-256 verification failed for $([IO.Path]::GetFileName($Path))."
    }
}

function Receive-PinnedFile([uri]$Uri, [string]$Path, [long]$MaximumBytes) {
    # Follow only HTTPS redirects to official GitHub download infrastructure.
    $allowedHosts = @('github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com', 'raw.githubusercontent.com')
    $currentUri = $Uri
    for ($redirect = 0; $redirect -le 5; $redirect++) {
        if ($currentUri.Scheme -ne 'https' -or -not $currentUri.IsDefaultPort -or
            $currentUri.UserInfo -ne '' -or $allowedHosts -notcontains $currentUri.DnsSafeHost) {
            throw 'Download redirected outside the permitted HTTPS hosts.'
        }
        $response = $null
        try {
            $response = $script:HttpClient.GetAsync($currentUri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            $status = [int]$response.StatusCode
            if ($status -in @(301, 302, 303, 307, 308)) {
                if ($null -eq $response.Headers.Location -or $redirect -eq 5) {
                    throw 'Invalid or excessive download redirects.'
                }
                $currentUri = [uri]::new($currentUri, $response.Headers.Location)
                continue
            }
            $response.EnsureSuccessStatusCode() | Out-Null
            if ($null -ne $response.Content.Headers.ContentLength -and $response.Content.Headers.ContentLength -gt $MaximumBytes) {
                throw 'Download exceeds its size limit.'
            }
            $inputStream = $null
            $outputStream = $null
            try {
                $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $outputStream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $buffer = New-Object byte[] 81920
                [long]$total = 0
                while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $total += $read
                    if ($total -gt $MaximumBytes) { throw 'Download exceeds its size limit.' }
                    $outputStream.Write($buffer, 0, $read)
                }
                if ($total -eq 0) { throw 'Empty download.' }
            }
            finally {
                if ($null -ne $outputStream) { $outputStream.Dispose() }
                if ($null -ne $inputStream) { $inputStream.Dispose() }
            }
            return
        }
        finally {
            if ($null -ne $response) { $response.Dispose() }
        }
    }
}

function Install-VerifiedFile([string]$Source, [string]$Target) {
    Assert-NotReparsePoint $Target
    if ([IO.File]::Exists($Target)) {
        # Windows PowerShell otherwise binds $null to an invalid empty backup path.
        [IO.File]::Replace($Source, $Target, [NullString]::Value)
    }
    else {
        [IO.File]::Move($Source, $Target)
    }
}

Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Assert-NotReparsePoint $RuntimeDirectory
[IO.Directory]::CreateDirectory($RuntimeDirectory) | Out-Null
Assert-NotReparsePoint $Destination
Assert-NotReparsePoint $LicenseDestination
$downloadId = [guid]::NewGuid().ToString('N')
$archivePath = Join-Path $RuntimeDirectory ('.download-' + $downloadId + '.zip')
$binaryPath = Join-Path $RuntimeDirectory ('.download-' + $downloadId + '.exe')
$licensePath = Join-Path $RuntimeDirectory ('.download-' + $downloadId + '.license')
$handler = New-Object Net.Http.HttpClientHandler
$handler.AllowAutoRedirect = $false
$script:HttpClient = New-Object Net.Http.HttpClient($handler)
$script:HttpClient.Timeout = [TimeSpan]::FromMinutes(3)
$script:HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd('YaoMiangYun-CoreFetcher/1.0')

try {
    Receive-PinnedFile $ArchiveUri $archivePath (100MB)
    Assert-Sha256 $archivePath $ArchiveSha256
    Receive-PinnedFile $LicenseUri $licensePath (1MB)
    Assert-Sha256 $licensePath $LicenseSha256

    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $executableEntry = $null
        foreach ($entry in $archive.Entries) {
            # No archive-provided path is ever passed to a filesystem extraction API.
            $name = $entry.FullName
            if ([IO.Path]::IsPathRooted($name) -or $name.Contains('\') -or $name.Contains(':') -or
                $name.IndexOf([char]0) -ge 0 -or @($name.Split('/') | Where-Object { $_ -eq '..' -or $_ -eq '.' }).Count -gt 0) {
                throw 'Unsafe path in verified archive.'
            }
            $unixType = ($entry.ExternalAttributes -shr 16) -band 0xF000
            if ($unixType -eq 0xA000) { throw 'Symbolic link in archive.' }
            if ([string]::Equals($name, $ExpectedEntry, [StringComparison]::Ordinal)) {
                if ($null -ne $executableEntry) { throw 'Duplicate executable in archive.' }
                $executableEntry = $entry
            }
        }
        if ($null -eq $executableEntry -or $executableEntry.Length -le 0 -or $executableEntry.Length -gt 100MB) {
            throw 'Expected executable is absent or has an invalid size.'
        }
        $inputStream = $null
        $outputStream = $null
        try {
            $inputStream = $executableEntry.Open()
            $outputStream = [IO.File]::Open($binaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $inputStream.CopyTo($outputStream)
        }
        finally {
            if ($null -ne $outputStream) { $outputStream.Dispose() }
            if ($null -ne $inputStream) { $inputStream.Dispose() }
        }
    }
    finally { $archive.Dispose() }

    Install-VerifiedFile $licensePath $LicenseDestination
    Install-VerifiedFile $binaryPath $Destination
    Write-Output "Installed official sing-box $CoreVersion (windows-amd64)."
    Write-Output ('Executable SHA-256: ' + (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant())
}
finally {
    $script:HttpClient.Dispose()
    $handler.Dispose()
    # Delete only the three exact temporary file names created by this invocation.
    foreach ($temporaryFile in @($archivePath, $binaryPath, $licensePath)) {
        if ([IO.File]::Exists($temporaryFile)) { [IO.File]::Delete($temporaryFile) }
    }
}
