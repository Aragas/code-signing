<#
.SYNOPSIS
  Adds an author-signed copy of every NuGet package in an artifact, for GitHub Packages.

.DESCRIPTION
  nuget.org only accepts author-signed packages once the certificate is registered with the publishing account, and
  then requires it for every package that account pushes. So the packages themselves stay without a package signature
  for nuget.org, and each <folder>/<package>.nupkg gets a copy at <folder>/package-signed/<package>.nupkg with one, for GPR.
  Runs after the binaries inside the packages are signed, the package signature covers them.
  The certificate is read from the store SimplySign Desktop registered it in.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Thumbprint,
    [string]$Timestamper = 'http://time.certum.pl'
)

$ErrorActionPreference = 'Stop'

$packages = @(Get-ChildItem -Path $Root -Recurse -File |
    Where-Object { $_.Extension -eq '.nupkg' -and $_.Directory.Name -ne 'package-signed' })
if ($packages.Count -eq 0) {
    Write-Host "No NuGet packages to sign."
    return
}

$certificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1
if (-not $certificate) { throw "Certificate $Thumbprint was not found in Cert:\CurrentUser\My." }

# .NET 9 and later take a SHA-2 fingerprint (.NET 10 refuses SHA-1), earlier SDKs only SHA-1
$sdkMajor = [int]((dotnet --version).Split('.')[0])
$fingerprint = if ($sdkMajor -ge 9) { $certificate.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256) } else { $certificate.Thumbprint }
Write-Host "Signing packages with .NET SDK $sdkMajor and fingerprint $fingerprint."

$copies = foreach ($package in $packages) {
    $folder = Join-Path $package.DirectoryName 'package-signed'
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $copy = Join-Path $folder $package.Name
    Copy-Item -Path $package.FullName -Destination $copy -Force
    $copy
}

foreach ($copy in $copies) {
    dotnet nuget sign $copy --certificate-fingerprint $fingerprint --certificate-store-location CurrentUser --certificate-store-name My --hash-algorithm SHA256 --timestamper $Timestamper --timestamp-hash-algorithm SHA256 --overwrite
    if ($LASTEXITCODE -ne 0) { throw "dotnet nuget sign failed for $copy." }

    dotnet nuget verify $copy --all
    if ($LASTEXITCODE -ne 0) { throw "dotnet nuget verify failed for $copy." }
    Write-Host "Signed package copy: $copy"
}
