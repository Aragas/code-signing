<#
.SYNOPSIS
  Discovers files within an artifact that match patterns configured in config.json and outputs their paths for SignTool.

.DESCRIPTION
  Evaluates file patterns relative to the artifact root using forward slashes ('/').
  The '*' and '?' wildcards match any character sequence, including directory separators.

  Patterns formatted as "<package>!<entry>" target files embedded inside NuGet packages:
  '<package>' matches '.nupkg' files in the artifact, and '<entry>' matches files within them.
  Matching files are extracted to a temporary working directory for signing, and Update-SignedPackages.ps1
  repackages them after signing completes.

  Every pattern must match at least one file to ensure renamed or relocated binaries are not silently skipped.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$PatternsJson,
    [Parameter(Mandatory)][string]$WorkFolder
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression

$root = (Resolve-Path $Root).Path
$patterns = @($PatternsJson | ConvertFrom-Json)
if ($patterns.Count -eq 0) { throw "No file patterns were provided." }
New-Item -ItemType Directory -Path $WorkFolder -Force | Out-Null

$all = @(Get-ChildItem -Path $root -Recurse -File | ForEach-Object {
    [pscustomobject]@{ Path = $_.FullName; Relative = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/') }
})
$files = [System.Collections.Generic.List[string]]::new()
$entries = [System.Collections.Generic.List[object]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

foreach ($pattern in $patterns) {
    $parts = $pattern.Replace('\', '/') -split '!', 2
    $matched = 0

    if ($parts.Count -eq 1) {
        foreach ($file in ($all | Where-Object { $_.Relative -like $parts[0] })) {
            $matched++
            if ($seen.Add($file.Path)) {
                $files.Add($file.Path)
                Write-Host "Found file to sign: $($file.Relative)"
            }
        }
    } else {
        $packages = $all | Where-Object { $_.Relative -like $parts[0] -and $_.Relative.EndsWith('.nupkg', [StringComparison]::OrdinalIgnoreCase) }
        foreach ($package in $packages) {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($package.Path)
            try {
                foreach ($zipEntry in ($zip.Entries | Where-Object { $_.Length -gt 0 -and $_.FullName -like $parts[1] })) {
                    $matched++
                    $key = "$($package.Path)!$($zipEntry.FullName)"
                    if (-not $seen.Add($key)) { continue }

                    $extracted = Join-Path $WorkFolder ([string]$entries.Count) $zipEntry.FullName
                    New-Item -ItemType Directory -Path (Split-Path $extracted -Parent) -Force | Out-Null
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($zipEntry, $extracted)
                    $files.Add($extracted)
                    $entries.Add([pscustomobject]@{ Package = $package.Path; Entry = $zipEntry.FullName; File = $extracted })
                    Write-Host "Found package entry to sign: $($zipEntry.FullName) (in $($package.Relative))"
                }
            } finally {
                $zip.Dispose()
            }
        }
    }

    if ($matched -eq 0) { throw "No files in the artifact matched pattern '$pattern'." }
}

$list = Join-Path $WorkFolder 'files.txt'
$map = Join-Path $WorkFolder 'packages.json'
Set-Content -Path $list -Value $files
ConvertTo-Json -InputObject @($entries) -Depth 3 | Set-Content -Path $map
if ($env:GITHUB_OUTPUT) {
    "list=$list" >> $env:GITHUB_OUTPUT
    "map=$map" >> $env:GITHUB_OUTPUT
}
