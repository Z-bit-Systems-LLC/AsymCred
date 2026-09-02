# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Print the AsymCred version from CMakeLists.txt.
.DESCRIPTION
    Z-bit Systems' release workflow keeps a canonical project version in
    one place per repo. OSDP-Embedded uses `rust/Cargo.toml`; AsymCred
    has no Rust half, so the canonical version is the top-level
    CMakeLists.txt's `project(asymcred VERSION x.y.z ...)`. This script
    reads and prints it; pair with Set-Version.ps1 to bump.

    Note that CMake's project() VERSION accepts only numeric
    MAJOR.MINOR.PATCH — it rejects SemVer pre-release suffixes like
    `-rc.1`. AsymCred therefore does not use pre-release versions; see
    Set-Version.ps1 for the full reasoning.
.PARAMETER Format
    'Simple'   - version string only (default; useful in CI / scripts)
    'Detailed' - labelled, colored output for interactive use, including
                 how the version compares with the newest git tag.
.EXAMPLE
    ./scripts/Get-Version.ps1
    0.1.0
.EXAMPLE
    ./scripts/Get-Version.ps1 -Format Detailed
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Simple', 'Detailed')]
    [string]$Format = 'Simple'
)

$ErrorActionPreference = 'Stop'

# Resolve repo root (script lives in <repo>/scripts/). Chain Join-Path
# calls — Windows PowerShell 5.1 only accepts a single ChildPath
# argument per call.
$repoRoot   = Resolve-Path (Join-Path $PSScriptRoot '..')
$cmakeLists = Join-Path $repoRoot 'CMakeLists.txt'

if (-not (Test-Path $cmakeLists)) {
    throw "CMakeLists.txt not found at: $cmakeLists"
}

# Walk the file line by line looking for the project() VERSION line,
# stopping at the first match. Comments are stripped first so a `#`
# comment mentioning a version can never be picked up. A single regex
# over the whole file would have to special-case that.
$lines   = Get-Content $cmakeLists
$version = $null
foreach ($raw in $lines) {
    $code = ($raw -split '#', 2)[0].Trim()
    if ($code -match '^VERSION\s+(\d+\.\d+\.\d+)\s*$') {
        $version = $Matches[1]
        break
    }
}

if (-not $version) {
    throw "Could not find a project() VERSION line in $cmakeLists"
}

if ($Format -eq 'Simple') {
    Write-Output $version
    return
}

Write-Host 'AsymCred version: ' -NoNewline -ForegroundColor Yellow
Write-Host $version -ForegroundColor Green

# Interactive extra: say whether this version has been tagged yet, which
# is the question you are actually asking when you run this by hand
# before cutting a release.
Push-Location $repoRoot
try {
    & git rev-parse --verify --quiet "refs/tags/v$version" *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  tag v$version exists" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  tag v$version does NOT exist yet" -ForegroundColor DarkYellow
    }

    $newest = (& git describe --tags --abbrev=0 2>$null)
    if ($LASTEXITCODE -eq 0 -and $newest) {
        Write-Host "  newest tag reachable from HEAD: $(($newest | Out-String).Trim())" -ForegroundColor DarkGray
    }
    else {
        Write-Host '  no tags in this repository yet' -ForegroundColor DarkGray
    }

    # The git probes above are expected to fail on an untagged repo.
    # Reset so this script's own exit status reflects "the version was
    # read successfully", not the last incidental git call.
    $global:LASTEXITCODE = 0
}
finally {
    Pop-Location
}
