# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Bump the AsymCred version in CMakeLists.txt.
.DESCRIPTION
    Updates the one place that carries the project version:
      * CMakeLists.txt - project(asymcred VERSION x.y.z ...)

    That is deliberately the *only* place. Nothing else in the repo
    encodes the library version: there is no package manifest, and
    card/build.xml's `version="1.1"` is the PKOC applet's CAP package
    version — a property of the standard the applet implements, not of
    this library — so this script must never touch it.

    No pre-release suffixes. CMake's project() VERSION accepts only
    numeric MAJOR.MINOR.PATCH and errors on `0.2.0-rc.1`, and AsymCred
    has no second manifest (OSDP-Embedded keeps the full SemVer in
    rust/Cargo.toml) to hold the suffix. Rather than record a version
    that disagrees with the tag, or park the real string in a variable
    nothing reads, pre-releases are simply not used here. If AsymCred
    ever needs them, add the canonical string somewhere the build
    actually consumes it and teach Get-Version.ps1 to prefer it.
.PARAMETER Version
    The new version, numeric SemVer: MAJOR.MINOR.PATCH. Required.
.PARAMETER DryRun
    Print what would change without writing anything.
.EXAMPLE
    ./scripts/Set-Version.ps1 -Version 0.2.0
.EXAMPLE
    ./scripts/Set-Version.ps1 -Version 0.2.0 -DryRun
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [switch]$DryRun = $false
)

$ErrorActionPreference = 'Stop'

# Numeric SemVer only — see the .DESCRIPTION note above. The message
# names the constraint rather than just rejecting, so the next person
# does not have to read this file to find out why.
if ($Version -match '^\d+\.\d+\.\d+-') {
    throw ("Pre-release versions are not supported in this repo: '$Version'. " +
           "CMake's project() VERSION accepts only MAJOR.MINOR.PATCH, and " +
           "CMakeLists.txt is AsymCred's only version record. Use a plain " +
           "numeric version.")
}
if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)$') {
    throw "Invalid version: '$Version'. Expected numeric SemVer like '0.2.0'."
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

# Update a single line inside `Path` matched by predicate `LineMatches`.
# `Replacement` is invoked with the matched line and returns the new
# text. Errors if zero or more than one line matches — we want each bump
# to touch exactly one place per file, so a refactor that adds a second
# candidate line fails loudly instead of silently updating the wrong one.
function Update-Lines {
    param(
        [string]      $Path,
        [scriptblock] $LineMatches,
        [scriptblock] $Replacement,
        [string]      $Description
    )
    $full = Join-Path $repoRoot $Path
    if (-not (Test-Path $full)) { throw "Not found: $full" }

    $lines = Get-Content $full
    $matchIndices = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if (& $LineMatches $lines[$i] $i) { $matchIndices += $i }
    }
    if ($matchIndices.Count -eq 0) {
        throw "$Path : no line matched ($Description)"
    }
    if ($matchIndices.Count -gt 1) {
        throw "$Path : ambiguous - $($matchIndices.Count) lines matched ($Description)"
    }
    $i = $matchIndices[0]
    $newLine = & $Replacement $lines[$i]
    if ($newLine -eq $lines[$i]) {
        Write-Host "  (no change) $Path - $Description" -ForegroundColor DarkGray
        return
    }

    if ($DryRun) {
        Write-Host "  [dry-run]   $Path - $Description" -ForegroundColor Cyan
        Write-Host "              - $($lines[$i])" -ForegroundColor DarkGray
        Write-Host "              + $newLine"      -ForegroundColor Cyan
    }
    else {
        $lines[$i] = $newLine
        Set-Content -Path $full -Value $lines
        Write-Host "  updated     $Path - $Description" -ForegroundColor Green
    }
}

Write-Host "Setting version to: $Version" -ForegroundColor Yellow
if ($DryRun) {
    Write-Host '(dry run - no files will be modified)' -ForegroundColor Cyan
}

# CMakeLists.txt - the `VERSION x.y.z` line inside project(). Anchored to
# a line that is *only* a VERSION clause so `cmake_minimum_required(
# VERSION 3.16)` cannot match: that line has text before VERSION.
Update-Lines `
    -Path 'CMakeLists.txt' `
    -LineMatches {
        param($line)
        $code = ($line -split '#', 2)[0].Trim()
        return ($code -match '^VERSION\s+\d+\.\d+\.\d+$')
    } `
    -Replacement {
        param($line)
        [regex]::Replace($line, '(VERSION\s+)\d+\.\d+\.\d+', ('${1}' + $Version))
    } `
    -Description 'project() VERSION'

if ($DryRun) {
    Write-Host "`nDry run complete. Re-run without -DryRun to apply." -ForegroundColor Cyan
}
else {
    Write-Host "`nVersion bumped to $Version. Next steps:" -ForegroundColor Yellow
    Write-Host '  git add CMakeLists.txt'
    Write-Host "  git commit -m `"Bump version to $Version`""
    Write-Host "  git tag v$Version"
    Write-Host "  git push origin main && git push origin v$Version"
    Write-Host ''
    Write-Host '  (scripts/New-Release.ps1 does all of the above for you.)' -ForegroundColor DarkGray
}
