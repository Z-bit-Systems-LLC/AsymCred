# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Run every pre-push quality gate locally — the checks CI enforces.
.DESCRIPTION
    Mirrors ci/azure-pipelines.yml so a clean run here means the Azure
    pipeline should pass. Gates:

      Release (the ci/build-c.yml gate)
        1. cmake --preset release   (warnings = errors)
        2. cmake --build --preset release
        3. ctest --preset release

      Sanitizers (the ci/sanitize.yml gate)
        4. cmake --preset asan
        5. cmake --build --preset asan
        6. ctest --preset asan       (ASAN_OPTIONS/UBSAN_OPTIONS as in CI)

      Cross-compile (the ci/cross-arm64.yml gate)
        7. cmake --preset arm64      (build only; binaries are not run)
        8. cmake --build --preset arm64

    Every gate runs even if an earlier one fails (dependent steps are
    skipped, not silently passed), so one invocation surfaces all
    problems at once. The script exits non-zero if any gate failed. Run
    it by hand before pushing; New-Release.ps1 also runs it once before
    tagging a release. There is deliberately no git pre-push hook running
    it a second time.

    Platform note. CI is Linux/GCC; this script is expected to run on the
    author's Windows workstation too, where the two non-native gates
    behave differently:

      * Sanitizers. MSVC supports /fsanitize=address but not UBSan, and
        its ASan needs the clang_rt runtime DLLs resolvable at test time.
        The gate is therefore skipped on Windows by default; pass -Asan
        to attempt it anyway. On Linux it always runs.
      * Cross-compile. Skipped unless aarch64-linux-gnu-gcc is on PATH,
        which in practice means Linux. The gate is not simulated on
        Windows; CI covers it.

    So a green run on Windows is a weaker signal than a green pipeline —
    it verifies the Release gate and reports the rest as SKIP rather than
    quietly passing them.

    On Windows the C presets need a Visual Studio toolchain; the script
    locates one with vswhere and imports its environment, so a plain
    PowerShell works — a Developer PowerShell for VS is not required.
.PARAMETER SkipRelease
    Skip the Release build/test gate.
.PARAMETER SkipAsan
    Skip the sanitizer gate even where it would otherwise run.
.PARAMETER SkipCross
    Skip the aarch64 cross-compile gate.
.PARAMETER Asan
    Attempt the sanitizer gate on Windows/MSVC, where it is skipped by
    default (see the platform note above).
.EXAMPLE
    ./scripts/Check-Code.ps1
    Run all applicable gates. Use before every push.
.EXAMPLE
    ./scripts/Check-Code.ps1 -SkipCross
    Everything except the cross-compile gate.
#>

[CmdletBinding()]
param(
    [switch]$SkipRelease,
    [switch]$SkipAsan,
    [switch]$SkipCross,
    [switch]$Asan
)

# Don't let $ErrorActionPreference = 'Stop' abort the whole run on the
# first failing external tool — we want to collect every gate's result.
# Native-command failures are detected via $LASTEXITCODE instead.
$ErrorActionPreference = 'Continue'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

# $IsWindows is automatic in PowerShell 7+ but undefined in Windows
# PowerShell 5.1, where the platform is always Windows.
$onWindows = if ($null -ne $IsWindows) { $IsWindows } else { $true }

function Test-Tool {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# When cmake isn't already on PATH (i.e. we're not running from a
# "Developer PowerShell for VS"), locate a Visual Studio install and
# import its build environment so the CMake/MSVC stack can run instead of
# being skipped. cmake and cl ship *inside* Visual Studio and are absent
# from a plain shell's PATH.
#
# This deliberately does NOT short-circuit just because `cmake` already
# resolves. An enclosing shell can reorder PATH such that `cmake`
# resolves fine while `link` resolves to something else entirely (git's
# bundled MSYS2 sh does exactly that — its coreutils `link` shadows
# MSVC's linker), producing a confusing link failure instead of a clean
# skip or pass. So always locate VS and re-prepend its tool dirs; only
# fall back to trusting an already-correct PATH when VS genuinely can't
# be found. Lifted from OSDP-Embedded's Check-Code.ps1, which learned
# this the hard way.
function Initialize-VsToolchain {
    if (-not $onWindows) { return [bool](Test-Tool 'cmake') }

    $vsRoot = $null
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $vsRoot = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null | Select-Object -First 1
    }
    if (-not $vsRoot) {
        foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if (-not $pf) { continue }
            $base = Join-Path $pf 'Microsoft Visual Studio'
            if (-not (Test-Path $base)) { continue }
            $hit = Get-ChildItem $base -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending |
                ForEach-Object { Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue } |
                Where-Object { Test-Path (Join-Path $_.FullName 'VC\Auxiliary\Build\vcvars64.bat') } |
                Select-Object -First 1
            if ($hit) { $vsRoot = $hit.FullName; break }
        }
    }
    if (-not $vsRoot) { return [bool](Test-Tool 'cmake') }

    $vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path $vcvars)) { return [bool](Test-Tool 'cmake') }

    # Import the environment vcvars64 produces (PATH, INCLUDE, LIB, ...)
    # into this process — the standard "source vcvars into PowerShell"
    # trick: run it in cmd, dump `set`, and copy each variable across.
    cmd /c "`"$vcvars`" >nul 2>&1 && set" 2>$null | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }

    # Belt and suspenders: vcvars has been seen to set INCLUDE/LIB but
    # leave cmake/cl/rc off PATH. Prepend the bundled cmake and the
    # newest MSVC toolset / Windows SDK tool dirs so the executables
    # resolve regardless. Newest dir wins, so a VS update needs no edit
    # here.
    $extra = @()
    foreach ($rel in @(
        'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin',
        'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja')) {
        $b = Join-Path $vsRoot $rel
        if (Test-Path $b) { $extra += $b }
    }

    $msvcRoot = Join-Path $vsRoot 'VC\Tools\MSVC'
    if (Test-Path $msvcRoot) {
        $ts = Get-ChildItem $msvcRoot -Directory -ErrorAction SilentlyContinue |
              Sort-Object Name -Descending | Select-Object -First 1
        if ($ts) {
            $b = Join-Path $ts.FullName 'bin\Hostx64\x64'
            if (Test-Path $b) { $extra += $b }
        }
    }

    foreach ($pf in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if (-not $pf) { continue }
        $sdkRoot = Join-Path $pf 'Windows Kits\10\bin'
        if (-not (Test-Path $sdkRoot)) { continue }
        $sdk = Get-ChildItem $sdkRoot -Directory -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -match '^\d+\.' -and (Test-Path (Join-Path $_.FullName 'x64\rc.exe')) } |
               Sort-Object Name -Descending | Select-Object -First 1
        if ($sdk) { $extra += (Join-Path $sdk.FullName 'x64'); break }
    }

    if ($extra.Count) { $env:Path = ($extra -join ';') + ';' + $env:Path }

    return [bool](Test-Tool 'cmake')
}

# Results accumulator. Each entry: @{ Name; Status } where Status is one
# of 'pass', 'fail', 'skip'.
$results = [System.Collections.Generic.List[object]]::new()

function Write-Header {
    param([string]$Text)
    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Cyan
}

# Run one gate. $Action invokes a native tool; success is judged by
# $LASTEXITCODE being 0. A non-zero exit or a thrown exception counts as
# failure. Returns $true on pass so callers can gate dependent steps.
function Invoke-Gate {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Header $Name
    $global:LASTEXITCODE = 0
    $ok = $true
    try {
        & $Action
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    }
    catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
        $ok = $false
    }
    if ($ok) {
        Write-Host "    [PASS] $Name" -ForegroundColor Green
        $results.Add([pscustomobject]@{ Name = $Name; Status = 'pass' })
    }
    else {
        Write-Host "    [FAIL] $Name" -ForegroundColor Red
        $results.Add([pscustomobject]@{ Name = $Name; Status = 'fail' })
    }
    return $ok
}

function Skip-Gate {
    param([Parameter(Mandatory)][string]$Name, [string]$Reason)
    Write-Header $Name
    Write-Host "    [SKIP] $Name - $Reason" -ForegroundColor DarkYellow
    $results.Add([pscustomobject]@{ Name = $Name; Status = 'skip' })
}

Push-Location $repoRoot
try {
    $haveCmake = Initialize-VsToolchain

    # ---- Release gate (mirrors ci/build-c.yml) -----------------------
    #
    # The `release` preset sets CMAKE_BUILD_TYPE=Release with
    # ASYMCRED_BUILD_TESTS=ON and ASYMCRED_WERROR=ON — the same
    # configuration CI builds.
    if ($SkipRelease) {
        Skip-Gate 'Release build + tests' '-SkipRelease was passed'
    }
    elseif (-not $haveCmake) {
        Skip-Gate 'Release build + tests' 'cmake not found - install CMake, or (on Windows) Visual Studio with the C++ workload'
    }
    else {
        $configured = Invoke-Gate 'CMake configure (release preset)' {
            cmake --preset release
        }
        if ($configured) {
            $built = Invoke-Gate 'CMake build (release preset)' {
                cmake --build --preset release
            }
            if ($built) {
                Invoke-Gate 'CTest (release preset)' {
                    ctest --preset release
                } | Out-Null
            }
            else {
                Skip-Gate 'CTest (release preset)' 'build failed'
            }
        }
        else {
            Skip-Gate 'CMake build (release preset)' 'configure failed'
            Skip-Gate 'CTest (release preset)'       'configure failed'
        }
    }

    # ---- Sanitizer gate (mirrors ci/sanitize.yml) --------------------
    if ($SkipAsan) {
        Skip-Gate 'Sanitizer build + tests' '-SkipAsan was passed'
    }
    elseif (-not $haveCmake) {
        Skip-Gate 'Sanitizer build + tests' 'cmake not found'
    }
    elseif ($onWindows -and -not $Asan) {
        Skip-Gate 'Sanitizer build + tests' 'skipped on Windows/MSVC (no UBSan; ASan needs the clang_rt runtime on PATH) - pass -Asan to try anyway. CI runs this gate on Linux.'
    }
    else {
        $configured = Invoke-Gate 'CMake configure (asan preset)' {
            cmake --preset asan
        }
        if ($configured) {
            $built = Invoke-Gate 'CMake build (asan preset)' {
                cmake --build --preset asan
            }
            if ($built) {
                Invoke-Gate 'CTest (asan preset)' {
                    # Same options CI uses, so a finding fails here the
                    # way it would there rather than being printed and
                    # walked past.
                    # detect_leaks=0 matches CI; see ci/sanitize.yml for
                    # why (LSan needs ptrace, which the LXC agents deny,
                    # and this library allocates nothing anyway).
                    $env:ASAN_OPTIONS  = 'abort_on_error=1:halt_on_error=1:detect_leaks=0:print_stacktrace=1'
                    $env:UBSAN_OPTIONS = 'print_stacktrace=1:halt_on_error=1'
                    try {
                        ctest --preset asan
                    }
                    finally {
                        Remove-Item Env:ASAN_OPTIONS  -ErrorAction SilentlyContinue
                        Remove-Item Env:UBSAN_OPTIONS -ErrorAction SilentlyContinue
                    }
                } | Out-Null
            }
            else {
                Skip-Gate 'CTest (asan preset)' 'build failed'
            }
        }
        else {
            Skip-Gate 'CMake build (asan preset)' 'configure failed'
            Skip-Gate 'CTest (asan preset)'       'configure failed'
        }
    }

    # ---- Cross-compile gate (mirrors ci/cross-arm64.yml) -------------
    #
    # Build only: an x86_64 workstation cannot run the aarch64 binaries,
    # exactly as on the CI agent.
    if ($SkipCross) {
        Skip-Gate 'Cross-compile (aarch64)' '-SkipCross was passed'
    }
    elseif (-not $haveCmake) {
        Skip-Gate 'Cross-compile (aarch64)' 'cmake not found'
    }
    elseif (-not (Test-Tool 'aarch64-linux-gnu-gcc')) {
        Skip-Gate 'Cross-compile (aarch64)' 'aarch64-linux-gnu-gcc not on PATH (apt install gcc-aarch64-linux-gnu). CI runs this gate on Linux.'
    }
    else {
        $configured = Invoke-Gate 'CMake configure (arm64 preset)' {
            cmake --preset arm64
        }
        if ($configured) {
            Invoke-Gate 'CMake build (arm64 preset)' {
                cmake --build --preset arm64
            } | Out-Null
        }
        else {
            Skip-Gate 'CMake build (arm64 preset)' 'configure failed'
        }
    }
}
finally {
    Pop-Location
}

# ---- Summary ---------------------------------------------------------
Write-Host ''
Write-Host '==================== SUMMARY ====================' -ForegroundColor Cyan
foreach ($r in $results) {
    switch ($r.Status) {
        'pass' { Write-Host '  PASS  ' -ForegroundColor Green      -NoNewline }
        'fail' { Write-Host '  FAIL  ' -ForegroundColor Red        -NoNewline }
        'skip' { Write-Host '  SKIP  ' -ForegroundColor DarkYellow -NoNewline }
    }
    Write-Host $r.Name
}
Write-Host '================================================' -ForegroundColor Cyan

$failed  = @($results | Where-Object Status -eq 'fail').Count
$skipped = @($results | Where-Object Status -eq 'skip').Count
if ($failed -gt 0) {
    Write-Host ''
    Write-Host "$failed gate(s) failed - do not push." -ForegroundColor Red
    exit 1
}
if ($skipped -gt 0) {
    Write-Host ''
    Write-Host "All run gates passed, but $skipped were skipped - CI still covers those." -ForegroundColor DarkYellow
    exit 0
}
Write-Host ''
Write-Host 'All gates passed - safe to push.' -ForegroundColor Green
exit 0
