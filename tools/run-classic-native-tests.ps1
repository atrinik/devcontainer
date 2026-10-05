# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
$ErrorActionPreference = 'Stop'
$bundle = $PSScriptRoot
$env:PATH = "${bundle};${env:PATH}"
$inventory = Get-Content -Raw (Join-Path $bundle 'classic-check-toolchain.json') | ConvertFrom-Json
$tests = $inventory.verification.native_tests
if ($tests.Count -ne 8) { throw 'Expected eight declared native tests' }

function Invoke-QualifiedNativeTest {
    param([string]$Executable, [string[]]$Arguments, [int]$TimeoutMs)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $bundle $Executable
    $start.WorkingDirectory = $bundle
    $start.UseShellExecute = $false
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit($TimeoutMs)) {
            $process.Kill($true)
            [void]$process.WaitForExit(5000)
            throw "$Executable exceeded its ${TimeoutMs}-ms qualification deadline"
        }
        if ($process.ExitCode -ne 0) { throw "$Executable failed: $($process.ExitCode)" }
    } finally {
        $process.Dispose()
    }
}

foreach ($test in $tests) {
    $arguments = @($test.arguments | ForEach-Object {
        if ([IO.Path]::IsPathRooted($_) -or $_ -like '../*' -or $_ -like '..\*') {
            throw "Unsafe native-test argument: $_"
        }
        Join-Path $bundle $_
    })
    $limit = if ($test.executable -eq 'atrinik-curl-cancellation-probe.exe') { 15000 } else { 60000 }
    Invoke-QualifiedNativeTest $test.executable $arguments $limit
}

$ca = Join-Path $bundle 'ca-bundle.crt'
$expected = $inventory.verification.public_ca.sha256
if ((Get-FileHash -Algorithm SHA256 $ca).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Public CA bundle does not match the pinned Classic consumer'
}
if ($inventory.verification.public_ca.endpoint -ne 'https://curl.se/') {
    throw 'Unexpected public TLS qualification endpoint'
}
Invoke-QualifiedNativeTest 'atrinik-curl-cancellation-probe.exe' @('--public-ca', $ca, 'https://curl.se/') 15000
