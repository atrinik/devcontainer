# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
$ErrorActionPreference = 'Stop'
$bundle = $PSScriptRoot
$env:PATH = "${bundle};${env:PATH}"
$inventory = Get-Content -Raw (Join-Path $bundle 'classic-check-toolchain.json') | ConvertFrom-Json
$tests = $inventory.verification.native_tests
if ($tests.Count -ne 8) { throw 'Expected eight declared native tests' }
$caresNotice = $inventory.runtime_contract.cares_license
$noticePath = Join-Path $bundle $caresNotice.bundle_name
if ((Get-FileHash -Algorithm SHA256 $noticePath).Hash.ToLowerInvariant() -ne $caresNotice.sha256) {
    throw 'c-ares license notice does not match the pinned producer'
}

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

foreach ($library in @('glib', 'cairo')) {
    $dllName = if ($library -eq 'glib') { 'libglib-2.0-0.dll' } else { 'libcairo-2.dll' }
    $probeName = "atrinik-$library-tls-probe.exe"
    # Check the same DLL whose private callback/flag RVAs are compiled into the probe.
    $tlsReceipt = Get-Content -Raw (Join-Path $bundle "$library-tls.json") | ConvertFrom-Json
    $dllHash = (Get-FileHash -Algorithm SHA256 (Join-Path $bundle $dllName)).Hash.ToLowerInvariant()
    if ($tlsReceipt.schema_version -ne 1 -or $tlsReceipt.dll -ne $dllName -or $dllHash -ne $tlsReceipt.sha256) {
        throw 'Library TLS probe does not match the staged DLL'
    }
    $probeHash = (Get-FileHash -Algorithm SHA256 (Join-Path $bundle $probeName)).Hash.ToLowerInvariant()
    if ($probeHash -ne $tlsReceipt.probe_sha256) { throw "Library TLS probe executable differs from its producer receipt" }
    $probeStart = [Diagnostics.ProcessStartInfo]::new()
    $probeStart.FileName = Join-Path $bundle $probeName
    $probeStart.WorkingDirectory = $bundle
    $probeStart.UseShellExecute = $false
    $probeStart.RedirectStandardOutput = $true
    $probeStart.RedirectStandardError = $true
    $probeStart.Environment['G_DEBUG'] = 'fatal-criticals'
    $probeProcess = [Diagnostics.Process]::Start($probeStart)
    try {
        Write-Host "$library TLS qualification pid=$($probeProcess.Id) dll_sha256=$dllHash"
        $stdout = $probeProcess.StandardOutput.ReadToEndAsync()
        $stderr = $probeProcess.StandardError.ReadToEndAsync()
        $timedOut = -not $probeProcess.WaitForExit(15000)
        if ($timedOut) {
            $probeProcess.Kill($true)
            if (-not $probeProcess.WaitForExit(5000)) { throw 'Library TLS probe did not stop after timeout' }
        }
        $out = $stdout.GetAwaiter().GetResult()
        $err = $stderr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $bundle "$library-tls.stdout.log"), $out)
        [IO.File]::WriteAllText((Join-Path $bundle "$library-tls.stderr.log"), $err)
        Write-Host $out
        if ($err) { Write-Host $err }
        if ($timedOut) { throw 'Library TLS probe exceeded 15000 ms' }
        if ($probeProcess.ExitCode -ne 0) { throw "Library TLS probe failed: $($probeProcess.ExitCode)" }
        $expected = if ($library -eq 'glib') { 'process_attach_invoked=1 private_destructors=1 explicit_unload=1' } else { 'process_attach_initialized=2 surface_font_smoke=1 explicit_unload=1 reload=1' }
        if ($out -notmatch $expected -or $err) {
            throw 'Library TLS callback/destructor/unload evidence is incomplete or emitted diagnostics'
        }
    } finally {
        $probeProcess.Dispose()
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

$audio = Get-Content -Raw (Join-Path $bundle 'audio-toolchain.json') | ConvertFrom-Json
$opus = Join-Path $bundle 'opus-probe.opus'
if ((Get-FileHash -Algorithm SHA256 $opus).Hash.ToLowerInvariant() -ne $audio.fixture.sha256) {
    throw 'Opus fixture does not match the pinned audio producer'
}
Invoke-QualifiedNativeTest 'atrinik-sdl3-mixer-probe.exe' @($opus) 60000
