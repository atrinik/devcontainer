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

# Check the same DLL whose private callback/flag RVAs are compiled into the probe.
$glib = Get-Content -Raw (Join-Path $bundle 'glib-tls.json') | ConvertFrom-Json
$glibHash = (Get-FileHash -Algorithm SHA256 (Join-Path $bundle 'libglib-2.0-0.dll')).Hash.ToLowerInvariant()
if ($glib.schema_version -ne 1 -or $glib.dll -ne 'libglib-2.0-0.dll' -or $glibHash -ne $glib.sha256) {
    throw 'GLib TLS probe does not match the staged DLL'
}
$probeHash = (Get-FileHash -Algorithm SHA256 (Join-Path $bundle 'atrinik-glib-tls-probe.exe')).Hash.ToLowerInvariant()
if ($probeHash -ne $glib.probe_sha256) { throw 'GLib TLS probe executable differs from its producer receipt' }
$glibStart = [Diagnostics.ProcessStartInfo]::new()
$glibStart.FileName = Join-Path $bundle 'atrinik-glib-tls-probe.exe'
$glibStart.WorkingDirectory = $bundle
$glibStart.UseShellExecute = $false
$glibStart.RedirectStandardOutput = $true
$glibStart.RedirectStandardError = $true
$glibStart.Environment['G_DEBUG'] = 'fatal-criticals'
$glibProcess = [Diagnostics.Process]::Start($glibStart)
try {
    Write-Host "GLib TLS qualification pid=$($glibProcess.Id) dll_sha256=$glibHash"
    $stdout = $glibProcess.StandardOutput.ReadToEndAsync()
    $stderr = $glibProcess.StandardError.ReadToEndAsync()
    $timedOut = -not $glibProcess.WaitForExit(15000)
    if ($timedOut) {
        $glibProcess.Kill($true)
        if (-not $glibProcess.WaitForExit(5000)) { throw 'GLib TLS probe did not stop after timeout' }
    }
    $out = $stdout.GetAwaiter().GetResult()
    $err = $stderr.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $bundle 'glib-tls.stdout.log'), $out)
    [IO.File]::WriteAllText((Join-Path $bundle 'glib-tls.stderr.log'), $err)
    Write-Host $out
    if ($err) { Write-Host $err }
    if ($timedOut) { throw 'GLib TLS probe exceeded 15000 ms' }
    if ($glibProcess.ExitCode -ne 0) { throw "GLib TLS probe failed: $($glibProcess.ExitCode)" }
    if ($out -notmatch 'process_attach_invoked=1 private_destructors=1 explicit_unload=1' -or $err) {
        throw 'GLib TLS callback/destructor/unload evidence is incomplete or emitted diagnostics'
    }
} finally {
    $glibProcess.Dispose()
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
