# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
$ErrorActionPreference = 'Stop'
$bundle = $PSScriptRoot
$metadata = Get-Content -Raw (Join-Path $bundle 'qualification.json') | ConvertFrom-Json
if ($metadata.schema_version -ne 1 -or $metadata.library -notin @('glib', 'cairo')) {
    throw 'Unsupported GLib qualification bundle'
}
foreach ($file in $metadata.files.PSObject.Properties) {
    if ([IO.Path]::IsPathRooted($file.Name) -or '..' -in ($file.Name -split '[/\\]')) {
        throw 'Unsafe GLib qualification path'
    }
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $bundle $file.Name)).Hash.ToLowerInvariant()
    if ($actual -ne $file.Value) { throw "Qualification file changed: $($file.Name)" }
}
$library = $metadata.library
$dllName = if ($library -eq 'glib') { 'libglib-2.0-0.dll' } else { 'libcairo-2.dll' }
$probeName = "atrinik-$library-tls-probe.exe"
if ($metadata.tls.dll -ne $dllName) { throw 'TLS report library mismatch' }
if ($library -eq 'cairo') {
    $glibDependency = $metadata.repaired_dependencies.glib
    if (-not $glibDependency -or $glibDependency.tls.library -ne 'glib' -or
        $glibDependency.sha256 -ne $glibDependency.tls.sha256) {
        throw 'Cairo lacks sealed repaired GLib dependency evidence'
    }
}
$results = @()
foreach ($lane in @('original', 'relinked', 'candidate')) {
    $directory = Join-Path $bundle $lane
    foreach ($name in @($probeName, $dllName)) {
        if (-not $metadata.files.PSObject.Properties["$lane/$name"]) { throw "Unsealed $lane/$name" }
    }
    $dllHash = (Get-FileHash -Algorithm SHA256 (Join-Path $directory $dllName)).Hash.ToLowerInvariant()
    if ($lane -eq 'candidate' -and $dllHash -ne $metadata.tls.sha256) { throw 'Candidate TLS report mismatch' }
    if ($library -eq 'cairo') {
        $glibPath = "$lane/libglib-2.0-0.dll"
        $sealed = $metadata.files.PSObject.Properties[$glibPath]
        if (-not $sealed -or $sealed.Value -ne $glibDependency.sha256 -or
            (Get-FileHash -Algorithm SHA256 (Join-Path $bundle $glibPath)).Hash.ToLowerInvariant() -ne $glibDependency.sha256) {
            throw 'Cairo controls must share the identical repaired GLib dependency'
        }
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $directory $probeName
    $start.WorkingDirectory = $directory
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['PATH'] = "${directory};$env:SystemRoot\System32;$env:SystemRoot"
    $start.Environment['G_DEBUG'] = 'fatal-criticals'
    $process = [Diagnostics.Process]::Start($start)
    try {
        $pidValue = $process.Id
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit(15000)
        if ($timedOut) {
            $process.Kill($true)
            if (-not $process.WaitForExit(5000)) { throw "$lane did not stop after timeout" }
        }
        $out = $stdout.GetAwaiter().GetResult()
        $err = $stderr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $bundle "$lane.stdout.txt"), $out)
        [IO.File]::WriteAllText((Join-Path $bundle "$lane.stderr.txt"), $err)
        $result = [ordered]@{ lane = $lane; pid = $pidValue; dll_sha256 = $dllHash;
            exit_code = $process.ExitCode; timed_out = $timedOut; passed = $false }
        if (-not $timedOut) {
            if ($lane -eq 'candidate') {
                $expected = if ($library -eq 'glib') { 'process_attach_invoked=1 private_destructors=1 explicit_unload=1' } else { 'process_attach_initialized=2 surface_font_smoke=1 explicit_unload=1 reload=1' }
                $result.passed = $process.ExitCode -eq 0 -and -not $err -and $out -match $expected
            } else {
                $expected = if ($library -eq 'glib') { 'TLS callback not invoked' } else { 'Cairo TLS registration missing' }
                $result.passed = $process.ExitCode -ne 0 -and $err -match $expected
            }
        }
        $results += $result
        $results | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $bundle 'native-results.json')
        Write-Host ($result | ConvertTo-Json -Compress)
        if (-not $result.passed) { throw "$lane failed GLib TLS qualification; inspect separate stdout/stderr" }
    } finally {
        $process.Dispose()
    }
}
