# TrafficWatch tools\run_py_once.ps1
# Hardened one-shot Python runner for apply/patch helpers.
# Always passes a script path or -c (never bare python). Closes stdin. Enforces timeout.
# On timeout, kills the exact child PID only (never image-name / cmdline pattern).
param(
  [Parameter(Mandatory = $false)] [string] $File = "",
  [Parameter(Mandatory = $false)] [string] $Code = "",
  [Parameter(ValueFromRemainingArguments = $true)] [string[]] $PyArgs = @(),
  [int] $TimeoutSec = 120,
  [string] $Python = "",
  [string] $WorkingDirectory = "",
  # After exact-PID timeout kill, wait before callers reuse a bound port (see tools/test_gate.py).
  [double] $AfterKillGapSec = 1.5
)
$ErrorActionPreference = "Stop"
if (-not $File -and -not $Code) {
  throw "run_py_once: pass -File path.py or -Code '...' (never bare python)"
}
if ($File -and $Code) {
  throw "run_py_once: pass only one of -File or -Code"
}
if ($TimeoutSec -lt 1) { $TimeoutSec = 1 }
if ($TimeoutSec -gt 3600) { $TimeoutSec = 3600 }

if (-not $Python) {
  $venvPy = Join-Path (Split-Path $PSScriptRoot -Parent) ".venv\Scripts\python.exe"
  if (Test-Path -LiteralPath $venvPy) { $Python = $venvPy }
  else { $Python = "python.exe" }
}
if (-not $WorkingDirectory) {
  $WorkingDirectory = Split-Path $PSScriptRoot -Parent
}

$argList = New-Object System.Collections.Generic.List[string]
if ($File) {
  if (-not (Test-Path -LiteralPath $File)) { throw "run_py_once: file not found: $File" }
  $argList.Add((Resolve-Path -LiteralPath $File).Path) | Out-Null
} else {
  $argList.Add("-c") | Out-Null
  $argList.Add($Code) | Out-Null
}
foreach ($a in $PyArgs) { $argList.Add([string]$a) | Out-Null }

$stdout = Join-Path $env:TEMP ("tw-pyonce-out-{0}.txt" -f [guid]::NewGuid().ToString("n"))
$stderr = Join-Path $env:TEMP ("tw-pyonce-err-{0}.txt" -f [guid]::NewGuid().ToString("n"))
$stdinEmpty = Join-Path $env:TEMP ("tw-pyonce-stdin-{0}.txt" -f [guid]::NewGuid().ToString("n"))
# Empty file as stdin so Python never blocks on interactive stdin
[System.IO.File]::WriteAllText($stdinEmpty, "")

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Python
# Quote args safely
$psi.Arguments = ($argList | ForEach-Object {
  $s = [string]$_
  if ($s -match '[\s"]') { '"' + ($s.Replace('"','\"')) + '"' } else { $s }
}) -join ' '
$psi.WorkingDirectory = $WorkingDirectory
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true

$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
[void]$p.Start()
# Close stdin immediately so helpers cannot idle waiting for input
$p.StandardInput.Close()

$outTask = $p.StandardOutput.ReadToEndAsync()
$errTask = $p.StandardError.ReadToEndAsync()
$exited = $p.WaitForExit($TimeoutSec * 1000)
if (-not $exited) {
  $kid = $p.Id
  try { $p.Kill() } catch {}
  try { Stop-Process -Id $kid -Force -ErrorAction SilentlyContinue } catch {}
  Write-Output "TIMEOUT after ${TimeoutSec}s; killed exact PID $kid"
  if ($AfterKillGapSec -gt 0) {
    # LISTEN/TIME_WAIT can linger; shared test_gate also waits this gap.
    Start-Sleep -Seconds $AfterKillGapSec
  }
  try { Write-Output $outTask.Result } catch {}
  try { Write-Output $errTask.Result } catch {}
  exit 124
}
$outTask.Wait()
$errTask.Wait()
if ($outTask.Result) { Write-Output $outTask.Result.TrimEnd() }
if ($errTask.Result) { Write-Output $errTask.Result.TrimEnd() }
exit $p.ExitCode
