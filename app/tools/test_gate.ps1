# Shared TrafficWatch TEST-PORT gate (Claude + Prototype).
# Thin wrapper around tools/test_gate.py so both agents share one implementation.
#
# Rules (see test_gate.py):
#   1. ANY HTTP answer from the test port (incl. 401/403) = in use. /api/health
#      401 is a live TW without a cookie, NOT a free port.
#   2. No TCP LISTEN owner before launching a test server.
#   3. Exact-PID kill then a short gap before reusing the port.
#      Never kill protected PIDs (TW_PROTECTED_PIDS). Never image-name / cmdline pattern kills.
#
# Usage:
#   powershell -File tools\test_gate.ps1 check
#   powershell -File tools\test_gate.ps1 wait -Port 8767
#   powershell -File tools\test_gate.ps1 kill -KillPid 12345
#   powershell -File tools\test_gate.ps1 selftest
# Dot-source:
#   . tools\test_gate.ps1
#   Assert-TwTestPortFree
#   Stop-TwExactPid -KillPid 12345
param(
  [Parameter(Position = 0)] [string] $Command = "",
  [string] $HostName = "127.0.0.1",
  [int] $Port = 8767,
  [double] $TimeoutSec = 15,
  [int[]] $KillPid = @(),
  [double] $GapSec = 1.5
)

$ErrorActionPreference = "Stop"
$TwRoot = Split-Path $PSScriptRoot -Parent
$TwGatePy = Join-Path $PSScriptRoot "test_gate.py"
$TwPython = Join-Path $TwRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $TwPython)) { $TwPython = "python.exe" }

function Invoke-TwTestGate {
  param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $GateArgs)
  if (-not (Test-Path -LiteralPath $TwGatePy)) {
    throw "test_gate.ps1: missing $TwGatePy"
  }
  & $TwPython $TwGatePy @GateArgs
  return $LASTEXITCODE
}

function Assert-TwTestPortFree {
  param([string] $HostName = "127.0.0.1", [int] $Port = 8767)
  $code = Invoke-TwTestGate @("check", "--host", $HostName, "--port", "$Port")
  if ($code -ne 0) { throw "test_gate: port $Port is in use (any HTTP answer or LISTEN owner)" }
}

function Wait-TwTestPortFree {
  param([string] $HostName = "127.0.0.1", [int] $Port = 8767, [double] $TimeoutSec = 15)
  $code = Invoke-TwTestGate @("wait", "--host", $HostName, "--port", "$Port", "--timeout", "$TimeoutSec")
  if ($code -ne 0) { throw "test_gate: port $Port did not free within ${TimeoutSec}s" }
}

function Stop-TwExactPid {
  param([Parameter(Mandatory = $true)] [int[]] $KillPid, [double] $GapSec = 1.5)
  if (-not $KillPid -or $KillPid.Count -eq 0) { throw "Stop-TwExactPid: pass -KillPid" }
  $kargs = New-Object System.Collections.Generic.List[string]
  [void]$kargs.Add("kill")
  foreach ($id in $KillPid) { [void]$kargs.Add("--pid"); [void]$kargs.Add([string]$id) }
  [void]$kargs.Add("--gap"); [void]$kargs.Add([string]$GapSec)
  $code = Invoke-TwTestGate @($kargs.ToArray())
  if ($code -ne 0) { throw "test_gate: exact-PID kill failed" }
}

if ($MyInvocation.InvocationName -eq ".") { return }

if (-not $Command) {
  Write-Host "usage: test_gate.ps1 check|wait|kill|selftest"
  exit 2
}
switch ($Command.ToLowerInvariant()) {
  "check" {
    exit (Invoke-TwTestGate @("check", "--host", $HostName, "--port", "$Port"))
  }
  "wait" {
    exit (Invoke-TwTestGate @("wait", "--host", $HostName, "--port", "$Port", "--timeout", "$TimeoutSec"))
  }
  "kill" {
    if (-not $KillPid -or $KillPid.Count -eq 0) { throw "test_gate.ps1 kill: pass -KillPid" }
    $kargs = New-Object System.Collections.Generic.List[string]
    [void]$kargs.Add("kill")
    foreach ($id in $KillPid) { [void]$kargs.Add("--pid"); [void]$kargs.Add([string]$id) }
    [void]$kargs.Add("--gap"); [void]$kargs.Add([string]$GapSec)
    exit (Invoke-TwTestGate @($kargs.ToArray()))
  }
  "selftest" {
    exit (Invoke-TwTestGate @("selftest"))
  }
  default { throw "test_gate.ps1: unknown command $Command" }
}
