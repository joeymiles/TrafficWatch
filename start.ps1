# TrafficWatch - start on this PC (Windows)
# ASCII only -- no em dashes or smart quotes.
# First-run asks consent before pip, IPinfo signup, MMDB download, or browser fallback.
# Healthy installs (venv + packages already present) launch silently.

param(
  [switch]$Desktop = $true,
  [switch]$Browser,
  [switch]$NoBrowser,
  [int]$Port = 8767
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$AppRoot = Join-Path $PSScriptRoot "app"
if (-not (Test-Path $AppRoot)) { throw "app/ folder missing - expected application code under app/" }

function Write-LaunchError {
  param([string]$Message)
  $dataDir = Join-Path $PSScriptRoot "data"
  New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
  $errFile = Join-Path $dataDir "last-launch-error.txt"
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $text = "TrafficWatch launch failed at $ts`r`n$Message`r`n"
  [System.IO.File]::WriteAllText($errFile, $text, [System.Text.Encoding]::ASCII)
  try {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($Message, "TrafficWatch") | Out-Null
  } catch {}
}

function Ask-YesNo {
  param([string]$Text, [string]$Title = "TrafficWatch")
  try {
    Add-Type -AssemblyName System.Windows.Forms
    $r = [System.Windows.Forms.MessageBox]::Show(
      $Text,
      $Title,
      [System.Windows.Forms.MessageBoxButtons]::YesNo,
      [System.Windows.Forms.MessageBoxIcon]::Question
    )
    return ($r -eq [System.Windows.Forms.DialogResult]::Yes)
  } catch {
    Write-Host $Text
    $a = Read-Host "Type YES to continue"
    return ($a -eq "YES")
  }
}

function Test-WebView2 {
  $paths = @(
    "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application",
    "$env:ProgramFiles\Microsoft\EdgeWebView\Application"
  )
  foreach ($p in $paths) {
    if ($p -and (Test-Path $p)) { return $true }
  }
  $key = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
  if (Test-Path $key) { return $true }
  return $false
}

function Find-SystemPython {
  $cmds = @(
    @("py", "-3"),
    @("py"),
    @("python")
  )
  foreach ($c in $cmds) {
    try {
      $exe = $c[0]
      $arg = @()
      if ($c.Count -gt 1) { $arg = $c[1..($c.Count-1)] }
      $arg += @("-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 2)")
      & $exe @arg 2>$null
      if ($LASTEXITCODE -eq 0) { return ,@($c) }
    } catch {}
  }
  return $null
}

try {
  if ($Browser) { $Desktop = $false }
  if ($NoBrowser) { $Desktop = $false; $Browser = $false }

  $env:PYTHONUTF8 = "1"
  Write-Host "=== TrafficWatch ===" -ForegroundColor Cyan
  Write-Host "Folder: $PSScriptRoot"

  $dataDir = Join-Path $PSScriptRoot "data"
  New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
  $ipinfoToken = Join-Path $dataDir "ipinfo.token"
  $ipinfoSkip = Join-Path $dataDir "ipinfo.skip"
  $geoSkip = Join-Path $dataDir "geo.skip"
  $geoMmdb = Join-Path $dataDir "dbip-city-lite.mmdb"

  $venv = Join-Path $PSScriptRoot ".venv"
  $py = Join-Path $venv "Scripts\python.exe"
  $pyw = Join-Path $venv "Scripts\pythonw.exe"

  $needVenv = -not (Test-Path $py)
  $needPip = $true
  if (-not $needVenv) {
    try {
      & $py -c "import flask, flask_socketio, psutil, geoip2, webview" 2>$null
      if ($LASTEXITCODE -eq 0) { $needPip = $false }
    } catch {
      $needPip = $true
    }
  }

  if ($needVenv -or $needPip) {
    $sysPy = Find-SystemPython
    if (-not $sysPy) {
      $msg = "TrafficWatch needs Python 3.10 or newer on PATH. Install it from https://www.python.org/downloads/ and check Add python.exe to PATH. TrafficWatch will not download Python for you."
      Write-Host "ERROR: $msg" -ForegroundColor Red
      Write-LaunchError -Message $msg
      exit 1
    }

    $pipMsg = "TrafficWatch needs Python packages (Flask, psutil, pywebview, and others listed in requirements.txt). OK to create a local .venv and run pip install -r requirements.txt? This uses the network once. No = the app will not start until packages are installed."
    if (-not (Ask-YesNo -Text $pipMsg -Title "TrafficWatch - install packages?")) {
      $later = "Skipped package install. Later, in this folder: py -3 -m venv .venv   then   .venv\Scripts\pip install -r requirements.txt   then run start.ps1 again."
      Write-Host $later -ForegroundColor Yellow
      Write-LaunchError -Message $later
      exit 1
    }

    if ($needVenv) {
      Write-Host "Creating venv..."
      $created = $false
      try {
        if ($sysPy.Count -gt 1) {
          & $sysPy[0] $sysPy[1] -m venv .venv
        } else {
          & $sysPy[0] -m venv .venv
        }
        if (Test-Path $py) { $created = $true }
      } catch { $created = $false }
      if (-not $created) {
        throw "Could not create .venv. Is Python 3.10+ on PATH with the venv module?"
      }
    }
    if (-not (Test-Path $py)) {
      throw "venv python.exe missing after create"
    }

    Write-Host "Installing requirements (you agreed)..."
    $coreReq = Join-Path $env:TEMP "tw-requirements-core.txt"
    Get-Content (Join-Path $AppRoot "requirements.txt") |
      Where-Object { $_ -notmatch '(?i)^\s*pystray' } |
      Set-Content -Encoding ascii $coreReq
    & $py -m pip install -r $coreReq -q
    if ($LASTEXITCODE -ne 0) { throw "pip install core requirements failed" }
    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $py -c "import pystray" 2>$null
    if ($LASTEXITCODE -ne 0) {
      & $py -m pip install "pystray>=0.19.0" -q
      if ($LASTEXITCODE -ne 0) {
        Write-Host "Optional tray (pystray) skipped - window will still open." -ForegroundColor Yellow
      }
    }
    $ErrorActionPreference = $oldEap
  }

  # IPinfo: reuse data\ipinfo.token or env. Never invent. Do not re-ask if present or skipped.
  $haveIPinfo = $false
  if ($env:IPINFO_TOKEN -or $env:IPINFO_LITE_TOKEN) { $haveIPinfo = $true }
  if (Test-Path $ipinfoToken) {
    $existing = ((Get-Content -Path $ipinfoToken -Raw -ErrorAction SilentlyContinue) + "").Trim()
    if ($existing.Length -gt 0) { $haveIPinfo = $true }
  }
  if ((-not $haveIPinfo) -and (-not (Test-Path $ipinfoSkip))) {
    $ipMsg = "Optional: IPinfo Lite improves ASN/org labels on the globe (free Lite token; stop if a card is required). Set it up now? Yes opens https://ipinfo.io/signup so you can paste a token. Skip = ASN stays empty. Token is stored only in data\ipinfo.token on this PC. Never emailed."
    if (Ask-YesNo -Text $ipMsg -Title "TrafficWatch - IPinfo Lite?") {
      try { Start-Process "https://ipinfo.io/signup" } catch {}
      $tok = ""
      try {
        Add-Type -AssemblyName Microsoft.VisualBasic
        $tok = [Microsoft.VisualBasic.Interaction]::InputBox("Paste your IPinfo Lite token. It is stored only in data\ipinfo.token. Leave blank to skip.", "TrafficWatch IPinfo", "")
      } catch {
        Write-Host "Paste IPinfo token (input hidden from logs). Blank = skip."
        $tok = Read-Host
      }
      $tok = (($tok + "").Trim())
      if ($tok.Length -gt 0) {
        [System.IO.File]::WriteAllText($ipinfoToken, $tok, [System.Text.Encoding]::ASCII)
        Write-Host "IPinfo token saved to data\ipinfo.token"
      } else {
        [System.IO.File]::WriteAllText($ipinfoSkip, "skipped", [System.Text.Encoding]::ASCII)
        Write-Host "IPinfo skipped. ASN fields stay empty until data\ipinfo.token exists."
      }
    } else {
      [System.IO.File]::WriteAllText($ipinfoSkip, "skipped", [System.Text.Encoding]::ASCII)
      Write-Host "IPinfo skipped. ASN fields stay empty until data\ipinfo.token exists."
    }
  }

  $noGeo = $false
  if (Test-Path $geoMmdb) {
    $noGeo = $false
  } elseif (Test-Path $geoSkip) {
    $noGeo = $true
  } else {
    $geoMsg = "Optional: download the free DB-IP City Lite map database (personal / non-commercial use) into data\ so remotes can pin on the globe. OK to download on first start? No = launch without the download (list still works; fewer arcs)."
    if (Ask-YesNo -Text $geoMsg -Title "TrafficWatch - GeoIP map data?") {
      $noGeo = $false
    } else {
      [System.IO.File]::WriteAllText($geoSkip, "skipped", [System.Text.Encoding]::ASCII)
      $noGeo = $true
    }
  }

  $listening = $false
  try {
    $ipgp = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $listening = [bool](@($ipgp.GetActiveTcpListeners()) | Where-Object { $_.Port -eq $Port })
  } catch { $listening = $false }
  if ($listening) {
    Write-Host "Port $Port already in use - trying to show existing TrafficWatch..." -ForegroundColor Yellow
    $shown = $false
    try {
      $tokPath = Join-Path $PSScriptRoot "data\desktop_show_token.txt"
      $tok = ""
      if (Test-Path $tokPath) {
        $tok = ((Get-Content -Path $tokPath -Raw -ErrorAction SilentlyContinue) + "").Trim()
      }
      $hdr = @{}
      if ($tok) { $hdr["X-TW-Token"] = $tok }
      $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/desktop/show" -Method POST -Headers $hdr -UseBasicParsing -TimeoutSec 2
      if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300) { $shown = $true }
    } catch { $shown = $false }
    if (-not $shown) {
      try { Start-Process "http://127.0.0.1:$Port/" } catch {}
    }
    Write-Host "If no window appeared, check the system tray (Show / Quit)." -ForegroundColor Yellow
    exit 0
  }

  $desktopPy = Join-Path $AppRoot "desktop.py"
  if (-not (Test-Path $desktopPy)) {
    throw "desktop.py missing"
  }

  if ($Desktop -and -not (Test-WebView2)) {
    $wvMsg = "The desktop window needs Microsoft Edge WebView2, which was not found. Open TrafficWatch in your system browser instead? No = exit. You can install WebView2 from Microsoft later for the desktop window."
    if (Ask-YesNo -Text $wvMsg -Title "TrafficWatch - browser fallback?") {
      $Desktop = $false
      $Browser = $true
    } else {
      $later = "Skipped browser fallback. Install Edge WebView2 from https://developer.microsoft.com/microsoft-edge/webview2/ then run start.ps1 again."
      Write-LaunchError -Message $later
      exit 1
    }
  }

  $extraArgs = @()
  if ($noGeo) { $extraArgs += "--no-geo-download" }

  if ($Desktop) {
    Write-Host "Starting desktop app (pywebview) on http://127.0.0.1:$Port/ ..." -ForegroundColor Green
    Write-Host "Close the window or click Quit to stop the backend."
    $argLine = @("desktop.py") + $extraArgs
    if (Test-Path $pyw) {
      Start-Process -FilePath $pyw -ArgumentList $argLine -WorkingDirectory $AppRoot
    } else {
      Start-Process -FilePath $py -ArgumentList $argLine -WorkingDirectory $AppRoot -WindowStyle Hidden
    }
    exit 0
  } else {
    $argsList = @("app.py", "--host", "127.0.0.1", "--port", "$Port") + $extraArgs
    if ($Browser) { $argsList += "--browser" }
    Write-Host "Starting http://127.0.0.1:$Port/ (browser mode)..." -ForegroundColor Green
    Push-Location $AppRoot
    try { & $py @argsList; exit $LASTEXITCODE } finally { Pop-Location }
  }
} catch {
  $msg = $_.Exception.Message
  if (-not $msg) { $msg = "$_" }
  Write-Host "ERROR: $msg" -ForegroundColor Red
  Write-LaunchError -Message $msg
  exit 1
}
