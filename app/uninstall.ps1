# TrafficWatch uninstall (Windows)
# ASCII only -- no em dashes or smart quotes.
#
# Always removes what TrafficWatch owns:
#   running TrafficWatch processes from THIS folder (exact PIDs), firewall rules named
#   TrafficWatch-block-*, the desktop shortcut that points at THIS folder, .venv.
# Restores system settings the elevated helper changed, using data\system_baseline.json.
# Warns, then deletes user data (data\: history, tokens, map DBs, logs, WebView storage).
# Never removes Python, Edge, WebView2 or other tools. WebView2 is only offered as a
# default-off link to Windows Settings because other apps share it.
#
# -DryRun: show what would happen, change nothing, no elevation.
# -Quiet: no dialogs; deletes data and (non-git) folder with default options. For scripted/test use.
# -NoElevate: do not relaunch as admin; admin-only steps are attempted and reported if they fail.

param(
  [switch]$DryRun,
  [switch]$Quiet,
  [switch]$NoElevate,
  [switch]$Elevated
)

$ErrorActionPreference = 'Stop'
$AppDir = $PSScriptRoot
$Root = Split-Path -Parent $AppDir
$DataDir = Join-Path $Root 'data'
$VenvDir = Join-Path $Root '.venv'
$LogFile = Join-Path $env:TEMP 'TrafficWatch-uninstall.txt'
$script:Report = New-Object System.Collections.Generic.List[string]

function Note([string]$Text) {
  $prefix = ''
  if ($DryRun) { $prefix = '[dry-run] ' }
  $script:Report.Add($prefix + $Text)
  Write-Host ($prefix + $Text)
}

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-SafeRoot {
  # Refuse to touch anything unless this really is a TrafficWatch folder.
  $ok = (Test-Path (Join-Path $Root 'start.ps1')) -and (Test-Path (Join-Path $AppDir 'desktop.py')) -and (Test-Path (Join-Path $AppDir 'helper\tw_helper.ps1'))
  $full = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
  $bad = @([System.IO.Path]::GetPathRoot($full).TrimEnd('\'), $env:USERPROFILE.TrimEnd('\'), $env:SystemRoot.TrimEnd('\'), [Environment]::GetFolderPath('Desktop').TrimEnd('\'))
  if (-not $ok -or ($bad -contains $full)) { throw "Refusing to uninstall: $Root does not look like a TrafficWatch folder." }
  if ((Test-Reparse $Root) -or (Test-Reparse $AppDir)) { throw "Refusing to uninstall: $Root or its app folder is a link; run the uninstaller from the real folder." }
}

function Show-Options {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  $isGit = Test-Path (Join-Path $Root '.git')
  $f = New-Object System.Windows.Forms.Form
  $f.Text = 'Uninstall TrafficWatch'
  $f.StartPosition = 'CenterScreen'
  $f.FormBorderStyle = 'FixedDialog'
  $f.MaximizeBox = $false
  $f.MinimizeBox = $false
  $f.ClientSize = New-Object System.Drawing.Size(520, 330)
  $ico = Join-Path $AppDir 'static\trafficwatch.ico'
  if (Test-Path $ico) { try { $f.Icon = New-Object System.Drawing.Icon($ico) } catch {} }

  $lbl = New-Object System.Windows.Forms.Label
  $lbl.Location = New-Object System.Drawing.Point(16, 14)
  $lbl.Size = New-Object System.Drawing.Size(490, 96)
  $lbl.Text = "This stops TrafficWatch and removes what it installed on this PC: its desktop shortcut, its Python environment (.venv), its firewall block rules (TrafficWatch-block-*), and it restores the Windows logging settings it turned on.`r`n`r`nPython, Edge and WebView2 are not removed.`r`n`r`nFolder: $Root"
  $f.Controls.Add($lbl)

  $cbData = New-Object System.Windows.Forms.CheckBox
  $cbData.Location = New-Object System.Drawing.Point(16, 120)
  $cbData.Size = New-Object System.Drawing.Size(490, 40)
  $cbData.Checked = $true
  $cbData.Text = 'Delete my TrafficWatch data (connection history, saved tokens, map databases, logs). This cannot be undone.'
  $f.Controls.Add($cbData)

  $cbFolder = New-Object System.Windows.Forms.CheckBox
  $cbFolder.Location = New-Object System.Drawing.Point(16, 166)
  $cbFolder.Size = New-Object System.Drawing.Size(490, 40)
  if ($isGit) {
    $cbFolder.Checked = $false
    $cbFolder.Enabled = $false
    $cbFolder.Text = 'Remove the program folder (disabled: this folder is a git checkout; delete it yourself if you want)'
  } else {
    $cbFolder.Checked = $true
    $cbFolder.Text = 'Remove the TrafficWatch program folder after uninstall'
  }
  $f.Controls.Add($cbFolder)

  $cbWv = New-Object System.Windows.Forms.CheckBox
  $cbWv.Location = New-Object System.Drawing.Point(16, 212)
  $cbWv.Size = New-Object System.Drawing.Size(490, 40)
  $cbWv.Checked = $false
  $cbWv.Text = 'Also open Windows Settings > Apps so I can remove Microsoft Edge WebView2 myself (other apps may need it)'
  $f.Controls.Add($cbWv)

  $ok = New-Object System.Windows.Forms.Button
  $ok.Text = 'Uninstall'
  $ok.Location = New-Object System.Drawing.Point(318, 280)
  $ok.Size = New-Object System.Drawing.Size(90, 30)
  $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $f.Controls.Add($ok)

  $cancel = New-Object System.Windows.Forms.Button
  $cancel.Text = 'Cancel'
  $cancel.Location = New-Object System.Drawing.Point(416, 280)
  $cancel.Size = New-Object System.Drawing.Size(90, 30)
  $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
  $f.Controls.Add($cancel)
  $f.AcceptButton = $cancel
  $f.CancelButton = $cancel

  if ($f.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
  $opts = @{ DeleteData = $cbData.Checked; RemoveFolder = ($cbFolder.Enabled -and $cbFolder.Checked); OpenApps = $cbWv.Checked }
  if ($opts.DeleteData) {
    $warn = [System.Windows.Forms.MessageBox]::Show(
      "Delete all TrafficWatch data in:`r`n$DataDir`r`n`r`nConnection history, tokens, map databases and logs will be gone. Continue?",
      'Uninstall TrafficWatch - delete data?',
      [System.Windows.Forms.MessageBoxButtons]::YesNo,
      [System.Windows.Forms.MessageBoxIcon]::Warning,
      [System.Windows.Forms.MessageBoxDefaultButton]::Button2)
    if ($warn -ne [System.Windows.Forms.DialogResult]::Yes) { return $null }
  }
  return $opts
}

function Stop-TrafficWatch {
  # Trailing backslash so a sibling folder like TrafficWatch-wt-x never matches.
  $rootLower = ($Root.TrimEnd('\') + '\').ToLowerInvariant()
  $venvLower = ($VenvDir.TrimEnd('\') + '\').ToLowerInvariant()
  # start.ps1 launches "pythonw desktop.py" with a relative path, so the folder is often not in
  # the command line. Also match our .venv interpreter, and the pid the app recorded in data\app.pid.
  $recordedPid = 0
  $pidFile = Join-Path $DataDir 'app.pid'
  if (Test-Path -LiteralPath $pidFile) {
    try { $recordedPid = [int]((Get-Content -Raw -LiteralPath $pidFile | ConvertFrom-Json).pid) } catch { $recordedPid = 0 }
  }
  $procs = @(Get-CimInstance Win32_Process | Where-Object {
      $cl = [string]$_.CommandLine
      $exe = ([string]$_.ExecutablePath).ToLowerInvariant()
      $isOurScript = ($cl -match '(?i)(desktop\.py|app\.py|tw_helper\.ps1)') -or
        (($_.Name -eq 'msedgewebview2.exe') -and $cl.ToLowerInvariant().Contains($rootLower))
      $_.ProcessId -ne $PID -and $isOurScript -and (
        $cl.ToLowerInvariant().Contains($rootLower) -or
        $exe.StartsWith($venvLower) -or
        ($recordedPid -gt 0 -and [int]$_.ProcessId -eq $recordedPid -and $exe -match 'python')
      )
    })
  if (-not $procs.Count) { Note 'No running TrafficWatch processes from this folder.'; return }
  foreach ($p in $procs) {
    Note ("Stop PID {0} ({1})" -f $p.ProcessId, $p.Name)
    if (-not $DryRun) {
      # Child WebView2 processes often exit with their parent; already-gone is fine.
      if (Get-Process -Id ([int]$p.ProcessId) -ErrorAction SilentlyContinue) {
        try { Stop-Process -Id ([int]$p.ProcessId) -Force -ErrorAction Stop } catch { Note ("  could not stop PID {0}: {1}" -f $p.ProcessId, $_.Exception.Message) }
      }
    }
  }
  if (-not $DryRun) { Start-Sleep -Milliseconds 1500 }
}

function Remove-FirewallRules {
  $rules = @(Get-NetFirewallRule -DisplayName 'TrafficWatch-block-*' -ErrorAction SilentlyContinue)
  if (-not $rules.Count) { Note 'No TrafficWatch firewall rules.'; return }
  foreach ($r in $rules) {
    Note ("Remove firewall rule {0}" -f $r.DisplayName)
    if (-not $DryRun) { try { Remove-NetFirewallRule -Name $r.Name -ErrorAction Stop } catch { Note ("  failed: {0}" -f $_.Exception.Message) } }
  }
}

function Restore-SystemSettings {
  $path = Join-Path $DataDir 'system_baseline.json'
  if (-not (Test-Path $path)) {
    Note 'No system_baseline.json: TrafficWatch has no recorded setting changes to undo. (Installs older than this uninstaller did not record them; the DNS-Client Operational log may still be on - harmless, and can be turned off in Event Viewer.)'
    return
  }
  # data\ is user-writable; values only ever select between fixed on/off actions below.
  $b = (Get-Content -Raw -LiteralPath $path) | ConvertFrom-Json
  foreach ($pair in @(@('dns_client_operational', 'Microsoft-Windows-DNS-Client/Operational'), @('kernel_network_analytic', 'Microsoft-Windows-Kernel-Network/Analytic'))) {
    $val = $b.($pair[0])
    if ($val -eq 'disabled') {
      Note ("Turn off event log {0} (was off before TrafficWatch)" -f $pair[1])
      if (-not $DryRun) {
        try {
          $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $pair[1]
          if ($cfg.IsEnabled) { $cfg.IsEnabled = $false; $cfg.SaveChanges() }
        } catch { Note ("  failed: {0}" -f $_.Exception.Message) }
      }
    }
  }
  $ap = [string]$b.auditpol_wfp_connection
  if ($ap) {
    $parts = $ap -split ';'
    $s = 'disable'; $fl = 'disable'
    # Compare the recorded values only, not the "success=" / "failure=" labels.
    $sv = ($parts[0] -replace '^(?i)success=', '')
    $fv = ''
    if ($parts.Count -gt 1) { $fv = ($parts[1] -replace '^(?i)failure=', '') }
    if ($sv -match '(?i)^(success|enable)') { $s = 'enable' }
    if ($fv -match '(?i)^(failure|enable)') { $fl = 'enable' }
    Note ("Restore audit policy 'Filtering Platform Connection' to success:{0} failure:{1}" -f $s, $fl)
    if (-not $DryRun) {
      # Native stderr becomes a terminating error under -ErrorAction Stop in PS 5.1; judge by exit code.
      $oldEap = $ErrorActionPreference
      $ErrorActionPreference = 'Continue'
      $out = & auditpol.exe /set /subcategory:"Filtering Platform Connection" /success:$s /failure:$fl 2>&1 | Out-String
      $code = $LASTEXITCODE
      $ErrorActionPreference = $oldEap
      if ($code -ne 0) { Note ("  failed (exit {0}): {1}" -f $code, $out.Trim()) }
    }
  }
}

function Remove-Shortcut {
  $lnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'TrafficWatch.lnk'
  if (-not (Test-Path $lnk)) { Note 'No TrafficWatch desktop shortcut.'; return }
  $target = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
  $mine = ($target.Arguments + ' ' + $target.TargetPath).ToLowerInvariant().Contains(($Root.TrimEnd('\') + '\').ToLowerInvariant())
  if (-not $mine) { Note "Desktop shortcut $lnk points elsewhere; left alone."; return }
  Note "Remove desktop shortcut $lnk"
  if (-not $DryRun) { Remove-Item -LiteralPath $lnk -Force }
}

function Test-Reparse([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
  return ($item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint))
}

function Remove-TreeNoFollow([string]$Path) {
  # This runs elevated: never traverse junctions/symlinks. A link is removed as a link;
  # its target is left untouched. Plain files and folders are removed bottom-up.
  $failed = 0
  foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
    $isLink = [bool]($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
    try {
      if ($child.PSIsContainer -and $isLink) {
        [System.IO.Directory]::Delete($child.FullName, $false)
      } elseif ($child.PSIsContainer) {
        $failed += Remove-TreeNoFollow $child.FullName
        [System.IO.Directory]::Delete($child.FullName, $false)
      } else {
        $child.Attributes = [System.IO.FileAttributes]::Normal
        [System.IO.File]::Delete($child.FullName)
      }
    } catch { $failed++ }
  }
  return $failed
}

function Remove-Dir([string]$Path, [string]$Label) {
  if (-not (Test-Path -LiteralPath $Path)) { Note "No $Label."; return }
  if (Test-Reparse $Path) {
    Note "$Label ($Path) is a link to somewhere else; removing only the link."
    if (-not $DryRun) { try { [System.IO.Directory]::Delete($Path, $false) } catch { Note ("  failed: {0}" -f $_.Exception.Message) } }
    return
  }
  Note "Delete $Label ($Path)"
  if (-not $DryRun) {
    $failed = Remove-TreeNoFollow $Path
    try { [System.IO.Directory]::Delete($Path, $false) } catch { $failed++ }
    if ($failed) { Note ("  {0} item(s) could not be deleted (in use?)" -f $failed) }
  }
}

# --- main ---
try {
  Assert-SafeRoot
  if (-not $DryRun -and -not $NoElevate -and -not (Test-Admin)) {
    # Firewall rules and audit policy need admin. Relaunch elevated (one UAC prompt).
    $args2 = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Elevated"
    try {
      Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $args2 -Verb RunAs | Out-Null
    } catch {
      Add-Type -AssemblyName System.Windows.Forms
      [System.Windows.Forms.MessageBox]::Show('Uninstall needs administrator approval to remove firewall rules and restore Windows settings. Nothing was changed.', 'Uninstall TrafficWatch') | Out-Null
    }
    exit 0
  }

  if ($DryRun -or $Quiet) {
    $opts = @{ DeleteData = $true; RemoveFolder = -not (Test-Path (Join-Path $Root '.git')); OpenApps = $false }
  } else {
    $opts = Show-Options
    if ($null -eq $opts) { exit 0 }
  }

  Note "TrafficWatch uninstall: $Root"
  # Each step is independent: a failure is reported and the rest still run.
  foreach ($step in @('Stop-TrafficWatch', 'Remove-FirewallRules', 'Restore-SystemSettings', 'Remove-Shortcut')) {
    try { & $step } catch { Note ("{0} failed: {1}" -f $step, $_.Exception.Message) }
  }
  Remove-Dir $VenvDir 'Python environment (.venv)'
  if ($opts.DeleteData) { Remove-Dir $DataDir 'user data (data\)' } else { Note 'Kept user data (data\).' }
  if ($opts.OpenApps) {
    Note 'Open Windows Settings > Apps (remove WebView2 there only if nothing else needs it).'
    if (-not $DryRun) { Start-Process 'ms-settings:appsfeatures' }
  }
  if ($opts.RemoveFolder) {
    Note "Remove program folder $Root (after this window closes)"
    if (-not $DryRun) {
      # Wait for this script and any child processes to release the folder, then retry once.
      $cmd = "/c ping -n 4 127.0.0.1 >nul & rmdir /s /q `"$Root`" & ping -n 6 127.0.0.1 >nul & if exist `"$Root`" rmdir /s /q `"$Root`""
      Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgumentList $cmd -WindowStyle Hidden -WorkingDirectory $env:TEMP | Out-Null
    }
  }
  Note 'Done.'
  [System.IO.File]::WriteAllLines($LogFile, $script:Report)
  if (-not $DryRun -and -not $Quiet) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(("TrafficWatch was uninstalled.`r`n`r`n" + ($script:Report -join "`r`n")), 'Uninstall TrafficWatch') | Out-Null
  }
  exit 0
} catch {
  $msg = $_.Exception.Message
  $script:Report.Add("ERROR: $msg")
  try { [System.IO.File]::WriteAllLines($LogFile, $script:Report) } catch {}
  Write-Host "ERROR: $msg"
  if (-not $DryRun -and -not $Quiet) {
    try {
      Add-Type -AssemblyName System.Windows.Forms
      [System.Windows.Forms.MessageBox]::Show("Uninstall stopped: $msg`r`nDetails: $LogFile", 'Uninstall TrafficWatch') | Out-Null
    } catch {}
  }
  exit 1
}
