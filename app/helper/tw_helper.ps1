# TrafficWatch elevated sidecar (Tier 1 phase-1 DNS + phase-2 TCP/bytes).
# ASCII only -- no em dashes or smart quotes.
# Long-running named-pipe server. Must be started elevated (UAC) from the
# unelevated app (Status -> Enable live DNS). Not launched by start.ps1.
# Returns parsed DNS + TCP fields only. Never writes event XML to disk. No tokens.

param(
  [int]$ParentPid = 0,
  [string]$ClientSid = '',
  [string]$PipeName = 'TrafficWatch-helper',
  [int]$IdleExitSec = 90,
  # Storm guard (#69): fail soft instead of pegging CPU / interrupts.
  [int]$StormEventsPerSec = 1500,
  [int]$StormIntrDpcPct = 25,
  [int]$StormCooldownSec = 600
)

$ErrorActionPreference = 'Stop'
$script:Shutdown = $false
$script:DnsEnabled = $false
$script:LogEnabled = $false
$script:LogError = ''
$script:EventsCount = 0
$script:LastError = ''
$script:ClientConnected = $false
$script:LastClientUtc = [datetime]::UtcNow
$script:Watcher = $null
$script:Pipe = $null
$script:Writer = $null
$script:WriteLock = New-Object object
$script:ProcCache = @{}
$script:Mutex = $null
$script:DnsQueue = New-Object System.Collections.Concurrent.ConcurrentQueue[object]

# --- TCP / bytes (phase-2) ---
$script:TcpEnabled = $false
$script:TcpSource = 'none'
$script:TcpLimited = $false
$script:TcpError = ''
$script:TcpEventsCount = 0
$script:TcpWatcher = $null
$script:TcpQueue = New-Object System.Collections.Concurrent.ConcurrentQueue[object]
$script:TcpFlows = @{}
$script:TcpFlowLock = New-Object object
$script:TcpQueueCap = 400
$script:TcpStormDrops = 0
$script:StormTrips = 0
$script:StormRate = 0
$script:StormIntrPct = 0
$script:StormTrippedUtc = $null
$script:StormLastUtc = $null
$global:TwKnSeen = [long]0
$global:TwWfpSeen = [long]0
$global:TwStormTripped = $false
$script:TcpLastFlushUtc = [datetime]::UtcNow
$script:KnLogWasEnabled = $null
$script:AuditPolChanged = $false
$script:AuditPolPrevSuccess = $null
$script:AuditPolPrevFailure = $null
$script:WfpWatcher = $null

function Test-Elevated {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Hide-Window {
  try {
    Add-Type -Name TwWin -Namespace TwNative -MemberDefinition @"
[DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
"@ -ErrorAction SilentlyContinue
    $hwnd = [TwNative.TwWin]::GetConsoleWindow()
    if ($hwnd -ne [IntPtr]::Zero) { [TwNative.TwWin]::ShowWindow($hwnd, 0) | Out-Null }
  } catch {}
}

function Get-ProcName {
  param([int]$ProcessId)
  if ($ProcessId -le 0) { return $null }
  $now = [datetime]::UtcNow
  $hit = $script:ProcCache[$ProcessId]
  if ($hit -and ($now - $hit.ts).TotalSeconds -lt 20) { return $hit.name }
  $n = $null
  try { $n = (Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName } catch {
    try { $n = [System.Diagnostics.Process]::GetProcessById($ProcessId).ProcessName } catch { $n = $null }
  }
  $script:ProcCache[$ProcessId] = @{ name = $n; ts = $now }
  return $n
}

function Convert-UIntToIPv4 {
  param($raw)
  if ($null -eq $raw -or $raw -eq '') { return $null }
  try {
    if ($raw -is [string] -and $raw -match '^\d+\.\d+\.\d+\.\d+$') { return $raw }
    $n = [uint32]0
    if (-not [uint32]::TryParse([string]$raw, [ref]$n)) {
      try { $n = [uint32]$raw } catch { return $null }
    }
    $bytes = [BitConverter]::GetBytes($n)
    return ('{0}.{1}.{2}.{3}' -f $bytes[0], $bytes[1], $bytes[2], $bytes[3])
  } catch { return $null }
}

function Send-Obj {
  param($obj)
  $w = $script:Writer
  if (-not $w) { return }
  try {
    $json = ($obj | ConvertTo-Json -Compress -Depth 5)
    if (-not $json) { return }
    [void][System.Threading.Monitor]::Enter($script:WriteLock)
    try {
      $w.WriteLine($json)
      $w.Flush()
    } finally {
      [System.Threading.Monitor]::Exit($script:WriteLock)
    }
  } catch {
    $script:LastError = 'write failed'
    $script:ClientConnected = $false
  }
}

function Enqueue-Tcp {
  param($row)
  if (-not $row) { return }
  while ($script:TcpQueue.Count -ge $script:TcpQueueCap) {
    $drop = $null
    if ($script:TcpQueue.TryDequeue([ref]$drop)) {
      $script:TcpStormDrops++
      $script:TcpLimited = $true
    } else { break }
  }
  [void]$script:TcpQueue.Enqueue($row)
}

function Get-FlowKey {
  param($lip, $lport, $rip, $rport)
  return ('{0}|{1}|{2}|{3}' -f ($lip + ''), ($lport + ''), ($rip + ''), ($rport + ''))
}

function Upsert-TcpFlow {
  param(
    [string]$Kind,
    [string]$Dir,
    $PidVal,
    $Proc,
    $LocalIp,
    $LocalPort,
    $RemoteIp,
    $RemotePort,
    [long]$AddOut = 0,
    [long]$AddIn = 0,
    [string]$Ts = ''
  )
  if (-not $RemoteIp -and -not $LocalIp) { return }
  $key = Get-FlowKey $LocalIp $LocalPort $RemoteIp $RemotePort
  $now = [datetime]::UtcNow
  $ts = $Ts
  if (-not $ts) { $ts = $now.ToString('o') }
  [void][System.Threading.Monitor]::Enter($script:TcpFlowLock)
  try {
    $f = $script:TcpFlows[$key]
    if (-not $f) {
      $f = @{
        key = $key
        dir = $(if ($Dir) { $Dir } else { 'connect' })
        pid = $PidVal
        proc = $Proc
        local_ip = $LocalIp
        local_port = $LocalPort
        remote_ip = $RemoteIp
        remote_port = $RemotePort
        bytes_out = [long]0
        bytes_in = [long]0
        open_utc = $now
        dirty = $false
        closed = $false
      }
      $script:TcpFlows[$key] = $f
      if ($Kind -eq 'open' -or $Kind -eq 'connect' -or $Kind -eq 'accept') {
        Enqueue-Tcp @{
          t = 'tcp'
          kind = 'open'
          dir = $f.dir
          pid = $f.pid
          proc = $f.proc
          local_ip = $f.local_ip
          local_port = $f.local_port
          remote_ip = $f.remote_ip
          remote_port = $f.remote_port
          bytes_out = 0
          bytes_in = 0
          duration_ms = $null
          ts = $ts
        }
      }
    }
    if ($Dir) { $f.dir = $Dir }
    if ($PidVal -and (-not $f.pid -or [int]$f.pid -le 0)) { $f.pid = $PidVal }
    if ($Proc -and -not $f.proc) { $f.proc = $Proc }
    if ($AddOut -gt 0) { $f.bytes_out = [long]$f.bytes_out + $AddOut; $f.dirty = $true }
    if ($AddIn -gt 0) { $f.bytes_in = [long]$f.bytes_in + $AddIn; $f.dirty = $true }
    if ($Kind -eq 'close') {
      $dur = [int]([Math]::Max(0, ($now - $f.open_utc).TotalMilliseconds))
      Enqueue-Tcp @{
        t = 'tcp'
        kind = 'close'
        dir = $f.dir
        pid = $f.pid
        proc = $f.proc
        local_ip = $f.local_ip
        local_port = $f.local_port
        remote_ip = $f.remote_ip
        remote_port = $f.remote_port
        bytes_out = [long]$f.bytes_out
        bytes_in = [long]$f.bytes_in
        duration_ms = $dur
        ts = $ts
      }
      $script:TcpFlows.Remove($key)
    }
  } finally {
    [System.Threading.Monitor]::Exit($script:TcpFlowLock)
  }
}

function Flush-TcpBytes {
  $now = [datetime]::UtcNow
  if (($now - $script:TcpLastFlushUtc).TotalSeconds -lt 1.0) { return }
  $script:TcpLastFlushUtc = $now
  $snap = @()
  [void][System.Threading.Monitor]::Enter($script:TcpFlowLock)
  try {
    foreach ($k in @($script:TcpFlows.Keys)) {
      $f = $script:TcpFlows[$k]
      if (-not $f -or -not $f.dirty) { continue }
      $f.dirty = $false
      $dur = [int]([Math]::Max(0, ($now - $f.open_utc).TotalMilliseconds))
      $snap += @{
        t = 'tcp'
        kind = 'bytes'
        dir = $f.dir
        pid = $f.pid
        proc = $f.proc
        local_ip = $f.local_ip
        local_port = $f.local_port
        remote_ip = $f.remote_ip
        remote_port = $f.remote_port
        bytes_out = [long]$f.bytes_out
        bytes_in = [long]$f.bytes_in
        duration_ms = $dur
        ts = $now.ToString('o')
      }
    }
    # Cap live flow table
    if ($script:TcpFlows.Count -gt 800) {
      $old = $script:TcpFlows.GetEnumerator() | Sort-Object { $_.Value.open_utc } | Select-Object -First ($script:TcpFlows.Count - 600)
      foreach ($e in $old) { $script:TcpFlows.Remove($e.Key) }
      $script:TcpLimited = $true
    }
  } finally {
    [System.Threading.Monitor]::Exit($script:TcpFlowLock)
  }
  foreach ($row in $snap) { Enqueue-Tcp $row }
}

function Save-SystemBaseline {
  # Record the pre-TrafficWatch value of a system setting the first time we change it,
  # so Uninstall can restore it even after a crash. Existing keys are never overwritten.
  param([string]$Key, [string]$Value)
  try {
    $dir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $path = Join-Path $dir 'system_baseline.json'
    $map = @{}
    if (Test-Path $path) {
      $obj = (Get-Content -Raw -Path $path) | ConvertFrom-Json
      foreach ($p in $obj.PSObject.Properties) { $map[$p.Name] = [string]$p.Value }
    }
    if ($map.ContainsKey($Key)) { return }
    $map[$Key] = $Value
    [System.IO.File]::WriteAllText($path, ($map | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding $false))
  } catch {}
}

function Enable-DnsLog {
  try {
    $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration 'Microsoft-Windows-DNS-Client/Operational'
    if (-not $cfg.IsEnabled) {
      Save-SystemBaseline -Key 'dns_client_operational' -Value 'disabled'
      $cfg.IsEnabled = $true
      $cfg.SaveChanges()
    }
    $script:LogEnabled = [bool]$cfg.IsEnabled
    if (-not $script:LogEnabled) { $script:LogError = 'Operational log still disabled' }
  } catch {
    $script:LogEnabled = $false
    $script:LogError = $_.Exception.Message
  }
}

function Start-DnsWatch {
  if ($script:Watcher) { return $true }
  Enable-DnsLog
  try {
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery (
      'Microsoft-Windows-DNS-Client/Operational',
      [System.Diagnostics.Eventing.Reader.PathType]::LogName,
      '*'
    )
    $w = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($q)
    $md = @{ Queue = $script:DnsQueue }
    $null = Register-ObjectEvent -InputObject $w -EventName EventRecordWritten -SourceIdentifier 'TW-DnsWritten' -MessageData $md -Action {
      try {
        $e = $EventArgs
        if (-not $e -or -not $e.EventRecord) { return }
        $rec = $e.EventRecord
        $name = $null
        $status = $null
        $resultsRaw = $null
        try {
          $xml = [xml]$rec.ToXml()
          foreach ($d in @($xml.Event.EventData.Data)) {
            if (-not $d.Name) { continue }
            $val = [string]$d.'#text'
            switch ($d.Name) {
              'QueryName' { $name = $val }
              'Name' { if (-not $name) { $name = $val } }
              'QueryStatus' { $status = $val }
              'QueryResults' { $resultsRaw = $val }
              'Address' { if (-not $resultsRaw) { $resultsRaw = $val } }
              'IPAddress' { if (-not $resultsRaw) { $resultsRaw = $val } }
              'IpAddress' { if (-not $resultsRaw) { $resultsRaw = $val } }
            }
          }
        } catch { return }
        if (-not $name) { $name = '' }
        $name = $name.Trim().TrimEnd('.')
        $ips = New-Object System.Collections.Generic.List[string]
        if ($resultsRaw) {
          $rx4 = [regex]'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b'
          foreach ($m in $rx4.Matches($resultsRaw)) {
            $ip = $m.Value
            if (-not $ips.Contains($ip)) { [void]$ips.Add($ip) }
          }
        }
        if (-not $name -and $ips.Count -eq 0) { return }
        $stNum = 0
        [void][int]::TryParse($status, [ref]$stNum)
        $nx = $false
        if ($stNum -eq 9003 -or $stNum -eq 0x232B) { $nx = $true }
        if ($status -and ($status -match 'NXDOMAIN')) { $nx = $true }
        if ($resultsRaw -and ($resultsRaw -match 'NXDOMAIN')) { $nx = $true }
        $procId = 0
        try { $procId = [int]$rec.ProcessId } catch { $procId = 0 }
        $proc = $null
        if ($procId -gt 0) {
          try { $proc = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch {
            try { $proc = [System.Diagnostics.Process]::GetProcessById($procId).ProcessName } catch { $proc = $null }
          }
        }
        $ts = [datetime]::UtcNow.ToString('o')
        try { $ts = $rec.TimeCreated.ToUniversalTime().ToString('o') } catch {}
        $row = @{
          t = 'dns'
          pid = $(if ($procId -gt 0) { $procId } else { $null })
          proc = $proc
          name = $(if ($name) { $name } else { $null })
          status = $(if ($status) { $status } else { $null })
          nxdomain = $nx
          results = @($ips)
          ts = $ts
        }
        [void]$Event.MessageData.Queue.Enqueue($row)
      } catch {}
    }
    $w.Enabled = $true
    $script:Watcher = $w
    $script:DnsEnabled = $true
    return $true
  } catch {
    $script:LastError = $_.Exception.Message
    $script:DnsEnabled = $false
    $script:LogError = $script:LastError
    return $false
  }
}

function Drain-DnsQueue {
  $item = $null
  while ($script:DnsQueue.TryDequeue([ref]$item)) {
    $script:EventsCount++
    Send-Obj $item
  }
}

function Drain-TcpQueue {
  Flush-TcpBytes
  $item = $null
  while ($script:TcpQueue.TryDequeue([ref]$item)) {
    $script:TcpEventsCount++
    Send-Obj $item
  }
}

function Drain-AllQueues {
  Drain-DnsQueue
  Drain-TcpQueue
}

function Stop-DnsWatch {
  try {
    Unregister-Event -SourceIdentifier 'TW-DnsWritten' -ErrorAction SilentlyContinue
    Get-Event -SourceIdentifier 'TW-DnsWritten' -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
  } catch {}
  if ($script:Watcher) {
    try { $script:Watcher.Enabled = $false } catch {}
    try { $script:Watcher.Dispose() } catch {}
    $script:Watcher = $null
  }
  $script:DnsEnabled = $false
}

function Enable-KernelNetworkLog {
  try {
    $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration 'Microsoft-Windows-Kernel-Network/Analytic'
    $script:KnLogWasEnabled = [bool]$cfg.IsEnabled
    if (-not $cfg.IsEnabled) {
      Save-SystemBaseline -Key 'kernel_network_analytic' -Value 'disabled'
      $cfg.IsEnabled = $true
      $cfg.SaveChanges()
    }
    return [bool]$cfg.IsEnabled
  } catch {
    $script:TcpError = ('Kernel-Network enable: ' + $_.Exception.Message)
    return $false
  }
}

function Restore-KernelNetworkLog {
  if ($null -eq $script:KnLogWasEnabled) { return }
  try {
    $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration 'Microsoft-Windows-Kernel-Network/Analytic'
    if ([bool]$cfg.IsEnabled -ne [bool]$script:KnLogWasEnabled) {
      $cfg.IsEnabled = [bool]$script:KnLogWasEnabled
      $cfg.SaveChanges()
    }
  } catch {}
  $script:KnLogWasEnabled = $null
}

function Parse-KnEvent {
  param($rec)
  # Returns hashtable action=send|recv|connect|accept|close + fields, or $null
  try {
    $id = [int]$rec.Id
  } catch { return $null }
  # IPv4: 10 send, 11 recv, 12 connect, 13 disconnect, 15 accept
  # IPv6: 26 send, 27 recv, 28 connect, 29 disconnect, 31 accept
  $action = $null
  switch ($id) {
    10 { $action = 'send' }
    11 { $action = 'recv' }
    12 { $action = 'connect' }
    13 { $action = 'close' }
    15 { $action = 'accept' }
    26 { $action = 'send' }
    27 { $action = 'recv' }
    28 { $action = 'connect' }
    29 { $action = 'close' }
    31 { $action = 'accept' }
    default { return $null }
  }
  $procId = 0
  $size = [long]0
  $saddr = $null
  $daddr = $null
  $sport = $null
  $dport = $null
  try {
    $xml = [xml]$rec.ToXml()
    foreach ($d in @($xml.Event.EventData.Data)) {
      if (-not $d.Name) { continue }
      $val = [string]$d.'#text'
      switch ($d.Name) {
        'PID' { [void][int]::TryParse($val, [ref]$procId) }
        'ProcessId' { if ($procId -le 0) { [void][int]::TryParse($val, [ref]$procId) } }
        'size' { [void][long]::TryParse($val, [ref]$size) }
        'Size' { if ($size -le 0) { [void][long]::TryParse($val, [ref]$size) } }
        'saddr' { $saddr = Convert-UIntToIPv4 $val; if (-not $saddr) { $saddr = $val } }
        'daddr' { $daddr = Convert-UIntToIPv4 $val; if (-not $daddr) { $daddr = $val } }
        'SourceAddress' { if (-not $saddr) { $saddr = Convert-UIntToIPv4 $val; if (-not $saddr) { $saddr = $val } } }
        'DestAddress' { if (-not $daddr) { $daddr = Convert-UIntToIPv4 $val; if (-not $daddr) { $daddr = $val } } }
        'sport' { $sport = 0; [void][int]::TryParse($val, [ref]$sport) }
        'dport' { $dport = 0; [void][int]::TryParse($val, [ref]$dport) }
        'SourcePort' { if ($null -eq $sport) { $sport = 0; [void][int]::TryParse($val, [ref]$sport) } }
        'DestPort' { if ($null -eq $dport) { $dport = 0; [void][int]::TryParse($val, [ref]$dport) } }
      }
    }
  } catch { return $null }
  if ($procId -le 0) {
    try { $procId = [int]$rec.ProcessId } catch { $procId = 0 }
  }
  # Local/remote by action: connect/send use saddr=local; accept uses daddr as local peer view
  $lip = $saddr; $lport = $sport; $rip = $daddr; $rport = $dport
  $dir = 'connect'
  if ($action -eq 'accept') {
    $dir = 'accept'
    # accept: saddr often remote, daddr local -- swap if needed later via psutil match
    $lip = $daddr; $lport = $dport; $rip = $saddr; $rport = $sport
  } elseif ($action -eq 'recv') {
    # recv still saddr=local typically
    $dir = 'connect'
  }
  return @{
    action = $action
    dir = $dir
    pid = $(if ($procId -gt 0) { $procId } else { $null })
    size = $size
    local_ip = $lip
    local_port = $lport
    remote_ip = $rip
    remote_port = $rport
  }
}

function Start-KernelNetworkWatch {
  if (-not (Enable-KernelNetworkLog)) { return $false }
  try {
    # Filter to TCP connect/send/recv/accept/disconnect (v4+v6)
    $xpath = '*[System[(EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=15 or EventID=26 or EventID=27 or EventID=28 or EventID=29 or EventID=31)]]'
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery (
      'Microsoft-Windows-Kernel-Network/Analytic',
      [System.Diagnostics.Eventing.Reader.PathType]::LogName,
      $xpath
    )
    $w = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($q)
    $null = Register-ObjectEvent -InputObject $w -EventName EventRecordWritten -SourceIdentifier 'TW-TcpKnWritten' -Action {
      # Count before any work; once the storm guard trips, do nothing per event.
      $global:TwKnSeen++
      if ($global:TwStormTripped) { return }
      try {
        $e = $EventArgs
        if (-not $e -or -not $e.EventRecord) { return }
        $rec = $e.EventRecord
        $id = 0
        try { $id = [int]$rec.Id } catch { return }
        $action = $null
        switch ($id) {
          10 { $action = 'send' }
          11 { $action = 'recv' }
          12 { $action = 'connect' }
          13 { $action = 'close' }
          15 { $action = 'accept' }
          26 { $action = 'send' }
          27 { $action = 'recv' }
          28 { $action = 'connect' }
          29 { $action = 'close' }
          31 { $action = 'accept' }
          default { return }
        }
        $procId = 0
        $size = [long]0
        $saddrRaw = $null
        $daddrRaw = $null
        $sport = $null
        $dport = $null
        try {
          $xml = [xml]$rec.ToXml()
          foreach ($d in @($xml.Event.EventData.Data)) {
            if (-not $d.Name) { continue }
            $val = [string]$d.'#text'
            switch ($d.Name) {
              'PID' { [void][int]::TryParse($val, [ref]$procId) }
              'size' { [void][long]::TryParse($val, [ref]$size) }
              'saddr' { $saddrRaw = $val }
              'daddr' { $daddrRaw = $val }
              'sport' { $sport = 0; [void][int]::TryParse($val, [ref]$sport) }
              'dport' { $dport = 0; [void][int]::TryParse($val, [ref]$dport) }
            }
          }
        } catch { return }
        function _u2ip([string]$raw) {
          if (-not $raw) { return $null }
          if ($raw -match '^\d+\.\d+\.\d+\.\d+$') { return $raw }
          $n = [uint32]0
          if (-not [uint32]::TryParse($raw, [ref]$n)) { return $raw }
          $b = [BitConverter]::GetBytes($n)
          return ('{0}.{1}.{2}.{3}' -f $b[0], $b[1], $b[2], $b[3])
        }
        $saddr = _u2ip $saddrRaw
        $daddr = _u2ip $daddrRaw
        if ($procId -le 0) { try { $procId = [int]$rec.ProcessId } catch { $procId = 0 } }
        $proc = $null
        if ($procId -gt 0) {
          # Per-packet Get-Process was a large share of the per-event cost; cache names.
          if (-not $global:TwProcNames) { $global:TwProcNames = @{} }
          if ($global:TwProcNames.ContainsKey($procId)) {
            $proc = $global:TwProcNames[$procId]
          } else {
            try { $proc = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { $proc = $null }
            if ($global:TwProcNames.Count -gt 2000) { $global:TwProcNames.Clear() }
            $global:TwProcNames[$procId] = $proc
          }
        }
        $lip = $saddr; $lport = $sport; $rip = $daddr; $rport = $dport
        $dir = 'connect'
        if ($action -eq 'accept') {
          $dir = 'accept'
          $lip = $daddr; $lport = $dport; $rip = $saddr; $rport = $sport
        }
        $ts = [datetime]::UtcNow.ToString('o')
        try { $ts = $rec.TimeCreated.ToUniversalTime().ToString('o') } catch {}
        $payload = @{
          action = $action
          dir = $dir
          pid = $(if ($procId -gt 0) { $procId } else { $null })
          proc = $proc
          local_ip = $lip
          local_port = $lport
          remote_ip = $rip
          remote_port = $rport
          size = $size
          ts = $ts
        }
        # Stash on a static queue via synchronized hashtable
        if (-not $global:TwTcpKnInbox) {
          $global:TwTcpKnInbox = New-Object System.Collections.Concurrent.ConcurrentQueue[object]
        }
        [void]$global:TwTcpKnInbox.Enqueue($payload)
      } catch {}
    }
    $w.Enabled = $true
    $script:TcpWatcher = $w
    if (-not $global:TwTcpKnInbox) {
      $global:TwTcpKnInbox = New-Object System.Collections.Concurrent.ConcurrentQueue[object]
    }
    $script:TcpSource = 'kernel-network'
    $script:TcpEnabled = $true
    $script:TcpError = ''
    return $true
  } catch {
    $script:TcpError = $_.Exception.Message
    return $false
  }
}

function Consume-KnInbox {
  if (-not $global:TwTcpKnInbox) { return }
  $item = $null
  $n = 0
  while ($global:TwTcpKnInbox.TryDequeue([ref]$item)) {
    $n++
    if ($n -gt 2000) {
      $script:TcpLimited = $true
      # drain rest without processing
      while ($global:TwTcpKnInbox.TryDequeue([ref]$item)) { $script:TcpStormDrops++ }
      break
    }
    $a = [string]$item.action
    $procId = $item.pid
    $proc = $item.proc
    if ($a -eq 'connect' -or $a -eq 'accept') {
      Upsert-TcpFlow -Kind 'open' -Dir $item.dir -PidVal $procId -Proc $proc `
        -LocalIp $item.local_ip -LocalPort $item.local_port `
        -RemoteIp $item.remote_ip -RemotePort $item.remote_port -Ts $item.ts
    } elseif ($a -eq 'send') {
      Upsert-TcpFlow -Kind 'bytes' -Dir $item.dir -PidVal $procId -Proc $proc `
        -LocalIp $item.local_ip -LocalPort $item.local_port `
        -RemoteIp $item.remote_ip -RemotePort $item.remote_port `
        -AddOut ([long]$item.size) -Ts $item.ts
    } elseif ($a -eq 'recv') {
      Upsert-TcpFlow -Kind 'bytes' -Dir $item.dir -PidVal $procId -Proc $proc `
        -LocalIp $item.local_ip -LocalPort $item.local_port `
        -RemoteIp $item.remote_ip -RemotePort $item.remote_port `
        -AddIn ([long]$item.size) -Ts $item.ts
    } elseif ($a -eq 'close') {
      Upsert-TcpFlow -Kind 'close' -Dir $item.dir -PidVal $procId -Proc $proc `
        -LocalIp $item.local_ip -LocalPort $item.local_port `
        -RemoteIp $item.remote_ip -RemotePort $item.remote_port -Ts $item.ts
    }
  }
}

function Get-AuditPolState {
  $out = @{ success = $null; failure = $null }
  try {
    $raw = & auditpol.exe /get /subcategory:"Filtering Platform Connection" 2>&1 | Out-String
    if ($raw -match '(?i)Success\s*[:=]\s*(\w+)') { $out.success = $Matches[1] }
    if ($raw -match '(?i)Failure\s*[:=]\s*(\w+)') { $out.failure = $Matches[1] }
    # alternate format: "Filtering Platform Connection  Success  Failure"
    if (-not $out.success -and $raw -match '(?i)Filtering Platform Connection\s+(\w+)\s+(\w+)') {
      $out.success = $Matches[1]
      $out.failure = $Matches[2]
    }
  } catch {}
  return $out
}

function Enable-WfpAudit {
  $prev = Get-AuditPolState
  $script:AuditPolPrevSuccess = $prev.success
  $script:AuditPolPrevFailure = $prev.failure
  $already = ($prev.success -match '(?i)enable')
  if ($already) {
    $script:AuditPolChanged = $false
    return $true
  }
  try {
    Save-SystemBaseline -Key 'auditpol_wfp_connection' -Value ('success=' + $prev.success + ';failure=' + $prev.failure)
    $null = & auditpol.exe /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable 2>&1
    $script:AuditPolChanged = $true
    return $true
  } catch {
    $script:TcpError = ('auditpol: ' + $_.Exception.Message)
    return $false
  }
}

function Restore-WfpAudit {
  if (-not $script:AuditPolChanged) { return }
  try {
    $s = 'disable'
    $f = 'disable'
    if ($script:AuditPolPrevSuccess -match '(?i)enable') { $s = 'enable' }
    if ($script:AuditPolPrevFailure -match '(?i)enable') { $f = 'enable' }
    $null = & auditpol.exe /set /subcategory:"Filtering Platform Connection" /success:$s /failure:$f 2>&1
  } catch {}
  $script:AuditPolChanged = $false
}

function Start-WfpWatch {
  if (-not (Enable-WfpAudit)) { return $false }
  try {
    $xpath = '*[System[(EventID=5156 or EventID=5158)]]'
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery (
      'Security',
      [System.Diagnostics.Eventing.Reader.PathType]::LogName,
      $xpath
    )
    $w = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($q)
    $null = Register-ObjectEvent -InputObject $w -EventName EventRecordWritten -SourceIdentifier 'TW-TcpWfpWritten' -Action {
      $global:TwWfpSeen++
      if ($global:TwStormTripped) { return }
      try {
        $e = $EventArgs
        if (-not $e -or -not $e.EventRecord) { return }
        $rec = $e.EventRecord
        $id = 0
        try { $id = [int]$rec.Id } catch { return }
        if ($id -ne 5156 -and $id -ne 5158) { return }
        $procId = 0
        $app = $null
        $dirRaw = ''
        $src = $null
        $dst = $null
        $sport = $null
        $dport = $null
        $proto = $null
        try {
          $xml = [xml]$rec.ToXml()
          foreach ($d in @($xml.Event.EventData.Data)) {
            if (-not $d.Name) { continue }
            $val = [string]$d.'#text'
            switch ($d.Name) {
              'ProcessID' { [void][int]::TryParse($val, [ref]$procId) }
              'Application' { $app = $val }
              'Direction' { $dirRaw = $val }
              'SourceAddress' { $src = $val }
              'DestAddress' { $dst = $val }
              'SourcePort' { $sport = 0; [void][int]::TryParse($val, [ref]$sport) }
              'DestPort' { $dport = 0; [void][int]::TryParse($val, [ref]$dport) }
              'Protocol' { $proto = $val }
            }
          }
        } catch { return }
        # TCP only (6)
        if ($proto -and $proto -ne '6' -and $proto -ne 'TCP') { return }
        $dir = 'connect'
        if ($dirRaw -match '14592|Inbound|%%14592') { $dir = 'accept' }
        elseif ($dirRaw -match '14593|Outbound|%%14593') { $dir = 'connect' }
        $proc = $null
        if ($app) {
          try { $proc = [System.IO.Path]::GetFileNameWithoutExtension($app) } catch { $proc = $app }
        }
        if (-not $proc -and $procId -gt 0) {
          try { $proc = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch {}
        }
        # Direction: outbound connect -> local=src remote=dst; inbound accept -> local=dst remote=src
        if ($dir -eq 'accept') {
          $lip = $dst; $lport = $dport; $rip = $src; $rport = $sport
        } else {
          $lip = $src; $lport = $sport; $rip = $dst; $rport = $dport
        }
        $ts = [datetime]::UtcNow.ToString('o')
        try { $ts = $rec.TimeCreated.ToUniversalTime().ToString('o') } catch {}
        if (-not $global:TwTcpWfpInbox) {
          $global:TwTcpWfpInbox = New-Object System.Collections.Concurrent.ConcurrentQueue[object]
        }
        [void]$global:TwTcpWfpInbox.Enqueue(@{
          action = $(if ($id -eq 5158) { 'bind' } else { 'open' })
          dir = $dir
          pid = $(if ($procId -gt 0) { $procId } else { $null })
          proc = $proc
          local_ip = $lip
          local_port = $lport
          remote_ip = $rip
          remote_port = $rport
          ts = $ts
        })
      } catch {}
    }
    $w.Enabled = $true
    $script:WfpWatcher = $w
    if (-not $global:TwTcpWfpInbox) {
      $global:TwTcpWfpInbox = New-Object System.Collections.Concurrent.ConcurrentQueue[object]
    }
    $script:TcpSource = 'wfp'
    $script:TcpEnabled = $true
    $script:TcpLimited = $true  # WFP has direction, not bytes
    if (-not $script:TcpError) { $script:TcpError = 'WFP direction only (no per-flow bytes)' }
    return $true
  } catch {
    $script:TcpError = $_.Exception.Message
    Restore-WfpAudit
    return $false
  }
}

function Consume-WfpInbox {
  if (-not $global:TwTcpWfpInbox) { return }
  $item = $null
  $n = 0
  while ($global:TwTcpWfpInbox.TryDequeue([ref]$item)) {
    $n++
    if ($n -gt 1500) {
      $script:TcpLimited = $true
      while ($global:TwTcpWfpInbox.TryDequeue([ref]$item)) { $script:TcpStormDrops++ }
      break
    }
    if ([string]$item.action -eq 'bind') { continue }
    Upsert-TcpFlow -Kind 'open' -Dir $item.dir -PidVal $item.pid -Proc $item.proc `
      -LocalIp $item.local_ip -LocalPort $item.local_port `
      -RemoteIp $item.remote_ip -RemotePort $item.remote_port -Ts $item.ts
  }
}

function Invoke-StormGuard {
  # Called from the main loops (every ~200 ms - 1 s); evaluates once per second.
  $now = [datetime]::UtcNow
  if ($null -eq $script:StormLastUtc) {
    $script:StormLastUtc = $now
    $script:StormLastSeen = [long]($global:TwKnSeen + $global:TwWfpSeen)
    $script:StormHotRate = 0
    $script:StormHotIntr = 0
    return
  }
  $dt = ($now - $script:StormLastUtc).TotalSeconds
  if ($dt -lt 1.0) { return }
  $seen = [long]($global:TwKnSeen + $global:TwWfpSeen)
  $rate = ($seen - $script:StormLastSeen) / $dt
  $script:StormLastUtc = $now
  $script:StormLastSeen = $seen
  $script:StormRate = [int]$rate
  if (-not $script:TcpEnabled) { $script:StormHotRate = 0; $script:StormHotIntr = 0; return }

  if ($rate -gt $StormEventsPerSec) { $script:StormHotRate++ } else { $script:StormHotRate = 0 }

  $intr = -1
  if (-not $script:IntrCounterFailed) { try {
    if (-not $script:IntrCounter) {
      $script:IntrCounter = New-Object System.Diagnostics.PerformanceCounter('Processor', '% Interrupt Time', '_Total')
      $script:DpcCounter = New-Object System.Diagnostics.PerformanceCounter('Processor', '% DPC Time', '_Total')
      [void]$script:IntrCounter.NextValue(); [void]$script:DpcCounter.NextValue()
    } else {
      $intr = [double]$script:IntrCounter.NextValue() + [double]$script:DpcCounter.NextValue()
    }
  } catch {
    $intr = -1
    $script:IntrCounterFailed = $true
    $script:IntrCounter = $null
    $script:DpcCounter = $null
  } }
  $script:StormIntrPct = [int][Math]::Max(0, $intr)
  if ($intr -gt $StormIntrDpcPct) { $script:StormHotIntr++ } else { $script:StormHotIntr = 0 }

  $why = $null
  if ($script:StormHotRate -ge 3) { $why = ('event storm: {0}/s for 3s (limit {1}/s)' -f [int]$rate, $StormEventsPerSec) }
  elseif ($script:StormHotIntr -ge 3) { $why = ('interrupt+DPC CPU {0}% for 3s (limit {1}%)' -f [int]$intr, $StormIntrDpcPct) }
  if ($why) { Invoke-StormFailSoft $why }
}

function Invoke-StormFailSoft([string]$Why) {
  $global:TwStormTripped = $true
  $src = $script:TcpSource
  Stop-TcpWatch
  # Restore only returns the log to its pre-helper state; if it was already on,
  # the kernel keeps paying per-packet cost. Force it off on a storm.
  try {
    $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration 'Microsoft-Windows-Kernel-Network/Analytic'
    if ($cfg.IsEnabled) { $cfg.IsEnabled = $false; $cfg.SaveChanges() }
  } catch {}
  $script:TcpSource = 'none'
  $script:TcpLimited = $true
  $script:StormTrippedUtc = [datetime]::UtcNow
  $script:StormTrips++
  if ($script:StormTrips -ge 3) {
    $next = 'Live capture stays off until you restart it (Settings: Enable live DNS).'
  } else {
    $next = 'Retry allowed after ' + [int](($StormCooldownSec * [Math]::Pow(2, $script:StormTrips - 1)) / 60) + ' min.'
  }
  $script:TcpError = ('Paused ' + $src + ' capture to protect the PC (' + $Why + '). Connections still update from the normal poll. ' + $next)
  $script:StormHotRate = 0
  $script:StormHotIntr = 0
  try { if ($script:Writer) { Send-Obj (Get-StatusObj) } } catch {}
}

function Start-TcpWatch {
  if ($script:TcpEnabled) { return $true }
  if ($script:StormTrips -ge 3) {
    # Tripped three times this helper session: stay poll-only until the helper restarts.
    $script:TcpLimited = $true
    return $false
  }
  $cool = $StormCooldownSec * [Math]::Pow(2, [Math]::Max(0, $script:StormTrips - 1))
  if ($script:StormTrippedUtc -and (([datetime]::UtcNow - $script:StormTrippedUtc).TotalSeconds -lt $cool)) {
    # Still cooling down after a storm trip: stay in poll-only mode.
    $script:TcpLimited = $true
    return $false
  }
  $global:TwStormTripped = $false
  # Prefer Kernel-Network Analytic (bytes + connect/accept). Fallback WFP 5156.
  if (Start-KernelNetworkWatch) { return $true }
  $knErr = $script:TcpError
  if (Start-WfpWatch) {
    if ($knErr) { $script:TcpError = ('KN failed (' + $knErr + '); using WFP') }
    return $true
  }
  $script:TcpEnabled = $false
  $script:TcpSource = 'none'
  $script:TcpLimited = $true
  return $false
}

function Stop-TcpWatch {
  try {
    Unregister-Event -SourceIdentifier 'TW-TcpKnWritten' -ErrorAction SilentlyContinue
    Get-Event -SourceIdentifier 'TW-TcpKnWritten' -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
  } catch {}
  try {
    Unregister-Event -SourceIdentifier 'TW-TcpWfpWritten' -ErrorAction SilentlyContinue
    Get-Event -SourceIdentifier 'TW-TcpWfpWritten' -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
  } catch {}
  if ($script:TcpWatcher) {
    try { $script:TcpWatcher.Enabled = $false } catch {}
    try { $script:TcpWatcher.Dispose() } catch {}
    $script:TcpWatcher = $null
  }
  if ($script:WfpWatcher) {
    try { $script:WfpWatcher.Enabled = $false } catch {}
    try { $script:WfpWatcher.Dispose() } catch {}
    $script:WfpWatcher = $null
  }
  Restore-KernelNetworkLog
  Restore-WfpAudit
  $script:TcpEnabled = $false
}

function Get-StatusObj {
  return @{
    t = 'status'
    elevated = $true
    dns = [bool]$script:DnsEnabled
    log_enabled = [bool]$script:LogEnabled
    log_error = $script:LogError
    events = [int]$script:EventsCount
    limited = -not [bool]$script:DnsEnabled
    last_error = $script:LastError
    pipe = $PipeName
    tcp = [bool]$script:TcpEnabled
    tcp_source = $script:TcpSource
    tcp_events = [int]$script:TcpEventsCount
    tcp_limited = [bool]$script:TcpLimited
    tcp_error = $script:TcpError
    tcp_storm_drops = [int]$script:TcpStormDrops
    storm_trips = [int]$script:StormTrips
    storm_event_rate = [int]$script:StormRate
    storm_intr_dpc_pct = [int]$script:StormIntrPct
    ts = [datetime]::UtcNow.ToString('o')
  }
}

function Invoke-Op {
  param([string]$line)
  $line = ($line + '').Trim()
  if (-not $line) { return }
  $op = $null
  try {
    $msg = $line | ConvertFrom-Json
    $op = [string]$msg.op
  } catch {
    return
  }
  switch ($op) {
    'ping' { Send-Obj @{ t = 'pong'; ts = [datetime]::UtcNow.ToString('o') } }
    'status' { Send-Obj (Get-StatusObj) }
    'dns_start' {
      $ok = Start-DnsWatch
      # Auto-start TCP alongside DNS (one helper, one UAC)
      $tok = Start-TcpWatch
      Send-Obj @{ t = 'ok'; op = 'dns_start'; ok = $ok; limited = -not $ok; tcp = $tok; tcp_limited = [bool]$script:TcpLimited }
    }
    'dns_stop' {
      Stop-DnsWatch
      Send-Obj @{ t = 'ok'; op = 'dns_stop' }
    }
    'tcp_start' {
      $ok = Start-TcpWatch
      Send-Obj @{ t = 'ok'; op = 'tcp_start'; ok = $ok; limited = [bool]$script:TcpLimited; source = $script:TcpSource }
    }
    'tcp_stop' {
      Stop-TcpWatch
      Send-Obj @{ t = 'ok'; op = 'tcp_stop' }
    }
    'shutdown' {
      Send-Obj @{ t = 'ok'; op = 'shutdown' }
      $script:Shutdown = $true
    }
    default { return }
  }
}

function Test-ParentGone {
  if ($ParentPid -le 0) { return $false }
  try {
    $p = Get-Process -Id $ParentPid -ErrorAction Stop
    return $false
  } catch {
    return $true
  }
}

function New-HelperPipe {
  Add-Type -AssemblyName System.Core
  $sec = New-Object System.IO.Pipes.PipeSecurity
  $ident = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $userSid = $ident.User
  $sysSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
  $right = [System.IO.Pipes.PipeAccessRights]::FullControl
  $allow = [System.Security.AccessControl.AccessControlType]::Allow
  $sec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($userSid, $right, $allow)))
  $sec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($sysSid, $right, $allow)))
  if ($ClientSid) {
    try {
      $cs = New-Object System.Security.Principal.SecurityIdentifier $ClientSid
      if ($cs -ne $userSid) {
        $sec.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule($cs, $right, $allow)))
      }
    } catch {}
  }
  $dir = [System.IO.Pipes.PipeDirection]::InOut
  $mode = [System.IO.Pipes.PipeTransmissionMode]::Byte
  $opts = [System.IO.Pipes.PipeOptions]::Asynchronous
  return New-Object System.IO.Pipes.NamedPipeServerStream($PipeName, $dir, 1, $mode, $opts, 65536, 65536, $sec)
}

# --- main ---
Hide-Window
if (-not (Test-Elevated)) {
  Write-Error 'TrafficWatch helper must be started elevated (UAC).'
  exit 2
}

try {
  $script:Mutex = New-Object System.Threading.Mutex($false, ('Global\TrafficWatch-helper'))
  if (-not $script:Mutex.WaitOne(0)) {
    exit 0
  }
} catch {}

Enable-DnsLog
[void](Start-DnsWatch)
[void](Start-TcpWatch)

$utf8 = New-Object System.Text.UTF8Encoding $false

try {
  while (-not $script:Shutdown) {
    if (Test-ParentGone) { break }
    $idle = ([datetime]::UtcNow - $script:LastClientUtc).TotalSeconds
    if (-not $script:ClientConnected -and $idle -gt $IdleExitSec) { break }

    if ($script:Pipe) {
      try { $script:Pipe.Dispose() } catch {}
      $script:Pipe = $null
    }
    $script:Writer = $null
    $pipe = $null
    try { $pipe = New-HelperPipe } catch {
      $script:LastError = $_.Exception.Message
      Start-Sleep -Seconds 2
      continue
    }
    $script:Pipe = $pipe

    $connected = $false
    try {
      $iar = $pipe.BeginWaitForConnection($null, $null)
      while (-not $script:Shutdown) {
        if (Test-ParentGone) { $script:Shutdown = $true; break }
        $idle = ([datetime]::UtcNow - $script:LastClientUtc).TotalSeconds
        if ($idle -gt $IdleExitSec) { $script:Shutdown = $true; break }
        Consume-KnInbox
        Consume-WfpInbox
        Drain-AllQueues
        Invoke-StormGuard
        if ($iar.AsyncWaitHandle.WaitOne(1000)) {
          $pipe.EndWaitForConnection($iar)
          $connected = $true
          break
        }
      }
    } catch {
      $script:LastError = 'pipe wait failed'
      Start-Sleep -Milliseconds 400
      continue
    }
    if (-not $connected) { break }

    $script:ClientConnected = $true
    $script:LastClientUtc = [datetime]::UtcNow
    $reader = $null
    try {
      $script:Writer = New-Object System.IO.StreamWriter($pipe, $utf8, 65536, $true)
      $script:Writer.AutoFlush = $true
      $reader = New-Object System.IO.StreamReader($pipe, $utf8, $false, 65536, $true)
      Send-Obj (Get-StatusObj)
      while (-not $script:Shutdown -and $pipe.IsConnected) {
        if (Test-ParentGone) { $script:Shutdown = $true; break }
        try {
          $iar2 = $reader.ReadLineAsync()
          while (-not $iar2.IsCompleted) {
            if ($script:Shutdown) { break }
            if (Test-ParentGone) { $script:Shutdown = $true; break }
            Consume-KnInbox
            Consume-WfpInbox
            Drain-AllQueues
            Invoke-StormGuard
            Start-Sleep -Milliseconds 200
          }
          if ($script:Shutdown) { break }
          $line = $iar2.Result
          if ($null -eq $line) { break }
          $script:LastClientUtc = [datetime]::UtcNow
          Invoke-Op $line
        } catch {
          break
        }
      }
    } finally {
      $script:ClientConnected = $false
      $script:LastClientUtc = [datetime]::UtcNow
      $script:Writer = $null
      try { if ($reader) { $reader.Dispose() } } catch {}
      try { $pipe.Disconnect() } catch {}
    }
  }
} finally {
  Stop-DnsWatch
  Stop-TcpWatch
  try { if ($script:Pipe) { $script:Pipe.Dispose() } } catch {}
  try { if ($script:Mutex) { $script:Mutex.ReleaseMutex(); $script:Mutex.Dispose() } } catch {}
}

exit 0
