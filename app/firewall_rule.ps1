param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('block', 'unblock', 'list')]
    [string]$Action,
    [string]$Name = '',
    [string]$RemoteAddress = '',
    [ValidateSet('Inbound', 'Outbound')]
    [string]$Direction = 'Outbound',
    [string]$Prefix = 'TrafficWatch-block-',
    [string]$Description = 'TrafficWatch one-click block (user confirmed)'
)
$ErrorActionPreference = 'Stop'
if ($Action -eq 'list') {
    $rules = Get-NetFirewallRule -DisplayName ($Prefix + '*') -ErrorAction SilentlyContinue
    if (-not $rules) { Write-Output '[]'; exit 0 }
    $out = @()
    foreach ($r in @($rules)) {
        $addr = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r).RemoteAddress
        $out += [pscustomobject]@{
            name = $r.DisplayName
            enabled = [bool]$r.Enabled
            direction = [string]$r.Direction
            action = [string]$r.Action
            remote = ($addr -join ',')
            description = [string]$r.Description
        }
    }
    $out | ConvertTo-Json -Compress -Depth 3
    exit 0
}
if ($Action -eq 'block') {
    if (-not $Name -or -not $RemoteAddress) { throw 'Name and RemoteAddress required' }
    if (Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue) {
        Write-Output 'exists'
        exit 0
    }
    New-NetFirewallRule -DisplayName $Name -Direction $Direction -Action Block -RemoteAddress $RemoteAddress -Profile Any -Description $Description | Out-Null
    Write-Output 'created'
    exit 0
}
if ($Action -eq 'unblock') {
    if (-not $Name) { throw 'Name required' }
    $r = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
    if (-not $r) { Write-Output 'missing'; exit 0 }
    Remove-NetFirewallRule -DisplayName $Name
    Write-Output 'removed'
    exit 0
}
