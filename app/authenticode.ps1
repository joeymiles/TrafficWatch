param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)
$ErrorActionPreference = 'Stop'
# Cloud placeholders (OneDrive etc) can hang Get-AuthenticodeSignature forever.
if ($Path -match '(?i)OneDrive|\\CloudStorage\\|\\iCloudDrive|Dropbox|Google Drive') {
  @{ Status = 'Skipped'; Publisher = $null; Issuer = $null; Expired = $null } | ConvertTo-Json -Compress
  exit 0
}
$s = Get-AuthenticodeSignature -LiteralPath $Path
$pub = $null
$iss = $null
$exp = $null
if ($s.SignerCertificate) {
    $pub = $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    $iss = $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
    $exp = ($s.SignerCertificate.NotAfter -lt (Get-Date))
}
@{ Status = [string]$s.Status; Publisher = $pub; Issuer = $iss; Expired = $exp } | ConvertTo-Json -Compress
