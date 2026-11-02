<#
.SYNOPSIS
  Signs one file with Azure Trusted Signing. package.ps1 calls it when GAINSAY_SIGN_SCRIPT points here.

.DESCRIPTION
  Needs the TrustedSigning PowerShell module and these environment variables:
    SIGNING_ENDPOINT   e.g. https://eus.codesigning.azure.net/
    SIGNING_ACCOUNT    the Trusted Signing account name
    SIGNING_PROFILE    the certificate profile name
  plus credentials Azure can read from the environment (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET).
  Any other signing service works too: point GAINSAY_SIGN_SCRIPT at your own script that takes the file path.
#>
param([Parameter(Mandatory)][string]$File)

$ErrorActionPreference = 'Stop'
foreach ($name in 'SIGNING_ENDPOINT', 'SIGNING_ACCOUNT', 'SIGNING_PROFILE') {
  if (-not [Environment]::GetEnvironmentVariable($name)) { throw "$name is not set." }
}

Invoke-TrustedSigning -Endpoint $env:SIGNING_ENDPOINT -CodeSigningAccountName $env:SIGNING_ACCOUNT `
  -CertificateProfileName $env:SIGNING_PROFILE -Files $File -FileDigest SHA256 `
  -TimestampRfc3161 'http://timestamp.acs.microsoft.com' -TimestampDigest SHA256

$sig = Get-AuthenticodeSignature $File
if ($sig.Status -ne 'Valid') { throw "Signature check failed: $($sig.Status)" }
Write-Host "Signed by $($sig.SignerCertificate.Subject)"
