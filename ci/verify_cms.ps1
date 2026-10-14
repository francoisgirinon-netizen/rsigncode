# Has the Windows cryptographic API (SignedCms, CryptMsg underneath) verify the signatures
# that rsigncode builds, as a Markdown table on the output.
#
#   pwsh ci/verify_cms.ps1 -Signatures work/cms -Reference crates/rsigncode/tests/data
#
# <Signatures>/*.p7 are written by `examples/cms.rs`. Two controls keep the check honest:
# the signatures SignTool made (<Reference>/signtool_*.p7) must verify, or the harness is
# wrong; and a signature of rsigncode with its last byte changed must not. Exit status 1
# when a signature of rsigncode or a control does not behave as expected.
param(
    [Parameter(Mandatory = $true)][string]$Signatures,
    [Parameter(Mandatory = $true)][string]$Reference
)
$ErrorActionPreference = 'Stop'

# The signature only (`verifySignatureOnly`): the test certificates are self-signed.
function Test-Signature([byte[]]$Bytes) {
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    try {
        $cms.Decode($Bytes)
        $cms.CheckSignature($true)
        return $null
    } catch {
        return $_.Exception.Message.Trim()
    }
}

$failed = $false
$rows = @()
function Add-Row([string]$Name, [string]$Expect, $Error) {
    $ok = if ($Expect -eq 'valid') { $null -eq $Error } else { $null -ne $Error }
    if (-not $ok) { $script:failed = $true }
    $result = if ($null -eq $Error) { 'valid' } else { "refused: $Error" }
    $script:rows += "| $Name | $Expect | $result | $(if ($ok) { 'ok' } else { '**FAIL**' }) |"
}

foreach ($f in (Get-ChildItem $Reference -Filter 'signtool_*.p7' | Sort-Object Name)) {
    Add-Row "SignTool $($f.BaseName)" 'valid' (Test-Signature ([IO.File]::ReadAllBytes($f.FullName)))
}
foreach ($f in (Get-ChildItem $Signatures -Filter '*.p7' | Sort-Object Name)) {
    Add-Row "rsigncode $($f.BaseName)" 'valid' (Test-Signature ([IO.File]::ReadAllBytes($f.FullName)))
}
$bytes = [IO.File]::ReadAllBytes((Join-Path $Signatures 'rsa2048-sha256.p7'))
$bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 1
Add-Row 'rsigncode rsa2048-sha256, last byte changed' 'refused' (Test-Signature $bytes)

"### Windows verifies the signatures of rsigncode"
""
"| Signature | Expected | CryptoAPI | |"
"|---|---|---|---|"
$rows
if ($failed) { exit 1 }
