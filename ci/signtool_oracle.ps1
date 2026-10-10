# Runs the real SignTool and imagehlp on every file of a directory and records the raw
# results (no interpretation) in <out>/raw.json, for `signtool_oracle.py extract`.
#
#   pwsh ci/signtool_oracle.ps1 -Fixtures work/fixtures -Out work/signtool
#
# For each file and each of SHA-1 and SHA-256:
#   - `signtool sign /dg` writes the unsigned PKCS #7 (.p7u) that holds the file digest;
#   - `signtool sign /fd <alg> /ph` signs a copy with page hashes;
# and for each file the image checksum by imagehlp (`MapFileAndCheckSumW` on the file and
# `CheckSumMappedFile` on a buffer in memory).
param(
    [Parameter(Mandatory = $true)][string]$Fixtures,
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$Fixtures = (Resolve-Path $Fixtures).Path
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path

$signtool = (Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
    Sort-Object { [version]($_.Directory.Parent.Name) } | Select-Object -Last 1).FullName
Write-Output "signtool: $signtool"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class ImageHlp {
    [DllImport("imagehlp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint MapFileAndCheckSumW(string fileName, out uint headerSum, out uint checkSum);

    [DllImport("imagehlp.dll", SetLastError = true)]
    public static extern IntPtr CheckSumMappedFile(IntPtr baseAddress, uint fileLength, out uint headerSum, out uint checkSum);

    // CheckSumMappedFile on a copy of the bytes in memory. Returns false when imagehlp
    // does not find PE headers.
    public static bool CheckSumBuffer(byte[] data, out uint headerSum, out uint checkSum) {
        GCHandle h = GCHandle.Alloc(data, GCHandleType.Pinned);
        try {
            IntPtr nt = CheckSumMappedFile(h.AddrOfPinnedObject(), (uint)data.Length, out headerSum, out checkSum);
            return nt != IntPtr.Zero;
        } finally {
            h.Free();
        }
    }
}
"@

$meta = [ordered]@{
    signtool         = $signtool
    signtool_version = (Get-Item $signtool).VersionInfo.FileVersion
    imagehlp_version = (Get-Item "$env:SystemRoot\System32\imagehlp.dll").VersionInfo.FileVersion
    os               = [System.Environment]::OSVersion.VersionString
    image_os         = $env:ImageOS
    image_version    = $env:ImageVersion
}

$pfx = Join-Path $Out 'cert.pfx'
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=rsigncode oracle' -CertStoreLocation Cert:\CurrentUser\My
$pw = ConvertTo-SecureString -String 'test' -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pw | Out-Null

function Invoke-SignTool([string[]]$Arguments) {
    $text = (& $signtool @Arguments 2>&1 | Out-String).Trim()
    [ordered]@{ exit = $LASTEXITCODE; output = $text.Replace($Out, '<out>').Replace($Fixtures, '<fixtures>') }
}

$files = [ordered]@{}
foreach ($f in (Get-ChildItem $Fixtures -File | Sort-Object Name)) {
    $name = $f.BaseName
    $entry = [ordered]@{ file = $f.Name; size = $f.Length }

    $hs = [uint32]0; $cs = [uint32]0
    $ret = [ImageHlp]::MapFileAndCheckSumW($f.FullName, [ref]$hs, [ref]$cs)
    $entry.map_file_and_checksum = [ordered]@{ ret = $ret; header_sum = $hs; checksum = $cs }
    $hs = [uint32]0; $cs = [uint32]0
    $ok = [ImageHlp]::CheckSumBuffer([IO.File]::ReadAllBytes($f.FullName), [ref]$hs, [ref]$cs)
    $entry.checksum_mapped_file = [ordered]@{ found_headers = $ok; header_sum = $hs; checksum = $cs }

    foreach ($alg in 'sha1', 'sha256') {
        $dgDir = Join-Path $Out "dg/$alg"
        $signedDir = Join-Path $Out "signed/$alg"
        New-Item -ItemType Directory -Force $dgDir, $signedDir | Out-Null
        $dg = Invoke-SignTool @('sign', '/dg', $dgDir, '/fd', $alg, '/f', $pfx, '/p', 'test', $f.FullName)
        $copy = Join-Path $signedDir $f.Name
        Copy-Item $f.FullName $copy
        $sign = Invoke-SignTool @('sign', '/fd', $alg, '/ph', '/f', $pfx, '/p', 'test', $copy)
        $entry[$alg] = [ordered]@{
            dg     = $dg
            p7u    = "dg/$alg/$($f.Name).p7u"
            sign   = $sign
            signed = "signed/$alg/$($f.Name)"
        }
        Write-Output ("{0,-32} {1,-6} dg={2} sign={3}" -f $name, $alg, $dg.exit, $sign.exit)
    }
    $files[$name] = $entry
}

[ordered]@{ meta = $meta; files = $files } | ConvertTo-Json -Depth 8 |
    Out-File -Encoding utf8 (Join-Path $Out 'raw.json')
Remove-Item $pfx
