# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary,
    [Parameter(Mandatory)][ValidateSet('x64', 'Arm64')][string]$Architecture
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or -not $env:RUNNER_TEMP) {
    throw 'The throwaway signing identity requires a GitHub-hosted Windows runner.'
}

$sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$signTool = Get-ChildItem $sdk -Recurse -Filter 'signtool.exe' |
    Where-Object { $_.Directory.Name -ceq 'x64' } |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($null -eq $signTool) { throw 'Windows SDK SignTool is unavailable.' }

function Sign-Fixture([string]$Path, [string]$Thumbprint) {
    & $signTool.FullName sign /sha1 $Thumbprint /fd SHA256 $Path
    if ($LASTEXITCODE -ne 0) { throw 'Could not sign the fixture.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne $Thumbprint) {
        throw 'The artifact failed validation against its exact offline fixture signer.'
    }
}

$work = Join-Path $env:RUNNER_TEMP ([Guid]::NewGuid().ToString())
[void](New-Item $work -ItemType Directory)
$certificate = $null
try {
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=probectl Windows packaging fixture' `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    $thumbprint = $certificate.Thumbprint
    $cer = Join-Path $work 'fixture.cer'
    Export-Certificate -Cert $certificate -FilePath $cer | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\CurrentUser\Root | Out-Null

    $executable = Join-Path $work 'probectl-endpoint.exe'
    $msi = Join-Path $work 'probectl-endpoint.msi'
    Copy-Item -LiteralPath $Binary -Destination $executable
    Sign-Fixture $executable $thumbprint

    $packaging = Join-Path $PSScriptRoot '..\deploy\packaging\windows'
    & (Join-Path $packaging 'Build-EndpointMsi.ps1') -Binary $executable -Architecture $Architecture `
        -Version '0.0.1' -OutputMsi $msi -TestUnsigned
    & (Join-Path $packaging 'Test-EndpointMsi.ps1') -Msi $msi -Architecture $Architecture `
        -ExpectedVersion '0.0.1' -AllowUnsignedFixture
    Sign-Fixture $msi $thumbprint
} finally {
    if ($null -ne $certificate) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\Root\$($certificate.Thumbprint)" -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $work -Recurse -Force
}
