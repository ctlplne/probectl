# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository. On its Change Date,
# each version converts to the Mozilla Public License 2.0.

#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary,
    [Parameter(Mandatory)][ValidateSet('x64', 'Arm64')][string]$Architecture
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') { throw 'The native Windows Installer tools are required.' }
$stage = Join-Path ([IO.Path]::GetTempPath()) ('.probectl-endpoint-payload-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stage)
try {
    $good = Join-Path $stage 'fixture.msi'
    $bad = Join-Path $stage 'wrong-digest.msi'
    $build = Join-Path $PSScriptRoot 'Build-EndpointMsi.ps1'
    $verify = Join-Path $PSScriptRoot 'Test-EndpointMsi.ps1'
    & $build -Binary $Binary -Architecture $Architecture -Version '0.0.1' -OutputMsi $good -TestUnsigned
    & $verify -Msi $good -Architecture $Architecture -ExpectedVersion '0.0.1' -AllowUnsignedFixture
    [IO.File]::Copy($good, $bad)

    $installer = $database = $view = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase($bad, 1)
        $otherDigest = '0' * 64
        $view = $database.OpenView(('UPDATE `Property` SET `Value` = ''{0}'' WHERE `Property` = ''ProbectlExecutableSHA256''' -f $otherDigest))
        $view.Execute()
        $view.Close()
        $database.Commit()
    } finally {
        foreach ($object in @($view, $database, $installer)) {
            if ($null -ne $object) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object) }
        }
    }

    $refused = $false
    try {
        & $verify -Msi $bad -Architecture $Architecture -ExpectedVersion '0.0.1' -AllowUnsignedFixture
    } catch {
        if ($_.Exception.Message -ne 'The embedded endpoint executable does not match the declared SHA-256.') { throw }
        $refused = $true
    }
    if (-not $refused) { throw 'The verifier accepted an incorrect executable digest.' }
    Write-Output 'The verifier accepted the native fixture and rejected its mismatched digest.'
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
