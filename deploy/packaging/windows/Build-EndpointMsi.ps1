# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository. On its Change Date,
# each version converts to the Mozilla Public License 2.0.

#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Signed')]
param(
    [Parameter(Mandatory)][string]$Binary,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][ValidateSet('x64', 'Arm64')][string]$Architecture,
    [Parameter(Mandatory)][string]$OutputMsi,
    [Parameter(Mandatory, ParameterSetName = 'Signed')][string]$SignTool,
    [Parameter(Mandatory, ParameterSetName = 'Signed')][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory, ParameterSetName = 'Signed')][uri]$TimestampServer,
    [Parameter(Mandatory, ParameterSetName = 'Fixture')][switch]$TestUnsigned
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PortableExecutableMachine([string]$Path) {
    $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($Path))
    try {
        if ($reader.BaseStream.Length -lt 70 -or $reader.ReadUInt16() -ne 0x5A4D) {
            throw 'Endpoint input must be a Windows executable.'
        }
        $reader.BaseStream.Position = 0x3C
        $header = $reader.ReadUInt32()
        if ($header -lt 64 -or $header -gt ($reader.BaseStream.Length - 6)) {
            throw 'Endpoint executable has an invalid PE header.'
        }
        $reader.BaseStream.Position = $header
        if ($reader.ReadUInt32() -ne 0x4550) {
            throw 'Endpoint executable has an invalid PE signature.'
        }
        return $reader.ReadUInt16()
    } finally {
        $reader.Dispose()
    }
}

function Write-AsciiLines([string]$Path, [string]$Text) {
    $archive = ($Text -replace '\r?\n', "`r`n") + "`r`n"
    [IO.File]::WriteAllText($Path, $archive, [Text.Encoding]::ASCII)
}

function Import-MsiTable($Database, [string]$Directory, [string]$Name, [string]$Text) {
    $nameWithExtension = "$Name.idt"
    Write-AsciiLines (Join-Path $Directory $nameWithExtension) $Text
    $Database.Import($Directory, $nameWithExtension)
}

function Set-MsiIndexedProperty($Object, [string]$Property, [int]$Index, $Value) {
    [void]$Object.GetType().InvokeMember($Property, 'SetProperty', $null, $Object, @($Index, $Value))
}

function Release-ComObject($Object) {
    if ($null -ne $Object) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($Object)
    }
}

function Sign-Artifact([string]$Path) {
    & $SignTool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampServer.AbsoluteUri /td SHA256 $Path
    if ($LASTEXITCODE -ne 0) { throw 'SignTool could not sign the artifact.' }
}

function Confirm-ArtifactSignature([string]$Path) {
    & $SignTool verify /pa /all /tw $Path
    if ($LASTEXITCODE -ne 0) { throw 'The artifact failed Authenticode or timestamp verification.' }
}

if ($env:OS -ne 'Windows_NT') { throw 'The native Windows Installer tools are required.' }
if ($Version -notmatch '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4})$') {
    throw 'MSI version must have three numeric components.'
}
$productVersion = [version]$Version
if ($productVersion.Major -gt 255 -or $productVersion.Minor -gt 255 -or $productVersion.Build -gt 65535) {
    throw 'MSI version components must fit the Windows Installer ProductVersion range.'
}
if ($PSCmdlet.ParameterSetName -eq 'Fixture' -and -not $TestUnsigned) {
    throw 'An unsigned fixture requires -TestUnsigned.'
}
if (-not $TestUnsigned -and (-not $TimestampServer.IsAbsoluteUri -or $TimestampServer.Scheme -ne 'https' -or
    -not $TimestampServer.Host -or $TimestampServer.UserInfo -or $TimestampServer.Query -or $TimestampServer.Fragment)) {
    throw 'Use an HTTPS timestamp server URL without credentials, a query, or a fragment.'
}
$source = (Resolve-Path -LiteralPath $Binary).ProviderPath
$destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputMsi)
if ([IO.Path]::GetExtension($destination) -ine '.msi' -or (Test-Path -LiteralPath $destination)) {
    throw 'Choose a new .msi output path.'
}
$target = @{
    x64   = @{ Machine = 0x8664; Platform = 'x64';   Code = 1; Component = '{BD615766-F1F2-4C4F-94D2-A16016E622D4}' }
    Arm64 = @{ Machine = 0xAA64; Platform = 'Arm64'; Code = 2; Component = '{ECEC002B-9C05-4AA4-9738-FEB488C62746}' }
}[$Architecture]
# Product identity is stable for one version and architecture. The upgrade
# family spans architectures so a device carries at most one installation.
$productCode = '{{26C10E0D-E049-48B3-A376-{0:X2}{1:X2}{2:X4}{3:X4}}}' -f `
    $productVersion.Major, $productVersion.Minor, $productVersion.Build, $target.Code
$upgradeCode = '{D4C099E4-92DC-4737-BD24-758D2AB73508}'
$packageCode = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'
$parent = [IO.Path]::GetDirectoryName($destination)
[void][IO.Directory]::CreateDirectory($parent)
$stage = Join-Path $parent ('.probectl-endpoint-msi-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stage)

$payloadLease = $null
try {
    $payload = Join-Path $stage 'probectl-endpoint.exe'
    [IO.File]::Copy($source, $payload)
    if ((Get-PortableExecutableMachine $payload) -ne $target.Machine) {
        throw 'Endpoint executable does not match the package architecture.'
    }
    if (-not $TestUnsigned) { Sign-Artifact $payload }
    # Keep the same verified bytes readable by makecab while denying writes
    # and replacement after hashing.
    $payloadLease = [IO.File]::Open($payload, 'Open', 'Read', 'Read')
    if ((Get-PortableExecutableMachine $payload) -ne $target.Machine) {
        throw 'Endpoint executable does not match the package architecture.'
    }
    if (-not $TestUnsigned) { Confirm-ArtifactSignature $payload }
    $fileSize = $payloadLease.Length
    if ($fileSize -le 0 -or $fileSize -gt [int]::MaxValue) { throw 'Endpoint executable has an invalid MSI file size.' }
    $payloadDigest = (Get-FileHash -InputStream $payloadLease -Algorithm SHA256).Hash.ToLowerInvariant()
    $repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).ProviderPath
    $licensePath = Join-Path $stage 'LICENSE.txt'
    $noticePath = Join-Path $stage 'NOTICE.txt'
    [IO.File]::Copy((Join-Path $repo 'LICENSE'), $licensePath)
    [IO.File]::Copy((Join-Path $repo 'NOTICE'), $noticePath)
    $licenseSize = (Get-Item -LiteralPath $licensePath).Length
    $noticeSize = (Get-Item -LiteralPath $noticePath).Length

    # The cabinet member must match the key in the MSI File table.
    $cabinetInstructions = @'
.Set CabinetNameTemplate=endpoint.cab
.Set DiskDirectoryTemplate=.
.Set MaxDiskSize=0
.Set Cabinet=on
.Set Compress=on
.Set CompressionType=MSZIP
probectl-endpoint.exe EndpointExe
LICENSE.txt EndpointLicense
NOTICE.txt EndpointNotice
'@
    Write-AsciiLines (Join-Path $stage 'endpoint.ddf') $cabinetInstructions
    Push-Location -LiteralPath $stage
    try {
        & "$env:SystemRoot\System32\makecab.exe" /F endpoint.ddf
        if ($LASTEXITCODE -ne 0) { throw 'Could not build the endpoint payload cabinet.' }
    } finally {
        Pop-Location
    }
    $cabinet = Join-Path $stage 'endpoint.cab'
    if (-not (Test-Path -LiteralPath $cabinet -PathType Leaf)) { throw 'Endpoint cabinet was not created.' }

    $package = Join-Path $stage 'probectl-endpoint.msi'
    $installer = $database = $summary = $record = $view = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase($package, 3) # msiOpenDatabaseModeCreate
        Import-MsiTable $database $stage 'Property' @"
Property`tValue
s72`tl0
Property`tProperty
ProductCode`t$productCode
ProductVersion`t$Version
ProductLanguage`t1033
ProductName`tprobectl Endpoint
Manufacturer`tctlplne
UpgradeCode`t$upgradeCode
ALLUSERS`t1
ProbectlExecutableSHA256`t$payloadDigest
SecureCustomProperties`tPROBECTL_RELATED;PROBECTL_NEWER
"@
        Import-MsiTable $database $stage 'Directory' @"
Directory`tDirectory_Parent`tDefaultDir
s72`tS72`tl255
Directory`tDirectory
TARGETDIR`t`tSourceDir
ProgramFiles64Folder`tTARGETDIR`t.
ProbectlDir`tProgramFiles64Folder`tPROBECTL|probectl
EndpointDir`tProbectlDir`tENDPOINT|Endpoint
"@
        Import-MsiTable $database $stage 'Component' @"
Component`tComponentId`tDirectory_`tAttributes`tCondition`tKeyPath
s72`tS38`ts72`ti2`tS255`tS72
Component`tComponent
EndpointFiles`t$($target.Component)`tEndpointDir`t256`t`tEndpointExe
"@
        Import-MsiTable $database $stage 'File' @"
File`tComponent_`tFileName`tFileSize`tVersion`tLanguage`tAttributes`tSequence
s72`ts72`tl255`ti4`tS72`tS20`tI2`ti4
File`tFile
EndpointExe`tEndpointFiles`tPROBEEND.EXE|probectl-endpoint.exe`t$fileSize`t`t`t16896`t1
EndpointLicense`tEndpointFiles`tLICENSE.txt`t$licenseSize`t`t`t16896`t2
EndpointNotice`tEndpointFiles`tNOTICE.txt`t$noticeSize`t`t`t16896`t3
"@
        Import-MsiTable $database $stage 'Feature' @"
Feature`tFeature_Parent`tTitle`tDescription`tDisplay`tLevel`tDirectory_`tAttributes
s38`tS38`tL64`tL255`tI2`ti2`tS72`ti2
Feature`tFeature
Endpoint`t`tprobectl Endpoint`tDigital experience monitoring for managed devices`t1`t1`tEndpointDir`t0
"@
        Import-MsiTable $database $stage 'FeatureComponents' @"
Feature_`tComponent_
s38`ts72
FeatureComponents`tFeature_`tComponent_
Endpoint`tEndpointFiles
"@
        Import-MsiTable $database $stage 'Media' @"
DiskId`tLastSequence`tDiskPrompt`tCabinet`tVolumeLabel`tSource
i2`ti4`tL64`tS255`tS32`tS72
Media`tDiskId
1`t3`t`t#endpoint.cab`t`t
"@
        Import-MsiTable $database $stage 'Registry' @"
Registry`tRoot`tKey`tName`tValue`tComponent_
s72`ti2`tl255`tL255`tL0`ts72
Registry`tRegistry
EndpointAtLogin`t2`tSoftware\Microsoft\Windows\CurrentVersion\Run`tprobectl Endpoint`t"[#EndpointExe]" --managed`tEndpointFiles
"@
        Import-MsiTable $database $stage 'Upgrade' @"
UpgradeCode`tVersionMin`tVersionMax`tLanguage`tAttributes`tRemove`tActionProperty
s38`tS20`tS20`tS255`ti4`tS255`ts72
Upgrade`tUpgradeCode`tVersionMin`tVersionMax`tLanguage`tAttributes
$upgradeCode`t`t$Version`t`t512`t`tPROBECTL_RELATED
$upgradeCode`t$Version`t`t`t2`t`tPROBECTL_NEWER
"@
        Import-MsiTable $database $stage 'LaunchCondition' @"
Condition`tDescription
s255`tl255
LaunchCondition`tCondition
Installed OR NOT PROBECTL_NEWER`tA newer version of probectl Endpoint is installed.
"@
        Import-MsiTable $database $stage 'InstallExecuteSequence' @"
Action`tCondition`tSequence
s72`tS255`tI2
InstallExecuteSequence`tAction
FindRelatedProducts`t`t25
LaunchConditions`t`t100
CostInitialize`t`t800
FileCost`t`t900
CostFinalize`t`t1000
InstallValidate`t`t1400
InstallInitialize`t`t1500
RemoveExistingProducts`tPROBECTL_RELATED AND NOT Installed`t1510
ProcessComponents`t`t1600
UnpublishFeatures`t`t1800
RemoveRegistryValues`t`t2600
RemoveFiles`t`t3500
RemoveFolders`t`t3600
InstallFiles`t`t4000
WriteRegistryValues`t`t5000
RegisterProduct`t`t6100
PublishFeatures`t`t6300
PublishProduct`t`t6400
InstallFinalize`t`t6600
"@
        Import-MsiTable $database $stage 'InstallUISequence' @"
Action`tCondition`tSequence
s72`tS255`tI2
InstallUISequence`tAction
ExecuteAction`t`t1300
"@
        $view = $database.OpenView('INSERT INTO `_Streams` (`Name`, `Data`) VALUES (?, ?)')
        $record = $installer.CreateRecord(2)
        Set-MsiIndexedProperty $record 'StringData' 1 'endpoint.cab'
        $record.SetStream(2, $cabinet)
        $view.Execute($record)
        $view.Close()

        $summary = $database.GetType().InvokeMember('SummaryInformation', 'GetProperty', $null, $database, @(12))
        Set-MsiIndexedProperty $summary 'Property' 1 1252
        Set-MsiIndexedProperty $summary 'Property' 2 'Installation Database'
        Set-MsiIndexedProperty $summary 'Property' 3 'probectl Endpoint'
        Set-MsiIndexedProperty $summary 'Property' 4 'ctlplne'
        Set-MsiIndexedProperty $summary 'Property' 7 ($target.Platform + ';1033')
        Set-MsiIndexedProperty $summary 'Property' 9 $packageCode
        Set-MsiIndexedProperty $summary 'Property' 14 500
        Set-MsiIndexedProperty $summary 'Property' 15 2 # embedded compressed files
        $summary.Persist()
        $database.Commit()
    } finally {
        Release-ComObject $summary
        Release-ComObject $record
        Release-ComObject $view
        Release-ComObject $database
        Release-ComObject $installer
    }
    if (-not $TestUnsigned) {
        Sign-Artifact $package
        Confirm-ArtifactSignature $package
    }
    [IO.File]::Move($package, $destination)
    Write-Output "Built $destination ($productCode)"
} finally {
    if ($null -ne $payloadLease) { $payloadLease.Dispose() }
    Remove-Item -LiteralPath $stage -Recurse -Force
}
