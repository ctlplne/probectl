# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository. On its Change Date,
# each version converts to the Mozilla Public License 2.0.

#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Signed')]
param(
    [Parameter(Mandatory)][string]$Msi,
    [Parameter(Mandatory)][string]$ExpectedVersion,
    [Parameter(Mandatory)][ValidateSet('x64', 'Arm64')][string]$Architecture,
    [Parameter(Mandatory, ParameterSetName = 'Signed')][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory, ParameterSetName = 'Fixture')][switch]$AllowUnsignedFixture
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Release-ComObject($Object) {
    if ($null -ne $Object) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($Object)
    }
}

function Read-MsiScalar($Database, [string]$Query, [string]$Property = 'StringData') {
    $view = $record = $extra = $null
    try {
        $view = $Database.OpenView($Query)
        $view.Execute()
        $record = $view.Fetch()
        if ($null -eq $record) { return $null }
        $extra = $view.Fetch()
        if ($null -ne $extra) { throw 'Expected at most one MSI table row.' }
        return $record.GetType().InvokeMember($Property, 'GetProperty', $null, $record, @(1))
    } finally {
        Release-ComObject $extra
        Release-ComObject $record
        if ($null -ne $view) { $view.Close() }
        Release-ComObject $view
    }
}

function Confirm-EndpointFiles($Database) {
    $expected = @{
        EndpointExe = 'PROBEEND.EXE|probectl-endpoint.exe'
        EndpointLicense = 'LICENSE.txt'
        EndpointNotice = 'NOTICE.txt'
    }
    $view = $record = $null
    try {
        $view = $Database.OpenView('SELECT `File`, `FileName` FROM `File`')
        $view.Execute()
        for ($index = 0; $index -lt 3; $index++) {
            $record = $view.Fetch()
            if ($null -eq $record) { throw 'MSI is missing an endpoint payload file.' }
            $key = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(1))
            $name = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(2))
            if (-not $expected.ContainsKey($key) -or $name -cne $expected[$key]) {
                throw 'MSI payload must contain the endpoint executable, LICENSE.txt, and NOTICE.txt.'
            }
            $expected.Remove($key)
            Release-ComObject $record
            $record = $null
        }
        $record = $view.Fetch()
        if ($null -ne $record) { throw 'MSI contains an unexpected payload file.' }
    } finally {
        Release-ComObject $record
        if ($null -ne $view) { $view.Close() }
        Release-ComObject $view
    }
}

function Copy-MsiCabinet($Record, [long]$Length, [string]$Destination) {
    $output = [IO.File]::Open($Destination, 'CreateNew', 'Write', 'None')
    try {
        $buffer = [byte[]]::new(65536)
        $remaining = $Length
        while ($remaining -ge 2) {
            $bytes = [int][Math]::Min($remaining - ($remaining % 2), $buffer.Length)
            # Direct mode reads the original byte pairs. A text encoding
            # could replace unpaired surrogate values in the cabinet bytes.
            $pairs = [string]$Record.ReadStream(1, $bytes, 3)
            if ($pairs.Length * 2 -ne $bytes) { throw 'The embedded cabinet is truncated.' }
            [Buffer]::BlockCopy($pairs.ToCharArray(), 0, $buffer, 0, $bytes)
            $output.Write($buffer, 0, $bytes)
            $remaining -= $bytes
        }
        if ($remaining -eq 1) {
            $last = $Record.ReadStream(1, 1, 0)
            if ($null -eq $last) { throw 'The embedded cabinet is truncated.' }
            $output.WriteByte([byte]($last -band 255))
        }
    } finally {
        $output.Dispose()
    }
}

function Confirm-TimestampedPublisher($Signature, [string]$Publisher, [string]$Artifact) {
    if ($Signature.Status -ne 'Valid' -or $null -eq $Signature.SignerCertificate -or
        $null -eq $Signature.TimeStamperCertificate -or $Signature.SignerCertificate.Thumbprint -ine $Publisher) {
        throw "The $Artifact must carry a valid, timestamped Authenticode signature from the expected publisher."
    }
}

function Confirm-EndpointPayload($Record, [long]$PackageSize, [long]$ExpectedSize, [string]$ExpectedDigest, [string]$Publisher) {
    $cabinetSize = $Record.GetType().InvokeMember('DataSize', 'GetProperty', $null, $Record, @(1))
    if ($cabinetSize -le 4 -or $cabinetSize -gt $PackageSize -or $ExpectedSize -le 0 -or $ExpectedSize -gt 64MB) {
        throw 'The embedded cabinet or endpoint executable has an invalid size.'
    }
    $stage = Join-Path ([IO.Path]::GetTempPath()) ('.probectl-endpoint-verify-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($stage)
    $payload = $null
    try {
        $cabinet = Join-Path $stage 'endpoint.cab'
        Copy-MsiCabinet $Record $cabinetSize $cabinet
        & "$env:SystemRoot\System32\expand.exe" $cabinet '-f:EndpointExe' $stage | Out-Null
        $member = Join-Path $stage 'EndpointExe'
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $member -PathType Leaf)) {
            throw 'The embedded endpoint executable could not be extracted.'
        }
        $executable = Join-Path $stage 'probectl-endpoint.exe'
        [IO.File]::Move($member, $executable)
        $payload = [IO.File]::Open($executable, 'Open', 'Read', 'Read')
        if ($payload.Length -ne $ExpectedSize) { throw 'The embedded endpoint executable size differs.' }
        $actual = (Get-FileHash -InputStream $payload -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $ExpectedDigest) { throw 'The embedded endpoint executable does not match the declared SHA-256.' }
        if ($Publisher) {
            Confirm-TimestampedPublisher (Get-AuthenticodeSignature -LiteralPath $executable) $Publisher 'embedded endpoint executable'
        }
        return $actual
    } finally {
        if ($null -ne $payload) { $payload.Dispose() }
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}

if ($env:OS -ne 'Windows_NT') { throw 'The native Windows Installer tools are required.' }
$path = (Resolve-Path -LiteralPath $Msi).ProviderPath
$packageLease = [IO.File]::Open($path, 'Open', 'Read', 'Read')
$installer = $database = $summary = $view = $record = $null
try {
    if ($packageLease.Length -le 0 -or $packageLease.Length -gt 64MB) {
        throw 'MSI exceeds the endpoint package size limit.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($AllowUnsignedFixture) {
        if ($signature.Status -ne 'NotSigned') { throw 'The fixture must be an unsigned MSI.' }
    } else {
        Confirm-TimestampedPublisher $signature $CertificateThumbprint 'MSI'
    }
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($path, 0)
    $summary = $database.GetType().InvokeMember('SummaryInformation', 'GetProperty', $null, $database, @(0))
    $platform = $summary.GetType().InvokeMember('Property', 'GetProperty', $null, $summary, @(7))
    if ($platform -ne "$Architecture;1033") { throw 'MSI architecture or language metadata differs.' }
    $version = Read-MsiScalar $database 'SELECT `Value` FROM `Property` WHERE `Property` = ''ProductVersion'''
    if ($version -ne $ExpectedVersion) { throw 'MSI product version differs.' }
    $scope = Read-MsiScalar $database 'SELECT `Value` FROM `Property` WHERE `Property` = ''ALLUSERS'''
    if ($scope -ne '1') { throw 'MSI must use per-machine install scope.' }
    $executableDigest = Read-MsiScalar $database 'SELECT `Value` FROM `Property` WHERE `Property` = ''ProbectlExecutableSHA256'''
    if ($executableDigest -cnotmatch '^[0-9a-f]{64}$') { throw 'MSI has no valid executable SHA-256.' }
    Confirm-EndpointFiles $database
    $executableSize = Read-MsiScalar $database 'SELECT `FileSize` FROM `File` WHERE `File` = ''EndpointExe''' 'IntegerData'
    $autostart = Read-MsiScalar $database 'SELECT `Value` FROM `Registry`'
    if ($autostart -cne '"[#EndpointExe]" --managed') { throw 'MSI changed the managed per-user launch command.' }
    $startupLocation = Read-MsiScalar $database 'SELECT `Key` FROM `Registry`'
    $startupRoot = Read-MsiScalar $database 'SELECT `Root` FROM `Registry`' 'IntegerData'
    if ($startupRoot -ne 2 -or $startupLocation -ne 'Software\Microsoft\Windows\CurrentVersion\Run') {
        throw 'MSI must register the launch command in the per-machine Run key.'
    }
    $customAction = Read-MsiScalar $database 'SELECT `Name` FROM `_Tables` WHERE `Name` = ''CustomAction'''
    if ($null -ne $customAction) { throw 'MSI must not include installation custom actions.' }
    $media = Read-MsiScalar $database 'SELECT `Cabinet` FROM `Media`'
    $lastSequence = Read-MsiScalar $database 'SELECT `LastSequence` FROM `Media`' 'IntegerData'
    if ($media -ne '#endpoint.cab' -or $lastSequence -ne 3) {
        throw 'The embedded cabinet must include the executable and both license files.'
    }
    $upgradeFamily = Read-MsiScalar $database 'SELECT `Value` FROM `Property` WHERE `Property` = ''UpgradeCode'''
    if ($upgradeFamily -ne '{D4C099E4-92DC-4737-BD24-758D2AB73508}') { throw 'MSI changed its upgrade family.' }
    $upgradeStep = Read-MsiScalar $database 'SELECT `Sequence` FROM `InstallExecuteSequence` WHERE `Action` = ''RemoveExistingProducts''' 'IntegerData'
    if ($upgradeStep -ne 1510) { throw 'MSI must remove the old release inside the upgrade transaction.' }
    $view = $database.OpenView('SELECT `Data` FROM `_Streams` WHERE `Name` = ''endpoint.cab''')
    $view.Execute()
    $record = $view.Fetch()
    if ($null -eq $record) { throw 'MSI cabinet is missing.' }
    $measuredDigest = Confirm-EndpointPayload $record $packageLease.Length $executableSize $executableDigest $CertificateThumbprint
    if ($AllowUnsignedFixture) {
        Write-Output "Verified unsigned fixture metadata and executable for $ExpectedVersion ($Architecture)."
    } else {
        $packageDigest = (Get-FileHash -InputStream $packageLease -Algorithm SHA256).Hash.ToLowerInvariant()
        $goArchitecture = if ($Architecture -eq 'x64') { 'amd64' } else { 'arm64' }
        [pscustomobject]@{
            package_version = $version
            platform = "windows/$goArchitecture"
            package_digest = "sha256:$packageDigest"
            executable_identity = "sha256:$measuredDigest"
        } | ConvertTo-Json -Compress
    }
} finally {
    try {
        Release-ComObject $record
        if ($null -ne $view) { $view.Close() }
        Release-ComObject $view
        Release-ComObject $summary
        Release-ComObject $database
        Release-ComObject $installer
    } finally {
        $packageLease.Dispose()
    }
}
