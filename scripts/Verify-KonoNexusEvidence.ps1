#Requires -Version 5.1

<#
.SYNOPSIS
Verifies KonoNexus WAN evidence against the exact tester build shipped in this package.

.EXAMPLE
.\Verify-KonoNexusEvidence.ps1 -Report .\KonoNexus-WAN-report.json

.EXAMPLE
.\Verify-KonoNexusEvidence.ps1 -Pair .\home-nat-pair.json

.EXAMPLE
.\Verify-KonoNexusEvidence.ps1 -Matrix .\wan-matrix.json -RequireReady
#>
[CmdletBinding(DefaultParameterSetName = "Report")]
param(
    [Parameter(Mandatory, ParameterSetName = "Report")]
    [ValidateNotNullOrEmpty()]
    [string] $Report,

    [Parameter(Mandatory, ParameterSetName = "Pair")]
    [ValidateNotNullOrEmpty()]
    [string] $Pair,

    [Parameter(Mandatory, ParameterSetName = "Matrix")]
    [ValidateNotNullOrEmpty()]
    [string] $Matrix,

    [Parameter(ParameterSetName = "Matrix")]
    [switch] $RequireReady
)

$ErrorActionPreference = "Stop"
$packageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$probe = Join-Path $packageRoot "kononexus_probe.exe"
$buildManifest = Join-Path $packageRoot "QUALIFIED-BUILD.txt"

if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) {
    throw "Missing verifier: $probe"
}
if (-not (Test-Path -LiteralPath $buildManifest -PathType Leaf)) {
    throw "Missing qualified-build manifest: $buildManifest"
}

$expectedBuild = (Get-Content -LiteralPath $buildManifest -Raw).Trim()
if ($expectedBuild -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\+git\.[0-9a-f]{40}$') {
    throw "Invalid qualified-build identity in $buildManifest"
}

$evidencePath = switch ($PSCmdlet.ParameterSetName) {
    "Report" { $Report }
    "Pair" { $Pair }
    "Matrix" { $Matrix }
    default { throw "Unsupported evidence mode" }
}
$resolvedEvidence = (Resolve-Path -LiteralPath $evidencePath).Path

$probeArguments = switch ($PSCmdlet.ParameterSetName) {
    "Report" { @("--verify-report", $resolvedEvidence) }
    "Pair" { @("--verify-pair", $resolvedEvidence) }
    "Matrix" { @("--verify-matrix", $resolvedEvidence) }
    default { throw "Unsupported evidence mode" }
}
$probeArguments += @("--expected-tester-build", $expectedBuild)

$verificationOutput = @(& $probe @probeArguments 2>&1)
$probeExitCode = $LASTEXITCODE
$verificationOutput | ForEach-Object { Write-Output $_ }

if ($probeExitCode -ne 0) {
    exit $probeExitCode
}
if ($RequireReady -and -not ($verificationOutput | Where-Object {
            $_.ToString().Trim() -eq "MANUAL_REVIEW_READY=1"
        })) {
    [Console]::Error.WriteLine("The matrix is valid but not complete and eligible for manual review.")
    exit 2
}

Write-Output "QUALIFIED_BUILD_MATCH=1"
