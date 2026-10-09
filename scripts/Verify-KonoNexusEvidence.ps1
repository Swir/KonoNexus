#Requires -Version 5.1

<#
.SYNOPSIS
Creates or verifies KonoNexus WAN evidence against the exact tester build shipped in this package.

.EXAMPLE
.\Verify-KonoNexusEvidence.ps1 -Report .\KonoNexus-WAN-report.json

.EXAMPLE
.\Verify-KonoNexusEvidence.ps1 -ReportA .\pc-a.json -ReportB .\pc-b.json -Scenario home_nat_pair -NetworkLabel "ISP A / ISP B" -PairOutput .\home-nat-pair.json -RequireEligible

.EXAMPLE
.\Verify-KonoNexusEvidence.ps1 -PairFiles ".\same-lan.json;.\home-nat-pair.json" -MatrixOutput .\wan-matrix.json -RequireReady
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

    [Parameter(Mandatory, ParameterSetName = "CreatePair")]
    [ValidateNotNullOrEmpty()]
    [string] $ReportA,

    [Parameter(Mandatory, ParameterSetName = "CreatePair")]
    [ValidateNotNullOrEmpty()]
    [string] $ReportB,

    [Parameter(Mandatory, ParameterSetName = "CreatePair")]
    [ValidateSet(
        "same_lan",
        "home_nat_pair",
        "home_to_mobile",
        "dual_mobile_cgnat",
        "public_ipv6",
        "direct_interruption",
        "restart_reconnect"
    )]
    [string] $Scenario,

    [Parameter(Mandatory, ParameterSetName = "CreatePair")]
    [ValidateNotNullOrEmpty()]
    [string] $NetworkLabel,

    [Parameter(Mandatory, ParameterSetName = "CreatePair")]
    [ValidateNotNullOrEmpty()]
    [string] $PairOutput,

    [Parameter(Mandatory, ParameterSetName = "CreateMatrix")]
    [ValidateNotNullOrEmpty()]
    [string] $PairFiles,

    [Parameter(Mandatory, ParameterSetName = "CreateMatrix")]
    [ValidateNotNullOrEmpty()]
    [string] $MatrixOutput,

    [Parameter(ParameterSetName = "Pair")]
    [Parameter(ParameterSetName = "CreatePair")]
    [switch] $RequireEligible,

    [Parameter(ParameterSetName = "Matrix")]
    [Parameter(ParameterSetName = "CreateMatrix")]
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

function Resolve-EvidenceFile {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $resolved = Resolve-Path -LiteralPath $Path
    if (-not (Test-Path -LiteralPath $resolved.Path -PathType Leaf)) {
        throw "Evidence path is not a file: $Path"
    }
    return $resolved.Path
}

function Resolve-OutputFile {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    return [IO.Path]::GetFullPath($Path)
}

function Invoke-KonoNexusProbe {
    param(
        [Parameter(Mandatory)]
        [string[]] $Arguments
    )

    $output = @(& $probe @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $output | ForEach-Object { Write-Output $_ }
        exit $exitCode
    }
    return $output
}

$verificationOutput = @()

switch ($PSCmdlet.ParameterSetName) {
    "Report" {
        $reportPath = Resolve-EvidenceFile -Path $Report
        $verificationOutput = @(Invoke-KonoNexusProbe -Arguments @(
                "--verify-report", $reportPath,
                "--expected-tester-build", $expectedBuild
            ))
    }
    "Pair" {
        $pairPath = Resolve-EvidenceFile -Path $Pair
        $verificationOutput = @(Invoke-KonoNexusProbe -Arguments @(
                "--verify-pair", $pairPath,
                "--expected-tester-build", $expectedBuild
            ))
    }
    "Matrix" {
        $matrixPath = Resolve-EvidenceFile -Path $Matrix
        $verificationOutput = @(Invoke-KonoNexusProbe -Arguments @(
                "--verify-matrix", $matrixPath,
                "--expected-tester-build", $expectedBuild
            ))
    }
    "CreatePair" {
        $reportAPath = Resolve-EvidenceFile -Path $ReportA
        $reportBPath = Resolve-EvidenceFile -Path $ReportB
        $pairOutputPath = Resolve-OutputFile -Path $PairOutput

        $creationOutput = @(Invoke-KonoNexusProbe -Arguments @(
                "--pair-report", $reportAPath, $reportBPath,
                "--scenario", $Scenario,
                "--network-label", $NetworkLabel,
                "--pair-output", $pairOutputPath
            ))
        $creationOutput | ForEach-Object { Write-Output $_ }

        $verificationOutput = @(Invoke-KonoNexusProbe -Arguments @(
                "--verify-pair", $pairOutputPath,
                "--expected-tester-build", $expectedBuild
            ))
    }
    "CreateMatrix" {
        $pairFileValues = @($PairFiles.Split(";") | ForEach-Object {
                $_.Trim()
            } | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            })
        if ($pairFileValues.Count -eq 0) {
            throw "PairFiles must contain at least one path"
        }

        $matrixArguments = @()
        foreach ($pairFile in $pairFileValues) {
            $matrixArguments += @(
                "--matrix-pair",
                (Resolve-EvidenceFile -Path $pairFile)
            )
        }
        $matrixOutputPath = Resolve-OutputFile -Path $MatrixOutput
        $matrixArguments += @("--matrix-output", $matrixOutputPath)

        $creationOutput = @(Invoke-KonoNexusProbe -Arguments $matrixArguments)
        $creationOutput | ForEach-Object { Write-Output $_ }

        $verificationOutput = @(Invoke-KonoNexusProbe -Arguments @(
                "--verify-matrix", $matrixOutputPath,
                "--expected-tester-build", $expectedBuild
            ))
    }
    default {
        throw "Unsupported evidence mode"
    }
}

$verificationOutput | ForEach-Object { Write-Output $_ }

if ($RequireEligible -and -not ($verificationOutput | Where-Object {
            $_.ToString().Trim() -eq "MATRIX_ROW_ELIGIBLE=1"
        })) {
    [Console]::Error.WriteLine("The pair is valid but is not eligible for the final WAN matrix.")
    exit 2
}

if ($RequireReady -and -not ($verificationOutput | Where-Object {
            $_.ToString().Trim() -eq "MANUAL_REVIEW_READY=1"
        })) {
    [Console]::Error.WriteLine("The matrix is valid but not complete and eligible for manual review.")
    exit 2
}

Write-Output "QUALIFIED_BUILD_MATCH=1"
