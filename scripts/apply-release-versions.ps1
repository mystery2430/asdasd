# Applies the optional release versions from the environment.
#
# Workflow inputs are NEVER interpolated into this script or into the workflow's
# PowerShell. The workflow maps them to CORE_VERSION / DIVERT_VERSION /
# CLI_VERSION environment variables; this script validates each one as strict
# SemVer 2.0.0 and only then passes it to cargo as a separate argument.
#
# `-SelfTest` exercises the validator against malformed versions, empty
# identifiers, leading zeros, and shell-injection payloads. It runs in normal PR
# CI (.github/workflows/build.yml) as well as in the release workflow, so
# weakening the validator fails a pull request.
param(
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "semver.ps1")

function Resolve-CrateVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Crate,
        [AllowNull()][string]$Value
    )

    $null = Assert-SafeCrateName -Name $Crate
    if ($null -eq $Value) { return $null }
    $trimmed = $Value.Trim()
    if ($trimmed.Length -eq 0) { return $null }   # blank means "leave unchanged"
    if (-not (Test-ReleaseVersion -Value $trimmed)) {
        # The value is untrusted text: report the shape expected, never echo it
        # into logs.
        throw "$Crate : input is not a valid SemVer 2.0.0 version (expected e.g. 1.2.3 or 1.2.3-rc.1)"
    }
    return $trimmed
}

function Get-RequestedVersions {
    <#
      Reads and validates every input *before* any manifest is touched, so a bad
      divert version cannot leave core already bumped.
    #>
    return [ordered]@{
        "bosphorus-core"   = Resolve-CrateVersion -Crate "bosphorus-core"   -Value $env:CORE_VERSION
        "bosphorus-divert" = Resolve-CrateVersion -Crate "bosphorus-divert" -Value $env:DIVERT_VERSION
        "bosphorus-cli"    = Resolve-CrateVersion -Crate "bosphorus-cli"    -Value $env:CLI_VERSION
    }
}

function Apply-Versions {
    $wanted = Get-RequestedVersions

    foreach ($crate in $wanted.Keys) {
        $v = $wanted[$crate]
        if ($null -eq $v) {
            Write-Host "$crate : unchanged"
            continue
        }
        # Name and version each reach cargo as one argument; nothing is rebuilt
        # into a command string.
        & cargo set-version --package $crate $v
        if ($LASTEXITCODE -ne 0) {
            throw "cargo set-version failed for $crate"
        }
    }
}

function Assert-Rejected {
    param([string]$Value, [string]$Why)
    if (Test-ReleaseVersion -Value $Value) {
        throw "validator accepted an invalid version ($Why): '$Value'"
    }
    # ...and the entry point the workflow actually uses must reject it too.
    $previous = $env:CORE_VERSION
    try {
        $env:CORE_VERSION = $Value
        try {
            $null = Get-RequestedVersions
            throw "Get-RequestedVersions accepted an invalid version ($Why)"
        }
        catch {
            if ($_.Exception.Message -like "Get-RequestedVersions accepted*") { throw }
        }
    }
    finally {
        $env:CORE_VERSION = $previous
    }
}

if ($SelfTest) {
    $valid = @(
        "1.2.3",
        "0.0.0",
        "1.2.3-rc.1",
        "1.2.3-0",
        "1.2.3-alpha-1",
        "1.2.3-0.3.7",
        "1.2.3+build.7",
        "1.2.3-rc.1+build.7",
        "10.20.30-beta+sha.abc",
        "0.1.0-x.7.z.92"
    )
    foreach ($v in $valid) {
        if (-not (Test-ReleaseVersion -Value $v)) { throw "valid version rejected: $v" }
        $got = Resolve-CrateVersion -Crate "bosphorus-cli" -Value "  $v  "
        if ($got -ne $v) { throw "valid version changed: $v -> $got" }
    }

    $invalid = @(
        @("1.2", "too few components"),
        @("1.2.3.4", "too many components"),
        @("01.2.3", "leading zero in major"),
        @("1.02.3", "leading zero in minor"),
        @("1.2.03", "leading zero in patch"),
        @("1.2.3-01", "leading zero in numeric prerelease identifier"),
        @("1.2.3-0.01", "leading zero in a later prerelease identifier"),
        @("1.2.3-.", "dash followed by a lone dot"),
        @("1.2.3-.", "empty prerelease identifier"),
        @("1.2.3-", "empty prerelease"),
        @("1.2.3-a..b", "empty prerelease identifier"),
        @("1.2.3+.", "plus followed by a lone dot"),
        @("1.2.3+", "empty build metadata"),
        @("1.2.3+a..b", "empty build identifier"),
        @("1.2.3-+build", "empty prerelease before build"),
        @("v1.2.3", "leading v"),
        @("1.2.3-beta!", "invalid character"),
        @("1.2.3_rc1", "underscore"),
        @("1.2.3'", "quote"),
        @("1.2.3; Write-Host PWNED", "semicolon"),
        @("1.2.3`nWrite-Host PWNED", "newline"),
        @('1.2.3$(Write-Host PWNED)', "subexpression"),
        @("1.2.3 | whoami", "pipe"),
        @("1.2.3 && whoami", "command chaining"),
        @("1.2.3 --version", "argument injection")
    )
    foreach ($case in $invalid) {
        Assert-Rejected -Value $case[0] -Why $case[1]
    }

    # Surrounding whitespace is trimmed (a human typing into a workflow box) and
    # only the trimmed value is used.
    foreach ($padded in @("  1.2.3  ", "`t1.2.3`t")) {
        $got = Resolve-CrateVersion -Crate "bosphorus-cli" -Value $padded
        if ($got -ne "1.2.3") { throw "whitespace was not trimmed: '$got'" }
    }

    # Blank means "leave unchanged", not version 0.0.0.
    foreach ($blank in @($null, "", "   ")) {
        if ($null -ne (Resolve-CrateVersion -Crate "bosphorus-cli" -Value $blank)) {
            throw "blank input must mean unchanged"
        }
    }

    # Crate names are constants, but a future edit must not be able to turn one
    # into something else.
    try {
        $null = Assert-SafeCrateName -Name "bosphorus-core; whoami"
        throw "unsafe crate name accepted"
    }
    catch {
        if ($_.Exception.Message -like "unsafe crate name accepted") { throw }
    }

    Write-Host "release input validation self-test: OK"
    exit 0
}

try {
    Apply-Versions
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
