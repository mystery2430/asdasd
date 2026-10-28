# Applies the optional release versions from the environment.
#
# User-supplied workflow inputs are NEVER interpolated into this script. The
# caller maps them to CORE_VERSION / DIVERT_VERSION / CLI_VERSION environment
# variables. Only a strictly validated SemVer string is then passed to cargo as
# a separate argument.
param(
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"

# SemVer 2.0.0, restricted to the numeric core plus optional pre-release/build.
$SemverPattern = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$'

function Resolve-CrateVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Crate,
        [AllowNull()][string]$Value
    )

    if ($null -eq $Value) { return $null }
    $trimmed = $Value.Trim()
    if ($trimmed.Length -eq 0) { return $null }
    if ($trimmed.Length -gt 128) {
        throw "$Crate : version is too long"
    }
    # -cmatch is case-sensitive and the anchors reject quotes, semicolons,
    # newlines, backticks, $(), pipes -- anything that is not SemVer data.
    if ($trimmed -cnotmatch $SemverPattern) {
        throw "$Crate : '$trimmed' is not a version (expected e.g. 1.2.3 or 1.2.3-rc1)"
    }
    return $trimmed
}

function Apply-Versions {
    $wanted = [ordered]@{
        "bosphorus-core"   = Resolve-CrateVersion -Crate "bosphorus-core"   -Value $env:CORE_VERSION
        "bosphorus-divert" = Resolve-CrateVersion -Crate "bosphorus-divert" -Value $env:DIVERT_VERSION
        "bosphorus-cli"    = Resolve-CrateVersion -Crate "bosphorus-cli"    -Value $env:CLI_VERSION
    }

    # Validate every input before mutating any manifest.
    foreach ($crate in $wanted.Keys) {
        $v = $wanted[$crate]
        if ($null -eq $v) {
            Write-Host "$crate : unchanged"
            continue
        }
        & cargo set-version --package $crate $v
        if ($LASTEXITCODE -ne 0) {
            throw "cargo set-version failed for $crate"
        }
    }
}

function Assert-Invalid {
    param([string]$Crate, [string]$Value)
    try {
        $null = Resolve-CrateVersion -Crate $Crate -Value $Value
        throw "validator accepted malicious value: $Value"
    }
    catch {
        if ($_.Exception.Message -like "validator accepted*") { throw }
    }
}

if ($SelfTest) {
    $valid = @("1.2.3", "0.0.0", "1.2.3-rc.1", "1.2.3+build.7", "10.20.30-beta+sha.abc")
    foreach ($v in $valid) {
        $got = Resolve-CrateVersion -Crate "self-test" -Value "  $v  "
        if ($got -ne $v) { throw "valid version rejected or changed: $v -> $got" }
    }

    $invalid = @(
        "1.2",
        "01.2.3",
        "v1.2.3",
        "1.2.3'",
        "1.2.3; Write-Host PWNED",
        "1.2.3`nWrite-Host PWNED",
        '1.2.3$(Write-Host PWNED)',
        "1.2.3 | whoami",
        "1.2.3 && whoami",
        "1.2.3 --version"
    )
    foreach ($v in $invalid) {
        Assert-Invalid -Crate "self-test" -Value $v
    }

    # Blank means "leave unchanged", not version 0.0.0.
    if ($null -ne (Resolve-CrateVersion -Crate "self-test" -Value "   ")) {
        throw "blank input must mean unchanged"
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
