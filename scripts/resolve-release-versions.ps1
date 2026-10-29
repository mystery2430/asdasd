# Reads the versions that actually landed in the manifests and exports the values
# the later steps need. No workflow input is interpolated here, and every manifest
# value is validated with the same strict SemVer 2.0.0 check the inputs use, so a
# hand-edited (or maliciously edited) Cargo.toml cannot smuggle anything else into
# an artifact name or a tag.
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "semver.ps1")

if (-not $env:GITHUB_ENV) {
    throw "GITHUB_ENV is not set"
}

$versions = @{}
foreach ($crate in @("bosphorus-core", "bosphorus-divert", "bosphorus-cli")) {
    $null = Assert-SafeCrateName -Name $crate
    $path = "crates/$crate/Cargo.toml"
    if (-not (Test-Path $path)) { throw "missing manifest: $path" }
    $match = Select-String -Path $path -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($null -eq $match) { throw "no version in $path" }
    $v = $match.Matches[0].Groups[1].Value
    if (-not (Test-ReleaseVersion -Value $v)) {
        throw "$crate has an invalid manifest version: '$v'"
    }
    $versions[$crate] = $v
    Write-Host "$crate $v"
}

$names = [ordered]@{
    cli_version    = "bosphorus-cli"
    core_version   = "bosphorus-core"
    divert_version = "bosphorus-divert"
}
foreach ($name in $names.Keys) {
    "$name=$($versions[$names[$name]])" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
}
