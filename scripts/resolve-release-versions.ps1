# Reads the versions that actually landed in the manifests and exports the two
# values later steps need. No workflow input is interpolated here.
$ErrorActionPreference = "Stop"

if (-not $env:GITHUB_ENV) {
    throw "GITHUB_ENV is not set"
}

$versions = @{}
foreach ($crate in "bosphorus-core", "bosphorus-divert", "bosphorus-cli") {
    $path = "crates/$crate/Cargo.toml"
    $match = Select-String -Path $path -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($null -eq $match) {
        throw "no version in $path"
    }
    $v = $match.Matches[0].Groups[1].Value
    if ($v -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
        throw "$crate has an invalid manifest version: $v"
    }
    $versions[$crate] = $v
    Write-Host "$crate $v"
}

"cli_version=$($versions['bosphorus-cli'])" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"core_version=$($versions['bosphorus-core'])" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"divert_version=$($versions['bosphorus-divert'])" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
