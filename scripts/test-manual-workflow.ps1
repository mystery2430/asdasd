# Regression guard for .github/workflows/manual-build.yml.
#
# It asserts the *security properties* of the real file rather than exact
# formatting, so ordinary edits keep working while a regression fails:
#
#   * a read-only `build` job and a separate, gated, writing `release` job;
#   * `build` cannot push, tag, or publish (so `mode: test` is artifact-only);
#   * `release` runs only for `mode: release`, needs `build`, and downloads the
#     same artifact `build` uploaded before publishing it;
#   * no workflow input and no ref value is interpolated into a `run:` program;
#   * the helpers that make this safe are actually invoked, by this workflow and
#     by normal PR CI;
#   * the shared strict SemVer validator still rejects the malformed cases
#     (checked behaviourally, by calling it).
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$path = Join-Path $root ".github/workflows/manual-build.yml"
$lines = Get-Content $path
$text = $lines -join "`n"

function Get-JobBlock {
    param([string]$Name)
    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -ceq "  ${Name}:") { $start = $i; break }
    }
    if ($start -lt 0) { throw "job '$Name' not found in manual-build.yml" }
    $end = $lines.Count
    for ($j = $start + 1; $j -lt $lines.Count; $j++) {
        if ($lines[$j] -match '^  [A-Za-z0-9_-]+:$') { $end = $j; break }
    }
    return ($lines[$start..($end - 1)] -join "`n")
}

$build = Get-JobBlock "build"
$release = Get-JobBlock "release"

# --- permissions and gating -------------------------------------------------
if ($build -notmatch 'permissions:\s*\n\s+contents:\s*read') {
    throw "build job must declare read-only contents permission"
}
if ($build -match 'contents:\s*write') {
    throw "build/test job must not have contents: write"
}
if ($release -notmatch 'permissions:\s*\n\s+contents:\s*write') {
    throw "release job must be the writer and declare contents: write"
}
if ($release -notmatch "if:\s*inputs\.mode\s*==\s*'release'") {
    throw "release job must be created only for mode=release"
}
if ($release -notmatch 'needs:\s*build') {
    throw "release job must depend on the tested build job"
}
if ($build -match '\$\{\{\s*inputs\.mode\s*\}\}') {
    # `mode` is a constrained choice, but it must still be data, not code.
    throw "mode input was interpolated into the build job program"
}

# --- test mode must be artifact-only ---------------------------------------
# Strip comments so documentation mentioning `git push` does not trip this.
$buildCode = ($build -split "`n" | Where-Object { $_.TrimStart() -notmatch '^#' }) -join "`n"
foreach ($forbidden in @('git push', 'git tag', 'action-gh-release', 'gh release', 'actions/create-release')) {
    if ($buildCode -match [regex]::Escape($forbidden)) {
        throw "build job must not publish or push (found '$forbidden'); that belongs to the release job"
    }
}
foreach ($needed in @('git ls-remote', 'git tag', 'git push', 'action-gh-release')) {
    if ($release -notmatch [regex]::Escape($needed)) {
        throw "release job is missing '$needed'"
    }
}
# The release must refuse a branch that moved during the build.
if ($release -notmatch 'refs/heads/\$\(\$env:GITHUB_REF_NAME\)' -and $release -notmatch 'Verify the branch has not advanced') {
    throw "release job must verify the target branch has not advanced before pushing"
}
if ($release -match 'git push[^\n]*--force') {
    throw "release job must never force-push"
}
# The tag must be re-checked inside the release job, after the build, before the
# publish step: a tag can be created while the build runs.
$publishAt = $release.IndexOf('action-gh-release')
$downloadAt = $release.IndexOf('actions/download-artifact@')
$tagCheckAt = $release.IndexOf('refs/tags/v$env:cli_version')
if ($publishAt -lt 0 -or $downloadAt -lt 0 -or $tagCheckAt -lt 0) {
    throw "release job must download the tested artifact and re-check the tag before publishing"
}
if (-not ($downloadAt -lt $tagCheckAt -and $tagCheckAt -lt $publishAt)) {
    throw "release job must re-check the release tag after downloading the artifact and before publishing"
}
# ...and it must consume the artifact the build job produced.
if ($release -notmatch 'actions/download-artifact@') {
    throw "release job does not download the tested artifact"
}
if ($release -notmatch 'Get-FileHash') {
    throw "release job must verify the downloaded artifact"
}

# --- no expression interpolation into shell programs ------------------------
# `${{ inputs.* }}` is user text and `${{ github.* }}` (notably `ref_name`) is
# repository text; both would become *code* inside a `run:` program. They may
# appear in `env:`/`with:`/`if:` (where they are data), never in the program.
$inRun = $false
$runIndent = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    # Block scalar first: `run: |` and `run: >` start a multi-line program. (A
    # lazy `(?!\|)` lookahead here would misclassify `run: |` as inline and skip
    # the whole block.)
    if (-not $inRun -and $line -match '^(\s*)(-\s*)?run:\s*[|>]') {
        $inRun = $true
        $runIndent = $Matches[1].Length
        continue
    }
    # Inline form: `- run: some command ${{ inputs.x }}`.
    if (-not $inRun -and $line -match '^\s*(-\s*)?run:\s*(\S.*)$') {
        if ($Matches[2] -match '\$\{\{\s*(inputs|github)\.') {
            throw "expression interpolated directly into a run value at line $($i + 1)"
        }
        continue
    }
    if ($inRun) {
        if ($line.Trim().Length -gt 0) {
            $indent = $line.Length - $line.TrimStart().Length
            if ($indent -le $runIndent) {
                $inRun = $false
            } elseif ($line -match '\$\{\{\s*(inputs|github)\.') {
                throw "expression interpolated directly into a run block at line $($i + 1)"
            }
        }
    }
}
# The ref used in the push must come from the environment...
$refEnv = '$env:' + 'GITHUB_REF_NAME'
if (-not $text.Contains($refEnv)) {
    throw "the release must read the target ref from the environment, not an expression"
}
# ...and must be validated before it is used in a refspec.
if ($release -notmatch 'GITHUB_REF_NAME' -or $release -notmatch 'cnotmatch') {
    throw "release job must validate the target ref before pushing to it"
}

# --- inputs are passed as environment variables ----------------------------
foreach ($name in @('CORE_VERSION', 'DIVERT_VERSION', 'CLI_VERSION')) {
    $pattern = '(?m)^\s+' + [regex]::Escape($name) + ':\s*\$\{\{\s*inputs\.'
    if ($build -notmatch $pattern) {
        throw "build job must pass $name through env:, not into a program"
    }
}
foreach ($script in @('scripts/apply-release-versions.ps1')) {
    if ($build -notmatch [regex]::Escape($script)) {
        throw "build job never invokes $script"
    }
    if ($release -notmatch [regex]::Escape($script)) {
        throw "release job never re-applies the validated versions via $script"
    }
}
foreach ($needle in @('scripts/apply-release-versions.ps1 -SelfTest', 'scripts/test-manual-workflow.ps1', 'scripts/resolve-release-versions.ps1')) {
    if ($build -notmatch [regex]::Escape($needle)) {
        throw "build job never invokes '$needle'"
    }
}

# --- the artifact must be the same file on both sides ----------------------
$uploadName = $null
$downloadName = $null
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match 'actions/upload-artifact@') {
        for ($j = $i + 1; $j -lt [Math]::Min($i + 8, $lines.Count); $j++) {
            if ($lines[$j] -match '^\s+name:\s*(.+)$') { $uploadName = $Matches[1].Trim(); break }
        }
    }
    if ($lines[$i] -match 'actions/download-artifact@') {
        for ($j = $i + 1; $j -lt [Math]::Min($i + 8, $lines.Count); $j++) {
            if ($lines[$j] -match '^\s+name:\s*(.+)$') { $downloadName = $Matches[1].Trim(); break }
        }
    }
}
if (-not $uploadName) { throw "no uploaded artifact found" }
if ($uploadName -ne $downloadName) {
    throw "release downloads '$downloadName' but build uploads '$uploadName'"
}
if ($uploadName -match '\$\{\{\s*(inputs|github\.ref_name)') {
    throw "artifact name interpolates an input or ref; it must use the resolved env values"
}
foreach ($part in @('env.cli_version', 'github.sha')) {
    if (-not $uploadName.Contains($part)) {
        throw "artifact name must include $part so it identifies the tested build"
    }
}

# --- PR CI must run these guards ------------------------------------------
$prPath = Join-Path $root ".github/workflows/build.yml"
$pr = Get-Content $prPath -Raw
foreach ($needle in @("apply-release-versions.ps1 -SelfTest", "test-manual-workflow.ps1")) {
    if (-not $pr.Contains($needle)) {
        throw "build.yml (PR CI) does not run '$needle'"
    }
}
if ($pr -notmatch 'pull_request') {
    throw "build.yml must run on pull_request"
}
if ($pr -match 'contents:\s*write') {
    throw "the PR CI workflow must not request write access"
}

# --- the shared validator must still be strict ----------------------------
# Behavioural, not a source search: a weakened pattern would start accepting
# these, and this test would fail.
. (Join-Path $PSScriptRoot "semver.ps1")
$mustReject = @(
    '01.2.3', '1.02.3', '1.2.03',            # leading zeros in the numeric core
    '1.2.3-01', '1.2.3-0.01',                # leading zeros in numeric prerelease ids
    '1.2.3-.', '1.2.3-', '1.2.3-a..b',       # empty / malformed prerelease ids
    '1.2.3+.', '1.2.3+', '1.2.3+a..b',       # empty build identifiers
    '1.2', '1.2.3.4', 'v1.2.3',
    '1.2.3; Write-Host PWNED', '1.2.3 | whoami', '1.2.3$(Write-Host PWNED)'
)
foreach ($v in $mustReject) {
    if (Test-ReleaseVersion -Value $v) { throw "semver.ps1 accepted an invalid version: '$v'" }
}
foreach ($v in @('1.2.3', '0.0.0', '1.2.3-rc.1', '1.2.3-0', '1.2.3+build.7', '1.2.3-rc.1+build.7')) {
    if (-not (Test-ReleaseVersion -Value $v)) { throw "semver.ps1 rejected a valid version: '$v'" }
}
foreach ($script in @('scripts/apply-release-versions.ps1', 'scripts/resolve-release-versions.ps1')) {
    $body = Get-Content (Join-Path $root $script) -Raw
    if (-not $body.Contains('semver.ps1')) {
        throw "$script does not use the shared strict SemVer validator"
    }
    if (-not $body.Contains('Test-ReleaseVersion')) {
        throw "$script does not call Test-ReleaseVersion"
    }
}

Write-Host "manual workflow safety checks: OK"
