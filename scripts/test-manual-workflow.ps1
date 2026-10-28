# Regression guard for the workflow itself: permissions split and no direct
# workflow-input interpolation inside `run:` programs.
$ErrorActionPreference = "Stop"
$path = ".github/workflows/manual-build.yml"
$lines = Get-Content $path
$text = $lines -join "`n"

function Get-JobBlock {
    param([string]$Name)
    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -ceq "  ${Name}:") { $start = $i; break }
    }
    if ($start -lt 0) { throw "job '$Name' not found" }
    $end = $lines.Count
    for ($j = $start + 1; $j -lt $lines.Count; $j++) {
        if ($lines[$j] -match '^  [A-Za-z0-9_-]+:$') { $end = $j; break }
    }
    return ($lines[$start..($end - 1)] -join "`n")
}

$build = Get-JobBlock "build"
$release = Get-JobBlock "release"

if ($build -notmatch 'permissions:\s*\n\s+contents:\s*read') {
    throw "build job must have read-only contents permission"
}
if ($build -match 'contents:\s*write') {
    throw "build/test job must not have contents: write"
}
if ($release -notmatch 'permissions:\s*\n\s+contents:\s*write') {
    throw "release job must be the only writer and declare contents: write"
}
if ($release -notmatch "if:\s*inputs\.mode\s*==\s*'release'") {
    throw "release job must be conditionally created only for mode=release"
}
if ($release -notmatch 'needs:\s*build') {
    throw "release job must depend on the tested build artifact"
}
if ($build -match '\$\{\{\s*inputs\.mode\s*\}\}') {
    # mode is a constrained choice, but it must still be data, not code.
    throw "mode input was interpolated into the build job program"
}

# A `run:` block is where shell injection matters. Inputs may appear in env:
# but never as `${{ inputs.* }}` inside the program text.
$inRun = $false
$runIndent = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if (-not $inRun -and $line -match '^(\s*)run:\s*\|') {
        $inRun = $true
        $runIndent = $Matches[1].Length
        continue
    }
    if ($inRun) {
        if ($line.Trim().Length -gt 0) {
            $indent = $line.Length - $line.TrimStart().Length
            if ($indent -le $runIndent) {
                $inRun = $false
            } elseif ($line -match '\$\{\{\s*inputs\.') {
                throw "workflow input interpolated directly into a run block at line $($i + 1)"
            }
        }
    }
}

# The semver validator lives in a script and must cover command syntax.
$validator = Get-Content "scripts/apply-release-versions.ps1" -Raw
foreach ($needle in @("Write-Host PWNED", "1.2.3'", "1.2.3 | whoami", '$(Write-Host')) {
    if (-not $validator.Contains($needle)) {
        throw "validator self-test is missing the malicious case: $needle"
    }
}

Write-Host "manual workflow safety checks: OK"
