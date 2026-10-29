# Strict SemVer 2.0.0 validation shared by the release scripts.
#
# One validator, used by both `apply-release-versions.ps1` (workflow inputs) and
# `resolve-release-versions.ps1` (manifest values), so the two can never disagree
# about what a version is. Everything here is pure string testing: a value is
# never handed to a shell, to `Invoke-Expression`, or to a command string.
#
# Why not a loose `[0-9A-Za-z.-]+` pattern: that accepts `1.2.3-.`, `1.2.3+.` and
# `1.2.3-01`, which are not versions. SemVer 2.0.0 rules enforced here:
#
#   version   ::= core ( '-' pre )? ( '+' build )?
#   core      ::= num '.' num '.' num            numeric, no leading zeros
#   pre       ::= id ( '.' id )*                  ids non-empty, numeric ids
#                                                 without leading zeros
#   build     ::= id ( '.' id )*                  ids non-empty
#   id        ::= [0-9A-Za-z-]+
#
# plus a length bound and a printable-ASCII check, so neither a pathological
# string nor a control character can reach a manifest.

$script:SemVerPattern = '^(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)(?:-(?<pre>(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+(?<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$'

function Test-SemVer {
    <#
      .SYNOPSIS
      Returns $true only for a strict SemVer 2.0.0 string.
    #>
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) { return $false }
    if ($Value.Length -eq 0 -or $Value.Length -gt 128) { return $false }
    foreach ($ch in $Value.ToCharArray()) {
        # Printable ASCII, no whitespace, no control characters. Anything else is
        # not SemVer and is a red flag in a version box.
        if ([int]$ch -lt 0x21 -or [int]$ch -gt 0x7e) { return $false }
    }
    return ($Value -cmatch $script:SemVerPattern)
}

function Test-NumericIdentifiers {
    <#
      .SYNOPSIS
      Rejects leading zeros in numeric prerelease identifiers.
      .DESCRIPTION
      The main pattern already encodes this; the explicit walk keeps the rule
      visible and fails loudly if a future simplification of the pattern would
      start accepting `1.2.3-01`. Assumes Test-SemVer already passed.
    #>
    param([Parameter(Mandatory = $true)][string]$Value)

    $core = $Value
    $plus = $core.IndexOf('+')
    if ($plus -ge 0) { $core = $core.Substring(0, $plus) }
    $dash = $core.IndexOf('-')
    if ($dash -lt 0) { return $true }
    $pre = $core.Substring($dash + 1)
    if ($pre.Length -eq 0) { return $false }
    foreach ($id in $pre.Split('.')) {
        if ($id.Length -eq 0) { return $false }
        if ($id -cmatch '^[0-9]+$' -and $id.Length -gt 1 -and $id.StartsWith('0')) {
            return $false
        }
    }
    return $true
}

function Test-ReleaseVersion {
    <#
      .SYNOPSIS
      The entry point the scripts use: full SemVer 2.0.0 plus the explicit
      numeric-identifier rule.
    #>
    param([AllowNull()][string]$Value)
    if (-not (Test-SemVer -Value $Value)) { return $false }
    return (Test-NumericIdentifiers -Value $Value)
}

function Assert-SafeCrateName {
    <#
      .SYNOPSIS
      Validates a crate name before it can reach `cargo --package`.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($Name -cnotmatch '^[a-z0-9][a-z0-9-]{0,63}$') {
        throw "refusing to use an unexpected crate name: '$Name'"
    }
    return $Name
}
