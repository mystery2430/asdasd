# Applying the hardened workflows

The two files in this directory are the hardened CI workflows. They could not be
committed to `.github/workflows/` directly because the credential available for
this task has no `workflow` scope: GitHub rejects both

```
git push   -> refusing to allow a Personal Access Token to create or update
              workflow `.github/workflows/build.yml` without `workflow` scope
API PUT    -> 403 Resource not accessible by personal access token
```

so they are shipped here verbatim for a one-step apply by someone with the
Workflows permission (or a classic token with `workflow` scope).

## Apply

```sh
git checkout fix/security-code
git pull

cp docs/ci/workflow-fix/manual-build.yml .github/workflows/manual-build.yml
cp docs/ci/workflow-fix/build.yml         .github/workflows/build.yml
git add .github/workflows
git commit -m "ci: apply hardened manual-build and PR CI workflows"
git push origin fix/security-code
```

Then delete this directory in the same or a follow-up commit; it exists only to
carry the files past the permission restriction.

## Verify before pushing

```sh
pwsh -NoProfile -File ./scripts/apply-release-versions.ps1 -SelfTest   # OK
pwsh -NoProfile -File ./scripts/test-manual-workflow.ps1              # OK
actionlint .github/workflows/manual-build.yml .github/workflows/build.yml
```

`scripts/test-manual-workflow.ps1` fails against the workflows currently in
`.github/workflows/` (they still interpolate `${{ inputs.* }}` and
`${{ github.ref_name }}` into PowerShell), and passes against these files. Both
files were also checked against twelve deliberate regressions — permission split,
input and ref injection in block and inline `run:` values, release gating,
publishing from the build job, release-time tag re-check, artifact-name parity,
a weakened SemVer rule, unwired guards, PR write permission, and a missing
branch-advance check — and the guard failed for each of them.

## What the files do

`manual-build.yml`

* `build` is read-only (`contents: read`), takes the version inputs as
  `CORE_VERSION` / `DIVERT_VERSION` / `CLI_VERSION` environment variables, runs the
  validator self-test and this guard, validates and applies the versions, syncs
  `Cargo.lock`, runs the tests, builds `release-dist`, smoke-tests the binary, and
  uploads one artifact named from the resolved versions and the commit SHA. It
  cannot commit, push, tag, or publish, so `mode: test` stays artifact-only.
* `release` needs `build`, runs only for `mode: release`, and is the only job with
  `contents: write`. It checks out `github.sha` (the tested commit), re-applies the
  same validated versions, resolves them again, downloads that exact artifact and
  verifies every file, validates `GITHUB_REF_NAME` from the environment as a plain
  branch name, fails if the branch advanced during the build, re-checks the tag
  after the download and before publishing, then commits the bumps, tags, and
  publishes — never with `--force`.

`build.yml`

* read-only on push, pull request, and manual dispatch, and it now runs
  `scripts/apply-release-versions.ps1 -SelfTest` and
  `scripts/test-manual-workflow.ps1`, so a weakened validator or a lost permission
  split fails a pull request instead of a release.
