#!/bin/sh
# Copy the hardened workflows into place. Run from the repository root on the PR
# branch, then commit and push with a credential that has `workflow` scope.
set -eu
test -f docs/ci/workflow-fix/manual-build.yml || {
    echo "run this from the repository root" >&2
    exit 1
}
cp docs/ci/workflow-fix/manual-build.yml .github/workflows/manual-build.yml
cp docs/ci/workflow-fix/build.yml .github/workflows/build.yml
echo "applied:"
git status --short .github/workflows
