# JD.RepoOps

Centralized reusable GitHub Actions workflows, composite actions, and repo contracts for .NET repository CI/CD, release, docs, security, and maintenance automation.

## Purpose

JD.RepoOps exists to reduce copy-paste drift across repositories by centralizing the common GitHub Actions logic used to review, scan, build, test, validate, label, release, document, and eventually deploy .NET repositories.

The intent is not to create a giant magical workflow blob that nobody understands. The intent is to create a stable, versioned automation platform that consumer repositories can call declaratively.

## Design goals

- Prefer reusable workflows as the primary consumer API
- Use composite actions for repeated step bundles
- Keep consumer repos small and declarative
- Support package libraries, source generators, SDKs, tooling repos, docs-heavy repos, and apps
- Allow explicit extension points for repo-specific validation and special handling
- Require versioned consumption by tag or SHA

## Repository layout

```text
.github/
  actions/
  workflows/
docs/
  adrs/
templates/
scripts/
```

## Initial workflow catalog

- `pr-validation.yml`
- `templates/workflows/reusable-release-package.yml`
- `publish-docs.yml`
- `codeql.yml`
- `dependency-submission.yml`
- `labeler.yml`

## Initial composite action catalog

- `load-repo-metadata`
- `setup-dotnet`
- `restore-dotnet`
- `build-dotnet`
- `test-dotnet`
- `coverage-report`
- `run-custom-script`
- `build-docfx`

## Script catalog

Standalone scripts for one-off or fleet-wide remediation that don't (yet)
warrant a full reusable workflow or composite action live under `scripts/`.
They are designed to be run directly against a repo checkout (locally or in
CI) rather than consumed via `workflow_call`.

- `scripts/Remediate-VulnerablePackages.ps1` - Idempotently fixes the
  recurring ".NET CI/CodeQL fails because NuGetAudit (NU1901-NU1904) is
  treated as an error and a direct/transitive package has a known
  vulnerability" class of problem. Detects vulnerable packages (via
  `dotnet restore`/`dotnet list package --vulnerable`), resolves the nearest
  non-vulnerable version per-advisory from the GitHub Advisory Database, and
  applies the minimal fix (direct version bump, or a transitive pin -
  handling both non-CPM `<PackageReference>` and CPM
  `Directory.Packages.props` repos), then re-verifies restore + build are
  green. Never relaxes NuGetAudit/TreatWarningsAsErrors and never touches
  tests. Supports `-WhatIf` for a dry run. See the script's comment-based
  help (`Get-Help ./scripts/Remediate-VulnerablePackages.ps1 -Full`) for
  parameters and exit codes.

## Consumer contract

Consumer repos should declare their behavior through `.github/repoops.yml` and then call these reusable workflows with `workflow_call`.

Example consumer workflow:

```yaml
name: CI

on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  validate:
    uses: JerrettDavis/JD.RepoOps/.github/workflows/pr-validation.yml@v1
    with:
      metadata_file: .github/repoops.yml
    secrets: inherit
```

## Next steps

- Harden the metadata schema
- Add release versioning and NuGet publishing primitives
- Add docs publishing and GitHub Pages guidance
- Add smoke-test fixtures for representative consumer repo types
- Migrate pilot repos such as TinyBDD, JD.Efcpt.Build, and PatternKit
