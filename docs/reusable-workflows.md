# Reusable Workflows

Reusable workflows are the primary consumer-facing API of JD.RepoOps.

## Why reusable workflows first

Composite actions are useful, but they only reduce repeated step bundles. The real maintenance burden across a large portfolio comes from duplicated job orchestration, permissions, matrices, conditions, release behavior, artifacts, and publishing flows. Reusable workflows solve that problem directly.

## Initial workflow set

### pr-validation.yml

Standard pull request and branch validation.

Responsibilities:
- checkout
- load repo metadata
- setup .NET SDKs
- restore
- run repo hygiene and generated-content validation when enabled
- build
- test
- collect and publish coverage when enabled
- validate docs when enabled

### release-package.yml

Standard package release orchestration.

Responsibilities:
- restore, build, and test in release mode
- compute version
- pack artifacts
- publish packages
- create release metadata

### publish-docs.yml

Standard documentation publication.

Responsibilities:
- run optional docs prebuild
- build docfx site
- validate output
- publish artifacts or pages

## Consumer usage

```yaml
jobs:
  validate:
    uses: JerrettDavis/JD.RepoOps/.github/workflows/pr-validation.yml@v1
    with:
      metadata_file: .github/repoops.yml
    secrets: inherit
```

## Versioning guidance

Consumers should pin to a stable tag or SHA. Do not consume from `main` once the platform is in active use across multiple repositories.
