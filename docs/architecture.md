# Architecture

JD.RepoOps is the source of truth for shared repository automation.

## Core idea

This repository centralizes the workflows, actions, templates, contracts, and documentation needed to maintain a broad portfolio of primarily .NET repositories.

Consumer repositories should stay small. They call versioned reusable workflows from this repository and optionally provide a `.github/repoops.yml` contract file to declare repo-specific behavior.

## Design principles

- Reusable workflows are the primary API for consumers
- Composite actions are the implementation building blocks
- Consumers should pin versions by tag or SHA rather than floating on `main`
- Repo-specific oddities should be handled through explicit extension points rather than forking the shared platform
- Documentation should be treated as part of the platform, not an afterthought

## Primary layers

### Reusable workflows

These orchestrate high-level jobs such as pull request validation, release, docs publishing, security scanning, labeling, and eventually deployment.

### Composite actions

These encapsulate repeated step bundles such as setting up .NET, restoring, building, testing, generating coverage, building docfx docs, and running custom scripts.

### Repo contract

Consumer repositories describe their behavior with `.github/repoops.yml` so the platform remains data-driven rather than repo-hardcoded.

## Expected evolution

1. Start with PR validation
2. Add richer metadata parsing
3. Add release and package publishing
4. Add docs publishing
5. Add security and maintenance automation
6. Migrate pilot repositories
