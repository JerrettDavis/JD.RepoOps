# Repo Metadata Contract

Each consuming repository declares its behavior using `.github/repoops.yml`.

## Example

```yaml
repo_type: package-library
solution: MySolution.sln


dotnet:
  sdk:
    - "8.0.x"
    - "9.0.x"

build:
  configuration: Release

test:
  enabled: true
  collect_coverage: true

docs:
  enabled: true
  config: docs/docfx.json

package:
  enabled: true
  publish_to_nuget: true

release:
  enabled: true
  version_strategy: gitversion

validation:
  custom_scripts:
    - ./build/Validate.ps1
```

## Philosophy

- Defaults should be strong and require minimal config
- Overrides should be explicit
- All workflows should read from this contract rather than hardcoding repo-specific logic
