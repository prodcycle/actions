# ProdCycle Compliance Action

A [GitHub Action](https://github.com/features/actions) for using [ProdCycle](https://prodcycle.com) to scan your repository for SOC 2, HIPAA, and NIST compliance violations.

You can use the Action as follows:

```yaml
name: Compliance Code Scanner
on:
  pull_request:
  push:
    branches: [main]

jobs:
  compliance:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: prodcycle/actions/compliance@v2
        with:
          api-key: ${{ secrets.PRODCYCLE_API_KEY }}
```

In order to use this action, you will need a ProdCycle API key (`pc_...`). See the [root README](../README.md#setup) for setup details, or [sign up at prodcycle.com](https://app.prodcycle.com).

## Modes

Managed automatically via `scan-mode: auto` (default):

- **Pull request**: scans only changed lines (diff mode)
- **Push to main**: scans the full codebase

## Inputs

| Input                   | Required | Default                     | Description                                                                                  |
| ----------------------- | -------- | --------------------------- | -------------------------------------------------------------------------------------------- |
| `api-key`               | Yes      |                             | ProdCycle API key (`pc_...`)                                                                 |
| `api-url`               | No       | `https://api.prodcycle.com` | ProdCycle API base URL                                                                       |
| `frameworks`            | No       | Workspace setting           | Comma-separated framework IDs (`soc2,hipaa,nist`)                                            |
| `fail-on`               | No       | `critical,high`             | Severities that fail the check                                                               |
| `severity-threshold`    | No       | `low`                       | Minimum severity to include in results                                                       |
| `include`               | No       | All changed files           | Glob patterns to include (`**/*.tf,**/*.yaml`)                                               |
| `exclude`               | No       | None                        | Glob patterns to exclude (`test/**,docs/**`)                                                 |
| `scan-mode`             | No       | `auto`                      | `auto` / `diff` (changed lines) / `full` (entire codebase)                                   |
| `annotate`              | No       | `true`                      | Create inline PR annotations                                                                 |
| `comment`               | No       | `true`                      | Post a summary comment                                                                       |
| `exclude-accepted-risk` | No       | `true`                      | Skip findings marked as accepted risk in ProdCycle                                           |

## Outputs

| Output           | Description                                       |
| ---------------- | ------------------------------------------------- |
| `passed`         | Whether the scan passed (`true`/`false`)          |
| `findings-count` | Total number of findings                          |
| `scan-id`        | ProdCycle scan ID for linking to the dashboard    |
| `summary`        | JSON summary by severity and framework            |

## Examples

See the [root README](../README.md#examples) for framework selection, output usage, self-hosted URLs, and more.
