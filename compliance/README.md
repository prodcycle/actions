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
| `frameworks`            | No       | Workspace setting           | Comma-separated framework IDs (`soc2,hipaa,nist-csf`)                                        |
| `fail-on`               | No       | `critical,high`             | Severities that fail the check                                                               |
| `severity-threshold`    | No       | `low`                       | Minimum severity to include in results                                                       |
| `include`               | No       | All changed files           | Glob patterns to include (`**/*.tf,**/*.yaml`)                                               |
| `exclude`               | No       | None                        | Glob patterns to exclude (`test/**,docs/**`)                                                 |
| `scan-mode`             | No       | `auto`                      | `auto` / `diff` (changed lines) / `full` (entire codebase)                                   |
| `annotate`              | No       | `true`                      | Create inline workflow annotations (`core.error`/`warning`/`notice`) for findings            |
| `comment`               | No       | `true`                      | Post a summary comment                                                                       |
| `review-event`          | No       | *(empty — back-compat)*     | PR review event: `auto` / `comment` / `request-changes` / `none` — see below                 |
| `exclude-accepted-risk` | No       | `true`                      | Skip findings marked as accepted risk in ProdCycle (requires `product-id` or `sync-config-id`) |
| `exclude-resolved`      | No       | `false`                     | Also skip findings marked resolved in ProdCycle (requires `product-id` or `sync-config-id`)  |
| `product-id`            | No       | None                        | ProdCycle product UUID this repo maps to (enables accepted-risk/resolved suppression)        |
| `sync-config-id`        | No       | None                        | ProdCycle sync-configuration UUID linking this repo to a product (alternative to `product-id`) |
| `github-token`          | No       | `${{ github.token }}`       | Token for PR comments/annotations (defaults to the automatic `GITHUB_TOKEN`)                 |
| `comment-identity`      | No       | `auto`                      | Who authors PR comments: `auto` / `app` / `github-token` (see below)                         |

### `review-event` values

Controls the formal PR review that the action submits when findings exist. Independent of `annotate`, which controls only the inline workflow annotations on the diff view.

| Value             | Behavior                                                                                                |
| ----------------- | ------------------------------------------------------------------------------------------------------- |
| `auto`            | `COMMENT` if the scan passed, `REQUEST_CHANGES` if it failed (historical behavior of `annotate: true`)  |
| `comment`         | Always `COMMENT` — inline review comments post but never flip the PR into "Changes requested"           |
| `request-changes` | Always `REQUEST_CHANGES` — every finding-bearing scan formally requests changes                         |
| `none`            | Skip the PR review entirely (inline workflow annotations controlled by `annotate` are unaffected)       |
| *(empty)*         | **Back-compat default:** `auto` when `annotate: true`, `none` when `annotate: false`                    |

Use `review-event: comment` (or `none`) when you want informative findings without blocking merges via the "Changes requested" review state.

## Outputs

| Output           | Description                                       |
| ---------------- | ------------------------------------------------- |
| `passed`         | Whether the scan passed (`true`/`false`)          |
| `findings-count` | Total number of findings                          |
| `scan-id`        | ProdCycle scan ID for linking to the dashboard    |
| `summary`        | JSON summary by severity and framework            |

## Examples

See the [root README](../README.md#examples) for framework selection, output usage, self-hosted URLs, and more.
