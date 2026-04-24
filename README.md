# ProdCycle Actions

A set of GitHub Actions for using [ProdCycle](https://prodcycle.com) in your CI/CD pipelines. A different action is available depending on your use case.

> **Requires a ProdCycle account.** These actions call the ProdCycle API, which requires a valid API key (`pc_...`). [Sign up at prodcycle.com](https://app.prodcycle.com) to get started.

## Supported Actions

| Action | Description |
| ------ | ----------- |
| [Compliance](compliance/) | Scan PR changes for SOC 2, HIPAA, and NIST compliance violations |

## Quick start

Here's an example using the Compliance Scanner action:

```yaml
# .github/workflows/compliance.yml
name: Compliance Code Scanner
on:
  pull_request:
  push:
    branches:
      - main
      - master

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

You can also reference the root action directly, which defaults to the Compliance Scanner:

```yaml
- uses: prodcycle/actions@v2
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
```

## Compliance Scanner

The Compliance Scanner scans pull request changes for compliance violations against SOC 2, HIPAA, and NIST frameworks via the ProdCycle API.

It supports two modes (managed automatically by default):

**1. Pull Request mode (diff scan)**
When run on a `pull_request` event:
- Collects the **diffs** of changed files from the PR (only the changed lines are analyzed)
- Sends them to the ProdCycle compliance check API
- Creates inline annotations on the PR for each finding
- Posts a summary comment with severity and framework breakdown
- Fails the check if findings match the configured severity threshold

**2. Push / Merge mode (full scan)**
When run on a `push` event (e.g., merge to `main`):
- Collects and scans the **entire codebase**
- Validates all tracked files against compliance frameworks
- Reports any findings in the GitHub Actions summary

### Inputs

| Input                | Required | Default                     | Description                                                              |
| -------------------- | -------- | --------------------------- | ------------------------------------------------------------------------ |
| `api-key`            | Yes      |                             | ProdCycle compliance API key (`pc_...`)                                  |
| `api-url`            | No       | `https://api.prodcycle.com` | ProdCycle API base URL                                                   |
| `frameworks`         | No       | Workspace setting           | Comma-separated framework IDs (`soc2,hipaa,nist-csf`)                    |
| `fail-on`            | No       | `critical,high`             | Comma-separated severities that fail the check                           |
| `severity-threshold` | No       | `low`                       | Minimum severity to include in results                                   |
| `include`            | No       | All changed files           | Comma-separated glob patterns to include (`**/*.tf,**/*.yaml`)           |
| `exclude`            | No       | None                        | Comma-separated glob patterns to exclude (`test/**,docs/**`)             |
| `scan-mode`          | No       | `auto`                      | `auto` (diff for PRs, full for pushes); `diff` (changed lines only); `full` (entire codebase) |
| `annotate`           | No       | `true`                      | Create inline workflow annotations (`core.error`/`warning`/`notice`) for findings |
| `comment`            | No       | `true`                      | Post a summary comment on the PR                                         |
| `review-event`       | No       | *(empty — see below)*        | PR review event: `auto` / `comment` / `request-changes` / `none`          |

### Outputs

| Output           | Description                                       |
| ---------------- | ------------------------------------------------- |
| `passed`         | Whether the scan passed (`true`/`false`)          |
| `findings-count` | Total number of findings                          |
| `scan-id`        | ProdCycle scan ID for linking to the dashboard    |
| `summary`        | JSON summary of results by severity and framework |

### Examples

#### Scan specific frameworks

```yaml
- uses: prodcycle/actions/compliance@v2
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    frameworks: soc2,hipaa,nist-csf
```

#### Only fail on critical findings

```yaml
- uses: prodcycle/actions/compliance@v2
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    fail-on: critical
```

#### Scan only infrastructure files

```yaml
- uses: prodcycle/actions/compliance@v2
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    include: "**/*.tf,**/*.yaml,**/*.yml,**/Dockerfile"
    exclude: "test/**,docs/**"
```

#### Use outputs in subsequent steps

```yaml
- uses: prodcycle/actions/compliance@v2
  id: compliance
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
  continue-on-error: true

- run: |
    echo "Passed: ${{ steps.compliance.outputs.passed }}"
    echo "Findings: ${{ steps.compliance.outputs.findings-count }}"
    echo "Scan: ${{ steps.compliance.outputs.scan-id }}"
```

#### Non-blocking compliance (comments only, never "Changes requested")

```yaml
- uses: prodcycle/actions/compliance@v2
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    review-event: comment
  continue-on-error: true
```

#### Explicit full codebase scan

```yaml
- uses: prodcycle/actions/compliance@v2
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    scan-mode: full
```

#### Self-hosted ProdCycle instance

```yaml
- uses: prodcycle/actions/compliance@v2
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    api-url: https://api.yourcompany.com
```

## Supported frameworks

| ID     | Framework                              |
| ------ | -------------------------------------- |
| `soc2` | SOC 2                                  |
| `hipaa`| HIPAA                                  |
| `nist-csf` | NIST Cybersecurity Framework 2.0   |

If no `frameworks` input is specified, the action uses the frameworks configured on your ProdCycle workspace.

## Prerequisites

- A **ProdCycle account** ([sign up at prodcycle.com](https://prodcycle.com))
- A **ProdCycle API key** generated from your workspace settings
- Compliance check enabled on your workspace

## Setup

### 1. Generate an API key

In ProdCycle, go to **Settings > API** and create a compliance check API key. The key starts with `pc_`.

### 2. Add the key to GitHub secrets

In your repository, go to **Settings > Secrets and variables > Actions** and add a new secret:

- **Name:** `PRODCYCLE_API_KEY`
- **Value:** Your `pc_...` key

### 3. Add the workflow

Create `.github/workflows/compliance.yml` in your repository with the configuration from the Quick start section above.

## Permissions

The actions require the following GitHub token permissions:

- `contents: read` to checkout and read changed files
- `pull-requests: write` to post annotations and summary comments

## Development

```bash
pnpm install
pnpm run type-check    # TypeScript check
pnpm run test          # Run tests
pnpm run build         # Bundle with ncc into compliance/dist/
pnpm run all           # All of the above
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## Support

- [ProdCycle Documentation](https://docs.prodcycle.com)
- [Report an issue](https://github.com/prodcycle/actions/issues)
- [Security policy](SECURITY.md)
- [Contact support](mailto:support@prodcycle.com)

## License

MIT. See [LICENSE](LICENSE) for details.
