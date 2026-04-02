# ProdCycle Compliance Code Scanner

A GitHub Action that scans pull request changes for compliance violations against SOC 2 and HIPAA frameworks via the [ProdCycle](https://prodcycle.com) API.

> **Requires a ProdCycle account.** This action calls the ProdCycle compliance API, which requires a valid API key (`pc_...`). [Sign up at prodcycle.com](https://app.prodcycle.com) to get started.

## How it works

On every pull request:

1. Collects changed files from the PR diff (full file content, not just the diff)
2. Sends them to the ProdCycle compliance check API
3. Creates inline annotations on the PR for each finding
4. Posts a summary comment with severity and framework breakdown
5. Fails the check if findings match the configured severity threshold

## Quick start

```yaml
# .github/workflows/compliance.yml
name: Compliance Code Scanner
on:
  pull_request:

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
      - uses: prodcycle/compliance-code-scanner@v1
        with:
          api-key: ${{ secrets.PRODCYCLE_API_KEY }}
```

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

Create `.github/workflows/compliance.yml` in your repository with the configuration above.

## Inputs

| Input                | Required | Default                     | Description                                                              |
| -------------------- | -------- | --------------------------- | ------------------------------------------------------------------------ |
| `api-key`            | Yes      |                             | ProdCycle compliance API key (`pc_...`)                                  |
| `api-url`            | No       | `https://api.prodcycle.com` | ProdCycle API base URL                                                   |
| `frameworks`         | No       | Workspace setting           | Comma-separated framework IDs (`soc2,hipaa`)                             |
| `fail-on`            | No       | `critical,high`             | Comma-separated severities that fail the check                           |
| `severity-threshold` | No       | `low`                       | Minimum severity to include in results                                   |
| `include`            | No       | All changed files           | Comma-separated glob patterns to include (`**/*.tf,**/*.yaml`)           |
| `exclude`            | No       | None                        | Comma-separated glob patterns to exclude (`test/**,docs/**`)             |
| `annotate`           | No       | `true`                      | Create inline PR annotations for findings                                |
| `comment`            | No       | `true`                      | Post a summary comment on the PR                                         |

## Outputs

| Output           | Description                                       |
| ---------------- | ------------------------------------------------- |
| `passed`         | Whether the scan passed (`true`/`false`)          |
| `findings-count` | Total number of findings                          |
| `scan-id`        | ProdCycle scan ID for linking to the dashboard    |
| `summary`        | JSON summary of results by severity and framework |

## Examples

### Scan specific frameworks

```yaml
- uses: prodcycle/compliance-code-scanner@v1
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    frameworks: soc2,hipaa
```

### Only fail on critical findings

```yaml
- uses: prodcycle/compliance-code-scanner@v1
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    fail-on: critical
```

### Scan only infrastructure files

```yaml
- uses: prodcycle/compliance-code-scanner@v1
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    include: "**/*.tf,**/*.yaml,**/*.yml,**/Dockerfile"
    exclude: "test/**,docs/**"
```

### Use outputs in subsequent steps

```yaml
- uses: prodcycle/compliance-code-scanner@v1
  id: compliance
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
  continue-on-error: true

- run: |
    echo "Passed: ${{ steps.compliance.outputs.passed }}"
    echo "Findings: ${{ steps.compliance.outputs.findings-count }}"
    echo "Scan: ${{ steps.compliance.outputs.scan-id }}"
```

### Self-hosted ProdCycle instance

```yaml
- uses: prodcycle/compliance-code-scanner@v1
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    api-url: https://api.yourcompany.com
```

## Supported frameworks

| ID     | Framework |
| ------ | --------- |
| `soc2` | SOC 2     |
| `hipaa`| HIPAA     |

If no `frameworks` input is specified, the action uses the frameworks configured on your ProdCycle workspace.

## Permissions

The action requires the following GitHub token permissions:

- `contents: read` to checkout and read changed files
- `pull-requests: write` to post annotations and summary comments

## Development

```bash
pnpm install
pnpm run type-check    # TypeScript check
pnpm run test          # Run tests
pnpm run build         # Bundle with ncc into dist/
pnpm run all           # All of the above
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## Support

- 📖 [ProdCycle Documentation](https://docs.prodcycle.com)
- 🐛 [Report an issue](https://github.com/prodcycle/compliance-code-scanner/issues)
- 🔒 [Security policy](SECURITY.md)
- 💬 [Contact support](mailto:support@prodcycle.com)

## License

MIT. See [LICENSE](LICENSE) for details.
