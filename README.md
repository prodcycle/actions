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
| `review-event`       | No       | `comment`                   | PR review event: `comment` (advisory, never blocks merge — the CI step still fails on blocking findings) / `request-changes` (blocks merge via the review) / `auto` (pre-v2.4 behavior: COMMENT on pass, REQUEST_CHANGES on fail) / `none` |
| `exclude-accepted-risk` | No   | `true`                      | Skip findings marked accepted-risk in ProdCycle. Requires `product-id` or `sync-config-id`. |
| `exclude-resolved`   | No       | `false`                     | Also skip findings marked resolved in ProdCycle (opt-in). Requires `product-id` or `sync-config-id`. |
| `product-id`         | No       |                             | ProdCycle product UUID this repo maps to. Enables accepted-risk / resolved suppression. |
| `sync-config-id`     | No       |                             | ProdCycle sync-config UUID linking this repo to a product. Alternative to `product-id`. |
| `github-token`       | No       | `${{ github.token }}`       | Token for PR comments and annotations. Defaults to the automatic `GITHUB_TOKEN`.        |
| `comment-identity`   | No       | `auto`                      | Who authors PR comments: `auto` (prodcycle[bot] when the App is installed, else github-actions[bot]), `app` (require the App), `github-token`. |

### Outputs

| Output           | Description                                       |
| ---------------- | ------------------------------------------------- |
| `passed`         | Whether the scan passed (`true`/`false`)          |
| `findings-count` | Total number of findings                          |
| `scan-id`        | ProdCycle scan ID for linking to the dashboard    |
| `summary`        | JSON summary of results by severity and framework |

### How comments appear on your PR

The scanner leaves three kinds of feedback, all branded as **ProdCycle Compliance**:

- **Inline review comments** on the exact lines a finding was detected, each with the rule, severity, message, and remediation.
- A single **summary comment** (updated in place on each run, never duplicated) with the severity and framework breakdown.
- Inline workflow **annotations** on the diff (via `annotate`).

**Posting as `prodcycle[bot]`.** With `comment-identity: auto` (the default), the action requests a short-lived token from the [ProdCycle GitHub App](https://github.com/apps/prodcycle) (using your `pc_` API key) so comments are authored by **`prodcycle[bot]`** with the ProdCycle name and avatar. This requires the ProdCycle GitHub App to be installed on the repository. If it isn't (or the backend is unreachable), the action transparently falls back to the built-in `GITHUB_TOKEN` and posts as `github-actions[bot]` — the comment content is identical, only the author differs. Set `comment-identity: github-token` to always use `github-actions[bot]`, or `app` to require the App identity.

**Auto-resolving fixed findings.** When a contributor pushes a fix and the finding disappears from the next scan, the action posts a brief "✅ Resolved by ProdCycle" reply and **marks that review thread resolved**. Only threads ProdCycle authored are ever touched — human and other-bot threads are left alone.

> ⚠️ **Auto-resolve requires the ProdCycle App.** GitHub does **not** allow the default `GITHUB_TOKEN` (`github-actions[bot]`) to call the `resolveReviewThread` GraphQL mutation — it returns "Resource not accessible by integration" even with `pull-requests: write`. Install the [ProdCycle GitHub App](https://github.com/apps/prodcycle) so the action posts as `prodcycle[bot]`, which **is** permitted to resolve threads. Without the App, inline comments still post (as `github-actions[bot]`) but old threads stay open across pushes — the action will log a one-time warning telling you exactly this.

### Respecting accepted-risk and resolved findings

When you mark a finding **Accept Risk** (or **Resolved**) in the ProdCycle dashboard, you usually don't want CI to keep failing on it. To honor those decisions, tell the action which ProdCycle **product** this repo maps to via `product-id` or `sync-config-id`:

```yaml
- uses: prodcycle/actions/compliance@v2
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    product-id: 123e4567-e89b-12d3-a456-426614174000
    exclude-resolved: true   # also suppress findings you've marked Resolved
```

- **Accepted-risk** findings are excluded by default (`exclude-accepted-risk: true`) — but **only when a product is identified**. Without `product-id`/`sync-config-id` there's no product to look up the decisions against, so nothing is suppressed.
- **Resolved** findings are excluded only when you opt in with `exclude-resolved: true`.
- Matching is by a line-stable fingerprint, so an accepted/resolved finding stays suppressed even after surrounding code moves.
- On pull-request (diff) scans the action never alters your product's stored findings — it only *reads* your accept/resolve decisions to filter the PR results. Reconciliation (marking findings resolved when they disappear) happens only on full-repo scans.

> ⚠️ **Accepted-risk vs Resolved — stickiness differs.** "Accepted-risk" status is carried forward into every new full scan, so it stays suppressed across runs. "Resolved" status is **not** carried forward: the next full scan re-detects the finding as `ACTIVE` (a new row), so `exclude-resolved` only suppresses it until the next full repo scan. Use **Accept Risk** for findings you'll never address; use **Resolve** for findings you've actually fixed.

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

#### Block the merge button via a "Changes requested" review

By default (`review-event: comment`) the action posts an advisory review and fails the CI step — branch protection enforces the block via the failed check. If you'd rather have the action itself post a "Changes requested" review (which blocks the merge button regardless of branch-protection config), opt in:

```yaml
- uses: prodcycle/actions/compliance@v2
  with:
    api-key: ${{ secrets.PRODCYCLE_API_KEY }}
    review-event: request-changes
```

Or use `auto` for the pre-v2.4 behavior (COMMENT on pass, REQUEST_CHANGES on fail).

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

### 4. (Optional) Install the ProdCycle GitHub App

To have comments authored by **`prodcycle[bot]`** (with the ProdCycle name and avatar) instead of `github-actions[bot]`, install the [ProdCycle GitHub App](https://github.com/apps/prodcycle) on your repository or organization:

- The App must be granted **`Pull requests: Read & write`** so the scanner can post reviews and resolve threads.
- No extra workflow config is needed — with `comment-identity: auto` (the default) the action automatically uses the App when it's installed, and falls back to `github-actions[bot]` when it isn't.

This step is **optional**: the scanner works fully without the App; only the comment author differs.

## Permissions

The action needs the following GitHub token permissions (set under `permissions:` in your workflow):

- `contents: read` to checkout and read changed files
- `pull-requests: write` to post annotations, summary comments, inline reviews, and to resolve threads when findings are fixed

When posting as `prodcycle[bot]`, the equivalent permission is granted to the ProdCycle GitHub App (step 4) rather than the workflow token.

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
