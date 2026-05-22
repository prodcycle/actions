# Backend dependency: `POST /v1/compliance/actions/github/installation-token`

> **Status:** implemented in `prodcycle/api` on the `/v1/compliance/actions/*`
> router (api tier, `pc_`-key auth + compliance feature gate) — see
> `ComplianceInteractiveController.getGithubInstallationToken`.

The Compliance action posts PR comments as **`prodcycle[bot]`** (the ProdCycle
GitHub App) when `comment-identity` is `auto` (default) or `app`. Because the
App's private key can't ship inside a customer's CI, the action asks the
ProdCycle backend to mint a short-lived, repo-scoped installation token using
the `pc_` API key it already holds.

Until this endpoint exists, the action degrades gracefully to `GITHUB_TOKEN`
(`github-actions[bot]`) — so shipping this endpoint is what flips the author to
`prodcycle[bot]`, with **no change required in the action**.

## Contract

```
POST {api-url}/v1/compliance/actions/github/installation-token
Authorization: Bearer pc_<key>
x-api-version: v1
Content-Type: application/json

{ "owner": "<repo owner>", "repo": "<repo name>" }
```

### Success — `200`

```jsonc
{
  "status": "success",
  "statusCode": 200,
  "data": {
    "token": "ghs_xxx",          // installation access token
    "expiresAt": "2026-05-21T23:10:00Z"  // optional; informational
  }
}
```

The action reads `data.token` (also accepts `data.installationToken`). Any
non-2xx response, missing token, or network error → silent fallback to
`GITHUB_TOKEN`. Failures are logged at debug level only, so a not-yet-deployed
endpoint is a no-op rather than an error.

## Implementation notes (existing building blocks)

All the pieces already exist in `prodcycle/api`:

- **Auth:** `complianceAuthMiddleware` resolves a `pc_` key →
  `{ organizationId, workspaceId, userId, ... }` on `req.complianceApiKey`
  (`api/src/api/middleware/compliance-auth.middleware.ts`).
- **Token minting:** `GitHubOAuthService.getInstallationAccessToken(organizationId)`
  already returns a cached/fresh installation token
  (`api/src/domain/integrations/github/github-oauth.service.ts`). It reads the
  installation id from the org's `integration_connections.provider_metadata.installationId`.
- **Route home:** alongside the other GitHub routes in
  `api/src/api/routes/integration.routes.ts`.

Sketch:

```ts
integrationRouter.post(
  "/github/installation-token",
  complianceAuthMiddleware,
  apiRateLimit,
  async (req, res, next) => {
    const orgId = (req as any).complianceApiKey?.organizationId;
    if (!orgId) return next(new UnauthorizedError("API key required"));
    // Optional hardening: verify { owner, repo } is in this workspace's
    // sync_configurations before handing back a token.
    const token = await githubOAuthService.getInstallationAccessToken(orgId);
    return ResponseBuilder.success(res, { token });
  },
);
```

### Recommended hardening

- Validate the requested `{ owner, repo }` is connected to the caller's
  workspace (look it up in `sync_configurations`) before returning a token, so
  a key for workspace A can't obtain a token for an unrelated repo.
- Installation tokens are org/installation-scoped, not single-repo. If tighter
  scoping is desired, pass `repositories` / `repository_ids` when calling
  `POST /app/installations/:id/access_tokens`.
- Ensure the App's permissions include `pull_requests: write` so the action can
  post reviews and resolve threads.
