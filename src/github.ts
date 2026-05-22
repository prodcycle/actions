// =============================================================================
// ProdCycle Compliance Code Scanner: GitHub identity resolution
// =============================================================================
//
// Decides *who* authors the PR comments and reviews.
//
// GitHub attributes every comment to whoever owns the token that posts it. The
// built-in `GITHUB_TOKEN` always posts as `github-actions[bot]`. To have the
// comments authored by the ProdCycle GitHub App (`prodcycle[bot]`, with the
// ProdCycle name + avatar) the action requests a short-lived, repo-scoped App
// token from the ProdCycle API using your `pc_` API key.
//
// If that token can't be obtained (the ProdCycle GitHub App isn't installed on
// the repo, an older API, or a network error) the action transparently falls
// back to `GITHUB_TOKEN` and keeps working — comments are simply authored by
// `github-actions[bot]` instead of `prodcycle[bot]`.
// =============================================================================

import * as core from "@actions/core";
import * as github from "@actions/github";

export type CommentIdentity = "prodcycle-app" | "github-actions";

/** How the action should choose the token used to post comments. */
export type CommentIdentityMode = "auto" | "app" | "github-token";

export interface GitHubAuth {
  octokit: ReturnType<typeof github.getOctokit>;
  token: string;
  /** Who comments will be authored by. */
  identity: CommentIdentity;
}

const APP_TOKEN_TIMEOUT_MS = 15_000;

/**
 * Resolve the octokit client used for all PR comment / review / thread-resolve
 * calls, preferring the ProdCycle App identity.
 *
 * - `auto` (default): try the App token, fall back to GITHUB_TOKEN.
 * - `app`: require the App token; warn + fall back if it can't be obtained.
 * - `github-token`: skip the App entirely (always github-actions[bot]).
 *
 * Returns `null` only when no usable token exists at all (no App token AND no
 * github-token) — callers should treat that as "skip PR interactions".
 */
export async function resolveGitHubAuth(
  apiUrl: string,
  apiKey: string,
  mode: CommentIdentityMode,
): Promise<GitHubAuth | null> {
  const fallbackToken =
    core.getInput("github-token") || process.env.GITHUB_TOKEN || "";

  if (mode !== "github-token") {
    const appToken = await mintProdcycleAppToken(apiUrl, apiKey);
    if (appToken) {
      core.info(
        "PR comments will be posted as prodcycle[bot] (ProdCycle GitHub App).",
      );
      return {
        octokit: github.getOctokit(appToken),
        token: appToken,
        identity: "prodcycle-app",
      };
    }
    if (mode === "app") {
      core.warning(
        "comment-identity=app but a ProdCycle App installation token could not " +
          "be obtained (is the ProdCycle GitHub App installed on this repo?). " +
          "Falling back to GITHUB_TOKEN — comments will be authored by github-actions[bot].",
      );
    } else {
      core.info(
        "ProdCycle App token unavailable; posting as github-actions[bot]. " +
          "Install the ProdCycle GitHub App to have comments authored by prodcycle[bot].",
      );
    }
  }

  if (!fallbackToken) return null;
  return {
    octokit: github.getOctokit(fallbackToken),
    token: fallbackToken,
    identity: "github-actions",
  };
}

/**
 * Ask the ProdCycle backend for a repo-scoped GitHub App installation token.
 * Returns the token string, or `null` on any failure (the caller falls back
 * to GITHUB_TOKEN). Failures are intentionally non-fatal and only logged at
 * debug level — a missing endpoint is an expected state, not an error.
 */
async function mintProdcycleAppToken(
  apiUrl: string,
  apiKey: string,
): Promise<string | null> {
  const { owner, repo } = github.context.repo;
  if (!owner || !repo) return null;

  const url = `${apiUrl.replace(/\/+$/, "")}/v1/compliance/actions/github/installation-token`;
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
        "x-api-version": "v1",
        "User-Agent": "prodcycle/actions/compliance",
      },
      body: JSON.stringify({ owner, repo }),
      signal: AbortSignal.timeout(APP_TOKEN_TIMEOUT_MS),
    });

    if (!response.ok) {
      core.debug(
        `installation-token endpoint returned ${response.status}; using GITHUB_TOKEN.`,
      );
      return null;
    }

    const envelope = (await response.json()) as {
      data?: { token?: string; installationToken?: string };
    };
    const token = envelope?.data?.token ?? envelope?.data?.installationToken;
    if (typeof token === "string" && token.length > 0) {
      core.setSecret(token);
      return token;
    }
    core.debug("installation-token response had no token field; using GITHUB_TOKEN.");
    return null;
  } catch (err) {
    core.debug(
      `installation-token request failed (${
        err instanceof Error ? err.message : String(err)
      }); using GITHUB_TOKEN.`,
    );
    return null;
  }
}
