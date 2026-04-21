// =============================================================================
// ProdCycle Compliance Code Scanner: Entry Point
// =============================================================================
//
// Flow:
//   1. Parse action inputs
//   2. Collect changed files from PR diff (or all files for full scan)
//   3. Send to ProdCycle /v1/compliance/validate
//   4. Create PR annotations + comment with results
//   5. Set outputs and fail if violations exceed threshold
// =============================================================================

import * as core from "@actions/core";
import * as github from "@actions/github";
import { collectChangedFiles, collectAllFiles, filterFindingsToDiff } from "./diff";
import { ComplianceApiClient } from "./api-client";
import {
  createAnnotations,
  postReviewComments,
  postSummaryComment,
  writeJobSummary,
} from "./annotate";
import type { ActionInputs } from "./types";

function parseInputs(): ActionInputs {
  const apiKey = core.getInput("api-key", { required: true });
  if (!apiKey.startsWith("pc_")) {
    throw new Error(
      'Invalid API key format. Expected a key starting with "pc_".',
    );
  }

  const rawMode = core.getInput("scan-mode") || "auto";
  if (!["auto", "diff", "full"].includes(rawMode)) {
    throw new Error(`Invalid scan-mode "${rawMode}". Must be one of: auto, diff, full.`);
  }

  const annotate = core.getBooleanInput("annotate");
  const rawReviewEvent = core.getInput("review-event").trim().toLowerCase();
  const reviewEvent = resolveReviewEvent(rawReviewEvent, annotate);

  return {
    apiKey,
    apiUrl: core.getInput("api-url") || "https://api.prodcycle.com",
    frameworks: parseCommaSeparated(core.getInput("frameworks")),
    failOn: parseCommaSeparated(core.getInput("fail-on") || "critical,high"),
    severityThreshold: core.getInput("severity-threshold") || "low",
    include: parseCommaSeparated(core.getInput("include")),
    exclude: parseCommaSeparated(core.getInput("exclude")),
    scanMode: rawMode as "auto" | "diff" | "full",
    annotate,
    comment: core.getBooleanInput("comment"),
    reviewEvent,
    excludeAcceptedRisk: core.getBooleanInput("exclude-accepted-risk"),
  };
}

/**
 * Resolve the `review-event` input to a concrete value.
 *
 * Empty string (the default) preserves back-compat with v2.0.x where
 * `annotate` alone gated the PR review:
 *  - `annotate: true`  → "auto"  (COMMENT on pass, REQUEST_CHANGES on fail)
 *  - `annotate: false` → "none"  (no PR review)
 */
export function resolveReviewEvent(
  raw: string,
  annotate: boolean,
): ActionInputs["reviewEvent"] {
  if (raw === "") {
    return annotate ? "auto" : "none";
  }
  const allowed = ["auto", "comment", "request-changes", "none"] as const;
  if (!(allowed as readonly string[]).includes(raw)) {
    throw new Error(
      `Invalid review-event "${raw}". Must be one of: ${allowed.join(", ")}.`,
    );
  }
  return raw as ActionInputs["reviewEvent"];
}

function parseCommaSeparated(value: string): string[] {
  if (!value.trim()) return [];
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

async function runDiffScan(
  context: typeof github.context,
  repoRoot: string,
  inputs: ActionInputs,
) {
  const baseSha = context.payload.pull_request?.base?.sha || "HEAD~1";
  const headSha =
    context.payload.pull_request?.head?.sha ||
    process.env.GITHUB_SHA ||
    "HEAD";

  core.info(`Diff scan: ${baseSha.substring(0, 8)} -> ${headSha.substring(0, 8)}`);

  return collectChangedFiles(
    baseSha,
    headSha,
    repoRoot,
    inputs.include,
    inputs.exclude,
  );
}

async function run(): Promise<void> {
  const inputs = parseInputs();

  // Mask the API key in logs
  core.setSecret(inputs.apiKey);

  // ── 1. Determine PR context ──

  const context = github.context;

  const repoRoot = process.env.GITHUB_WORKSPACE || process.cwd();
  let files;

  if (inputs.scanMode === "full") {
    // Full codebase scan — scan every file in the repo
    core.info("Running full codebase scan...");
    files = await collectAllFiles(repoRoot, inputs.include, inputs.exclude);
  } else if (inputs.scanMode === "auto") {
    // Auto mode — diff scan for PRs, full scan for pushes
    if (context.payload.pull_request) {
      core.info("Auto mode: PR detected, running diff scan...");
      files = await runDiffScan(context, repoRoot, inputs);
    } else {
      core.info("Auto mode: No PR detected, running full codebase scan...");
      files = await collectAllFiles(repoRoot, inputs.include, inputs.exclude);
    }
  } else {
    // Diff mode (explicitly requested) — only scan the diffs from the PR
    if (!context.payload.pull_request) {
      core.info("Not a pull request event. Falling back to full codebase scan.");
      files = await collectAllFiles(repoRoot, inputs.include, inputs.exclude);
    } else {
      files = await runDiffScan(context, repoRoot, inputs);
    }
  }

  if (files.length === 0) {
    core.info("No changed files to scan");
    core.setOutput("passed", "true");
    core.setOutput("findings-count", "0");
    core.setOutput("scan-id", "");
    core.setOutput("summary", "{}");
    return;
  }

  core.info(`Scanning ${files.length} file(s)...`);

  // ── 3. Call ProdCycle API ──

  const client = new ComplianceApiClient(inputs.apiUrl, inputs.apiKey);

  // Extract the PR author (the user who opened the pull request)
  const prAuthor = context.payload.pull_request?.user?.login as string | undefined;
  if (prAuthor) {
    core.info(`PR author: ${prAuthor}`);
  }

  let result = await client.validate(files, {
    frameworks: inputs.frameworks.length > 0 ? inputs.frameworks : undefined,
    severityThreshold: inputs.severityThreshold,
    failOn: inputs.failOn.length > 0 ? inputs.failOn : undefined,
    excludeAcceptedRisk: inputs.excludeAcceptedRisk,
    actor: prAuthor,
  });

  // In diff mode, filter out findings on lines outside the PR diff.
  // The API scans full file contents for context but we only surface
  // findings on lines the PR actually changed.
  if ((inputs.scanMode === "diff" || inputs.scanMode === "auto") && context.payload.pull_request) {
    result = filterFindingsToDiff(result, files, inputs.failOn);
  }

  core.info(
    `Scan complete: ${result.passed ? "PASSED" : "FAILED"} with ${result.findingsCount} finding(s)`,
  );

  // ── 4. Set outputs ──

  core.setOutput("passed", String(result.passed));
  core.setOutput("findings-count", String(result.findingsCount));
  core.setOutput("scan-id", result.scanId);
  core.setOutput("summary", JSON.stringify(result.summary));

  // ── 5. Annotate PR ──

  if (inputs.annotate && result.findings.length > 0) {
    createAnnotations(result.findings);
  }

  // ── 6. Post PR review with inline comments ──

  if (
    inputs.reviewEvent !== "none" &&
    context.payload.pull_request &&
    result.findings.length > 0
  ) {
    try {
      const resolvedEvent = resolveReviewEventForPass(
        inputs.reviewEvent,
        result.passed,
      );
      await postReviewComments(result.findings, resolvedEvent);
    } catch (err) {
      core.warning(
        `Failed to post PR review comments: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  // ── 7. Post PR summary comment ──

  if (inputs.comment && context.payload.pull_request) {
    try {
      await postSummaryComment(
        result.findings,
        result.summary,
        result.scanId,
        result.passed,
        inputs.apiUrl,
      );
    } catch (err) {
      core.warning(
        `Failed to post PR comment: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  // ── 8. Write job summary ──

  writeJobSummary(result.summary, result.scanId, result.passed, files.length);

  // ── 9. Fail the action if scan did not pass ──

  if (!result.passed) {
    core.setFailed(
      `Compliance check failed: ${result.findingsCount} finding(s) detected. See annotations for details.`,
    );
  }
}

/**
 * Collapse the user-facing `review-event` value to the concrete GitHub
 * review event string at the moment we know whether the scan passed.
 */
function resolveReviewEventForPass(
  event: Exclude<ActionInputs["reviewEvent"], "none">,
  passed: boolean,
): "COMMENT" | "REQUEST_CHANGES" {
  switch (event) {
    case "auto":
      return passed ? "COMMENT" : "REQUEST_CHANGES";
    case "comment":
      return "COMMENT";
    case "request-changes":
      return "REQUEST_CHANGES";
  }
}

run().catch((err) => {
  core.setFailed(
    `Action failed: ${err instanceof Error ? err.message : String(err)}`,
  );
});
