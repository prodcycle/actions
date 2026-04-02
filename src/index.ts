// =============================================================================
// ProdCycle Compliance Code Scanner — Entry Point
// =============================================================================
//
// Flow:
//   1. Parse action inputs
//   2. Collect changed files from PR diff
//   3. Send to ProdCycle /v1/compliance/validate
//   4. Create PR annotations + comment with results
//   5. Set outputs and fail if violations exceed threshold
// =============================================================================

import * as core from "@actions/core";
import * as github from "@actions/github";
import { collectChangedFiles } from "./diff";
import { ComplianceApiClient } from "./api-client";
import {
  createAnnotations,
  postSummaryComment,
  writeJobSummary,
} from "./annotate";
import type { ActionInputs } from "./types";

function parseInputs(): ActionInputs {
  const apiKey = core.getInput("api-key", { required: true });
  if (!apiKey.startsWith("cvk_")) {
    throw new Error(
      'Invalid API key format. Expected a key starting with "cvk_".',
    );
  }

  return {
    apiKey,
    apiUrl: core.getInput("api-url") || "https://api.prodcycle.com",
    frameworks: parseCommaSeparated(core.getInput("frameworks")),
    failOn: parseCommaSeparated(core.getInput("fail-on") || "critical,high"),
    severityThreshold: core.getInput("severity-threshold") || "low",
    include: parseCommaSeparated(core.getInput("include")),
    exclude: parseCommaSeparated(core.getInput("exclude")),
    annotate: core.getBooleanInput("annotate"),
    comment: core.getBooleanInput("comment"),
  };
}

function parseCommaSeparated(value: string): string[] {
  if (!value.trim()) return [];
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

async function run(): Promise<void> {
  const inputs = parseInputs();

  // Mask the API key in logs
  core.setSecret(inputs.apiKey);

  // ── 1. Determine PR context ──

  const context = github.context;

  if (!context.payload.pull_request) {
    core.info("Not a pull request event — scanning all files in workspace");
  }

  const baseSha =
    context.payload.pull_request?.base?.sha ||
    process.env.GITHUB_BASE_REF ||
    "HEAD~1";
  const headSha =
    context.payload.pull_request?.head?.sha || process.env.GITHUB_SHA || "HEAD";

  core.info(
    `Base: ${baseSha.substring(0, 8)} -> Head: ${headSha.substring(0, 8)}`,
  );

  // ── 2. Collect changed files ──

  const repoRoot = process.env.GITHUB_WORKSPACE || process.cwd();
  const files = await collectChangedFiles(
    baseSha,
    headSha,
    repoRoot,
    inputs.include,
    inputs.exclude,
  );

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

  const result = await client.validate(files, {
    frameworks: inputs.frameworks.length > 0 ? inputs.frameworks : undefined,
    severityThreshold: inputs.severityThreshold,
    failOn: inputs.failOn.length > 0 ? inputs.failOn : undefined,
  });

  core.info(
    `Scan complete: ${result.passed ? "PASSED" : "FAILED"} — ${result.findingsCount} finding(s)`,
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

  // ── 6. Post PR comment ──

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

  // ── 7. Write job summary ──

  writeJobSummary(result.summary, result.scanId, result.passed, files.length);

  // ── 8. Fail the action if scan did not pass ──

  if (!result.passed) {
    core.setFailed(
      `Compliance check failed: ${result.findingsCount} finding(s) detected. See annotations for details.`,
    );
  }
}

run().catch((err) => {
  core.setFailed(
    `Action failed: ${err instanceof Error ? err.message : String(err)}`,
  );
});
