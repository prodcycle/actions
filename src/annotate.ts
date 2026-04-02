// =============================================================================
// ProdCycle Compliance Code Scanner — PR Annotations & Comments
// =============================================================================

import * as core from "@actions/core";
import * as github from "@actions/github";
import type { ScanFinding, ValidateSummary } from "./types";

const SEVERITY_ICONS: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
};

const SEVERITY_LEVEL: Record<string, "error" | "warning" | "notice"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "notice",
};

/**
 * Create GitHub annotations for each finding.
 * These appear inline on the PR diff view.
 */
export function createAnnotations(findings: ScanFinding[]): void {
  for (const finding of findings) {
    const level = SEVERITY_LEVEL[finding.severity] || "warning";
    const title = `[${finding.severity.toUpperCase()}] ${finding.ruleId}`;
    const message = [
      finding.message,
      "",
      `Framework: ${finding.framework} (${finding.controlId})`,
      `Resource: ${finding.resourceType} — ${finding.resourceName}`,
      "",
      `Remediation: ${finding.remediation}`,
    ].join("\n");

    // Use @actions/core annotation which maps to the GitHub check annotation API
    if (level === "error") {
      core.error(message, { title, file: finding.resourcePath });
    } else if (level === "warning") {
      core.warning(message, { title, file: finding.resourcePath });
    } else {
      core.notice(message, { title, file: finding.resourcePath });
    }
  }
}

/**
 * Post or update a summary comment on the PR.
 */
export async function postSummaryComment(
  findings: ScanFinding[],
  summary: ValidateSummary,
  scanId: string,
  passed: boolean,
  apiUrl: string,
): Promise<void> {
  const token = core.getInput("github-token") || process.env.GITHUB_TOKEN;
  if (!token) {
    core.warning("No GitHub token available — skipping PR comment. Set the 'github-token' input or ensure GITHUB_TOKEN is in the environment.");
    return;
  }

  const context = github.context;
  if (!context.payload.pull_request) {
    core.debug("Not a pull request event — skipping PR comment");
    return;
  }

  const octokit = github.getOctokit(token);
  const prNumber = context.payload.pull_request.number;
  const { owner, repo } = context.repo;

  const body = buildCommentBody(findings, summary, scanId, passed, apiUrl);
  const marker = "<!-- prodcycle-compliance-code-scanner -->";
  const fullBody = `${marker}\n${body}`;

  // Look for an existing comment to update
  const { data: comments } = await octokit.rest.issues.listComments({
    owner,
    repo,
    issue_number: prNumber,
    per_page: 100,
  });

  const existing = comments.find((c) => c.body?.includes(marker));

  if (existing) {
    await octokit.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existing.id,
      body: fullBody,
    });
    core.debug(`Updated existing comment #${existing.id}`);
  } else {
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: prNumber,
      body: fullBody,
    });
    core.debug("Created new PR comment");
  }
}

function buildCommentBody(
  findings: ScanFinding[],
  summary: ValidateSummary,
  scanId: string,
  passed: boolean,
  apiUrl: string,
): string {
  const status = passed
    ? "### ✅ Compliance Check Passed"
    : "### ❌ Compliance Check Failed";

  const lines: string[] = [status, ""];

  // Summary table
  lines.push("| Metric | Count |");
  lines.push("|--------|-------|");
  lines.push(`| Total controls | ${summary.total} |`);
  lines.push(`| Passed | ${summary.passed} |`);
  lines.push(`| Failed | ${summary.failed} |`);
  lines.push("");

  // Severity breakdown
  if (Object.keys(summary.bySeverity).length > 0) {
    lines.push("**By severity:**");
    for (const [severity, count] of Object.entries(summary.bySeverity)) {
      const icon = SEVERITY_ICONS[severity] || "";
      lines.push(`- ${icon} ${severity}: ${count}`);
    }
    lines.push("");
  }

  // Framework breakdown
  if (Object.keys(summary.byFramework).length > 0) {
    lines.push("**By framework:**");
    for (const [framework, count] of Object.entries(summary.byFramework)) {
      lines.push(`- ${framework.toUpperCase()}: ${count} finding(s)`);
    }
    lines.push("");
  }

  // Top findings (limit to 10)
  if (findings.length > 0) {
    lines.push("<details>");
    lines.push(`<summary>Findings (${findings.length})</summary>`);
    lines.push("");

    const shown = findings.slice(0, 10);
    for (const f of shown) {
      const icon = SEVERITY_ICONS[f.severity] || "";
      lines.push(
        `- ${icon} **${f.ruleId}** in \`${f.resourcePath}\` — ${f.message}`,
      );
      lines.push(`  - Remediation: ${f.remediation}`);
    }

    if (findings.length > 10) {
      lines.push("");
      lines.push(`_...and ${findings.length - 10} more findings_`);
    }

    lines.push("");
    lines.push("</details>");
    lines.push("");
  }

  // Dashboard link
  const dashboardBase = apiUrl.replace("api.", "app.").replace(/\/+$/, "");
  lines.push(
    `[View full report](${dashboardBase}/compliance/scans/${scanId}) | Scan ID: \`${scanId}\``,
  );

  return lines.join("\n");
}

/**
 * Write a GitHub Actions job summary (visible in the Actions tab).
 */
export function writeJobSummary(
  summary: ValidateSummary,
  scanId: string,
  passed: boolean,
  fileCount: number,
): void {
  const status = passed ? "✅ Passed" : "❌ Failed";

  const md = [
    `## Compliance Code Scanner — ${status}`,
    "",
    `| Files scanned | Findings | Passed | Failed |`,
    `|:---:|:---:|:---:|:---:|`,
    `| ${fileCount} | ${summary.total} | ${summary.passed} | ${summary.failed} |`,
    "",
    `Scan ID: \`${scanId}\``,
  ].join("\n");

  core.summary.addRaw(md).write();
}
