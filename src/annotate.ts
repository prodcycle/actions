// =============================================================================
// ProdCycle Compliance Code Scanner: PR Annotations & Comments
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
      `Resource: ${finding.resourceType} (${finding.resourceName})`,
      "",
      `Remediation: ${finding.remediation}`,
    ].join("\n");

    // Use @actions/core annotation which maps to the GitHub check annotation API
    const annotationProps: core.AnnotationProperties = {
      title,
      file: finding.resourcePath,
      startLine: finding.startLine || undefined,
      endLine: finding.endLine || undefined,
    };

    if (level === "error") {
      core.error(message, annotationProps);
    } else if (level === "warning") {
      core.warning(message, annotationProps);
    } else {
      core.notice(message, annotationProps);
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
  _apiUrl: string,
): Promise<void> {
  const token = core.getInput("github-token") || process.env.GITHUB_TOKEN;
  if (!token) {
    core.warning("No GitHub token available. Skipping PR comment. Set the 'github-token' input or ensure GITHUB_TOKEN is in the environment.");
    return;
  }

  const context = github.context;
  if (!context.payload.pull_request) {
    core.debug("Not a pull request event. Skipping PR comment.");
    return;
  }

  const octokit = github.getOctokit(token);
  const prNumber = context.payload.pull_request.number;
  const { owner, repo } = context.repo;

  const headSha = context.payload.pull_request.head?.sha || "";
  const repoUrl = `https://github.com/${owner}/${repo}`;
  const body = buildCommentBody(findings, summary, scanId, passed, repoUrl, headSha);
  const marker = "<!-- prodcycle-actions-compliance -->";
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
  repoUrl: string,
  headSha: string,
): string {
  if (summary.total === 0) {
    const lines: string[] = [
      "### ✅ Compliance Check Passed",
      "",
      "No compliance findings were detected in this PR's changed files.",
      "",
      `Scan ID: \`${scanId}\``,
    ];
    return lines.join("\n");
  }

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
      let location: string;
      if (f.startLine && headSha) {
        const lineFragment = f.endLine && f.endLine !== f.startLine
          ? `L${f.startLine}-L${f.endLine}`
          : `L${f.startLine}`;
        const link = `${repoUrl}/blob/${headSha}/${f.resourcePath}#${lineFragment}`;
        location = `\`${f.resourcePath}\`, line ${f.startLine}${f.endLine && f.endLine !== f.startLine ? `-${f.endLine}` : ""} ([link](${link}))`;
      } else {
        location = `\`${f.resourcePath}\``;
      }
      lines.push(
        `- ${icon} **${f.ruleId}** in ${location}: ${f.message}`,
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

  // Scan ID for reference (dashboard page coming soon)
  lines.push(`Scan ID: \`${scanId}\``);

  return lines.join("\n");
}

/**
 * Post a PR review with inline comments on the specific lines where findings
 * were detected. This creates the same experience as review bots like Greptile —
 * comments appear directly on the diff with the relevant code highlighted.
 */
export async function postReviewComments(
  findings: ScanFinding[],
  passed: boolean,
): Promise<void> {
  const token = core.getInput("github-token") || process.env.GITHUB_TOKEN;
  if (!token) {
    core.warning("No GitHub token available. Skipping PR review comments.");
    return;
  }

  const context = github.context;
  if (!context.payload.pull_request) {
    core.debug("Not a pull request event. Skipping PR review comments.");
    return;
  }

  const octokit = github.getOctokit(token);
  const prNumber = context.payload.pull_request.number;
  const commitSha = context.payload.pull_request.head?.sha;
  const { owner, repo } = context.repo;

  // Only post review comments for findings that have line information
  const reviewableFindings = findings.filter((f) => f.startLine > 0 && f.endLine > 0);
  const skippedCount = findings.length - reviewableFindings.length;
  if (skippedCount > 0) {
    core.info(
      `${skippedCount} finding(s) lack line information (startLine/endLine). They will not appear as inline comments.`,
    );
  }
  if (reviewableFindings.length === 0) {
    return;
  }

  if (!commitSha) {
    core.warning("Could not determine head commit SHA. Skipping PR review.");
    return;
  }

  // Fetch existing review comments so we can skip duplicates
  const existingKeys = await fetchExistingCommentKeys(octokit, owner, repo, prNumber);

  // Fetch the PR diff ranges so we only comment on lines within the diff.
  // GitHub rejects review comments on lines outside the diff with 422.
  const diffRanges = await fetchDiffRanges(octokit, owner, repo, prNumber);

  const comments: ReviewComment[] = [];

  for (const f of reviewableFindings) {
    const icon = SEVERITY_ICONS[f.severity] || "";
    const fileRanges = diffRanges.get(f.resourcePath);

    // Check if the finding's end line falls within a diff hunk
    const inDiff = fileRanges?.some(
      (range) => f.endLine >= range.start && f.endLine <= range.end,
    );

    if (inDiff && fileRanges) {
      // Inline comment on the specific line(s)
      const body = [
        `${icon} **[${f.severity.toUpperCase()}] ${f.ruleId}**`,
        "",
        f.message,
        "",
        `> **Remediation:** ${f.remediation}`,
        "",
        `Framework: ${f.framework.toUpperCase()} (${f.controlId})`,
      ].join("\n");

      const comment: ReviewComment = {
        path: f.resourcePath,
        body,
        line: f.endLine,
        side: "RIGHT",
      };

      // Use multi-line comment if both start and end fall within the same hunk.
      if (f.startLine > 0 && f.startLine < f.endLine) {
        const sharedHunk = fileRanges.find(
          (range) =>
            f.startLine >= range.start &&
            f.startLine <= range.end &&
            f.endLine >= range.start &&
            f.endLine <= range.end,
        );
        if (sharedHunk) {
          comment.start_line = f.startLine;
          comment.start_side = "RIGHT";
        }
      }

      // Deduplicate: skip if an identical comment already exists
      const key = reviewCommentKey(comment.path, comment.line, f.ruleId);
      if (!existingKeys.has(key)) {
        comments.push(comment);
      } else {
        core.debug(`Skipping duplicate inline comment: ${key}`);
      }
    } else {
      // Finding is outside the diff — use a file-level comment so the
      // user still sees it in the "Files changed" view.
      const repoUrl = `https://github.com/${owner}/${repo}`;
      const lineFragment = f.startLine !== f.endLine
        ? `L${f.startLine}-L${f.endLine}`
        : `L${f.startLine}`;
      const fileLink = `${repoUrl}/blob/${commitSha}/${f.resourcePath}#${lineFragment}`;

      const body = [
        `${icon} **[${f.severity.toUpperCase()}] ${f.ruleId}** (line ${f.startLine}${f.endLine !== f.startLine ? `–${f.endLine}` : ""}) ([view](${fileLink}))`,
        "",
        f.message,
        "",
        `> **Remediation:** ${f.remediation}`,
        "",
        `Framework: ${f.framework.toUpperCase()} (${f.controlId})`,
        "",
        `_ℹ️ This finding is on a line outside the PR diff._`,
      ].join("\n");

      // Deduplicate: skip if an identical file-level comment already exists
      const key = reviewCommentKey(f.resourcePath, undefined, f.ruleId);
      if (!existingKeys.has(key)) {
        comments.push({
          path: f.resourcePath,
          body,
          subject_type: "file",
        });
      } else {
        core.debug(`Skipping duplicate file-level comment: ${key}`);
      }
    }
  }

  if (comments.length === 0) {
    const dedupCount = reviewableFindings.length;
    core.info(
      `All ${dedupCount} review comment(s) already exist on this PR. Skipping review.`,
    );
    return;
  }

  const event = passed ? "COMMENT" : "REQUEST_CHANGES";
  const reviewBody = passed
    ? "✅ **ProdCycle Compliance Scan** — findings detected but within acceptable thresholds."
    : "❌ **ProdCycle Compliance Scan** — compliance violations found that require attention.";

  const inlineCount = comments.filter((c) => !c.subject_type).length;
  const fileCount = comments.filter((c) => c.subject_type === "file").length;
  core.info(
    `Posting review: ${inlineCount} inline comment(s), ${fileCount} file-level comment(s).`,
  );
  for (const c of comments) {
    core.debug(`  - ${c.path}:${c.subject_type === "file" ? "file" : `${c.start_line ?? c.line}-${c.line}`}`);
  }

  try {
    await octokit.rest.pulls.createReview({
      owner,
      repo,
      pull_number: prNumber,
      commit_id: commitSha,
      event: event as "COMMENT" | "REQUEST_CHANGES",
      body: reviewBody,
      comments,
    });
    core.info(
      `Posted PR review with ${comments.length} inline comment(s).`,
    );
  } catch (err) {
    core.warning(
      `Batch review failed: ${err instanceof Error ? err.message : String(err)}. Falling back to individual comments.`,
    );

    // Fall back: post each comment individually, skipping those that
    // GitHub rejects (e.g. lines outside the diff).
    let posted = 0;
    for (const comment of comments) {
      try {
        if (comment.subject_type === "file") {
          await octokit.rest.pulls.createReviewComment({
            owner,
            repo,
            pull_number: prNumber,
            commit_id: commitSha,
            path: comment.path,
            body: comment.body,
            subject_type: "file",
          });
        } else {
          await octokit.rest.pulls.createReviewComment({
            owner,
            repo,
            pull_number: prNumber,
            commit_id: commitSha,
            path: comment.path,
            body: comment.body,
            line: comment.line,
            ...(comment.start_line ? { start_line: comment.start_line } : {}),
            side: "RIGHT" as const,
            ...(comment.start_line ? { start_side: "RIGHT" as const } : {}),
          });
        }
        posted++;
      } catch (commentErr) {
        core.debug(
          `Skipped comment on ${comment.path}:${comment.subject_type === "file" ? "file" : String(comment.line)}: ${commentErr instanceof Error ? commentErr.message : String(commentErr)}`,
        );
      }
    }

    if (posted > 0) {
      core.info(`Posted ${posted} of ${comments.length} comment(s) individually.`);
    } else {
      core.info(
        "No comments could be posted.",
      );
    }
  }
}

/** Shape expected by octokit pulls.createReview comments */
interface ReviewComment {
  path: string;
  body: string;
  /** Line number for inline comments. Omitted for file-level comments. */
  line?: number;
  side?: "RIGHT";
  start_line?: number;
  start_side?: "RIGHT";
  /** Set to "file" for file-level comments (findings outside the diff). */
  subject_type?: "file";
}

/**
 * Build a dedup key for a review comment: path + line + ruleId.
 * File-level comments use "file" instead of a line number.
 */
function reviewCommentKey(
  path: string,
  line: number | undefined,
  ruleId: string,
): string {
  return `${path}::${line ?? "file"}::${ruleId}`;
}

/**
 * Regex to extract the ruleId from a review comment body.
 * Matches the pattern: **[SEVERITY] RULE_ID**
 */
const RULE_ID_RE = /\*\*\[\w+\]\s+(.+?)\*\*/;

/**
 * Fetch existing review comments on the PR and build a set of dedup keys
 * so we can avoid posting the same comment twice across re-runs.
 */
async function fetchExistingCommentKeys(
  octokit: ReturnType<typeof github.getOctokit>,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<Set<string>> {
  const keys = new Set<string>();

  try {
    const comments = await octokit.paginate(
      octokit.rest.pulls.listReviewComments,
      { owner, repo, pull_number: prNumber, per_page: 100 },
    );

    for (const c of comments) {
      const match = c.body?.match(RULE_ID_RE);
      if (!match) continue;
      const ruleId = match[1];
      const line = c.line ?? undefined;
      // c.subject_type === "file" means file-level comment
      const isFileLevel = (c as { subject_type?: string }).subject_type === "file" || !line;
      keys.add(reviewCommentKey(c.path, isFileLevel ? undefined : line, ruleId));
    }
  } catch (err) {
    core.warning(
      `Failed to fetch existing review comments for dedup: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  return keys;
}

/** A range of lines in the "new" side of a diff hunk */
interface DiffRange {
  start: number;
  end: number;
}

/**
 * Fetch the list of files changed in a PR and parse their diff hunks
 * into line ranges on the "new" (right) side. Only lines within these
 * ranges can be targeted by `pulls.createReview` comments.
 */
async function fetchDiffRanges(
  octokit: ReturnType<typeof github.getOctokit>,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<Map<string, DiffRange[]>> {
  const ranges = new Map<string, DiffRange[]>();

  try {
    const files = await octokit.paginate(octokit.rest.pulls.listFiles, {
      owner,
      repo,
      pull_number: prNumber,
      per_page: 100,
    });

    for (const file of files) {
      if (!file.patch) continue;
      const fileRanges = parseDiffHunks(file.patch);
      if (fileRanges.length > 0) {
        ranges.set(file.filename, fileRanges);
      }
    }
  } catch (err) {
    core.warning(
      `Failed to fetch PR diff ranges: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  return ranges;
}

/**
 * Parse unified diff patch text to extract line ranges on the new (right) side.
 * Hunk headers look like: @@ -oldStart,oldCount +newStart,newCount @@
 */
export function parseDiffHunks(patch: string): DiffRange[] {
  const ranges: DiffRange[] = [];
  const hunkHeaderRe = /^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@/gm;
  let match: RegExpExecArray | null;

  while ((match = hunkHeaderRe.exec(patch)) !== null) {
    const start = parseInt(match[1], 10);
    const count = match[2] !== undefined ? parseInt(match[2], 10) : 1;
    if (count > 0) {
      ranges.push({ start, end: start + count - 1 });
    }
  }

  return ranges;
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
  let md: string;

  if (summary.total === 0) {
    md = [
      `## Compliance Code Scanner: ✅ Passed`,
      "",
      `${fileCount} file(s) scanned. No compliance findings detected.`,
      "",
      `Scan ID: \`${scanId}\``,
    ].join("\n");
  } else {
    const status = passed ? "✅ Passed" : "❌ Failed";
    md = [
      `## Compliance Code Scanner: ${status}`,
      "",
      `| Files scanned | Findings | Passed | Failed |`,
      `|:---:|:---:|:---:|:---:|`,
      `| ${fileCount} | ${summary.total} | ${summary.passed} | ${summary.failed} |`,
      "",
      `Scan ID: \`${scanId}\``,
    ].join("\n");
  }

  core.summary.addRaw(md).write();
}
