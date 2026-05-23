// =============================================================================
// ProdCycle Compliance Code Scanner: PR Annotations & Comments
// =============================================================================

import * as core from "@actions/core";
import * as github from "@actions/github";
import type { ScanFinding, ValidateSummary } from "./types";
import type { CommentIdentity } from "./github";

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

const PRODCYCLE_APP_URL = "https://app.prodcycle.com";
const PRODCYCLE_DOCS_URL = "https://docs.prodcycle.com/compliance";

/** Options shared by the comment-posting helpers. */
export interface PostOptions {
  /**
   * Pre-resolved octokit (typically the ProdCycle App identity from
   * resolveGitHubAuth). When omitted, falls back to the github-token input.
   */
  octokit?: ReturnType<typeof github.getOctokit>;
  /** Who the comment is authored by — drives the body's branding footer. */
  identity?: CommentIdentity;
  /** Scan ID, surfaced in the branding footer for cross-reference. */
  scanId?: string;
}

type Octokit = ReturnType<typeof github.getOctokit>;

/**
 * Use the caller-provided octokit (App identity) when present, otherwise build
 * one from the github-token input. Returns null when no token is available.
 */
function resolveOctokit(provided?: Octokit): Octokit | null {
  if (provided) return provided;
  const token = core.getInput("github-token") || process.env.GITHUB_TOKEN;
  if (!token) return null;
  return github.getOctokit(token);
}

/**
 * Branding footer appended to comment bodies. When ProdCycle posts as its own
 * App (`prodcycle[bot]`), the author already carries the brand, so the footer
 * stays light; with github-actions[bot] we make the ProdCycle attribution
 * explicit so it's clear who left the comment.
 */
function brandFooter(identity: CommentIdentity | undefined, scanId: string): string {
  const scan = scanId ? `Scan \`${scanId}\`` : "";
  if (identity === "prodcycle-app") {
    return `<sub>${scan ? scan + " · " : ""}[ProdCycle Compliance](${PRODCYCLE_APP_URL})</sub>`;
  }
  return `<sub>🛡️ Posted by [ProdCycle Compliance](${PRODCYCLE_APP_URL}) · [Docs](${PRODCYCLE_DOCS_URL})${scan ? " · " + scan : ""}</sub>`;
}

/**
 * Create GitHub annotations for each finding.
 * These appear inline on the PR diff view.
 */
export function createAnnotations(findings: ScanFinding[]): void {
  for (const finding of findings) {
    // Advisory findings are informational and never block — surface them as a
    // notice regardless of severity, and label them so reviewers know they
    // don't have to act on them to pass the check.
    const level = finding.advisory
      ? "notice"
      : SEVERITY_LEVEL[finding.severity] || "warning";
    const title = `[${finding.severity.toUpperCase()}]${finding.advisory ? " (advisory)" : ""} ${finding.ruleId}`;
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
  options: PostOptions = {},
): Promise<void> {
  const octokit = resolveOctokit(options.octokit);
  if (!octokit) {
    core.warning("No GitHub token available. Skipping PR comment. Set the 'github-token' input or ensure GITHUB_TOKEN is in the environment.");
    return;
  }

  const context = github.context;
  if (!context.payload.pull_request) {
    core.debug("Not a pull request event. Skipping PR comment.");
    return;
  }

  const prNumber = context.payload.pull_request.number;
  const { owner, repo } = context.repo;

  const headSha = context.payload.pull_request.head?.sha || "";
  const repoUrl = `https://github.com/${owner}/${repo}`;
  const body = buildCommentBody(findings, summary, scanId, passed, repoUrl, headSha, options.identity);
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
  identity?: CommentIdentity,
): string {
  const footer = ["", "---", brandFooter(identity, scanId)];

  if (summary.total === 0) {
    const lines: string[] = [
      "### 🛡️ ProdCycle Compliance · ✅ Passed",
      "",
      "No compliance findings were detected in this PR's changed files.",
      ...footer,
    ];
    return lines.join("\n");
  }

  const status = passed
    ? "### 🛡️ ProdCycle Compliance · ✅ Passed"
    : "### 🛡️ ProdCycle Compliance · ❌ Failed";

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
      const advisoryTag = f.advisory ? " _(advisory)_" : "";
      lines.push(
        `- ${icon} **${f.ruleId}**${advisoryTag} in ${location}: ${f.message}`,
      );
      lines.push(`  - Remediation: ${f.remediation}`);
    }

    if (findings.length > 10) {
      lines.push("");
      lines.push(`_...and ${findings.length - 10} more findings_`);
    }

    lines.push("");
    lines.push("</details>");
  }

  lines.push("", "---", brandFooter(identity, scanId));

  return lines.join("\n");
}

/**
 * Post a PR review with inline comments on the specific lines where findings
 * were detected. This creates the same experience as review bots like Greptile —
 * comments appear directly on the diff with the relevant code highlighted.
 */
export async function postReviewComments(
  findings: ScanFinding[],
  reviewEvent: "COMMENT" | "REQUEST_CHANGES",
  options: PostOptions = {},
): Promise<void> {
  const octokit = resolveOctokit(options.octokit);
  if (!octokit) {
    core.warning("No GitHub token available. Skipping PR review comments.");
    return;
  }

  const context = github.context;
  if (!context.payload.pull_request) {
    core.debug("Not a pull request event. Skipping PR review comments.");
    return;
  }

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
      const advisoryTag = f.advisory ? " _(advisory — non-blocking)_" : "";
      const body = [
        ruleMarker(f.ruleId),
        `${icon} **[${f.severity.toUpperCase()}] ${f.ruleId}**${advisoryTag}`,
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

      const advisoryTag = f.advisory ? " _(advisory — non-blocking)_" : "";
      const body = [
        ruleMarker(f.ruleId),
        `${icon} **[${f.severity.toUpperCase()}] ${f.ruleId}**${advisoryTag} (line ${f.startLine}${f.endLine !== f.startLine ? `–${f.endLine}` : ""}) ([view](${fileLink}))`,
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

  const event = reviewEvent;
  const reviewSummary =
    event === "COMMENT"
      ? "🛡️ **ProdCycle Compliance** — findings detected but within acceptable thresholds."
      : "🛡️ **ProdCycle Compliance** — compliance violations found that require attention.";
  const reviewBody = `${reviewSummary}\n\n---\n${brandFooter(options.identity, options.scanId ?? "")}`;

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
 * Hidden HTML-comment marker embedded at the top of every review comment
 * body produced by this action. Stable across body-format changes so dedup
 * keeps working even if the visible copy is reworded.
 *
 * Shape: `<!-- prodcycle-rule:RULE_ID -->`
 */
const RULE_MARKER_RE = /<!--\s*prodcycle-rule:(.+?)\s*-->/;

/**
 * Legacy extractor for the visible `**[SEVERITY] RULE_ID**` header. Kept as a
 * back-compat fallback so review comments posted before the marker existed
 * still dedup correctly on existing open PRs.
 */
const RULE_ID_RE = /\*\*\[\w+\]\s+(.+?)\*\*/;

function ruleMarker(ruleId: string): string {
  return `<!-- prodcycle-rule:${ruleId} -->`;
}

/**
 * Extract the ruleId from a review comment body. Prefers the structured
 * HTML-comment marker; falls back to parsing the visible header for older
 * comments posted before the marker was introduced.
 */
export function extractRuleIdFromBody(body: string | undefined | null): string | undefined {
  if (!body) return undefined;
  const markerMatch = body.match(RULE_MARKER_RE);
  if (markerMatch) return markerMatch[1];
  const legacyMatch = body.match(RULE_ID_RE);
  return legacyMatch ? legacyMatch[1] : undefined;
}

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
      const ruleId = extractRuleIdFromBody(c.body);
      if (!ruleId) continue;
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

/** A ProdCycle-authored review thread, keyed by the rule it was posted for. */
interface ProdcycleThread {
  /** GraphQL node id, needed for resolveReviewThread. */
  id: string;
  isResolved: boolean;
  path: string;
  ruleId: string;
  /** REST databaseId of the first comment, for posting a reply. */
  firstCommentId?: number;
}

/** Stable key matching a finding to the thread that reported it. */
function threadKey(path: string, ruleId: string): string {
  return `${path}::${ruleId}`;
}

/**
 * Resolve ProdCycle review threads whose finding is no longer present.
 *
 * After a contributor pushes a fix, the finding disappears from the next scan.
 * Without this, the original inline comment lingers as an unresolved thread
 * forever. Here we walk the PR's review threads, keep only the ones ProdCycle
 * authored (identified by the `<!-- prodcycle-rule:RULE_ID -->` marker), and
 * for any whose `(path, ruleId)` is no longer in the current findings we post a
 * short "resolved" reply and mark the thread resolved via GraphQL.
 *
 * Threads we didn't author (humans, other bots) are never touched. Requires the
 * token to have `pull-requests: write`. All failures are non-fatal.
 */
export async function resolveFixedReviewThreads(
  findings: ScanFinding[],
  options: PostOptions = {},
): Promise<void> {
  const octokit = resolveOctokit(options.octokit);
  if (!octokit) return;

  const context = github.context;
  if (!context.payload.pull_request) {
    core.debug("Not a pull request event. Skipping thread resolution.");
    return;
  }

  const prNumber = context.payload.pull_request.number;
  const headSha = context.payload.pull_request.head?.sha || "";
  const { owner, repo } = context.repo;

  // (path::ruleId) still flagged by the current scan — these stay open.
  const active = new Set<string>();
  for (const f of findings) active.add(threadKey(f.resourcePath, f.ruleId));

  let threads: ProdcycleThread[];
  try {
    threads = await fetchProdcycleReviewThreads(octokit, owner, repo, prNumber);
  } catch (err) {
    core.warning(
      `Could not fetch review threads to resolve: ${err instanceof Error ? err.message : String(err)}`,
    );
    return;
  }

  const stale = threads.filter(
    (t) => !t.isResolved && !active.has(threadKey(t.path, t.ruleId)),
  );
  if (stale.length === 0) {
    core.debug("No fixed ProdCycle review threads to resolve.");
    return;
  }

  const shortSha = headSha ? ` as of ${headSha.substring(0, 7)}` : "";
  let resolved = 0;
  let permissionDenied = 0;
  for (const t of stale) {
    try {
      // Resolve FIRST, then reply. If we replied first and the resolve call
      // then failed transiently, the thread would stay open and re-enter this
      // loop on every push — appending a duplicate "Resolved" reply each time.
      await resolveReviewThread(octokit, t.id);
      if (t.firstCommentId) {
        await octokit.rest.pulls.createReplyForReviewComment({
          owner,
          repo,
          pull_number: prNumber,
          comment_id: t.firstCommentId,
          body: `✅ Resolved by ProdCycle — \`${t.ruleId}\` is no longer detected${shortSha}.`,
        });
      }
      resolved++;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // GitHub returns "Resource not accessible by integration" when the
      // GITHUB_TOKEN (github-actions[bot]) tries to call resolveReviewThread —
      // the App backing GITHUB_TOKEN doesn't have the permission. The fix is
      // to post as the ProdCycle App; surface a single, actionable warning
      // explaining this rather than the same per-thread debug noise.
      if (/Resource not accessible by integration/i.test(msg)) permissionDenied++;
      core.debug(
        `Failed to resolve thread ${t.id} (${t.ruleId}): ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  if (resolved > 0) {
    core.info(
      `Resolved ${resolved} ProdCycle review thread(s) whose findings are now fixed.`,
    );
  }
  if (permissionDenied > 0) {
    // Surface the known GITHUB_TOKEN limitation once, with the fix, instead
    // of leaving the user wondering why threads stay open across pushes.
    core.warning(
      `Could not resolve ${permissionDenied} review thread(s): GitHub's default ` +
        `GITHUB_TOKEN (github-actions[bot]) is not permitted to call the ` +
        `resolveReviewThread GraphQL mutation, even with pull-requests: write. ` +
        `Install the ProdCycle GitHub App on this repository so the action posts ` +
        `as prodcycle[bot] — the App is permitted to resolve threads. See the ` +
        `"Posting as prodcycle[bot]" section of the action README.`,
    );
  }
}

const REVIEW_THREADS_QUERY = `
query($owner: String!, $repo: String!, $pr: Int!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $pr) {
      reviewThreads(first: 100, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          isResolved
          path
          comments(first: 1) { nodes { body databaseId } }
        }
      }
    }
  }
}`;

interface ReviewThreadsQueryResult {
  repository: {
    pullRequest: {
      reviewThreads: {
        pageInfo: { hasNextPage: boolean; endCursor: string | null };
        nodes: Array<{
          id: string;
          isResolved: boolean;
          path: string;
          comments: { nodes: Array<{ body: string; databaseId: number }> };
        }>;
      };
    };
  };
}

/**
 * Page through a PR's review threads and return only those ProdCycle authored,
 * tagged with the ruleId parsed from their leading comment marker.
 */
async function fetchProdcycleReviewThreads(
  octokit: Octokit,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<ProdcycleThread[]> {
  const out: ProdcycleThread[] = [];
  let cursor: string | null = null;

  for (;;) {
    const data: ReviewThreadsQueryResult = await octokit.graphql(
      REVIEW_THREADS_QUERY,
      { owner, repo, pr: prNumber, cursor },
    );
    const conn = data.repository.pullRequest.reviewThreads;
    for (const node of conn.nodes) {
      const first = node.comments.nodes[0];
      const ruleId = extractRuleIdFromBody(first?.body);
      if (!ruleId) continue; // not a ProdCycle thread
      out.push({
        id: node.id,
        isResolved: node.isResolved,
        path: node.path,
        ruleId,
        firstCommentId: first?.databaseId,
      });
    }
    if (!conn.pageInfo.hasNextPage) break;
    cursor = conn.pageInfo.endCursor;
  }

  return out;
}

async function resolveReviewThread(octokit: Octokit, threadId: string): Promise<void> {
  await octokit.graphql(
    `mutation($id: ID!) { resolveReviewThread(input: { threadId: $id }) { thread { id } } }`,
    { id: threadId },
  );
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
