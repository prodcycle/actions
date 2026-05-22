// =============================================================================
// ProdCycle Compliance Code Scanner: Diff Collection
// =============================================================================
//
// Collects changed files from a PR by comparing the base and head refs.
// Supports two modes:
//   - diff mode (default): sends only the unified diff for each changed file
//   - full mode: scans the entire codebase (all files in the repo)
// =============================================================================

import * as core from "@actions/core";
import * as exec from "@actions/exec";
import * as fs from "node:fs";
import * as path from "node:path";
import { minimatch } from "minimatch";
import type { ChangedFile, ValidateResponse } from "./types";

const MAX_FILE_SIZE = 512 * 1024; // 512 KB per file
const MAX_TOTAL_FILES = 500;

/** Regex to parse unified diff hunk headers: @@ -old +newStart,newCount @@ */
const HUNK_HEADER_RE = /^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@/gm;

/**
 * Get the list of files changed in the PR.
 * Uses git diff between the merge base and HEAD.
 */
export async function getChangedFilePaths(
  baseSha: string,
  headSha: string,
): Promise<string[]> {
  let stdout = "";

  await exec.exec(
    "git",
    ["diff", "--name-only", "--diff-filter=ACMR", `${baseSha}...${headSha}`],
    {
      listeners: {
        stdout: (data: Buffer) => {
          stdout += data.toString();
        },
      },
      silent: true,
    },
  );

  return stdout
    .trim()
    .split("\n")
    .filter((f) => f.length > 0);
}

/**
 * Filter file paths by include/exclude glob patterns.
 */
export function filterPaths(
  paths: string[],
  include: string[],
  exclude: string[],
): string[] {
  let filtered = paths;

  // If include patterns specified, only keep matching files
  if (include.length > 0) {
    filtered = filtered.filter((p) =>
      include.some((pattern) => minimatch(p, pattern)),
    );
  }

  // Remove excluded files
  if (exclude.length > 0) {
    filtered = filtered.filter(
      (p) => !exclude.some((pattern) => minimatch(p, pattern)),
    );
  }

  return filtered;
}

/**
 * Read file contents for a list of paths.
 * Skips files that are too large or unreadable.
 */
export function readFileContents(
  filePaths: string[],
  repoRoot: string,
): ChangedFile[] {
  const files: ChangedFile[] = [];

  for (const filePath of filePaths) {
    if (files.length >= MAX_TOTAL_FILES) {
      core.warning(
        `File limit reached (${MAX_TOTAL_FILES}). Remaining files skipped.`,
      );
      break;
    }

    const fullPath = path.resolve(repoRoot, filePath);

    try {
      const stat = fs.statSync(fullPath);
      if (stat.size > MAX_FILE_SIZE) {
        core.debug(
          `Skipping ${filePath}: exceeds ${MAX_FILE_SIZE} bytes (${stat.size})`,
        );
        continue;
      }

      const content = fs.readFileSync(fullPath, "utf-8");
      files.push({ path: filePath, content });
    } catch (err) {
      core.debug(
        `Skipping ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  return files;
}

/**
 * Get the unified diff for each changed file.
 * Returns a map of file path → unified diff text.
 */
export async function getFileDiffs(
  baseSha: string,
  headSha: string,
  filePaths: string[],
): Promise<Map<string, string>> {
  const diffs = new Map<string, string>();

  for (const filePath of filePaths) {
    let stdout = "";
    try {
      await exec.exec(
        "git",
        ["diff", `${baseSha}...${headSha}`, "--", filePath],
        {
          listeners: {
            stdout: (data: Buffer) => {
              stdout += data.toString();
            },
          },
          silent: true,
        },
      );
      if (stdout.trim()) {
        diffs.set(filePath, stdout.trim());
      }
    } catch (err) {
      core.debug(
        `Could not get diff for ${filePath}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  return diffs;
}

/**
 * Ensure the base SHA is available locally for diffing.
 */
async function ensureBaseSha(baseSha: string): Promise<void> {
  const hasBase = await exec.exec("git", ["cat-file", "-e", baseSha], {
    silent: true,
    ignoreReturnCode: true,
  });

  if (hasBase !== 0) {
    core.debug(`Base SHA ${baseSha} not found locally. Fetching...`);
    try {
      await exec.exec(
        "git",
        ["fetch", "--no-tags", "origin", baseSha],
        {
          silent: true,
          ignoreReturnCode: true,
        },
      );
    } catch {
      core.debug("Could not fetch base SHA. Continuing anyway.");
    }
  }
}

/**
 * Collect changed files for the PR with their diffs.
 * Sends full file content AND the unified diff so the API can scope
 * its analysis to the changed lines while still having full context.
 */
export async function collectChangedFiles(
  baseSha: string,
  headSha: string,
  repoRoot: string,
  include: string[],
  exclude: string[],
): Promise<ChangedFile[]> {
  await ensureBaseSha(baseSha);

  const changedPaths = await getChangedFilePaths(baseSha, headSha);
  core.info(`Found ${changedPaths.length} changed file(s) in PR`);

  const filteredPaths = filterPaths(changedPaths, include, exclude);
  if (filteredPaths.length !== changedPaths.length) {
    core.info(`After filtering: ${filteredPaths.length} file(s)`);
  }

  if (filteredPaths.length === 0) {
    return [];
  }

  // Read full file contents (for context) and attach diffs
  const baseFiles = readFileContents(filteredPaths, repoRoot);
  const diffMap = await getFileDiffs(baseSha, headSha, filteredPaths);

  // Attach diffs to the files that have them
  for (const file of baseFiles) {
    const diff = diffMap.get(file.path);
    if (diff) {
      file.diff = diff;
    }
  }

  return baseFiles;
}

/**
 * Parse unified diff text to extract changed line ranges on the new (right) side.
 */
export function parseDiffRanges(patch: string): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = [];
  // Reset lastIndex since we reuse a global regex pattern
  const re = new RegExp(HUNK_HEADER_RE.source, HUNK_HEADER_RE.flags);
  let match: RegExpExecArray | null;

  while ((match = re.exec(patch)) !== null) {
    const start = parseInt(match[1], 10);
    const count = match[2] !== undefined ? parseInt(match[2], 10) : 1;
    if (count > 0) {
      ranges.push({ start, end: start + count - 1 });
    }
  }

  return ranges;
}

/**
 * Filter API findings to only those whose lines overlap with the PR diff.
 * In diff scan mode, we should only surface findings on lines the PR actually
 * changed — not pre-existing issues on untouched lines.
 *
 * Also recalculates summary counts and pass/fail status.
 */
export function filterFindingsToDiff(
  result: ValidateResponse,
  files: ChangedFile[],
  failOn: string[],
): ValidateResponse {
  // Build a map of file path → diff line ranges
  const diffRangesByFile = new Map<string, Array<{ start: number; end: number }>>();
  for (const file of files) {
    if (file.diff) {
      const ranges = parseDiffRanges(file.diff);
      if (ranges.length > 0) {
        diffRangesByFile.set(file.path, ranges);
      }
    }
  }

  // If no diffs available (shouldn't happen in diff mode), return as-is
  if (diffRangesByFile.size === 0) {
    return result;
  }

  const filtered = result.findings.filter((f) => {
    const ranges = diffRangesByFile.get(f.resourcePath);
    if (!ranges) {
      // File not in the diff at all — drop the finding
      return false;
    }
    // Keep finding if any of its lines overlap with a diff hunk
    return ranges.some(
      (range) => f.endLine >= range.start && f.startLine <= range.end,
    );
  });

  const droppedCount = result.findings.length - filtered.length;
  if (droppedCount > 0) {
    core.info(
      `Filtered out ${droppedCount} finding(s) on lines outside the PR diff.`,
    );
  }

  // Recalculate summary
  const bySeverity: Record<string, number> = {};
  const byFramework: Record<string, number> = {};
  for (const f of filtered) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byFramework[f.framework] = (byFramework[f.framework] || 0) + 1;
  }

  const failOnSet = new Set(failOn.map((s) => s.toLowerCase()));
  // Advisory findings are informational — they never fail the check, matching
  // how the API computes its own verdict (advisory is excluded from `failed`).
  const blocking = filtered.filter(
    (f) => !f.advisory && failOnSet.has(f.severity.toLowerCase()),
  );
  const hasFailure = blocking.length > 0;

  return {
    ...result,
    findings: filtered,
    findingsCount: filtered.length,
    passed: !hasFailure,
    summary: {
      total: filtered.length,
      passed: filtered.length - blocking.length,
      failed: blocking.length,
      bySeverity,
      byFramework,
    },
  };
}

/**
 * Collect ALL files in the repository for a full codebase scan.
 * Uses git ls-files to enumerate tracked files, then applies filters.
 */
export async function collectAllFiles(
  repoRoot: string,
  include: string[],
  exclude: string[],
): Promise<ChangedFile[]> {
  let stdout = "";

  await exec.exec("git", ["ls-files", "--cached", "--others", "--exclude-standard"], {
    listeners: {
      stdout: (data: Buffer) => {
        stdout += data.toString();
      },
    },
    silent: true,
  });

  const allPaths = stdout
    .trim()
    .split("\n")
    .filter((f) => f.length > 0);

  core.info(`Found ${allPaths.length} file(s) in repository`);

  const filteredPaths = filterPaths(allPaths, include, exclude);
  if (filteredPaths.length !== allPaths.length) {
    core.info(`After filtering: ${filteredPaths.length} file(s)`);
  }

  if (filteredPaths.length === 0) {
    return [];
  }

  return readFileContents(filteredPaths, repoRoot);
}
