// =============================================================================
// ProdCycle Compliance Code Scanner — Diff Collection
// =============================================================================
//
// Collects changed files from a PR by comparing the base and head refs.
// Reads full file content (not just the diff) because the compliance scanner
// needs complete files to evaluate resource configurations accurately.
// =============================================================================

import * as core from "@actions/core";
import * as exec from "@actions/exec";
import * as fs from "node:fs";
import * as path from "node:path";
import { minimatch } from "minimatch";
import type { ChangedFile } from "./types";

const MAX_FILE_SIZE = 512 * 1024; // 512 KB per file
const MAX_TOTAL_FILES = 500;

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
 * Collect all changed files for the PR, filtered and with content.
 */
export async function collectChangedFiles(
  baseSha: string,
  headSha: string,
  repoRoot: string,
  include: string[],
  exclude: string[],
): Promise<ChangedFile[]> {
  // Ensure we have the full git history for the diff
  try {
    await exec.exec(
      "git",
      ["fetch", "--no-tags", "--depth=1", "origin", baseSha],
      {
        silent: true,
        ignoreReturnCode: true,
      },
    );
  } catch {
    core.debug("Could not fetch base SHA — may already be available");
  }

  const changedPaths = await getChangedFilePaths(baseSha, headSha);
  core.info(`Found ${changedPaths.length} changed file(s) in PR`);

  const filteredPaths = filterPaths(changedPaths, include, exclude);
  if (filteredPaths.length !== changedPaths.length) {
    core.info(`After filtering: ${filteredPaths.length} file(s)`);
  }

  if (filteredPaths.length === 0) {
    return [];
  }

  return readFileContents(filteredPaths, repoRoot);
}
