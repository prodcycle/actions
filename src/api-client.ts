// =============================================================================
// ProdCycle Compliance Code Scanner: API Client
// =============================================================================

import * as core from "@actions/core";
import type {
  ValidateRequest,
  ValidateResponse,
  ApiResponse,
  ChangedFile,
} from "./types";

const REQUEST_TIMEOUT_MS = 120_000; // 2 minutes
const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 2_000;

/**
 * Maximum payload size per request in bytes.
 * The API enforces a 5 MB limit; we target 4 MB to leave headroom for
 * JSON overhead (keys, brackets, escaping).
 */
const MAX_BATCH_BYTES = 4 * 1024 * 1024; // 4 MB

/** Rough overhead per file entry: key quoting, colon, comma, escaping margin */
const PER_FILE_OVERHEAD_BYTES = 128;

export class ComplianceApiClient {
  constructor(
    private readonly apiUrl: string,
    private readonly apiKey: string,
  ) {}

  /**
   * Call POST /v1/compliance/validate with changed files.
   *
   * When the payload would exceed the API's size limit, the files are
   * automatically split into batches and each batch is sent separately.
   * Results are merged into a single response.
   */
  async validate(
    files: ChangedFile[],
    options?: {
      frameworks?: string[];
      severityThreshold?: string;
      failOn?: string[];
    },
  ): Promise<ValidateResponse> {
    const batches = createBatches(files);

    if (batches.length === 1) {
      return this.sendBatch(batches[0], options);
    }

    core.info(
      `Payload too large for a single request. Splitting into ${batches.length} batch(es).`,
    );

    const results: ValidateResponse[] = [];
    for (let i = 0; i < batches.length; i++) {
      core.info(
        `Sending batch ${i + 1}/${batches.length} (${batches[i].length} file(s))...`,
      );
      const result = await this.sendBatch(batches[i], options);
      results.push(result);
    }

    return mergeResults(results);
  }

  /**
   * Send a single batch of files to the validate endpoint.
   */
  private async sendBatch(
    files: ChangedFile[],
    options?: {
      frameworks?: string[];
      severityThreshold?: string;
      failOn?: string[];
    },
  ): Promise<ValidateResponse> {
    const filesMap: Record<string, string> = {};
    for (const f of files) {
      filesMap[f.path] = f.content;
    }

    const body: ValidateRequest = {
      files: filesMap,
    };

    if (options?.frameworks && options.frameworks.length > 0) {
      body.frameworks = options.frameworks;
    }

    if (options?.severityThreshold || options?.failOn) {
      body.options = {
        severity_threshold: options.severityThreshold,
        fail_on: options.failOn,
        include_prompt: true,
      };
    }

    const url = `${this.apiUrl.replace(/\/+$/, "")}/v1/compliance/validate`;
    core.debug(`POST ${url} (${files.length} file(s))`);

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        core.info(`Retrying (attempt ${attempt + 1}/${MAX_RETRIES + 1})...`);
        await sleep(RETRY_DELAY_MS * attempt);
      }

      try {
        const response = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this.apiKey}`,
            "x-api-version": "v1",
            "User-Agent": "prodcycle/compliance-code-scanner",
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });

        if (!response.ok) {
          const text = await response.text().catch(() => "");
          const error = tryParseError(text);

          // Don't retry client errors (4xx) except 429
          if (
            response.status >= 400 &&
            response.status < 500 &&
            response.status !== 429
          ) {
            throw new Error(
              `API error ${response.status}: ${error || text || response.statusText}`,
            );
          }

          lastError = new Error(
            `API error ${response.status}: ${error || text || response.statusText}`,
          );
          continue;
        }

        const envelope =
          (await response.json()) as ApiResponse<ValidateResponse>;

        if (envelope.status !== "success" || !envelope.data) {
          throw new Error(
            `Unexpected API response: ${envelope.error?.message || JSON.stringify(envelope)}`,
          );
        }

        return envelope.data;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));

        // Don't retry non-retryable errors
        if (lastError.message.includes("API error 4")) {
          throw lastError;
        }
      }
    }

    throw lastError || new Error("Validate request failed after retries");
  }
}

/**
 * Split files into batches that each fit within MAX_BATCH_BYTES.
 * Uses a greedy bin-packing approach: add files to the current batch
 * until the next file would exceed the limit, then start a new batch.
 */
export function createBatches(files: ChangedFile[]): ChangedFile[][] {
  if (files.length === 0) return [[]];

  const batches: ChangedFile[][] = [];
  let currentBatch: ChangedFile[] = [];
  let currentSize = 0;

  for (const file of files) {
    const fileSize = estimateFileBytes(file);

    // If a single file exceeds the limit, it gets its own batch.
    // The API will reject it with a per-file size error, which is
    // more actionable than a total-payload error.
    if (currentBatch.length > 0 && currentSize + fileSize > MAX_BATCH_BYTES) {
      batches.push(currentBatch);
      currentBatch = [];
      currentSize = 0;
    }

    currentBatch.push(file);
    currentSize += fileSize;
  }

  if (currentBatch.length > 0) {
    batches.push(currentBatch);
  }

  return batches;
}

/** Estimate the JSON-serialized size of a file entry in bytes. */
function estimateFileBytes(file: ChangedFile): number {
  // Buffer.byteLength is accurate for UTF-8; add overhead for JSON key/value quoting
  return (
    Buffer.byteLength(file.path, "utf8") +
    Buffer.byteLength(file.content, "utf8") +
    PER_FILE_OVERHEAD_BYTES
  );
}

/**
 * Merge multiple batch responses into a single ValidateResponse.
 * - `passed` is true only if ALL batches passed.
 * - Findings are concatenated.
 * - Summary counts are summed.
 * - Uses the scanId from the last batch (most recent).
 */
function mergeResults(results: ValidateResponse[]): ValidateResponse {
  if (results.length === 1) return results[0];

  const merged: ValidateResponse = {
    passed: results.every((r) => r.passed),
    findingsCount: 0,
    findings: [],
    summary: {
      total: 0,
      passed: 0,
      failed: 0,
      bySeverity: {},
      byFramework: {},
    },
    scanId: results[results.length - 1].scanId,
  };

  for (const r of results) {
    merged.findingsCount += r.findingsCount;
    merged.findings.push(...r.findings);
    merged.summary.total += r.summary.total;
    merged.summary.passed += r.summary.passed;
    merged.summary.failed += r.summary.failed;

    for (const [severity, count] of Object.entries(r.summary.bySeverity)) {
      merged.summary.bySeverity[severity] =
        (merged.summary.bySeverity[severity] || 0) + count;
    }
    for (const [framework, count] of Object.entries(r.summary.byFramework)) {
      merged.summary.byFramework[framework] =
        (merged.summary.byFramework[framework] || 0) + count;
    }
  }

  // Concatenate prompts if any batches returned them
  const prompts = results.map((r) => r.prompt).filter(Boolean);
  if (prompts.length > 0) {
    merged.prompt = prompts.join("\n\n---\n\n");
  }

  return merged;
}

function tryParseError(text: string): string | undefined {
  try {
    const parsed = JSON.parse(text) as ApiResponse<unknown>;
    return parsed.error?.message;
  } catch {
    return undefined;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
