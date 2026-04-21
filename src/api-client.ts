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
 * The API enforces a 5 MB limit; we target 2 MB to leave ample headroom
 * for JSON overhead (keys, brackets, escaping of special characters).
 * If a batch still hits 413, the client will automatically re-split.
 */
const MAX_BATCH_BYTES = 2 * 1024 * 1024; // 2 MB (conservative to avoid 413s after JSON escaping)

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
      excludeAcceptedRisk?: boolean;
      actor?: string;
    },
  ): Promise<ValidateResponse> {
    const batches = createBatches(files);

    if (batches.length === 1) {
      try {
        return await this.sendBatch(batches[0], options);
      } catch (err) {
        if (err instanceof PayloadTooLargeError && batches[0].length > 1) {
          core.warning(
            "Single batch hit 413. Re-splitting into smaller batches.",
          );
          const mid = Math.ceil(batches[0].length / 2);
          return this.sendBatchesWithSplitting(
            [batches[0].slice(0, mid), batches[0].slice(mid)],
            options,
          );
        }
        throw err;
      }
    }

    core.info(
      `Payload too large for a single request. Splitting into ${batches.length} batch(es).`,
    );

    return this.sendBatchesWithSplitting(batches, options);
  }

  /**
   * Send a list of batches, automatically re-splitting any batch that
   * receives a 413 Payload Too Large response.
   */
  private async sendBatchesWithSplitting(
    batches: ChangedFile[][],
    options?: {
      frameworks?: string[];
      severityThreshold?: string;
      failOn?: string[];
      excludeAcceptedRisk?: boolean;
      actor?: string;
    },
  ): Promise<ValidateResponse> {
    // Use a queue so batches can be split further on 413
    const queue: ChangedFile[][] = [...batches];
    const results: ValidateResponse[] = [];
    let batchIndex = 0;

    while (queue.length > 0) {
      const batch = queue.shift()!;
      batchIndex++;
      core.info(
        `Sending batch ${batchIndex} (${batch.length} file(s))...`,
      );

      try {
        const result = await this.sendBatch(batch, options);
        results.push(result);
      } catch (err) {
        if (err instanceof PayloadTooLargeError && batch.length > 1) {
          core.warning(
            `Batch of ${batch.length} file(s) hit 413. Splitting in half and retrying.`,
          );
          const mid = Math.ceil(batch.length / 2);
          // Push the two halves to the front of the queue
          queue.unshift(batch.slice(0, mid), batch.slice(mid));
          batchIndex--; // adjust counter since this batch didn't succeed
        } else {
          throw err;
        }
      }
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
      excludeAcceptedRisk?: boolean;
      actor?: string;
    },
  ): Promise<ValidateResponse> {
    const filesMap: Record<string, string> = {};
    const diffsMap: Record<string, string> = {};
    let hasDiffs = false;

    for (const f of files) {
      filesMap[f.path] = f.content;
      if (f.diff) {
        diffsMap[f.path] = f.diff;
        hasDiffs = true;
      }
    }

    const body: ValidateRequest = {
      files: filesMap,
    };

    // When diffs are available (diff scan mode), include them so the API
    // can scope its analysis to only the changed lines.
    if (hasDiffs) {
      body.diffs = diffsMap;
    }

    if (options?.frameworks && options.frameworks.length > 0) {
      body.frameworks = options.frameworks;
    }

    if (options?.actor) {
      body.actor = options.actor;
    }

    if (options?.severityThreshold || options?.failOn || options?.excludeAcceptedRisk !== undefined) {
      body.options = {
        severity_threshold: options.severityThreshold,
        fail_on: options.failOn,
        include_prompt: true,
        exclude_accepted_risk: options.excludeAcceptedRisk,
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
            "User-Agent": "prodcycle/actions/compliance",
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });

        if (!response.ok) {
          const text = await response.text().catch(() => "");
          const error = tryParseError(text);

          // Surface 413 as a specific error so validate() can re-split
          if (response.status === 413) {
            throw new PayloadTooLargeError(
              `API error 413: ${error || text || "Request payload too large"}`,
            );
          }

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

        return normalizeFindings(envelope.data);
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));

        // Don't retry non-retryable errors (4xx, including 413)
        if (
          lastError instanceof PayloadTooLargeError ||
          lastError.message.includes("API error 4")
        ) {
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
  let size =
    Buffer.byteLength(file.path, "utf8") +
    Buffer.byteLength(file.content, "utf8") +
    PER_FILE_OVERHEAD_BYTES;

  // If diffs are present, they are also serialized in the payload
  if (file.diff) {
    size += Buffer.byteLength(file.diff, "utf8") + PER_FILE_OVERHEAD_BYTES;
  }

  return size;
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

/**
 * Custom error for 413 responses so the caller can catch and re-split.
 */
export class PayloadTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PayloadTooLargeError";
  }
}

/**
 * Normalize API response findings.
 * The API returns `line` and `endLine` but the action uses `startLine` and `endLine`.
 * This maps `line` → `startLine` so downstream code can use a consistent interface.
 */
/**
 * Normalize API response findings.
 * - Maps `line` → `startLine` (API uses `line`, action uses `startLine`)
 * - Maps `controlId` → `ruleId` when `ruleId` is absent (API doesn't return `ruleId`)
 */
function normalizeFindings(response: ValidateResponse): ValidateResponse {
  response.findings = response.findings.map((f) => ({
    ...f,
    ruleId: f.ruleId || f.controlId || "unknown",
    startLine: f.startLine || f.line || 0,
    endLine: f.endLine || 0,
  }));
  return response;
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
