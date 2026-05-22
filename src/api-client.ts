// =============================================================================
// ProdCycle Compliance Code Scanner: API Client
// =============================================================================

import * as core from "@actions/core";
import type {
  ValidateRequest,
  ValidateResponse,
  ValidateSummary,
  ScanFinding,
  ApiResponse,
  ChangedFile,
} from "./types";

/**
 * Per-request timeout and retry budget. Chunked-session scans on large
 * monorepos can take tens of seconds per request, so we mirror the
 * ProdCycle CLI's longer defaults (300s timeout, 3 retries) rather than the
 * old 120s/2 — the CLI hardened these after GA load testing. Both are
 * overridable via env for operators who want a different budget in CI.
 */
function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}
const REQUEST_TIMEOUT_MS = envInt("COMPLIANCE_REQUEST_TIMEOUT_MS", 300_000); // 5 min
const MAX_RETRIES = envInt("COMPLIANCE_MAX_RETRIES", 3);
const RETRY_DELAY_MS = 2_000;

/**
 * Hard ceiling on Retry-After honoring. Even if the server (or an
 * upstream proxy) asks for an absurd interval we cap it so a misbehaving
 * tier can't wedge the action job for the full GitHub-Actions step
 * timeout. Configurable via `COMPLIANCE_MAX_RETRY_AFTER_MS` for operators
 * who want a different ceiling in their CI.
 */
const MAX_RETRY_AFTER_MS = envInt("COMPLIANCE_MAX_RETRY_AFTER_MS", 60_000);

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
      excludeResolved?: boolean;
      productId?: string;
      syncConfigId?: string;
      reconcile?: boolean;
    },
  ): Promise<ValidateResponse> {
    const batches = createBatches(files);

    if (batches.length === 1) {
      try {
        return await this.sendBatch(batches[0], options);
      } catch (err) {
        if (err instanceof PayloadTooLargeError) {
          // Server hint: the 5 MB /validate cap was hit and we should
          // switch to chunked sessions instead of splitting forever.
          // Common path for large monorepo CI runs.
          if (err.suggestsChunkedEndpoint) {
            core.info(
              "Server returned 413 with suggestedEndpoint=/v1/compliance/scans. Switching to chunked-session flow.",
            );
            return this.postChunkedSession(files, options);
          }
          if (batches[0].length > 1) {
            core.warning(
              "Single batch hit 413. Re-splitting into smaller batches.",
            );
            const mid = Math.ceil(batches[0].length / 2);
            return this.sendBatchesWithSplitting(
              [batches[0].slice(0, mid), batches[0].slice(mid)],
              options,
            );
          }
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
   * Fallback path when /validate's 413 indicates the chunked-session
   * endpoint is the right answer. We:
   *   1. Open a session (`POST /v1/compliance/scans`) once for the
   *      whole CI run — gives us a single scanId in the dashboard.
   *   2. Append each batch (`POST /v1/compliance/scans/:id/chunks`)
   *      using the existing 2 MB batch sizing, which is well under
   *      the chunked-endpoint's 50 MB-per-chunk cap.
   *   3. Finalize (`POST /v1/compliance/scans/:id/complete`) — server
   *      computes the final summary + passed verdict.
   * Map the response to the ValidateResponse shape so callers don't
   * need to special-case which path was taken.
   */
  private async postChunkedSession(
    files: ChangedFile[],
    options?: {
      frameworks?: string[];
      severityThreshold?: string;
      failOn?: string[];
      excludeAcceptedRisk?: boolean;
      excludeResolved?: boolean;
      productId?: string;
      syncConfigId?: string;
      reconcile?: boolean;
    },
  ): Promise<ValidateResponse> {
    const session = await this.postRaw<{ scanId: string }>(
      "/v1/compliance/scans",
      this.buildOpenSessionBody(options),
    );
    core.info(`Opened chunked compliance scan session: ${session.scanId}`);

    const batches = createBatches(files);
    for (let i = 0; i < batches.length; i++) {
      core.info(
        `Appending chunk ${i + 1}/${batches.length} (${batches[i].length} file(s))...`,
      );
      await this.postRaw(
        `/v1/compliance/scans/${encodeURIComponent(session.scanId)}/chunks`,
        { files: batchToFilesMap(batches[i]) },
      );
    }

    core.info(`Finalizing scan ${session.scanId}...`);
    const finalResult = await this.postRaw<{
      scanId: string;
      passed: boolean;
      findingsCount: number;
      findings?: ScanFinding[];
      summary?: Partial<ValidateSummary>;
      prompt?: string;
    }>(
      `/v1/compliance/scans/${encodeURIComponent(session.scanId)}/complete`,
      {},
    );

    // The `/complete` response carries the verdict + counts but NOT the full
    // findings array (or a complete summary). Backfill them from the scan
    // detail endpoint — mirrors the ProdCycle CLI, and avoids crashing on an
    // absent `findings` field. The race where the detail isn't materialized
    // yet is rare; we degrade to an empty findings list if it's missing.
    let findings = finalResult.findings ?? [];
    let summary = finalResult.summary;
    if (findings.length === 0 && finalResult.findingsCount > 0) {
      const detail = await this.fetchScanDetail(session.scanId);
      if (detail) {
        findings = detail.findings ?? findings;
        summary = (detail.summary as Partial<ValidateSummary>) ?? summary;
      }
    }

    return normalizeFindings({
      passed: finalResult.passed,
      findingsCount: finalResult.findingsCount,
      findings,
      summary: completeSummary(summary, findings),
      scanId: session.scanId,
      prompt: finalResult.prompt,
    });
  }

  /**
   * GET /v1/compliance/scans/:id — used to backfill the findings array after a
   * chunked session, since `/complete` only returns the verdict + counts.
   * Returns `null` (non-fatal) if the detail can't be fetched.
   */
  private async fetchScanDetail(
    scanId: string,
  ): Promise<{ findings?: ScanFinding[]; summary?: unknown } | null> {
    try {
      return await this.requestRaw<{ findings?: ScanFinding[]; summary?: unknown }>(
        "GET",
        `/v1/compliance/scans/${encodeURIComponent(scanId)}`,
      );
    } catch (err) {
      core.warning(
        `Could not fetch scan detail to backfill findings: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
      return null;
    }
  }

  private buildOpenSessionBody(options?: {
    frameworks?: string[];
    severityThreshold?: string;
    failOn?: string[];
    excludeAcceptedRisk?: boolean;
  }): Record<string, unknown> {
    const body: Record<string, unknown> = {};
    if (options?.frameworks && options.frameworks.length > 0) {
      body.frameworks = options.frameworks;
    }
    // Always send `options` with `include_prompt: true` so the chunked
    // path produces the same response shape (with remediation prompt) as
    // sync `/validate`. Previously this object was elided when none of
    // severityThreshold / failOn / excludeAcceptedRisk were set, so a
    // bare `validate(files)` taking the chunked fallback would silently
    // omit the prompt.
    const optionsBody: Record<string, unknown> = { include_prompt: true };
    if (options?.severityThreshold) {
      optionsBody.severity_threshold = options.severityThreshold;
    }
    if (options?.failOn) {
      optionsBody.fail_on = options.failOn;
    }
    if (options?.excludeAcceptedRisk !== undefined) {
      optionsBody.exclude_accepted_risk = options.excludeAcceptedRisk;
    }
    body.options = optionsBody;
    return body;
  }

  /**
   * Generic POST helper used by the chunked-session paths. Mirrors the
   * retry + Retry-After logic in sendBatch but takes a free-form body
   * and returns the unwrapped envelope's `data`.
   */
  private postRaw<T>(
    endpoint: string,
    body: Record<string, unknown>,
  ): Promise<T> {
    return this.requestRaw<T>("POST", endpoint, body);
  }

  /**
   * Generic request helper used by the chunked-session paths (POST) and the
   * scan-detail backfill (GET). Mirrors the retry + Retry-After logic in
   * sendBatch and returns the unwrapped envelope's `data`.
   */
  private async requestRaw<T>(
    method: "GET" | "POST",
    endpoint: string,
    body?: Record<string, unknown>,
  ): Promise<T> {
    const url = `${this.apiUrl.replace(/\/+$/, "")}${endpoint}`;
    let lastError: Error | undefined;
    // Delay BEFORE the next attempt — set by the previous iteration. We
    // decide the wait at the end of an attempt (Retry-After OR linear
    // backoff, never both) rather than unconditionally at the top, so
    // honoring a server's `Retry-After: 30` doesn't get an extra
    // `RETRY_DELAY_MS * attempt` piled on top.
    let nextDelayMs = 0;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (nextDelayMs > 0) {
        await sleep(nextDelayMs);
        nextDelayMs = 0;
      }
      try {
        const headers: Record<string, string> = {
          Authorization: `Bearer ${this.apiKey}`,
          "x-api-version": "v1",
          "User-Agent": "prodcycle/actions/compliance",
        };
        if (body !== undefined) headers["Content-Type"] = "application/json";

        const response = await fetch(url, {
          method,
          headers,
          ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });

        if (!response.ok) {
          const text = await response.text().catch(() => "");
          if (response.status === 413) {
            const parsedBody = tryParseJson(text);
            throw new PayloadTooLargeError(
              `API error 413: ${tryParseError(text) || text || "Request payload too large"}`,
              parsedBody,
            );
          }
          if (response.status === 429 || response.status === 503) {
            const retryAfter = parseRetryAfter(response.headers.get("retry-after"));
            if (retryAfter !== null) {
              core.info(
                `${endpoint} responded ${response.status}; honoring Retry-After=${retryAfter}s before next attempt.`,
              );
              nextDelayMs = Math.min(retryAfter * 1000, MAX_RETRY_AFTER_MS);
            } else {
              nextDelayMs = RETRY_DELAY_MS * (attempt + 1);
            }
            lastError = new Error(
              `API error ${response.status}: ${tryParseError(text) || response.statusText}`,
            );
            continue;
          }
          if (response.status >= 400 && response.status < 500) {
            throw new Error(formatApiError(response.status, text, response.statusText));
          }
          lastError = new Error(formatApiError(response.status, text, response.statusText));
          nextDelayMs = RETRY_DELAY_MS * (attempt + 1);
          continue;
        }

        const envelope = (await response.json()) as ApiResponse<T>;
        if (envelope.status !== "success" || !envelope.data) {
          throw new Error(
            `Unexpected API response from ${endpoint}: ${envelope.error?.message || JSON.stringify(envelope)}`,
          );
        }
        return envelope.data;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (
          lastError instanceof PayloadTooLargeError ||
          lastError.message.includes("API error 4")
        ) {
          throw lastError;
        }
        // Network/timeout error — fall back to linear backoff.
        nextDelayMs = RETRY_DELAY_MS * (attempt + 1);
      }
    }

    throw lastError || new Error(`Request to ${endpoint} failed after retries`);
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
      excludeResolved?: boolean;
      productId?: string;
      syncConfigId?: string;
      reconcile?: boolean;
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
      excludeResolved?: boolean;
      productId?: string;
      syncConfigId?: string;
      reconcile?: boolean;
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

    if (options?.productId) {
      body.product_id = options.productId;
    }
    if (options?.syncConfigId) {
      body.sync_config_id = options.syncConfigId;
    }

    if (
      options?.severityThreshold ||
      options?.failOn ||
      options?.excludeAcceptedRisk !== undefined ||
      options?.excludeResolved !== undefined ||
      options?.reconcile !== undefined
    ) {
      body.options = {
        severity_threshold: options.severityThreshold,
        fail_on: options.failOn,
        include_prompt: true,
        exclude_accepted_risk: options.excludeAcceptedRisk,
        exclude_resolved: options.excludeResolved,
        reconcile: options.reconcile,
      };
    }

    const url = `${this.apiUrl.replace(/\/+$/, "")}/v1/compliance/validate`;
    core.debug(`POST ${url} (${files.length} file(s))`);

    let lastError: Error | undefined;
    // See `postRaw` — delay is set by the previous iteration so a
    // server-honored Retry-After replaces the linear backoff rather
    // than stacking on top of it.
    let nextDelayMs = 0;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (nextDelayMs > 0) {
        core.info(`Retrying (attempt ${attempt + 1}/${MAX_RETRIES + 1})...`);
        await sleep(nextDelayMs);
        nextDelayMs = 0;
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

          // Surface 413 as a specific error so validate() can re-split OR
          // switch to the chunked-session endpoint when the server's 413
          // response points there via `suggestedEndpoint`.
          if (response.status === 413) {
            const parsedBody = tryParseJson(text);
            throw new PayloadTooLargeError(
              `API error 413: ${error || text || "Request payload too large"}`,
              parsedBody,
            );
          }

          // Honor Retry-After on 429 (rate limit) and 503 (temporarily
          // unavailable). The server-specified interval REPLACES the linear
          // backoff for the next attempt; a missing header falls back to linear.
          if (response.status === 429 || response.status === 503) {
            const retryAfter = parseRetryAfter(response.headers.get("retry-after"));
            if (retryAfter !== null) {
              core.info(
                `API responded ${response.status}; honoring Retry-After=${retryAfter}s before next attempt.`,
              );
              nextDelayMs = Math.min(retryAfter * 1000, MAX_RETRY_AFTER_MS);
            } else {
              nextDelayMs = RETRY_DELAY_MS * (attempt + 1);
            }
          }

          // Don't retry client errors (4xx) except 429
          if (
            response.status >= 400 &&
            response.status < 500 &&
            response.status !== 429
          ) {
            throw new Error(formatApiError(response.status, text, response.statusText));
          }

          lastError = new Error(formatApiError(response.status, text, response.statusText));
          // 5xx (non-503) hits this path too — fall back to linear if
          // the 429/503 branch above didn't already set a delay.
          if (nextDelayMs === 0) {
            nextDelayMs = RETRY_DELAY_MS * (attempt + 1);
          }
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
        // Network/timeout error — fall back to linear backoff.
        if (nextDelayMs === 0) {
          nextDelayMs = RETRY_DELAY_MS * (attempt + 1);
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
  // Only `path` + `content` are sent in the request payload; the per-file diff
  // is kept locally for client-side diff filtering and is not transmitted.
  // Buffer.byteLength is accurate for UTF-8; add overhead for JSON key/value quoting.
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

/**
 * Custom error for 413 responses so the caller can catch and re-split.
 *
 * The parsed body is preserved so `validate()` can read
 * `error.details.suggestedEndpoint` and decide whether the right next
 * step is to keep splitting batches OR to switch to the chunked-session
 * endpoint. When the server points at the chunked-session endpoint, that's a
 * strong hint that the batch is large enough that further splitting will just
 * hit the same 413 again — chunked sessions are the right answer.
 */
export class PayloadTooLargeError extends Error {
  constructor(
    message: string,
    public readonly body: {
      error?: {
        details?: {
          suggestedEndpoint?: string;
          maxBytes?: number;
          maxFiles?: number;
          [key: string]: unknown;
        };
      };
    } | null = null,
  ) {
    super(message);
    this.name = "PayloadTooLargeError";
  }

  /** True when the server hints that we should switch to chunked sessions. */
  get suggestsChunkedEndpoint(): boolean {
    return (
      this.body?.error?.details?.suggestedEndpoint === "/v1/compliance/scans"
    );
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
/**
 * Build a complete `ValidateSummary` from a possibly-partial one returned by
 * the chunked `/complete` endpoint (which may only carry `total` + `bySeverity`).
 * Missing counts and the framework breakdown are recomputed from the findings
 * so downstream rendering has a consistent shape.
 */
function completeSummary(
  partial: Partial<ValidateSummary> | undefined,
  findings: ScanFinding[],
): ValidateSummary {
  const bySeverity: Record<string, number> = { ...(partial?.bySeverity ?? {}) };
  const byFramework: Record<string, number> = { ...(partial?.byFramework ?? {}) };

  if (Object.keys(bySeverity).length === 0) {
    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    }
  }
  if (Object.keys(byFramework).length === 0) {
    for (const f of findings) {
      byFramework[f.framework] = (byFramework[f.framework] || 0) + 1;
    }
  }

  const total = partial?.total ?? findings.length;
  const failed = partial?.failed ?? findings.filter((f) => !f.advisory).length;
  const passed = partial?.passed ?? Math.max(0, total - failed);

  return { total, passed, failed, bySeverity, byFramework };
}

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

/**
 * Build an error message for a non-2xx response. For 401/403 (the most
 * common first-time-user failure mode — wrong/missing/expired API key)
 * include an actionable hint pointing at the secret name and where to
 * check it. Other statuses get a plain `API error <code>: <body>`.
 */
function formatApiError(
  status: number,
  text: string,
  statusText: string,
): string {
  const parsed = tryParseError(text) || text || statusText;
  if (status === 401 || status === 403) {
    return (
      `API error ${status}: ${parsed} — check that the PRODCYCLE_API_KEY ` +
      `secret is set on this repo, starts with "pc_", and matches the ` +
      `workspace at https://app.prodcycle.com.`
    );
  }
  return `API error ${status}: ${parsed}`;
}

/**
 * Best-effort JSON parse — returns `null` if the body isn't JSON. Used to
 * pull `error.details.suggestedEndpoint` out of a 413 response without
 * throwing if the server returned a plain-text error.
 */
function tryParseJson(text: string): {
  error?: {
    details?: {
      suggestedEndpoint?: string;
      maxBytes?: number;
      maxFiles?: number;
      [key: string]: unknown;
    };
  };
} | null {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * Parse the value of a Retry-After response header, which can be either:
 *   - delta-seconds: an integer number of seconds (e.g. "30")
 *   - HTTP-date: an absolute date (e.g. "Wed, 21 Oct 2026 07:28:00 GMT")
 * Returns the wait in seconds, or null if the header is missing/unparseable.
 *
 * Helper for honoring the rate-limit (429) and service-unavailable (503)
 * server signals.
 */
function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds;
  const date = Date.parse(value);
  if (Number.isFinite(date)) {
    const delta = Math.max(0, Math.ceil((date - Date.now()) / 1000));
    return delta;
  }
  return null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Convert a batch (array of files w/ content) to the API's path→content map. */
function batchToFilesMap(batch: ChangedFile[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (const f of batch) map[f.path] = f.content;
  return map;
}
