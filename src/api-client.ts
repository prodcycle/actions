// =============================================================================
// ProdCycle Compliance Code Scanner — API Client
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

export class ComplianceApiClient {
  constructor(
    private readonly apiUrl: string,
    private readonly apiKey: string,
  ) {}

  /**
   * Call POST /v1/compliance/validate with changed files.
   */
  async validate(
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
    core.debug(`POST ${url} — ${files.length} file(s)`);

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
