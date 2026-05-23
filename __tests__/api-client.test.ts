import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock @actions/core before importing api-client
vi.mock("@actions/core", () => ({
  debug: vi.fn(),
  info: vi.fn(),
  warning: vi.fn(),
}));

import { ComplianceApiClient, createBatches, PayloadTooLargeError } from "../src/api-client";
import type { ChangedFile } from "../src/types";

describe("ComplianceApiClient", () => {
  const mockApiUrl = "https://api.prodcycle.com";
  const mockApiKey = "pc_test1234567890abcdef";

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("sends correct request to validate endpoint", async () => {
    const mockResponse = {
      status: "success",
      statusCode: 200,
      data: {
        passed: true,
        findingsCount: 0,
        findings: [],
        summary: {
          total: 5,
          passed: 5,
          failed: 0,
          bySeverity: {},
          byFramework: {},
        },
        scanId: "scan-123",
      },
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    const result = await client.validate(
      [{ path: "main.tf", content: 'resource "aws_s3_bucket" {}' }],
      { frameworks: ["soc2"] },
    );

    expect(result.passed).toBe(true);
    expect(result.scanId).toBe("scan-123");

    const [url, options] = fetchSpy.mock.calls[0];
    expect(url).toBe("https://api.prodcycle.com/v1/compliance/validate");
    expect((options as RequestInit).method).toBe("POST");
    expect((options as RequestInit).headers).toMatchObject({
      Authorization: `Bearer ${mockApiKey}`,
      "Content-Type": "application/json",
    });

    const body = JSON.parse((options as RequestInit).body as string);
    expect(body.files).toEqual({ "main.tf": 'resource "aws_s3_bucket" {}' });
    expect(body.frameworks).toEqual(["soc2"]);
  });

  it("never transmits diffs or actor in the request body", async () => {
    const mockResponse = {
      status: "success",
      statusCode: 200,
      data: {
        passed: true,
        findingsCount: 0,
        findings: [],
        summary: {
          total: 0,
          passed: 0,
          failed: 0,
          bySeverity: {},
          byFramework: {},
        },
        scanId: "scan-no-extra",
      },
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    // The file carries a local diff (used for client-side diff filtering) — it
    // must NOT be transmitted; the backend scans full content. `actor` was also
    // dropped (the API doesn't consume it).
    await client.validate([{ path: "main.tf", content: "x", diff: "@@ -1 +1 @@" }]);

    const body = JSON.parse(
      (fetchSpy.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.files).toEqual({ "main.tf": "x" });
    expect(body.diffs).toBeUndefined();
    expect(body.actor).toBeUndefined();
  });

  it("omits frameworks when not specified", async () => {
    const mockResponse = {
      status: "success",
      statusCode: 200,
      data: {
        passed: true,
        findingsCount: 0,
        findings: [],
        summary: {
          total: 0,
          passed: 0,
          failed: 0,
          bySeverity: {},
          byFramework: {},
        },
        scanId: "scan-456",
      },
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    await client.validate([{ path: "main.tf", content: "" }]);

    const body = JSON.parse(
      (fetchSpy.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.frameworks).toBeUndefined();
  });

  it("passes exclude_accepted_risk option in request body", async () => {
    const mockResponse = {
      status: "success",
      statusCode: 200,
      data: {
        passed: true,
        findingsCount: 0,
        findings: [],
        summary: {
          total: 0,
          passed: 0,
          failed: 0,
          bySeverity: {},
          byFramework: {},
        },
        scanId: "scan-789",
      },
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    await client.validate(
      [{ path: "main.tf", content: "" }],
      { excludeAcceptedRisk: true, severityThreshold: "low" },
    );

    const body = JSON.parse(
      (fetchSpy.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.options.exclude_accepted_risk).toBe(true);
  });

  it("sends exclude_accepted_risk: false when explicitly opted out", async () => {
    const mockResponse = {
      status: "success",
      statusCode: 200,
      data: {
        passed: true,
        findingsCount: 0,
        findings: [],
        summary: {
          total: 0,
          passed: 0,
          failed: 0,
          bySeverity: {},
          byFramework: {},
        },
        scanId: "scan-opt-out",
      },
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    await client.validate(
      [{ path: "main.tf", content: "" }],
      { excludeAcceptedRisk: false },
    );

    const body = JSON.parse(
      (fetchSpy.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.options).toBeDefined();
    expect(body.options.exclude_accepted_risk).toBe(false);
  });

  it("forwards product/sync identifiers and resolved/reconcile options", async () => {
    const mockResponse = {
      status: "success",
      statusCode: 200,
      data: {
        passed: true,
        findingsCount: 0,
        findings: [],
        summary: { total: 0, passed: 0, failed: 0, bySeverity: {}, byFramework: {} },
        scanId: "scan-suppress",
      },
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    await client.validate(
      [{ path: "main.tf", content: "" }],
      {
        productId: "prod-uuid",
        syncConfigId: "sync-uuid",
        excludeAcceptedRisk: true,
        excludeResolved: true,
        reconcile: false,
      },
    );

    const body = JSON.parse(
      (fetchSpy.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.product_id).toBe("prod-uuid");
    expect(body.sync_config_id).toBe("sync-uuid");
    expect(body.options.exclude_resolved).toBe(true);
    expect(body.options.reconcile).toBe(false);
  });

  it("omits product identifiers when not provided (back-compat)", async () => {
    const mockResponse = {
      status: "success",
      statusCode: 200,
      data: {
        passed: true,
        findingsCount: 0,
        findings: [],
        summary: { total: 0, passed: 0, failed: 0, bySeverity: {}, byFramework: {} },
        scanId: "scan-noprod",
      },
    };

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    await client.validate([{ path: "main.tf", content: "" }], { excludeAcceptedRisk: true });

    const body = JSON.parse(
      (fetchSpy.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.product_id).toBeUndefined();
    expect(body.sync_config_id).toBeUndefined();
  });

  it("throws on 4xx client errors without retrying", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 403,
      statusText: "Forbidden",
      text: async () =>
        JSON.stringify({ error: { message: "Invalid API key" } }),
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    await expect(
      client.validate([{ path: "main.tf", content: "" }]),
    ).rejects.toThrow("API error 403: Invalid API key");
  });

  it("includes an actionable hint on 401", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      text: async () => "",
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    await expect(
      client.validate([{ path: "main.tf", content: "" }]),
    ).rejects.toThrow(/PRODCYCLE_API_KEY/);
  });

  it("includes an actionable hint on 403", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 403,
      statusText: "Forbidden",
      text: async () => "",
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    await expect(
      client.validate([{ path: "main.tf", content: "" }]),
    ).rejects.toThrow(/PRODCYCLE_API_KEY/);
  });

  it("does not include the auth hint on non-auth 4xx errors", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 400,
      statusText: "Bad Request",
      text: async () => JSON.stringify({ error: { message: "Bad input" } }),
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    await expect(
      client.validate([{ path: "main.tf", content: "" }]),
    ).rejects.toThrow(/^API error 400: Bad input$/);
  });

  it("re-splits and retries on 413 Payload Too Large", async () => {
    const makeSuccessResponse = (scanId: string) => ({
      ok: true,
      json: async () => ({
        status: "success",
        statusCode: 200,
        data: {
          passed: true,
          findingsCount: 0,
          findings: [],
          summary: {
            total: 0,
            passed: 0,
            failed: 0,
            bySeverity: {},
            byFramework: {},
          },
          scanId,
        },
      }),
    } as Response);

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      // First call: all files in one batch → 413
      .mockResolvedValueOnce({
        ok: false,
        status: 413,
        statusText: "Payload Too Large",
        text: async () => "Request payload too large",
      } as Response)
      // After splitting: two batches succeed
      .mockResolvedValueOnce(makeSuccessResponse("scan-split-1"))
      .mockResolvedValueOnce(makeSuccessResponse("scan-split-2"));

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    const result = await client.validate([
      { path: "a.tf", content: "aaa" },
      { path: "b.tf", content: "bbb" },
    ]);

    // First attempt + 2 retried halves
    expect(fetchSpy).toHaveBeenCalledTimes(3);
    expect(result.passed).toBe(true);
    expect(result.scanId).toBe("scan-split-2");
  });

  it("throws 413 for a single file that is too large", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 413,
      statusText: "Payload Too Large",
      text: async () => "Request payload too large",
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    await expect(
      client.validate([{ path: "huge.tf", content: "x".repeat(10_000_000) }]),
    ).rejects.toThrow(PayloadTooLargeError);
  });

  it("retries on 5xx server errors", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({
        ok: false,
        status: 502,
        statusText: "Bad Gateway",
        text: async () => "Bad Gateway",
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          status: "success",
          statusCode: 200,
          data: {
            passed: true,
            findingsCount: 0,
            findings: [],
            summary: {
              total: 0,
              passed: 0,
              failed: 0,
              bySeverity: {},
              byFramework: {},
            },
            scanId: "scan-retry",
          },
        }),
      } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    const result = await client.validate([{ path: "main.tf", content: "" }]);

    expect(result.scanId).toBe("scan-retry");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("splits large payloads into multiple batches and merges results", async () => {
    // Create files that are large enough to require batching
    // Each file ~0.8 MB → 2 MB limit means ~2 files per batch, so 4 files = 2 batches
    const largeContent = "x".repeat(800 * 1024); // 0.8 MB
    const files: ChangedFile[] = Array.from({ length: 4 }, (_, i) => ({
      path: `file-${i}.tf`,
      content: largeContent,
    }));

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          status: "success",
          statusCode: 200,
          data: {
            passed: true,
            findingsCount: 1,
            findings: [
              {
                ruleId: "rule-1",
                controlId: "ctrl-1",
                severity: "high",
                confidence: "high",
                engine: "opa",
                framework: "soc2",
                resourceType: "aws_s3_bucket",
                resourcePath: "file-0.tf",
                resourceName: "bucket",
                message: "Finding in batch 1",
                remediation: "Fix it",
              },
            ],
            summary: {
              total: 3,
              passed: 2,
              failed: 1,
              bySeverity: { high: 1 },
              byFramework: { soc2: 1 },
            },
            scanId: "scan-batch-1",
          },
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          status: "success",
          statusCode: 200,
          data: {
            passed: false,
            findingsCount: 2,
            findings: [
              {
                ruleId: "rule-2",
                controlId: "ctrl-2",
                severity: "critical",
                confidence: "high",
                engine: "opa",
                framework: "hipaa",
                resourceType: "aws_rds",
                resourcePath: "file-4.tf",
                resourceName: "db",
                message: "Finding in batch 2",
                remediation: "Fix it too",
              },
              {
                ruleId: "rule-3",
                controlId: "ctrl-3",
                severity: "high",
                confidence: "medium",
                engine: "opa",
                framework: "soc2",
                resourceType: "aws_iam",
                resourcePath: "file-5.tf",
                resourceName: "role",
                message: "Another finding in batch 2",
                remediation: "Also fix",
              },
            ],
            summary: {
              total: 2,
              passed: 0,
              failed: 2,
              bySeverity: { critical: 1, high: 1 },
              byFramework: { hipaa: 1, soc2: 1 },
            },
            scanId: "scan-batch-2",
          },
        }),
      } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    const result = await client.validate(files);

    // Should have made 2 API calls
    expect(fetchSpy).toHaveBeenCalledTimes(2);

    // Merged result: passed=false because batch 2 failed
    expect(result.passed).toBe(false);

    // Findings merged: batch 1 has 1, batch 2 has 2
    expect(result.findingsCount).toBe(3);
    expect(result.findings).toHaveLength(3);
    expect(result.findings[0].ruleId).toBe("rule-1");
    expect(result.findings[1].ruleId).toBe("rule-2");
    expect(result.findings[2].ruleId).toBe("rule-3");

    // Summary merged
    expect(result.summary.total).toBe(5);
    expect(result.summary.passed).toBe(2);
    expect(result.summary.failed).toBe(3);
    expect(result.summary.bySeverity).toEqual({ high: 2, critical: 1 });
    expect(result.summary.byFramework).toEqual({ soc2: 2, hipaa: 1 });

    // scanId from last batch
    expect(result.scanId).toBe("scan-batch-2");
  });

  it("maps API 'line' field to 'startLine' in findings", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: "success",
        statusCode: 200,
        data: {
          passed: false,
          findingsCount: 1,
          findings: [
            {
              ruleId: "SOC2-3.5-01",
              controlId: "SOC2-3.5-01",
              severity: "high",
              confidence: "high",
              engine: "rego",
              framework: "soc2",
              resourceType: "source_code",
              resourcePath: "src/auth.ts",
              resourceName: "auth.ts",
              message: "Credential in log",
              remediation: "Remove it",
              line: 42,
              endLine: 45,
            },
          ],
          summary: { total: 1, passed: 0, failed: 1, bySeverity: { high: 1 }, byFramework: { soc2: 1 } },
          scanId: "scan-norm",
        },
      }),
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    const result = await client.validate([{ path: "src/auth.ts", content: "" }]);

    expect(result.findings[0].startLine).toBe(42);
    expect(result.findings[0].endLine).toBe(45);
  });

  it("maps controlId to ruleId when ruleId is absent", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: "success",
        statusCode: 200,
        data: {
          passed: false,
          findingsCount: 1,
          findings: [
            {
              controlId: "SOC2-3.5-01",
              severity: "high",
              confidence: "high",
              engine: "rego",
              framework: "soc2",
              resourceType: "source_code",
              resourcePath: "src/auth.ts",
              resourceName: "auth.ts",
              message: "Credential in log",
              remediation: "Remove it",
              line: 10,
              endLine: 10,
            },
          ],
          summary: { total: 1, passed: 0, failed: 1, bySeverity: { high: 1 }, byFramework: { soc2: 1 } },
          scanId: "scan-ruleid",
        },
      }),
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    const result = await client.validate([{ path: "src/auth.ts", content: "" }]);

    expect(result.findings[0].ruleId).toBe("SOC2-3.5-01");
  });

  it("defaults startLine and endLine to 0 when API omits line info", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: "success",
        statusCode: 200,
        data: {
          passed: false,
          findingsCount: 1,
          findings: [
            {
              ruleId: "SOC2-3.5-01",
              controlId: "SOC2-3.5-01",
              severity: "high",
              confidence: "high",
              engine: "rego",
              framework: "soc2",
              resourceType: "source_code",
              resourcePath: "src/auth.ts",
              resourceName: "auth.ts",
              message: "Credential in log",
              remediation: "Remove it",
            },
          ],
          summary: { total: 1, passed: 0, failed: 1, bySeverity: { high: 1 }, byFramework: { soc2: 1 } },
          scanId: "scan-no-lines",
        },
      }),
    } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    const result = await client.validate([{ path: "src/auth.ts", content: "" }]);

    expect(result.findings[0].startLine).toBe(0);
    expect(result.findings[0].endLine).toBe(0);
  });

  it("falls back to chunked-session flow when 413 includes suggestedEndpoint", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      // First call to /validate → 413 with suggestedEndpoint
      .mockResolvedValueOnce({
        ok: false,
        status: 413,
        statusText: "Payload Too Large",
        text: async () =>
          JSON.stringify({
            error: {
              message: "Payload exceeds 5 MB limit",
              details: {
                suggestedEndpoint: "/v1/compliance/scans",
                maxBytes: 5 * 1024 * 1024,
              },
            },
          }),
      } as Response)
      // openSession → returns scanId in envelope
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          status: "success",
          statusCode: 200,
          data: { scanId: "scan-chunked-99" },
        }),
      } as Response)
      // appendChunk
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          status: "success",
          statusCode: 200,
          data: { ok: true },
        }),
      } as Response)
      // completeSession → ValidateResponse-shaped data
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          status: "success",
          statusCode: 200,
          data: {
            passed: true,
            findingsCount: 0,
            findings: [],
            summary: {
              total: 1,
              passed: 1,
              failed: 0,
              bySeverity: {},
              byFramework: {},
            },
            scanId: "scan-chunked-99",
          },
        }),
      } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    const result = await client.validate(
      [{ path: "main.tf", content: "x" }],
      {
        frameworks: ["soc2"],
        productId: "prod-uuid",
        syncConfigId: "sync-uuid",
        excludeResolved: true,
        reconcile: false,
      },
    );

    expect(fetchSpy).toHaveBeenCalledTimes(4);
    const urls = fetchSpy.mock.calls.map((c) => c[0] as string);
    expect(urls[0]).toBe("https://api.prodcycle.com/v1/compliance/validate");
    expect(urls[1]).toBe("https://api.prodcycle.com/v1/compliance/scans");
    expect(urls[2]).toBe(
      "https://api.prodcycle.com/v1/compliance/scans/scan-chunked-99/chunks",
    );
    expect(urls[3]).toBe(
      "https://api.prodcycle.com/v1/compliance/scans/scan-chunked-99/complete",
    );
    expect(result.passed).toBe(true);
    expect(result.scanId).toBe("scan-chunked-99");

    // Open-session body forwards frameworks AND the product-aware options
    // (productId/syncConfigId at the top level; excludeResolved + reconcile
    // inside options). With reconcile=false, the backend detaches the row +
    // skips reconciliation while still applying suppression filtering.
    const openBody = JSON.parse(
      (fetchSpy.mock.calls[1][1] as RequestInit).body as string,
    );
    expect(openBody.frameworks).toEqual(["soc2"]);
    expect(openBody.product_id).toBe("prod-uuid");
    expect(openBody.sync_config_id).toBe("sync-uuid");
    expect(openBody.options.exclude_resolved).toBe(true);
    expect(openBody.options.reconcile).toBe(false);

    // Chunk body has the file in path→content map shape
    const chunkBody = JSON.parse(
      (fetchSpy.mock.calls[2][1] as RequestInit).body as string,
    );
    expect(chunkBody.files).toEqual({ "main.tf": "x" });
  });

  it("honors Retry-After on 429 then succeeds on retry", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: "Too Many Requests",
        headers: new Headers({ "retry-after": "0" }),
        text: async () =>
          JSON.stringify({ error: { message: "Rate limit" } }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          status: "success",
          statusCode: 200,
          data: {
            passed: true,
            findingsCount: 0,
            findings: [],
            summary: {
              total: 0,
              passed: 0,
              failed: 0,
              bySeverity: {},
              byFramework: {},
            },
            scanId: "scan-rl-ok",
          },
        }),
      } as Response);

    const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
    const result = await client.validate([{ path: "a.tf", content: "" }]);
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(result.scanId).toBe("scan-rl-ok");
  });

  it("Retry-After replaces (not stacks on top of) linear backoff", async () => {
    // With the old (buggy) code, a 429 with `retry-after: 5` would sleep
    // 5 s and then sleep `RETRY_DELAY_MS * 1` = 2 s on top. After the
    // fix only the 5 s sleep should fire. We assert this directly by
    // running fake timers and checking which delays were queued.
    vi.useFakeTimers({ toFake: ["setTimeout"] });
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");

    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: "Too Many Requests",
        headers: new Headers({ "retry-after": "5" }),
        text: async () =>
          JSON.stringify({ error: { message: "Rate limit" } }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          status: "success",
          statusCode: 200,
          data: {
            passed: true,
            findingsCount: 0,
            findings: [],
            summary: {
              total: 0,
              passed: 0,
              failed: 0,
              bySeverity: {},
              byFramework: {},
            },
            scanId: "scan-rl-replaces",
          },
        }),
      } as Response);

    try {
      const client = new ComplianceApiClient(mockApiUrl, mockApiKey);
      const promise = client.validate([{ path: "a.tf", content: "" }]);

      // Run all queued timers — under fake timers this doesn't actually
      // wait, just advances the virtual clock.
      await vi.runAllTimersAsync();
      const result = await promise;
      expect(result.scanId).toBe("scan-rl-replaces");

      // Inspect the recorded sleep durations. Filter out internal 0-ms
      // microtask scheduling and the AbortSignal.timeout() entries
      // (those use the request timeout = 120000 ms, not the retry path).
      const retrySleeps = setTimeoutSpy.mock.calls
        .map((c) => c[1])
        .filter(
          (d): d is number =>
            typeof d === "number" && d > 0 && d !== 120_000,
        );

      // Exactly one large delay should have been queued: 5 s. A second
      // entry of ~2000 ms would mean the linear-backoff is stacking on
      // top of Retry-After again.
      expect(retrySleeps).toEqual([5000]);
    } finally {
      vi.useRealTimers();
      setTimeoutSpy.mockRestore();
    }
  });
});

describe("createBatches", () => {
  it("returns a single batch for small payloads", () => {
    const files: ChangedFile[] = [
      { path: "a.tf", content: "small" },
      { path: "b.tf", content: "also small" },
    ];
    const batches = createBatches(files);
    expect(batches).toHaveLength(1);
    expect(batches[0]).toHaveLength(2);
  });

  it("splits large files into multiple batches", () => {
    const largeContent = "x".repeat(0.8 * 1024 * 1024); // 0.8 MB each
    const files: ChangedFile[] = [
      { path: "a.tf", content: largeContent },
      { path: "b.tf", content: largeContent },
      { path: "c.tf", content: largeContent },
      { path: "d.tf", content: largeContent },
      { path: "e.tf", content: largeContent },
    ];
    const batches = createBatches(files);
    // 0.8 MB * 2 = 1.6 MB fits in one batch (under 2 MB), so:
    // batch 1: a, b  (~1.6 MB)
    // batch 2: c, d  (~1.6 MB)
    // batch 3: e     (~0.8 MB)
    expect(batches).toHaveLength(3);
    expect(batches[0]).toHaveLength(2);
    expect(batches[1]).toHaveLength(2);
    expect(batches[2]).toHaveLength(1);
  });

  it("puts a single oversized file in its own batch", () => {
    const hugeContent = "x".repeat(5 * 1024 * 1024); // 5 MB
    const files: ChangedFile[] = [
      { path: "small.tf", content: "tiny" },
      { path: "huge.tf", content: hugeContent },
      { path: "another.tf", content: "also tiny" },
    ];
    const batches = createBatches(files);
    expect(batches).toHaveLength(3);
    expect(batches[0].map((f) => f.path)).toEqual(["small.tf"]);
    expect(batches[1].map((f) => f.path)).toEqual(["huge.tf"]);
    expect(batches[2].map((f) => f.path)).toEqual(["another.tf"]);
  });

  it("handles empty file list", () => {
    const batches = createBatches([]);
    expect(batches).toHaveLength(1);
    expect(batches[0]).toHaveLength(0);
  });
});
