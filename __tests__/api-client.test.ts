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
