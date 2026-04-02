import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock @actions/core before importing api-client
vi.mock("@actions/core", () => ({
  debug: vi.fn(),
  info: vi.fn(),
  warning: vi.fn(),
}));

import { ComplianceApiClient } from "../src/api-client";

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
});
