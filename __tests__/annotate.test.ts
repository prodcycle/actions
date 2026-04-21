import { describe, it, expect, vi, beforeEach } from "vitest";
import * as core from "@actions/core";
import type { ScanFinding } from "../src/types";

// Mock @actions/core
vi.mock("@actions/core", () => ({
  error: vi.fn(),
  warning: vi.fn(),
  notice: vi.fn(),
  info: vi.fn(),
  debug: vi.fn(),
  getInput: vi.fn(),
  summary: {
    addRaw: vi.fn().mockReturnThis(),
    write: vi.fn(),
  },
}));

// Mock @actions/github
const mockCreateReview = vi.fn();
const mockCreateReviewComment = vi.fn();
const mockListReviewComments = vi.fn();
const mockListFiles = vi.fn().mockResolvedValue({
  data: [
    {
      filename: "src/auth.ts",
      patch: "@@ -5,20 +5,25 @@\n some diff content",
    },
    {
      filename: "src/db.ts",
      patch: "@@ -18,5 +18,8 @@\n some diff content",
    },
  ],
});
const mockListComments = vi.fn().mockResolvedValue({ data: [] });
const mockCreateComment = vi.fn();
const mockUpdateComment = vi.fn();

const diffFiles = [
  {
    filename: "src/auth.ts",
    patch: "@@ -5,20 +5,25 @@\n some diff content",
  },
  {
    filename: "src/db.ts",
    patch: "@@ -18,5 +18,8 @@\n some diff content",
  },
];

// mockPaginate needs to return different data depending on the endpoint called
const mockPaginate = vi.fn().mockImplementation((endpoint: unknown) => {
  if (endpoint === mockListReviewComments) {
    return Promise.resolve([]);
  }
  // Default: return diff files (for listFiles)
  return Promise.resolve(diffFiles);
});

vi.mock("@actions/github", () => ({
  context: {
    payload: {
      pull_request: {
        number: 42,
        head: { sha: "abc123" },
        base: { sha: "def456" },
      },
    },
    repo: { owner: "test-owner", repo: "test-repo" },
  },
  getOctokit: vi.fn(() => ({
    rest: {
      pulls: { createReview: mockCreateReview, createReviewComment: mockCreateReviewComment, listFiles: mockListFiles, listReviewComments: mockListReviewComments },
      issues: {
        listComments: mockListComments,
        createComment: mockCreateComment,
        updateComment: mockUpdateComment,
      },
    },
    paginate: mockPaginate,
  })),
}));

function makeFinding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    ruleId: "HIPAA-164.312-a1",
    controlId: "164.312(a)(1)",
    severity: "high",
    confidence: "high",
    engine: "prodcycle",
    framework: "hipaa",
    resourceType: "code",
    resourcePath: "src/auth.ts",
    resourceName: "authenticateUser",
    startLine: 10,
    endLine: 15,
    message: "Missing encryption for data at rest",
    remediation: "Use AES-256 encryption for stored credentials",
    ...overrides,
  };
}

describe("parseDiffHunks", () => {
  it("extracts line ranges from unified diff patch", async () => {
    const { parseDiffHunks } = await import("../src/annotate");

    const patch = [
      "@@ -10,5 +10,8 @@ some context",
      " unchanged line",
      "+added line",
      "@@ -50,3 +53,6 @@ more context",
      "+another addition",
    ].join("\n");

    const ranges = parseDiffHunks(patch);
    expect(ranges).toEqual([
      { start: 10, end: 17 },
      { start: 53, end: 58 },
    ]);
  });

  it("handles single-line hunks without count", async () => {
    const { parseDiffHunks } = await import("../src/annotate");
    const patch = "@@ -1 +1 @@\n-old\n+new";
    const ranges = parseDiffHunks(patch);
    expect(ranges).toEqual([{ start: 1, end: 1 }]);
  });

  it("returns empty array for empty patch", async () => {
    const { parseDiffHunks } = await import("../src/annotate");
    expect(parseDiffHunks("")).toEqual([]);
  });
});

describe("annotate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(core.getInput).mockReturnValue("fake-token");
  });

  describe("createAnnotations", () => {
    it("creates error annotations for critical/high findings with line numbers", async () => {
      const { createAnnotations } = await import("../src/annotate");

      const findings = [makeFinding({ severity: "critical", startLine: 5, endLine: 10 })];
      createAnnotations(findings);

      expect(core.error).toHaveBeenCalledOnce();
      const call = vi.mocked(core.error).mock.calls[0];
      expect(call[1]).toMatchObject({
        file: "src/auth.ts",
        startLine: 5,
        endLine: 10,
      });
    });

    it("creates warning annotations for medium findings", async () => {
      const { createAnnotations } = await import("../src/annotate");

      createAnnotations([makeFinding({ severity: "medium" })]);
      expect(core.warning).toHaveBeenCalledOnce();
    });

    it("creates notice annotations for low findings", async () => {
      const { createAnnotations } = await import("../src/annotate");

      createAnnotations([makeFinding({ severity: "low" })]);
      expect(core.notice).toHaveBeenCalledOnce();
    });
  });

  describe("postReviewComments", () => {
    it("posts a PR review with inline comments for findings within the diff", async () => {
      const { postReviewComments } = await import("../src/annotate");

      const findings = [
        makeFinding({ startLine: 10, endLine: 15 }),
        makeFinding({
          ruleId: "SOC2-CC6.1",
          severity: "medium",
          resourcePath: "src/db.ts",
          startLine: 20,
          endLine: 20,
          message: "Unencrypted database connection",
        }),
      ];

      mockCreateReview.mockResolvedValue({ data: {} });
      await postReviewComments(findings, "REQUEST_CHANGES");

      // Called twice: once for listReviewComments (dedup), once for listFiles (diff ranges)
      expect(mockPaginate).toHaveBeenCalledTimes(2);
      expect(mockCreateReview).toHaveBeenCalledOnce();
      const call = mockCreateReview.mock.calls[0][0];

      expect(call.owner).toBe("test-owner");
      expect(call.repo).toBe("test-repo");
      expect(call.pull_number).toBe(42);
      expect(call.commit_id).toBe("abc123");
      expect(call.event).toBe("REQUEST_CHANGES");
      expect(call.comments).toHaveLength(2);

      // First comment: multi-line (startLine < endLine)
      expect(call.comments[0].path).toBe("src/auth.ts");
      expect(call.comments[0].line).toBe(15);
      expect(call.comments[0].start_line).toBe(10);

      // Second comment: single line (startLine === endLine)
      expect(call.comments[1].path).toBe("src/db.ts");
      expect(call.comments[1].line).toBe(20);
      expect(call.comments[1].start_line).toBeUndefined();
    });

    it("uses COMMENT event when scan passed", async () => {
      const { postReviewComments } = await import("../src/annotate");

      mockCreateReview.mockResolvedValue({ data: {} });
      await postReviewComments([makeFinding()], "COMMENT");

      expect(mockCreateReview.mock.calls[0][0].event).toBe("COMMENT");
    });

    it("skips findings without line information", async () => {
      const { postReviewComments } = await import("../src/annotate");

      const findings = [makeFinding({ startLine: 0, endLine: 0 })];
      mockCreateReview.mockResolvedValue({ data: {} });
      await postReviewComments(findings, "REQUEST_CHANGES");

      expect(mockCreateReview).not.toHaveBeenCalled();
    });

    it("skips findings where endLine is 0 even if startLine is set", async () => {
      const { postReviewComments } = await import("../src/annotate");

      const findings = [makeFinding({ startLine: 5, endLine: 0 })];
      mockCreateReview.mockResolvedValue({ data: {} });
      await postReviewComments(findings, "REQUEST_CHANGES");

      expect(mockCreateReview).not.toHaveBeenCalled();
    });

    it("skips when no github token is available", async () => {
      const { postReviewComments } = await import("../src/annotate");

      vi.mocked(core.getInput).mockReturnValue("");
      delete process.env.GITHUB_TOKEN;

      await postReviewComments([makeFinding()], "REQUEST_CHANGES");
      expect(mockCreateReview).not.toHaveBeenCalled();
    });

    it("warns but does not throw when review creation fails", async () => {
      const { postReviewComments } = await import("../src/annotate");

      mockCreateReview.mockRejectedValue(new Error("Validation Failed"));
      mockCreateReviewComment.mockRejectedValue(new Error("Line could not be resolved"));
      await postReviewComments([makeFinding()], "REQUEST_CHANGES");

      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining("Batch review failed"),
      );
    });

    it("includes severity icon and remediation in comment body", async () => {
      const { postReviewComments } = await import("../src/annotate");

      mockCreateReview.mockResolvedValue({ data: {} });
      await postReviewComments([makeFinding({ severity: "critical" })], "REQUEST_CHANGES");

      const body = mockCreateReview.mock.calls[0][0].comments[0].body;
      expect(body).toContain("🔴");
      expect(body).toContain("[CRITICAL]");
      expect(body).toContain("Remediation:");
      expect(body).toContain("AES-256");
    });

    it("posts file-level comments for findings outside the PR diff", async () => {
      const { postReviewComments } = await import("../src/annotate");

      // Finding on line 100 — well outside the diff range (5-29)
      const findings = [makeFinding({ startLine: 100, endLine: 105 })];
      mockCreateReview.mockResolvedValue({ data: {} });
      await postReviewComments(findings, "REQUEST_CHANGES");

      expect(mockCreateReview).toHaveBeenCalledOnce();
      const call = mockCreateReview.mock.calls[0][0];
      expect(call.comments).toHaveLength(1);
      expect(call.comments[0].subject_type).toBe("file");
      expect(call.comments[0].path).toBe("src/auth.ts");
      expect(call.comments[0].line).toBeUndefined();
      expect(call.comments[0].body).toContain("outside the PR diff");
      expect(call.comments[0].body).toContain("view");
    });

    it("falls back to individual comments when batch review fails", async () => {
      const { postReviewComments } = await import("../src/annotate");

      const findings = [
        makeFinding({ startLine: 10, endLine: 15 }),
        makeFinding({
          ruleId: "SOC2-CC6.1",
          severity: "medium",
          resourcePath: "src/db.ts",
          startLine: 20,
          endLine: 20,
          message: "Unencrypted database connection",
        }),
      ];

      mockCreateReview.mockRejectedValue(new Error("Unprocessable Entity"));
      // First individual comment succeeds, second fails
      mockCreateReviewComment
        .mockResolvedValueOnce({ data: {} })
        .mockRejectedValueOnce(new Error("Line could not be resolved"));

      await postReviewComments(findings, "REQUEST_CHANGES");

      expect(mockCreateReview).toHaveBeenCalledOnce();
      expect(mockCreateReviewComment).toHaveBeenCalledTimes(2);
      expect(core.info).toHaveBeenCalledWith(
        expect.stringContaining("Posted 1 of 2 comment(s) individually"),
      );
    });

    it("posts file-level comments for files not in the PR diff", async () => {
      const { postReviewComments } = await import("../src/annotate");

      const findings = [makeFinding({ resourcePath: "src/unknown.ts", startLine: 5, endLine: 10 })];
      mockCreateReview.mockResolvedValue({ data: {} });
      await postReviewComments(findings, "REQUEST_CHANGES");

      expect(mockCreateReview).toHaveBeenCalledOnce();
      const call = mockCreateReview.mock.calls[0][0];
      expect(call.comments[0].subject_type).toBe("file");
      expect(call.comments[0].path).toBe("src/unknown.ts");
    });

    it("skips inline comments that already exist on the PR", async () => {
      const { postReviewComments } = await import("../src/annotate");

      // Simulate an existing review comment matching the finding
      mockPaginate.mockImplementation((endpoint: unknown) => {
        if (endpoint === mockListReviewComments) {
          return Promise.resolve([
            {
              path: "src/auth.ts",
              line: 15,
              body: "🟠 **[HIGH] HIPAA-164.312-a1**\n\nMissing encryption",
            },
          ]);
        }
        return Promise.resolve(diffFiles);
      });

      const findings = [makeFinding({ startLine: 10, endLine: 15 })];
      mockCreateReview.mockResolvedValue({ data: {} });
      await postReviewComments(findings, "REQUEST_CHANGES");

      // All comments deduplicated — review should not be posted
      expect(mockCreateReview).not.toHaveBeenCalled();
      expect(core.info).toHaveBeenCalledWith(
        expect.stringContaining("already exist on this PR"),
      );
    });

    it("skips file-level comments that already exist on the PR", async () => {
      const { postReviewComments } = await import("../src/annotate");

      // Finding outside the diff (line 100) → file-level comment
      mockPaginate.mockImplementation((endpoint: unknown) => {
        if (endpoint === mockListReviewComments) {
          return Promise.resolve([
            {
              path: "src/auth.ts",
              subject_type: "file",
              body: "🟠 **[HIGH] HIPAA-164.312-a1** (line 100) ([view](...))\n\nMissing encryption",
            },
          ]);
        }
        return Promise.resolve(diffFiles);
      });

      const findings = [makeFinding({ startLine: 100, endLine: 105 })];
      mockCreateReview.mockResolvedValue({ data: {} });
      await postReviewComments(findings, "REQUEST_CHANGES");

      expect(mockCreateReview).not.toHaveBeenCalled();
      expect(core.info).toHaveBeenCalledWith(
        expect.stringContaining("already exist on this PR"),
      );
    });

    it("posts only new comments when some already exist", async () => {
      const { postReviewComments } = await import("../src/annotate");

      // One existing comment for HIPAA finding, but not for SOC2
      mockPaginate.mockImplementation((endpoint: unknown) => {
        if (endpoint === mockListReviewComments) {
          return Promise.resolve([
            {
              path: "src/auth.ts",
              line: 15,
              body: "🟠 **[HIGH] HIPAA-164.312-a1**\n\nMissing encryption",
            },
          ]);
        }
        return Promise.resolve(diffFiles);
      });

      const findings = [
        makeFinding({ startLine: 10, endLine: 15 }),
        makeFinding({
          ruleId: "SOC2-CC6.1",
          severity: "medium",
          resourcePath: "src/db.ts",
          startLine: 20,
          endLine: 20,
          message: "Unencrypted database connection",
        }),
      ];

      mockCreateReview.mockResolvedValue({ data: {} });
      await postReviewComments(findings, "REQUEST_CHANGES");

      expect(mockCreateReview).toHaveBeenCalledOnce();
      const call = mockCreateReview.mock.calls[0][0];
      // Only the SOC2 finding should be posted
      expect(call.comments).toHaveLength(1);
      expect(call.comments[0].path).toBe("src/db.ts");
    });
  });
});
