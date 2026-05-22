import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as core from "@actions/core";

vi.mock("@actions/core", () => ({
  info: vi.fn(),
  warning: vi.fn(),
  debug: vi.fn(),
  getInput: vi.fn(),
  setSecret: vi.fn(),
}));

const mockGetOctokit = vi.fn((token: string) => ({ __token: token }));

vi.mock("@actions/github", () => ({
  context: { repo: { owner: "acme", repo: "widgets" } },
  getOctokit: (token: string) => mockGetOctokit(token),
}));

function mockFetchOnce(status: number, body: unknown) {
  return vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response);
}

describe("resolveGitHubAuth", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(core.getInput).mockReturnValue("gh-token");
    delete process.env.GITHUB_TOKEN;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("mints a ProdCycle App token and authors as prodcycle[bot] in auto mode", async () => {
    const { resolveGitHubAuth } = await import("../src/github");
    const fetchSpy = mockFetchOnce(200, {
      status: "success",
      data: { token: "app-installation-token" },
    });

    const auth = await resolveGitHubAuth("https://api.prodcycle.com", "pc_key", "auto");

    expect(auth).not.toBeNull();
    expect(auth!.identity).toBe("prodcycle-app");
    expect(auth!.token).toBe("app-installation-token");
    expect(core.setSecret).toHaveBeenCalledWith("app-installation-token");
    // Correct endpoint + repo payload
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe("https://api.prodcycle.com/v1/github/installation-token");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      owner: "acme",
      repo: "widgets",
    });
  });

  it("falls back to GITHUB_TOKEN (github-actions) when the endpoint is unavailable", async () => {
    const { resolveGitHubAuth } = await import("../src/github");
    mockFetchOnce(404, { error: "not found" });

    const auth = await resolveGitHubAuth("https://api.prodcycle.com", "pc_key", "auto");

    expect(auth!.identity).toBe("github-actions");
    expect(auth!.token).toBe("gh-token");
  });

  it("warns when comment-identity=app but the App token cannot be obtained", async () => {
    const { resolveGitHubAuth } = await import("../src/github");
    mockFetchOnce(404, {});

    const auth = await resolveGitHubAuth("https://api.prodcycle.com", "pc_key", "app");

    expect(auth!.identity).toBe("github-actions");
    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining("comment-identity=app"),
    );
  });

  it("skips the App entirely in github-token mode (no network call)", async () => {
    const { resolveGitHubAuth } = await import("../src/github");
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const auth = await resolveGitHubAuth("https://api.prodcycle.com", "pc_key", "github-token");

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(auth!.identity).toBe("github-actions");
  });

  it("returns null when no token of any kind is available", async () => {
    const { resolveGitHubAuth } = await import("../src/github");
    vi.mocked(core.getInput).mockReturnValue("");
    mockFetchOnce(404, {});

    const auth = await resolveGitHubAuth("https://api.prodcycle.com", "pc_key", "auto");
    expect(auth).toBeNull();
  });

  it("falls back gracefully when the token request throws", async () => {
    const { resolveGitHubAuth } = await import("../src/github");
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("network down"));

    const auth = await resolveGitHubAuth("https://api.prodcycle.com", "pc_key", "auto");
    expect(auth!.identity).toBe("github-actions");
    expect(auth!.token).toBe("gh-token");
  });
});
