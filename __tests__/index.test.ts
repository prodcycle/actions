import { describe, it, expect } from "vitest";
import { resolveReviewEvent } from "../src/index";

describe("resolveReviewEvent", () => {
  describe("empty input (back-compat coupling with annotate)", () => {
    it("resolves to 'auto' when annotate=true", () => {
      expect(resolveReviewEvent("", true)).toBe("auto");
    });

    it("resolves to 'none' when annotate=false", () => {
      expect(resolveReviewEvent("", false)).toBe("none");
    });
  });

  describe("explicit values", () => {
    it.each(["auto", "comment", "request-changes", "none"] as const)(
      "accepts '%s' regardless of annotate",
      (value) => {
        expect(resolveReviewEvent(value, true)).toBe(value);
        expect(resolveReviewEvent(value, false)).toBe(value);
      },
    );
  });

  describe("invalid input", () => {
    it("throws on an unknown value", () => {
      expect(() => resolveReviewEvent("approve", true)).toThrow(
        /Invalid review-event/,
      );
    });
  });
});
