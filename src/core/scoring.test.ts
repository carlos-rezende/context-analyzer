import { describe, expect, it } from "vitest";
import { computeSeverityScore } from "./scoring";
import type { Finding } from "../shared/types";

function f(
  id: string,
  severity: Finding["severity"],
): Finding {
  return {
    id,
    category: "Test",
    title: "t",
    detail: "d",
    severity,
  };
}

describe("computeSeverityScore", () => {
  it("retorna 0 sem achados", () => {
    expect(computeSeverityScore([])).toBe(0);
  });

  it("normaliza para 0–100", () => {
    const score = computeSeverityScore([f("1", "high"), f("2", "medium")]);
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  it("peso maior para severidade alta", () => {
    const onlyHigh = computeSeverityScore([f("a", "high")]);
    const onlyInfo = computeSeverityScore([f("b", "info")]);
    expect(onlyHigh).toBeGreaterThan(onlyInfo);
  });
});
