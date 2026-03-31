import { describe, expect, it } from "vitest";
import { analyzeSetCookieHeaders } from "./cookies";

describe("analyzeSetCookieHeaders", () => {
  it("lista vazio sem cookies", () => {
    expect(analyzeSetCookieHeaders([])).toEqual([]);
  });

  it("marca cookie sem flags de segurança", () => {
    const f = analyzeSetCookieHeaders(["sessionid=abc; Path=/"]);
    expect(f.length).toBeGreaterThan(0);
    expect(f.some((x) => x.category === "Cookies")).toBe(true);
  });
});
