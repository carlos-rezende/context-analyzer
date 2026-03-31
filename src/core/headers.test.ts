import { describe, expect, it } from "vitest";
import { analyzeSecurityHeaders } from "./headers";

describe("analyzeSecurityHeaders", () => {
  it("lista ausências comuns quando vazio", () => {
    const f = analyzeSecurityHeaders({});
    const cats = new Set(f.map((x) => x.category));
    expect(cats.has("CSP")).toBe(true);
    expect(f.length).toBeGreaterThan(2);
  });

  it("não alerta CSP quando presente", () => {
    const f = analyzeSecurityHeaders({
      "content-security-policy": "default-src 'self'",
    });
    const cspMissing = f.find((x) => x.id === "hdr-csp-missing");
    expect(cspMissing).toBeUndefined();
  });

  it("alerta unsafe-inline no CSP (parser avançado)", () => {
    const f = analyzeSecurityHeaders({
      "content-security-policy": "script-src 'unsafe-inline'",
    });
    const unsafe = f.find((x) => x.id === "csp-unsafe-inline");
    expect(unsafe).toBeDefined();
  });
});
