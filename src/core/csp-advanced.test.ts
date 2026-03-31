import { describe, expect, it } from "vitest";
import { analyzeCspAdvanced, parseCspDirectives } from "./csp-advanced";

describe("parseCspDirectives", () => {
  it("extrai default-src e valores", () => {
    const m = parseCspDirectives("default-src 'self'; script-src 'unsafe-inline'");
    expect(m.get("default-src")).toEqual(["'self'"]);
    expect(m.get("script-src")).toEqual(["'unsafe-inline'"]);
  });

  it("diretiva sem valores", () => {
    const m = parseCspDirectives("upgrade-insecure-requests");
    expect(m.has("upgrade-insecure-requests")).toBe(true);
    expect(m.get("upgrade-insecure-requests")).toEqual([]);
  });
});

describe("analyzeCspAdvanced", () => {
  it("deteta unsafe-inline e unsafe-eval", () => {
    const f = analyzeCspAdvanced(
      "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'",
    );
    const ids = new Set(f.map((x) => x.id));
    expect(ids.has("csp-unsafe-inline")).toBe(true);
    expect(ids.has("csp-unsafe-eval")).toBe(true);
  });

  it("deteta upgrade-insecure-requests como info", () => {
    const f = analyzeCspAdvanced(
      "default-src 'self'; upgrade-insecure-requests",
    );
    const up = f.find((x) => x.id === "csp-upgrade-insecure");
    expect(up?.severity).toBe("info");
  });

  it("alerta script-src permissivo com *", () => {
    const f = analyzeCspAdvanced("script-src *");
    expect(f.some((x) => x.id === "csp-script-wide")).toBe(true);
  });
});
