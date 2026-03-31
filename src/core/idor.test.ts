import { describe, expect, it } from "vitest";
import {
  detectIdorHintsFromUrl,
  idorFindingsFromHints,
} from "./idor";

describe("detectIdorHintsFromUrl", () => {
  it("deteta segmento numérico no path", () => {
    const h = detectIdorHintsFromUrl("https://app.test/user/12345/perfil");
    expect(h.length).toBeGreaterThan(0);
  });

  it("deteta id numérico na query", () => {
    const h = detectIdorHintsFromUrl("https://app.test/x?id=99");
    expect(h.some((x) => x.includes("query") || x.includes("identificador"))).toBe(
      true,
    );
  });
});

describe("idorFindingsFromHints", () => {
  it("não gera achados sem indícios", () => {
    expect(idorFindingsFromHints([], "https://a.test/")).toEqual([]);
  });

  it("gera achado com indícios", () => {
    const f = idorFindingsFromHints(["segmento numérico"], "https://a.test/1");
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("medium");
  });
});
