import { describe, expect, it } from "vitest";
import {
  buildContextualXssHints,
  buildTestUrlWithParam,
  mergeXssHints,
  XSS_MANUAL_HINTS,
} from "./xss-hints";

describe("buildContextualXssHints", () => {
  it("gera pistas por parâmetros na query", () => {
    const u = "https://example.com/page?q=1&search=test";
    const hints = buildContextualXssHints(u, null);
    const labels = hints.map((h) => h.context);
    expect(labels.some((l) => l.includes("?q="))).toBe(true);
    expect(labels.some((l) => l.includes("?search="))).toBe(true);
  });

  it("inclui copyUrl (semi-automático) para parâmetros da URL", () => {
    const hints = buildContextualXssHints("https://ex.com/p?x=1", null);
    const forX = hints.find((h) => h.context.includes("?x="));
    expect(forX?.copyUrl).toBeDefined();
    const parsed = new URL(forX!.copyUrl!);
    expect(parsed.searchParams.get("x")).toBe(forX!.payload);
  });

  it("usa campos do DOM quando fornecidos", () => {
    const dom = {
      pageUrl: "https://x.test/",
      collectedAt: 0,
      endpoints: [],
      numericParameters: [{ name: "userId" }],
      suspiciousInputs: [
        {
          name: "comment",
          type: "textarea",
          reason: "html",
        },
      ],
      idorHints: [],
      domFindings: [],
    };
    const hints = buildContextualXssHints("https://x.test/", dom);
    expect(hints.some((h) => h.context.includes("comment"))).toBe(true);
    expect(hints.some((h) => h.context.includes("userId"))).toBe(true);
  });
});

describe("buildTestUrlWithParam", () => {
  it("substitui valor do parâmetro e codifica o payload", () => {
    const payload = "<svg onload=alert(1)>";
    const out = buildTestUrlWithParam(
      "https://a.test/path?foo=bar&q=old",
      "q",
      payload,
    );
    expect(out).not.toContain("old");
    expect(new URL(out!).searchParams.get("q")).toBe(payload);
  });
});

describe("mergeXssHints", () => {
  it("inclui genéricos após contextuais", () => {
    const merged = mergeXssHints("https://a.test/?x=1", null);
    expect(merged.length).toBeGreaterThanOrEqual(XSS_MANUAL_HINTS.length);
    expect(merged.some((m) => m.context !== "Genérico (referência)")).toBe(
      true,
    );
  });
});
