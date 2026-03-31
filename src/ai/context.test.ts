import { describe, expect, it } from "vitest";
import { buildAiPayloadFromAggregated } from "./context";
import type { AggregatedFindings } from "../shared/types";

describe("buildAiPayloadFromAggregated", () => {
  it("não inclui segredos — só metadados", () => {
    const agg: AggregatedFindings = {
      tabId: 1,
      pageUrl: "https://app.exemplo.org/pagina",
      updatedAt: Date.now(),
      findings: [
        {
          id: "x",
          category: "Teste",
          title: "T",
          detail: "D",
          severity: "info",
        },
      ],
      endpoints: [{ url: "https://api.exemplo.org/v1/recurso", source: "dom" }],
      observedHeaderNames: ["content-type"],
      dom: {
        pageUrl: "https://app.exemplo.org/pagina",
        collectedAt: Date.now(),
        endpoints: [],
        numericParameters: [{ name: "user_id" }],
        suspiciousInputs: [],
        idorHints: [],
        domFindings: [],
      },
    };
    const p = buildAiPayloadFromAggregated(agg);
    expect(p.pageHost).toBe("app.exemplo.org");
    expect(p.parameterNames).toContain("user_id");
    expect(p.endpointPaths.some((x) => x.includes("/v1/"))).toBe(true);
    expect(JSON.stringify(p)).not.toMatch(/cookie|token|password/i);
  });
});
