import type { AggregatedFindings, AiContextPayload } from "../shared/types";
import { sanitizePlainText } from "../shared/sanitize";

export function buildAiPayloadFromAggregated(
  agg: AggregatedFindings,
): AiContextPayload {
  const paths = agg.endpoints.map((e) => {
    try {
      const u = new URL(e.url);
      return u.pathname + u.search;
    } catch {
      return sanitizePlainText(e.url, 256);
    }
  });
  const paramNames = [
    ...new Set(
      (agg.dom?.numericParameters ?? []).map((p) => p.name).filter(Boolean),
    ),
  ];
  const headerNames = [...new Set(agg.observedHeaderNames ?? [])];
  return {
    pageHost: (() => {
      try {
        return new URL(agg.pageUrl).host;
      } catch {
        return "";
      }
    })(),
    endpointPaths: paths.slice(0, 120),
    parameterNames: paramNames.slice(0, 80),
    headerNames: headerNames.slice(0, 80),
    findingSummaries: agg.findings
      .map((f) => `${f.title}: ${f.detail}`)
      .slice(0, 40),
  };
}
