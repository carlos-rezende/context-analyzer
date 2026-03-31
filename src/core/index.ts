export { detectIdorHintsFromUrl, idorFindingsFromHints } from "./idor";
export { extractEndpointsFromPage } from "./endpoints";
export { analyzeSecurityHeaders } from "./headers";
export { analyzeSetCookieHeaders } from "./cookies";
export { analyzeInputsFromForms } from "./inputs";
export { computeSeverityScore } from "./scoring";
export { parseCspDirectives, analyzeCspAdvanced } from "./csp-advanced";
export { graphqlFindingsFromNetwork, graphqlDomFindingsFromPage } from "./graphql";
export { looksLikeJwt, jwtFindingsFromStorage } from "./jwt";

import type {
  AggregatedFindings,
  DomScanPayload,
  Finding,
  NetworkScanPayload,
} from "../shared/types";
import { analyzeSecurityHeaders } from "./headers";
import { analyzeSetCookieHeaders } from "./cookies";
import { graphqlFindingsFromNetwork } from "./graphql";
import { idorFindingsFromHints } from "./idor";

export function mergeNetworkIntoFindings(
  existing: Finding[],
  net: NetworkScanPayload,
): Finding[] {
  const headerFindings = analyzeSecurityHeaders(net.responseHeaders);
  const cookieFindings = analyzeSetCookieHeaders(net.setCookieHeaders);
  const graphqlFindings = graphqlFindingsFromNetwork(net);
  const dedup = new Map<string, Finding>();
  for (const f of [
    ...existing,
    ...headerFindings,
    ...cookieFindings,
    ...graphqlFindings,
  ]) {
    dedup.set(f.id, f);
  }
  return [...dedup.values()];
}

export function buildAggregatedFromDom(
  tabId: number,
  dom: DomScanPayload,
): AggregatedFindings {
  const idorF = idorFindingsFromHints(dom.idorHints, dom.pageUrl);
  const byId = new Map<string, Finding>();
  for (const f of [...dom.domFindings, ...idorF]) {
    byId.set(f.id, f);
  }
  const findings = [...byId.values()];

  return {
    tabId,
    pageUrl: dom.pageUrl,
    updatedAt: dom.collectedAt,
    findings,
    endpoints: dom.endpoints,
    dom,
  };
}
