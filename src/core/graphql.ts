import type { Finding, NetworkScanPayload } from "../shared/types";
import { sanitizePlainText, sanitizeUrlForDisplay } from "../shared/sanitize";

const GRAPHQL_PATH = /\/graphql(\/|\?|$)/i;
const APOLLO_URQL = /\b(apollo|urql|graphql-request|@apollo)\b/i;

function stableId(part: string): string {
  let h = 0;
  for (let i = 0; i < part.length; i++) {
    h = (h * 31 + part.charCodeAt(i)) | 0;
  }
  return `gql-${Math.abs(h).toString(36)}`;
}

export function graphqlFindingsFromNetwork(net: NetworkScanPayload): Finding[] {
  const findings: Finding[] = [];
  const url = net.url;
  const safeUrl = sanitizeUrlForDisplay(url);
  const ct = Object.entries(net.responseHeaders)
    .find(([k]) => k.toLowerCase() === "content-type")?.[1]
    ?.toLowerCase() ?? "";

  if (GRAPHQL_PATH.test(url) || url.toLowerCase().includes("graphql?")) {
    findings.push({
      id: stableId(`path-${safeUrl}`),
      category: "GraphQL",
      title: "URL sugere endpoint GraphQL",
      detail:
        "Caminho ou query compatível com GraphQL. Valide introspecção e autorização.",
      severity: "low",
      evidence: safeUrl.slice(0, 200),
    });
  }

  if (ct.includes("application/graphql") || ct.includes("graphql-response+json")) {
    findings.push({
      id: stableId(`ct-${safeUrl}`),
      category: "GraphQL",
      title: "Content-Type compatível com GraphQL",
      detail: "Resposta declarada como GraphQL.",
      severity: "info",
      evidence: sanitizePlainText(ct, 120),
    });
  }

  return findings;
}

export function graphqlDomFindingsFromPage(
  root: Pick<Document, "querySelectorAll">,
  pageUrl: string,
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  root.querySelectorAll("script[src]").forEach((el) => {
    const src = (el as HTMLScriptElement).src?.toLowerCase() ?? "";
    if (src.includes("graphql") && !seen.has("script-src")) {
      seen.add("script-src");
      findings.push({
        id: "gql-script-src",
        category: "GraphQL",
        title: "Script com referência a GraphQL",
        detail: "URL de script menciona GraphQL.",
        severity: "info",
        evidence: sanitizeUrlForDisplay((el as HTMLScriptElement).src).slice(0, 200),
      });
    }
  });

  root.querySelectorAll("script:not([src])").forEach((el) => {
    const text = el.textContent ?? "";
    if (text.length > 500_000) return;
    if (GRAPHQL_PATH.test(text) || APOLLO_URQL.test(text)) {
      if (!seen.has("inline")) {
        seen.add("inline");
        findings.push({
          id: "gql-inline-hint",
          category: "GraphQL",
          title: "Possível cliente GraphQL no bundle",
          detail:
            "Texto de script sugere Apollo/urql ou caminho /graphql. Confirme em rede.",
          severity: "info",
        });
      }
    }
  });

  try {
    const u = new URL(pageUrl);
    if (GRAPHQL_PATH.test(u.pathname)) {
      findings.push({
        id: "gql-page-path",
        category: "GraphQL",
        title: "Página em caminho /graphql",
        detail: "A URL atual pode ser o endpoint ou UI GraphQL.",
        severity: "low",
      });
    }
  } catch {
    /* ignore */
  }

  return findings;
}
