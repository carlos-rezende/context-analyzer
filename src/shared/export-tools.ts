import type { AggregatedFindings } from "./types";

/** HAR 1.2 mínimo a partir de pedidos observados (sem corpo de resposta completo). */
export function buildHarFromAggregated(agg: AggregatedFindings): {
  log: { version: string; creator: { name: string }; entries: unknown[] };
} {
  const reqs = agg.observedRequests ?? [];
  const entries = reqs.map((r) => ({
    startedDateTime: new Date(r.timestamp).toISOString(),
    time: 0,
    request: {
      method: r.method,
      url: r.url,
      httpVersion: "HTTP/1.1",
      headers: [],
      queryString: [],
      cookies: [],
      headersSize: -1,
      bodySize: -1,
    },
    response: {
      status: r.statusCode,
      statusText: "",
      httpVersion: "HTTP/1.1",
      headers: [],
      content: { size: 0, mimeType: "application/octet-stream" },
    },
    cache: {},
    timings: { send: 0, wait: 0, receive: 0 },
  }));

  return {
    log: {
      version: "1.2",
      creator: { name: "Context Analyzer" },
      entries,
    },
  };
}

/** Lista simples para importação em ferramentas (Burp colar / extensões). */
export function buildBurpStyleEndpointsJson(agg: AggregatedFindings): {
  target: string;
  generatedAt: string;
  items: { url: string; method?: string; source: string }[];
} {
  const items: { url: string; method?: string; source: string }[] = [];
  for (const e of agg.endpoints ?? []) {
    items.push({ url: e.url, method: e.methodGuess, source: e.source });
  }
  for (const r of agg.observedRequests ?? []) {
    items.push({ url: r.url, method: r.method, source: "observed" });
  }
  return {
    target: agg.pageUrl,
    generatedAt: new Date(agg.updatedAt).toISOString(),
    items,
  };
}

/** Esqueleto Nuclei para colar e editar (execução é externa ao browser). */
export function buildNucleiYamlSkeleton(host: string, paths: string[]): string {
  const safeHost = host.replace(/[^\w.-]/g, "") || "example.com";
  const pathLines = paths.slice(0, 15).map((p) => `        - "${p.replace(/"/g, '\\"')}"`);
  return `# Gerado por Context Analyzer — ajuste id/matchers e execute: nuclei -t ficheiro.yaml
id: context-analyzer-${safeHost}

info:
  name: Context Analyzer export (${safeHost})
  author: local
  severity: info

requests:
  - method: GET
    path:
${pathLines.length ? pathLines.join("\n") : '        - "/"'}
    matchers:
      - type: status
        status:
          - 200
`;
}

export function pathsFromAggregated(agg: AggregatedFindings): string[] {
  const out: string[] = [];
  for (const e of agg.endpoints ?? []) {
    try {
      const u = new URL(e.url);
      out.push(u.pathname + u.search);
    } catch {
      out.push(e.url.slice(0, 200));
    }
  }
  return [...new Set(out)].slice(0, 40);
}

export function hostFromAggregated(agg: AggregatedFindings): string {
  try {
    return new URL(agg.pageUrl).host;
  } catch {
    return "";
  }
}
