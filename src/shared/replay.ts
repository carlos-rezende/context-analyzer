import type { ObservedRequest } from "./types";

/** Snippet para colar na consola da página ou noutro contexto (pedido manual). */
export function buildFetchSnippet(req: ObservedRequest): string {
  const m = (req.method || "GET").toUpperCase();
  const u = req.url;
  if (m === "GET" || m === "HEAD") {
    return [
      `fetch(${JSON.stringify(u)}, {`,
      `  method: ${JSON.stringify(m)},`,
      `  credentials: "omit",`,
      `  mode: "cors",`,
      `}).then((r) => r.text()).then(console.log).catch(console.error);`,
    ].join("\n");
  }
  return [
    `fetch(${JSON.stringify(u)}, {`,
    `  method: ${JSON.stringify(m)},`,
    `  credentials: "omit",`,
    `  mode: "cors",`,
    `  headers: { "Content-Type": "application/json" },`,
    `  body: JSON.stringify({ /* corpo não observado pela extensão */ }),`,
    `}).then((r) => r.text()).then(console.log).catch(console.error);`,
  ].join("\n");
}

export function buildCurlLine(req: ObservedRequest): string {
  const m = (req.method || "GET").toUpperCase();
  const u = req.url.replace(/'/g, "'\\''");
  if (m === "GET") {
    return `curl -sS --compressed '${u}'`;
  }
  return `curl -sS -X ${m} --compressed '${u}'`;
}
