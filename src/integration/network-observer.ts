import type { NetworkScanPayload } from "../shared/types";

/** Converte cabeçalhos do webRequest para registo simples (somente leitura). */
export function parseHeaders(
  headers: chrome.webRequest.HttpHeader[] | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) return out;
  for (const h of headers) {
    if (!h.name || h.value === undefined) continue;
    const n = h.name.toLowerCase();
    if (n === "set-cookie") continue;
    out[h.name] = h.value;
  }
  return out;
}

export function collectSetCookieLines(
  headers: chrome.webRequest.HttpHeader[] | undefined,
): string[] {
  const lines: string[] = [];
  if (!headers) return lines;
  for (const h of headers) {
    if (h.name?.toLowerCase() === "set-cookie" && h.value) {
      lines.push(h.value);
    }
  }
  return lines;
}

export function toNetworkPayload(
  details: chrome.webRequest.WebResponseCacheDetails,
): NetworkScanPayload {
  const responseHeaders = parseHeaders(details.responseHeaders);
  return {
    tabId: details.tabId,
    url: details.url,
    statusCode: details.statusCode,
    responseHeaders,
    setCookieHeaders: collectSetCookieLines(details.responseHeaders),
  };
}
