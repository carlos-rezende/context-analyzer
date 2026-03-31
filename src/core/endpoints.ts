import type { EndpointRef } from "../shared/types";
import { sanitizeUrlForDisplay } from "../shared/sanitize";

const URL_IN_TEXT =
  /https?:\/\/[^\s"'<>()[\]{}]+/gi;
/** Clientes HTTP comuns em bundles (sem nomear pacotes específicos). */
const FETCH_LIKE =
  /(?:fetch|XMLHttpRequest|\w+\.(?:get|post|put|delete|patch))\s*\(\s*['"]([^'"]+)['"]/gi;
/** import('...') / import("...") em bundles ESM. */
const DYNAMIC_IMPORT =
  /import\s*\(\s*['"]([^'"]+)['"]\s*\)/gi;
/** import(`...`) — caminhos relativos ou URL. */
const DYNAMIC_IMPORT_BT =
  /import\s*\(\s*`([^`]+)`\s*\)/gi;

function pushUnique(out: EndpointRef[], url: string, source: EndpointRef["source"]) {
  const u = sanitizeUrlForDisplay(url);
  if (!u || u.startsWith("javascript:")) return;
  if (out.some((e) => e.url === u)) return;
  out.push({ url: u, source });
}

export function extractEndpointsFromPage(
  root: Pick<Document, "querySelectorAll">,
  pageUrl: string,
): EndpointRef[] {
  const out: EndpointRef[] = [];

  root.querySelectorAll("a[href]").forEach((a) => {
    const href = (a as HTMLAnchorElement).href;
    if (href) pushUnique(out, href, "dom");
  });

  root.querySelectorAll("[src]").forEach((el) => {
    const src = (el as HTMLImageElement).src;
    if (src) pushUnique(out, src, "dom");
  });

  root.querySelectorAll("form[action]").forEach((f) => {
    const action = (f as HTMLFormElement).action;
    if (action) pushUnique(out, action, "dom");
  });

  root.querySelectorAll("script").forEach((s) => {
    const text = s.textContent ?? "";
    let m: RegExpExecArray | null;
    FETCH_LIKE.lastIndex = 0;
    while ((m = FETCH_LIKE.exec(text)) !== null) {
      const raw = m[1];
      try {
        const abs = new URL(raw, pageUrl).href;
        pushUnique(out, abs, "dom");
      } catch {
        pushUnique(out, raw, "dom");
      }
    }
    URL_IN_TEXT.lastIndex = 0;
    while ((m = URL_IN_TEXT.exec(text)) !== null) {
      try {
        const abs = new URL(m[0], pageUrl).href;
        pushUnique(out, abs, "dom");
      } catch {
        /* skip */
      }
    }
    DYNAMIC_IMPORT.lastIndex = 0;
    while ((m = DYNAMIC_IMPORT.exec(text)) !== null) {
      const raw = m[1];
      try {
        const abs = new URL(raw, pageUrl).href;
        pushUnique(out, abs, "dom");
      } catch {
        pushUnique(out, raw, "dom");
      }
    }
    DYNAMIC_IMPORT_BT.lastIndex = 0;
    while ((m = DYNAMIC_IMPORT_BT.exec(text)) !== null) {
      const raw = m[1].trim();
      if (!raw || raw.includes("${")) continue;
      try {
        const abs = new URL(raw, pageUrl).href;
        pushUnique(out, abs, "dom");
      } catch {
        pushUnique(out, raw, "dom");
      }
    }
  });

  return out.slice(0, 200);
}
