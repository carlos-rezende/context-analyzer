/**
 * Sugestões de payloads para teste manual de XSS (nunca executadas pela extensão).
 * Combina exemplos genéricos com pistas derivadas do URL e do DOM observado.
 * Nível semi-automático: URLs completas com payload na query (só copiar; não envia pedidos).
 */
import type { DomScanPayload } from "./types";
import { sanitizePlainText } from "./sanitize";

/** Payloads de referência; sempre incluídos após os contextuais. */
export const XSS_MANUAL_HINTS: readonly string[] = [
  String.raw`<script>alert(document.domain)</script>`,
  String.raw`"><img src=x onerror=alert(1)>`,
  String.raw`'-alert(1)-'`,
  String.raw`javascript:alert(1)`,
  String.raw`<svg onload=alert(1)>`,
];

export interface XssHintItem {
  /** Onde aplicar / porquê (ex.: parâmetro de query, nome de campo). */
  context: string;
  payload: string;
  /**
   * URL de teste com este payload no parâmetro indicado (codificado na query).
   * A extensão não faz fetch; o utilizador cola na barra de endereço ou noutra ferramenta.
   */
  copyUrl?: string;
}

type PayloadKind = "html-attr" | "js-string" | "minimal";

const MAX_URL_CHARS = 8192;

function payloadForKind(kind: PayloadKind): string {
  switch (kind) {
    case "html-attr":
      return String.raw`"><img src=x onerror=alert(1)>`;
    case "js-string":
      return String.raw`'-alert(1)-'`;
    default:
      return String.raw`<svg onload=alert(1)>`;
  }
}

/** Heurística simples pelo nome do parâmetro/campo. */
function classifyName(name: string): PayloadKind {
  const n = name.toLowerCase();
  if (
    /^(q|query|search|keyword|s|term|text)$/i.test(n) ||
    /search|query|keyword/.test(n)
  ) {
    return "html-attr";
  }
  if (
    /^(callback|jsonp|cb|token|next|redirect|return|url|goto|dest)$/i.test(n) ||
    /redirect|callback|return/.test(n)
  ) {
    return "js-string";
  }
  return "minimal";
}

/**
 * Monta URL com `paramName=payload` na query (preserva resto da página; substitui valor desse parâmetro).
 * `URLSearchParams` codifica o payload de forma segura para uso na barra de endereço.
 */
export function buildTestUrlWithParam(
  pageUrl: string,
  paramName: string,
  payload: string,
): string | null {
  try {
    const u = new URL(pageUrl);
    u.searchParams.set(paramName, payload);
    const s = u.toString();
    if (s.length > MAX_URL_CHARS) return null;
    return s;
  } catch {
    return null;
  }
}

function optionalCopyUrl(
  pageUrl: string,
  paramName: string,
  payload: string,
): string | undefined {
  const u = buildTestUrlWithParam(pageUrl, paramName, payload);
  return u ?? undefined;
}

const MAX_QUERY_PARAMS = 12;
const MAX_SUSPICIOUS = 15;
const MAX_NUMERIC_FIELDS = 10;
const MAX_CONTEXTUAL = 28;

/**
 * Gera pistas a partir da página atual: parâmetros na query, campos de formulário
 * e nomes de campos “identificadores” já recolhidos pelo scan DOM.
 */
export function buildContextualXssHints(
  pageUrl: string,
  dom?: DomScanPayload | null,
): XssHintItem[] {
  const out: XssHintItem[] = [];
  const dedupe = new Set<string>();
  const baseUrl = sanitizePlainText(pageUrl, 2048);

  function push(
    context: string,
    payload: string,
    paramForUrl?: string,
  ): void {
    if (out.length >= MAX_CONTEXTUAL) return;
    const k = `${context}\n${payload}`;
    if (dedupe.has(k)) return;
    dedupe.add(k);
    let copyUrl: string | undefined;
    if (paramForUrl && baseUrl.length > 0) {
      copyUrl = optionalCopyUrl(baseUrl, paramForUrl, payload);
    }
    out.push(
      copyUrl ? { context, payload, copyUrl } : { context, payload },
    );
  }

  try {
    const u = new URL(baseUrl);
    const keys = [...u.searchParams.keys()];
    for (const key of keys.slice(0, MAX_QUERY_PARAMS)) {
      const safeKey = sanitizePlainText(key, 128);
      if (!safeKey) continue;
      const kind = classifyName(safeKey);
      const payload = payloadForKind(kind);
      push(`URL · ?${safeKey}=`, payload, safeKey);
    }
  } catch {
    /* URL inválida: só segue com DOM */
  }

  if (dom?.suspiciousInputs?.length) {
    for (const inp of dom.suspiciousInputs.slice(0, MAX_SUSPICIOUS)) {
      const name = sanitizePlainText(inp.name, 128);
      if (!name) continue;
      const kind =
        /^(?:textarea|text|search|email|url)$/i.test(inp.type) ||
        /message|comment|body|html|content/i.test(name)
          ? "html-attr"
          : classifyName(name);
      const payload = payloadForKind(kind);
      push(`Form · ${name} (${inp.type})`, payload, name);
    }
  }

  if (dom?.numericParameters?.length) {
    for (const p of dom.numericParameters.slice(0, MAX_NUMERIC_FIELDS)) {
      const name = sanitizePlainText(p.name, 128);
      if (!name) continue;
      const payload = payloadForKind("minimal");
      push(`Campo (ID) · ${name}`, payload, name);
    }
  }

  return out;
}

/** Contextuais primeiro; depois genéricos, sem duplicar o mesmo par context+payload. */
export function mergeXssHints(
  pageUrl: string,
  dom?: DomScanPayload | null,
): XssHintItem[] {
  const contextual = buildContextualXssHints(pageUrl, dom);
  const generic: XssHintItem[] = XSS_MANUAL_HINTS.map((payload) => ({
    context: "Genérico (referência)",
    payload,
  }));
  const seen = new Set<string>();
  const merged: XssHintItem[] = [];
  for (const item of [...contextual, ...generic]) {
    const k = `${item.context}|${item.payload}`;
    if (seen.has(k)) continue;
    seen.add(k);
    merged.push(item);
  }
  return merged;
}
