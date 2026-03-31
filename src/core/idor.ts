import type { Finding } from "../shared/types";
import { sanitizePlainText } from "../shared/sanitize";

const NUMERIC_SEGMENT = /\/(\d{1,18})(?:\/|$|\?)/g;
const ID_PARAM = /(?:^|[?&])(?:id|user_id|account_id|uid|order_id)=(\d+)/i;

export function detectIdorHintsFromUrl(pageUrl: string): string[] {
  const hints: string[] = [];
  try {
    const u = new URL(pageUrl);
    let m: RegExpExecArray | null;
    const path = u.pathname;
    while ((m = NUMERIC_SEGMENT.exec(path)) !== null) {
      hints.push(`segmento numérico no path: /.../${m[1]}`);
    }
    const q = u.search;
    const idm = ID_PARAM.exec(q);
    if (idm) {
      hints.push(`parâmetro de identificador numérico na query`);
    }
  } catch {
    /* ignore */
  }
  return hints.slice(0, 20);
}

export function idorFindingsFromHints(hints: string[], pageUrl: string): Finding[] {
  if (hints.length === 0) return [];
  const safe = sanitizePlainText(pageUrl, 512);
  return [
    {
      id: "idor-numeric-refs",
      category: "IDOR / acesso por ID",
      title: "Referências numéricas em URL",
      detail:
        "Foram encontrados segmentos ou parâmetros numéricos que podem indicar objetos endereçáveis por ID. Verifique autorização no servidor.",
      severity: "medium",
      evidence: `${hints.length} indício(s). Ex.: ${hints[0] ?? ""} — ${safe}`,
    },
  ];
}
