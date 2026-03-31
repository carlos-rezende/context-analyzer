import type { Finding } from "../shared/types";
import { sanitizePlainText } from "../shared/sanitize";
import { CWE, OWASP } from "../shared/weakness";

/** Divide diretivas CSP (sem tratar vírgulas dentro de nonces/hashes de forma perfeita). */
export function parseCspDirectives(
  raw: string,
): Map<string, string[]> {
  const map = new Map<string, string[]>();
  const s = raw.trim();
  if (!s) return map;
  const parts = s.split(";").map((p) => p.trim()).filter(Boolean);
  for (const p of parts) {
    const space = p.indexOf(" ");
    if (space === -1) {
      map.set(p.toLowerCase(), []);
      continue;
    }
    const name = p.slice(0, space).toLowerCase();
    const rest = p.slice(space + 1).trim();
    const values = rest.split(/\s+/).filter(Boolean);
    map.set(name, values);
  }
  return map;
}

export function analyzeCspAdvanced(cspRaw: string): Finding[] {
  const findings: Finding[] = [];
  const csp = sanitizePlainText(cspRaw, 8192);
  const dirs = parseCspDirectives(csp);

  if (!dirs.has("default-src") && !dirs.has("script-src")) {
    findings.push({
      id: "csp-no-default-script",
      category: "CSP",
      title: "Sem default-src nem script-src explícitos",
      detail:
        "Política pode herdar comportamento permissivo. Revise default-src e script-src.",
      severity: "low",
      weaknessRefs: [{ cwe: CWE.XSS, owasp: OWASP.A05_2021 }],
    });
  }

  const scriptSrc = dirs.get("script-src") ?? [];
  const defaultSrc = dirs.get("default-src") ?? [];
  const scriptCombined = scriptSrc.length > 0 ? scriptSrc : defaultSrc;
  if (scriptCombined.some((x) => x === "*" || x === "http:" || x === "https:")) {
    findings.push({
      id: "csp-script-wide",
      category: "CSP",
      title: "script-src/default-src muito permissivo",
      detail:
        "Origens amplas (*) ou esquemas soltos enfraquecem a CSP.",
      severity: "medium",
      evidence: sanitizePlainText(scriptCombined.join(" "), 200),
      weaknessRefs: [{ cwe: CWE.XSS, owasp: OWASP.A03_2021 }],
    });
  }

  if (/\bunsafe-inline\b/i.test(csp)) {
    findings.push({
      id: "csp-unsafe-inline",
      category: "CSP",
      title: "CSP com unsafe-inline",
      detail:
        "Scripts ou estilos inline podem contornar parte da mitigação de XSS.",
      severity: "medium",
      evidence: csp.slice(0, 240),
      weaknessRefs: [{ cwe: CWE.XSS, owasp: OWASP.A03_2021 }],
    });
  }
  if (/\bunsafe-eval\b/i.test(csp)) {
    findings.push({
      id: "csp-unsafe-eval",
      category: "CSP",
      title: "CSP com unsafe-eval",
      detail: "eval() e similares permanecem permitidos.",
      severity: "high",
      evidence: csp.slice(0, 240),
      weaknessRefs: [{ cwe: CWE.XSS, owasp: OWASP.A03_2021 }],
    });
  }

  const objectSrc = dirs.get("object-src");
  if (!objectSrc || objectSrc.length === 0) {
    findings.push({
      id: "csp-object-src-missing",
      category: "CSP",
      title: "object-src não definido",
      detail:
        "Plugins/embeds podem herdar default-src. Considere object-src 'none'.",
      severity: "low",
      weaknessRefs: [{ cwe: CWE.MIME_CONFUSION, owasp: OWASP.A05_2021 }],
    });
  }

  const baseUri = dirs.get("base-uri");
  if (!baseUri || baseUri.length === 0) {
    findings.push({
      id: "csp-base-uri-missing",
      category: "CSP",
      title: "base-uri não definido",
      detail:
        "A base URL de documentos pode ser influenciada por <base>. Avalie base-uri 'self'.",
      severity: "low",
      weaknessRefs: [{ cwe: CWE.CONFIG, owasp: OWASP.A05_2021 }],
    });
  }

  const frameAncestors = dirs.get("frame-ancestors");
  if (frameAncestors?.includes("*")) {
    findings.push({
      id: "csp-frame-ancestors-star",
      category: "CSP",
      title: "frame-ancestors inclui *",
      detail:
        "Qualquer origem pode incorporar a página em iframe (dependendo do restante da política).",
      severity: "medium",
      weaknessRefs: [{ cwe: CWE.CLICKJACK, owasp: OWASP.A05_2021 }],
    });
  }

  if (/\bupgrade-insecure-requests\b/i.test(csp)) {
    findings.push({
      id: "csp-upgrade-insecure",
      category: "CSP",
      title: "upgrade-insecure-requests ativo",
      detail: "Pedidos HTTP são promovidos para HTTPS quando possível.",
      severity: "info",
      weaknessRefs: [
        {
          note:
            "Mitigação positiva (não é vulnerabilidade); reduz risco associado a CWE-319.",
        },
      ],
    });
  }

  return findings;
}
