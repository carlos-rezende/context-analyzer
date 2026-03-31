import type { Finding } from "../shared/types";
import { sanitizePlainText } from "../shared/sanitize";
import { analyzeCspAdvanced } from "./csp-advanced";

function lowerKeys(h: Record<string, string>): Record<string, string> {
  const o: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    o[k.toLowerCase()] = v;
  }
  return o;
}

export function analyzeSecurityHeaders(
  headers: Record<string, string>,
): Finding[] {
  const h = lowerKeys(headers);
  const findings: Finding[] = [];

  if (!h["content-security-policy"] && !h["content-security-policy-report-only"]) {
    findings.push({
      id: "hdr-csp-missing",
      category: "CSP",
      title: "CSP ausente",
      detail:
        "Não foi observado cabeçalho Content-Security-Policy na resposta analisada. Considere política restritiva para reduzir XSS.",
      severity: "medium",
    });
  }

  if (!h["x-frame-options"] && !h["content-security-policy"]) {
    findings.push({
      id: "hdr-xfo-missing",
      category: "Clickjacking",
      title: "X-Frame-Options / frame-ancestors não evidentes",
      detail:
        "Sem X-Frame-Options nem CSP com frame-ancestors, o framing pode ser mais permissivo (dependendo do restante da política).",
      severity: "low",
    });
  }

  if (!h["strict-transport-security"]) {
    findings.push({
      id: "hdr-hsts-missing",
      category: "Transporte",
      title: "HSTS ausente",
      detail:
        "Strict-Transport-Security não observado nesta resposta. Avalie HSTS em HTTPS.",
      severity: "low",
    });
  }

  if (!h["x-content-type-options"]) {
    findings.push({
      id: "hdr-nosniff-missing",
      category: "Headers",
      title: "X-Content-Type-Options ausente",
      detail: "MIME sniffing pode ser mais permissivo sem nosniff.",
      severity: "low",
    });
  }

  if (!h["referrer-policy"]) {
    findings.push({
      id: "hdr-referrer-missing",
      category: "Privacidade",
      title: "Referrer-Policy ausente",
      detail: "Defina uma política explícita de referrer conforme necessidade.",
      severity: "info",
    });
  }

  if (h["content-security-policy"]) {
    const raw = h["content-security-policy"];
    const csp = sanitizePlainText(raw, 8192);
    for (const f of analyzeCspAdvanced(csp)) {
      findings.push(f);
    }
  }

  return findings;
}
