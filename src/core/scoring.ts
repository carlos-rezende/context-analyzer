import type { Finding, Severity } from "../shared/types";

const WEIGHT: Record<Severity, number> = {
  info: 1,
  low: 3,
  medium: 6,
  high: 10,
};

/** Pontuação 0–100: maior = mais risco / mais atenção (heurístico). */
export function computeSeverityScore(findings: Finding[]): number {
  if (findings.length === 0) return 0;
  let raw = 0;
  for (const f of findings) {
    raw += WEIGHT[f.severity] ?? 0;
  }
  const cap = findings.length * 10;
  const normalized = cap > 0 ? Math.round((raw / cap) * 100) : 0;
  return Math.min(100, Math.max(0, normalized));
}
