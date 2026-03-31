import type { Finding } from "../shared/types";
import { sanitizePlainText } from "../shared/sanitize";
import { CWE, OWASP } from "../shared/weakness";

/** Heurística: três segmentos base64url, tamanhos mínimos (sem validar assinatura). */
export function looksLikeJwt(value: string): boolean {
  if (!value || value.length < 40) return false;
  const parts = value.split(".");
  if (parts.length !== 3) return false;
  const [a, b, c] = parts;
  if (a.length < 20 || b.length < 10 || c.length < 10) return false;
  const token = /^[A-Za-z0-9_-]+$/;
  return token.test(a) && token.test(b) && token.test(c);
}

function keyId(key: string): string {
  let h = 0;
  for (let i = 0; i < key.length; i++) {
    h = (h * 31 + key.charCodeAt(i)) | 0;
  }
  return `jwt-${Math.abs(h).toString(36)}`;
}

/** Apenas metadados (nome da chave, comprimento); nunca envia o token completo. */
export function jwtFindingsFromStorage(
  local: Storage,
  session: Storage,
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  const scan = (storage: Storage, kind: "localStorage" | "sessionStorage") => {
    try {
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        if (!key) continue;
        let val: string | null;
        try {
          val = storage.getItem(key);
        } catch {
          continue;
        }
        if (!val || !looksLikeJwt(val)) continue;
        const safeKey = sanitizePlainText(key, 128);
        const id = `${kind}-${keyId(safeKey)}`;
        if (seen.has(id)) continue;
        seen.add(id);
        findings.push({
          id,
          category: "JWT",
          title: `Valor JWT-like em ${kind}`,
          detail:
            "Foi detetado padrão JWT (3 segmentos). Verifique se não é exposto a XSS ou extensões.",
          severity: "medium",
          evidence: `chave: ${safeKey}, comprimento: ${val.length}`,
          weaknessRefs: [{ cwe: CWE.JWT_EXPOSURE, owasp: OWASP.A02_2021 }],
        });
      }
    } catch {
      /* storage inacessível */
    }
  };

  scan(local, "localStorage");
  scan(session, "sessionStorage");
  return findings;
}
