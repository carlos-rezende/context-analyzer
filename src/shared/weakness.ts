/**
 * Referências a taxonomias públicas (CWE, OWASP Top 10).
 * CVE aplica-se a produtos/versões concretos — aqui usamos sobretudo CWE como classe de fraqueza.
 */
export interface WeaknessRef {
  cwe?: string;
  owasp?: string;
  /** Nota curta quando não há CVE específico (heurística genérica). */
  note?: string;
}

/** Atalhos comuns para reutilizar nos achados. */
export const OWASP = {
  A01_2021: "A01:2021 — Broken Access Control",
  A02_2021: "A02:2021 — Cryptographic Failures",
  A03_2021: "A03:2021 — Injection",
  A04_2021: "A04:2021 — Insecure Design",
  A05_2021: "A05:2021 — Security Misconfiguration",
  A07_2021: "A07:2021 — Identification and Authentication Failures",
} as const;

export const CWE = {
  XSS: "CWE-79 — Cross-site Scripting",
  CLICKJACK: "CWE-1021 — Improper Restriction of Rendered UI Layers",
  MITM_DOWNGRADE: "CWE-319 — Cleartext Transmission",
  MIME_CONFUSION: "CWE-693 — Protection Mechanism Failure",
  INFO_LEAK: "CWE-200 — Exposure of Sensitive Information",
  SESSION_FIXATION: "CWE-384 — Session Fixation",
  COOKIE_INSECURE: "CWE-614 — Sensitive Cookie Without Secure",
  COOKIE_HTTPONLY: "CWE-1004 — Sensitive Cookie Without HttpOnly",
  IDOR: "CWE-639 — Authorization Bypass Through User-Controlled Key",
  CONFIG: "CWE-16 — Configuration",
  GRAPHQL: "CWE-200 / CWE-284 — Improper Access Control (API)",
  JWT_EXPOSURE: "CWE-522 — Insufficiently Protected Credentials",
} as const;
