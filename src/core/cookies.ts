import type { Finding } from "../shared/types";
import { sanitizePlainText } from "../shared/sanitize";

export function analyzeSetCookieHeaders(setCookieLines: string[]): Finding[] {
  const findings: Finding[] = [];
  if (setCookieLines.length === 0) return findings;

  for (const line of setCookieLines.slice(0, 30)) {
    const namePart = line.split(";")[0]?.trim() ?? "";
    const cookieName = namePart.split("=")[0]?.trim() ?? "cookie";
    const lower = line.toLowerCase();

    const issues: string[] = [];
    if (!lower.includes("secure")) {
      issues.push("sem Secure");
    }
    if (!lower.includes("httponly")) {
      issues.push("sem HttpOnly");
    }
    if (!lower.includes("samesite")) {
      issues.push("sem SameSite");
    }

    if (issues.length > 0) {
      findings.push({
        id: `cookie-${cookieName}-${issues.join("-")}`.replace(/\s+/g, "-").slice(0, 80),
        category: "Cookies",
        title: `Cookie "${sanitizePlainText(cookieName, 64)}"`,
        detail: `Flags possivelmente insuficientes: ${issues.join(", ")}.`,
        severity: lower.includes("session") || /auth|token|jwt|sid/i.test(cookieName)
          ? "medium"
          : "low",
        evidence: sanitizePlainText(line, 400),
      });
    }
  }

  return findings;
}
