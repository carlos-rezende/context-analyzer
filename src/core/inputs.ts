import type { Finding } from "../shared/types";
import { sanitizePlainText } from "../shared/sanitize";

const SUSPICIOUS_NAMES =
  /(password|passwd|token|secret|api[_-]?key|auth|bearer|csrf)/i;

export function analyzeInputsFromForms(root: Document): {
  numericParameters: { name: string; sample?: string }[];
  suspiciousInputs: { name: string; type: string; reason: string }[];
  findings: Finding[];
} {
  const numericParameters: { name: string; sample?: string }[] = [];
  const suspiciousInputs: { name: string; type: string; reason: string }[] = [];
  const findings: Finding[] = [];

  const inputs = root.querySelectorAll<
    HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement
  >("input, textarea, select");

  inputs.forEach((el) => {
    const name = el.getAttribute("name") ?? el.getAttribute("id") ?? "";
    const type =
      el.tagName === "INPUT"
        ? ((el as HTMLInputElement).type || "text")
        : el.tagName.toLowerCase();
    const safeName = sanitizePlainText(name, 128);

    if (!safeName) return;

    if (/^id$|_id$|user|account|order|invoice|doc|num/i.test(safeName)) {
      numericParameters.push({ name: safeName });
    }

    if (SUSPICIOUS_NAMES.test(safeName)) {
      suspiciousInputs.push({
        name: safeName,
        type,
        reason: "nome sugere dado sensível ou token — rever exposição e CSRF",
      });
    }
  });

  if (suspiciousInputs.length > 0) {
    findings.push({
      id: "input-sensitive-names",
      category: "Inputs",
      title: "Campos com nomes sensíveis",
      detail:
        "Existem campos cujos nomes sugerem segredos ou autenticação. Valide transporte, armazenamento e proteção CSRF.",
      severity: "low",
      evidence: `${suspiciousInputs.length} campo(s)`,
    });
  }

  return { numericParameters, suspiciousInputs, findings };
}
