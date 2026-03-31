import {
  analyzeInputsFromForms,
  detectIdorHintsFromUrl,
  extractEndpointsFromPage,
  graphqlDomFindingsFromPage,
  jwtFindingsFromStorage,
} from "../core/index";
import type { DomScanPayload, Finding } from "../shared/types";
import type { ExtensionMessage } from "../shared/messages";
import { sanitizePlainText, sanitizeUrlForDisplay } from "../shared/sanitize";

const DEBOUNCE_MS = 400;

function scheduleScan(): void {
  const run = () => void runScan();
  const ric = (
    globalThis as unknown as { requestIdleCallback?: typeof requestIdleCallback }
  ).requestIdleCallback;
  if (typeof ric === "function") {
    ric(run, { timeout: 1200 });
  } else {
    setTimeout(run, 0);
  }
}

let debounceTimer: ReturnType<typeof setTimeout> | undefined;

function debouncedScan(): void {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    debounceTimer = undefined;
    scheduleScan();
  }, DEBOUNCE_MS);
}

function collectNumericParams(
  root: Document,
): { name: string; sample?: string }[] {
  const out: { name: string; sample?: string }[] = [];
  root.querySelectorAll("input[name], select[name]").forEach((el) => {
    const name = el.getAttribute("name");
    if (!name) return;
    const safe = sanitizePlainText(name, 128);
    if (/id|num|order|user|account|doc/i.test(safe)) {
      const val =
        "value" in el && typeof (el as HTMLInputElement).value === "string"
          ? sanitizePlainText((el as HTMLInputElement).value, 32)
          : undefined;
      out.push({ name: safe, sample: val });
    }
  });
  return out.slice(0, 50);
}

function extraDomFindings(
  pageUrl: string,
  numericParams: { name: string }[],
): Finding[] {
  const findings: Finding[] = [];
  if (numericParams.length > 0) {
    findings.push({
      id: "heuristic-numeric-params",
      category: "Parâmetros",
      title: "Parâmetros com nomes sugestivos de ID",
      detail:
        "Foram listados campos cujo nome sugere identificadores. Teste controlo de acesso e previsibilidade.",
      severity: "low",
      evidence: `${numericParams.length} campo(s)`,
    });
  }
  try {
    const u = new URL(pageUrl);
    if (u.searchParams.toString().length > 0) {
      findings.push({
        id: "heuristic-query-present",
        category: "Superfície",
        title: "Query string presente",
        detail:
          "Parâmetros na URL podem ser candidatos a manipulação (ex.: IDOR). Analise autorização.",
        severity: "info",
      });
    }
  } catch {
    /* ignore */
  }
  return findings;
}

async function runScan(): Promise<void> {
  const pageUrl = sanitizeUrlForDisplay(location.href);
  const endpoints = extractEndpointsFromPage(document, pageUrl);
  const inputAnalysis = analyzeInputsFromForms(document);
  const numericParameters = [
    ...collectNumericParams(document),
    ...inputAnalysis.numericParameters,
  ];
  const seen = new Set<string>();
  const mergedNumeric = numericParameters.filter((p) => {
    if (seen.has(p.name)) return false;
    seen.add(p.name);
    return true;
  });

  const idorHints = detectIdorHintsFromUrl(pageUrl);
  const domFindings: Finding[] = [
    ...inputAnalysis.findings,
    ...extraDomFindings(pageUrl, mergedNumeric),
    ...graphqlDomFindingsFromPage(document, pageUrl),
    ...jwtFindingsFromStorage(localStorage, sessionStorage),
  ];

  const payload: DomScanPayload = {
    pageUrl,
    collectedAt: Date.now(),
    endpoints,
    numericParameters: mergedNumeric.slice(0, 80),
    suspiciousInputs: inputAnalysis.suspiciousInputs.slice(0, 40),
    idorHints,
    domFindings,
  };

  const msg: ExtensionMessage = {
    type: "CONTENT_DOM_SCAN",
    payload,
  };

  try {
    await chrome.runtime.sendMessage(msg);
  } catch {
    /* extensão recarregada ou indisponível */
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", debouncedScan, { once: true });
} else {
  debouncedScan();
}

const mo = new MutationObserver(() => debouncedScan());
mo.observe(document.documentElement, {
  childList: true,
  subtree: true,
  attributes: true,
  attributeFilter: ["href", "src", "action"],
});

window.addEventListener("popstate", debouncedScan);
window.addEventListener("hashchange", debouncedScan);
