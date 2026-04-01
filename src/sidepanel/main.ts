import type { AggregatedFindings, ExtensionSettings } from "../shared/types";
import type { ExtensionMessage } from "../shared/messages";
import {
  buildBurpStyleEndpointsJson,
  buildHarFromAggregated,
  buildNucleiYamlSkeleton,
  hostFromAggregated,
  pathsFromAggregated,
} from "../shared/export-tools";
import { buildCurlLine, buildFetchSnippet } from "../shared/replay";
import { sanitizePlainText } from "../shared/sanitize";
import { mergeXssHints } from "../shared/xss-hints";

const findingsEl = document.getElementById("findings")!;
const endpointsEl = document.getElementById("endpoints")!;
const networkEl = document.getElementById("network-requests")!;
const scoreDisplayEl = document.getElementById("score-display")!;
const exportBtn = document.getElementById("export-json")!;
const exportHarBtn = document.getElementById("export-har")!;
const exportBurpBtn = document.getElementById("export-burp")!;
const exportNucleiBtn = document.getElementById("export-nuclei")!;
const aiEnabledEl = document.getElementById("ai-enabled") as HTMLInputElement;
const aiUrlEl = document.getElementById("ai-url") as HTMLInputElement;
const heuristicLevelEl = document.getElementById("heuristic-level") as HTMLSelectElement;
const saveBtn = document.getElementById("save-settings")!;
const aiBtn = document.getElementById("ai-suggest") as HTMLButtonElement;
const aiOut = document.getElementById("ai-out")!;

let lastAgg: AggregatedFindings | null = null;
let settingsCache: ExtensionSettings | null = null;

const COPY_FEEDBACK_MS = 1800;
const COPY_OK_LABEL = "Copiado!";

const copyButtonTimers = new WeakMap<HTMLButtonElement, ReturnType<typeof setTimeout>>();

/** Copia para a área de transferência e dá feedback visual no botão (todos os “Copiar …”). */
function copyWithFeedback(button: HTMLButtonElement, text: string): void {
  const prevText = button.textContent ?? "";
  const hadSecondary = button.classList.contains("secondary");
  const pending = copyButtonTimers.get(button);
  if (pending !== undefined) clearTimeout(pending);

  void navigator.clipboard.writeText(text).then(
    () => {
      button.classList.remove("btn-copy-error");
      button.classList.add("btn-copied");
      button.textContent = COPY_OK_LABEL;
      const tid = setTimeout(() => {
        button.classList.remove("btn-copied");
        button.textContent = prevText;
        if (hadSecondary) button.classList.add("secondary");
        copyButtonTimers.delete(button);
      }, COPY_FEEDBACK_MS);
      copyButtonTimers.set(button, tid);
    },
    () => {
      button.classList.remove("btn-copied");
      button.classList.add("btn-copy-error");
      button.textContent = "Falhou";
      const tid = setTimeout(() => {
        button.classList.remove("btn-copy-error");
        button.textContent = prevText;
        if (hadSecondary) button.classList.add("secondary");
        copyButtonTimers.delete(button);
      }, COPY_FEEDBACK_MS);
      copyButtonTimers.set(button, tid);
    },
  );
}

/** Pré-visualização da URL longa (meio truncado); hover mostra a URL completa. */
function truncateMiddle(s: string, max: number): string {
  if (s.length <= max) return s;
  const inner = max - 3;
  const head = Math.max(8, Math.floor(inner * 0.55));
  const tail = inner - head;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

function isCompact(): boolean {
  return settingsCache?.heuristicDetailLevel === "compact";
}

function maybeTruncate(text: string, max: number): string {
  if (!isCompact()) return text;
  if (text.length <= max) return text;
  return `${text.slice(0, max)}…`;
}

function renderFindings(agg: AggregatedFindings | null): void {
  findingsEl.innerHTML = "";
  endpointsEl.innerHTML = "";
  networkEl.innerHTML = "";

  if (!agg) {
    scoreDisplayEl.textContent = "—";
    findingsEl.innerHTML =
      '<p class="empty">Sem dados do separador ativo.</p>';
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "—";
    endpointsEl.appendChild(li);
    networkEl.innerHTML =
      '<p class="empty">Carregue uma página para ver pedidos de rede.</p>';
    renderXssHints(null);
    return;
  }

  const score = agg.severityScore ?? 0;
  scoreDisplayEl.textContent = `${score}/100`;

  if (!agg.findings || agg.findings.length === 0) {
    findingsEl.innerHTML =
      '<p class="empty">Nenhum achado ainda. Navegue ou interaja com a página; a análise é incremental.</p>';
  } else {
    for (const f of agg.findings) {
      const div = document.createElement("div");
      div.className = `finding severity-${f.severity}`;
      const detail = maybeTruncate(f.detail, 160);
      div.innerHTML = `
        <div class="finding-title">${escapeHtml(f.title)}</div>
        <div class="finding-meta">${escapeHtml(f.category)} · ${escapeHtml(f.severity)}</div>
        <div class="finding-detail">${escapeHtml(detail)}</div>
      `;
      if (f.weaknessRefs?.length) {
        const wr = document.createElement("div");
        wr.className = "finding-weakness";
        wr.textContent = f.weaknessRefs
          .map((r) => [r.cwe, r.owasp, r.note].filter(Boolean).join(" · "))
          .filter(Boolean)
          .join(" | ");
        div.appendChild(wr);
      }
      if (f.evidence) {
        const ev = document.createElement("div");
        ev.className = "finding-detail";
        ev.textContent = maybeTruncate(sanitizePlainText(f.evidence, 2000), 120);
        div.appendChild(ev);
      }
      findingsEl.appendChild(div);
    }
  }

  const eps = agg.endpoints ?? [];
  if (eps.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "Nenhum endpoint listado.";
    endpointsEl.appendChild(li);
  } else {
    for (const e of eps.slice(0, 80)) {
      const li = document.createElement("li");
      const tag =
        e.source === "network" ? " [rede]" : " [DOM]";
      li.textContent = `${sanitizePlainText(e.url, 2048)}${tag}`;
      endpointsEl.appendChild(li);
    }
  }

  const reqs = agg.observedRequests ?? [];
  if (reqs.length === 0) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent =
      "Ainda sem pedidos XHR/fetch registados neste separador (navegue ou interaja com a app).";
    networkEl.appendChild(p);
  } else {
    for (const r of reqs.slice(0, 40)) {
      const row = document.createElement("div");
      row.className = "net-row";
      const meta = document.createElement("div");
      meta.className = "net-meta";
      meta.textContent = `${r.method} ${r.statusCode} · ${r.type}`;
      const urlLine = document.createElement("div");
      urlLine.className = "net-url";
      urlLine.textContent = sanitizePlainText(r.url, 2048);
      const actions = document.createElement("div");
      actions.className = "net-actions";
      const b1 = document.createElement("button");
      b1.type = "button";
      b1.className = "btn tiny";
      b1.textContent = "Copiar fetch";
      b1.addEventListener("click", () => {
        copyWithFeedback(b1, buildFetchSnippet(r));
      });
      const b2 = document.createElement("button");
      b2.type = "button";
      b2.className = "btn tiny secondary";
      b2.textContent = "Copiar cURL";
      b2.addEventListener("click", () => {
        copyWithFeedback(b2, buildCurlLine(r));
      });
      actions.append(b1, b2);
      row.append(meta, urlLine, actions);
      networkEl.appendChild(row);
    }
  }

  updateAiButtonState();
  renderXssHints(agg);
}

function renderXssHints(agg: AggregatedFindings | null): void {
  const ul = document.getElementById("xss-hints");
  if (!ul) return;
  ul.innerHTML = "";
  const pageUrl = agg?.pageUrl ?? "";
  const dom = agg?.dom;
  const items = mergeXssHints(pageUrl, dom);
  for (const item of items) {
    const li = document.createElement("li");
    const ctx = document.createElement("div");
    ctx.className = "xss-context";
    ctx.textContent = item.context;
    const code = document.createElement("code");
    code.textContent = item.payload;
    li.appendChild(ctx);
    li.appendChild(code);
    if (item.copyUrl) {
      const preview = document.createElement("div");
      preview.className = "xss-url-preview";
      preview.textContent = truncateMiddle(item.copyUrl, 220);
      preview.title = item.copyUrl;
      li.appendChild(preview);
    }
    const actions = document.createElement("div");
    actions.className = "xss-actions";
    const bPayload = document.createElement("button");
    bPayload.type = "button";
    bPayload.className = "btn tiny secondary";
    bPayload.textContent = "Copiar payload";
    bPayload.addEventListener("click", () => {
      copyWithFeedback(bPayload, item.payload);
    });
    actions.appendChild(bPayload);
    if (item.copyUrl) {
      const bUrl = document.createElement("button");
      bUrl.type = "button";
      bUrl.className = "btn tiny";
      bUrl.textContent = "Copiar URL de teste";
      bUrl.title =
        "URL completa com o payload neste parâmetro (não envia pedido; cole na barra de endereço).";
      bUrl.addEventListener("click", () => {
        copyWithFeedback(bUrl, item.copyUrl!);
      });
      actions.appendChild(bUrl);
    }
    li.appendChild(actions);
    ul.appendChild(li);
  }
}

function escapeHtml(s: string): string {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function updateAiButtonState(): void {
  const enabled = aiEnabledEl.checked && aiUrlEl.value.trim().length > 0;
  aiBtn.disabled = !enabled;
}

async function refreshFindings(): Promise<void> {
  const res = (await chrome.runtime.sendMessage({
    type: "SIDEPANEL_GET_FINDINGS",
  } satisfies ExtensionMessage)) as ExtensionMessage | undefined;
  if (res && res.type === "SIDEPANEL_FINDINGS") {
    lastAgg = res.payload;
    renderFindings(res.payload);
  }
}

async function loadSettingsUi(): Promise<void> {
  const res = (await chrome.runtime.sendMessage({
    type: "SIDEPANEL_GET_SETTINGS",
  } satisfies ExtensionMessage)) as ExtensionMessage | undefined;
  if (res && res.type === "SIDEPANEL_SETTINGS") {
    applySettings(res.payload);
  }
}

function applySettings(s: ExtensionSettings): void {
  settingsCache = s;
  aiEnabledEl.checked = s.aiEnabled;
  aiUrlEl.value = s.aiEndpointUrl;
  heuristicLevelEl.value = s.heuristicDetailLevel;
  updateAiButtonState();
}

saveBtn.addEventListener("click", async () => {
  const res = (await chrome.runtime.sendMessage({
    type: "SIDEPANEL_SET_SETTINGS",
    payload: {
      aiEnabled: aiEnabledEl.checked,
      aiEndpointUrl: aiUrlEl.value.trim(),
      heuristicDetailLevel:
        heuristicLevelEl.value === "compact" ? "compact" : "normal",
    },
  } satisfies ExtensionMessage)) as ExtensionMessage | undefined;
  if (res && res.type === "SIDEPANEL_SETTINGS") {
    applySettings(res.payload);
    void refreshFindings();
  }
});

heuristicLevelEl.addEventListener("change", async () => {
  const res = (await chrome.runtime.sendMessage({
    type: "SIDEPANEL_SET_SETTINGS",
    payload: {
      heuristicDetailLevel:
        heuristicLevelEl.value === "compact" ? "compact" : "normal",
    },
  } satisfies ExtensionMessage)) as ExtensionMessage | undefined;
  if (res && res.type === "SIDEPANEL_SETTINGS") {
    applySettings(res.payload);
    renderFindings(lastAgg);
  }
});

aiEnabledEl.addEventListener("change", updateAiButtonState);
aiUrlEl.addEventListener("input", updateAiButtonState);

aiBtn.addEventListener("click", async () => {
  aiOut.textContent = "A pedir…";
  const res = (await chrome.runtime.sendMessage({
    type: "SIDEPANEL_REQUEST_AI_SUGGESTION",
  } satisfies ExtensionMessage)) as ExtensionMessage | undefined;
  if (res && res.type === "SIDEPANEL_AI_SUGGESTION_RESULT") {
    if (res.payload.error) {
      aiOut.textContent = `Erro: ${res.payload.error}`;
    } else {
      aiOut.textContent = res.payload.text || "(resposta vazia)";
    }
  } else {
    aiOut.textContent = "Resposta inesperada.";
  }
});

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

exportBtn.addEventListener("click", () => {
  if (!lastAgg) {
    return;
  }
  const blob = new Blob([JSON.stringify(lastAgg, null, 2)], {
    type: "application/json",
  });
  downloadBlob(blob, `context-analyzer-findings-${lastAgg.tabId}-${Date.now()}.json`);
});

exportHarBtn.addEventListener("click", () => {
  if (!lastAgg) return;
  const har = buildHarFromAggregated(lastAgg);
  const blob = new Blob([JSON.stringify(har, null, 2)], {
    type: "application/json",
  });
  downloadBlob(blob, `context-analyzer-${lastAgg.tabId}-${Date.now()}.har`);
});

exportBurpBtn.addEventListener("click", () => {
  if (!lastAgg) return;
  const data = buildBurpStyleEndpointsJson(lastAgg);
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  downloadBlob(blob, `context-analyzer-burp-${lastAgg.tabId}-${Date.now()}.json`);
});

exportNucleiBtn.addEventListener("click", () => {
  if (!lastAgg) return;
  const host = hostFromAggregated(lastAgg);
  const paths = pathsFromAggregated(lastAgg);
  const yaml = buildNucleiYamlSkeleton(host, paths);
  const blob = new Blob([yaml], { type: "text/yaml;charset=utf-8" });
  downloadBlob(blob, `context-analyzer-nuclei-${lastAgg.tabId}-${Date.now()}.yaml`);
});

chrome.runtime.onMessage.addListener((msg: unknown) => {
  if (
    msg &&
    typeof msg === "object" &&
    (msg as ExtensionMessage).type === "SIDEPANEL_FINDINGS"
  ) {
    const m = msg as Extract<ExtensionMessage, { type: "SIDEPANEL_FINDINGS" }>;
    lastAgg = m.payload;
    renderFindings(m.payload);
  }
});

renderXssHints(null);
void loadSettingsUi();
void refreshFindings();
