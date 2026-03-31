import type { AggregatedFindings, ExtensionSettings } from "../shared/types";
import type { ExtensionMessage } from "../shared/messages";
import { buildCurlLine, buildFetchSnippet } from "../shared/replay";
import { sanitizePlainText } from "../shared/sanitize";

const findingsEl = document.getElementById("findings")!;
const endpointsEl = document.getElementById("endpoints")!;
const networkEl = document.getElementById("network-requests")!;
const scoreDisplayEl = document.getElementById("score-display")!;
const exportBtn = document.getElementById("export-json")!;
const aiEnabledEl = document.getElementById("ai-enabled") as HTMLInputElement;
const aiUrlEl = document.getElementById("ai-url") as HTMLInputElement;
const heuristicLevelEl = document.getElementById("heuristic-level") as HTMLSelectElement;
const saveBtn = document.getElementById("save-settings")!;
const aiBtn = document.getElementById("ai-suggest") as HTMLButtonElement;
const aiOut = document.getElementById("ai-out")!;

let lastAgg: AggregatedFindings | null = null;
let settingsCache: ExtensionSettings | null = null;

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
        void navigator.clipboard.writeText(buildFetchSnippet(r));
      });
      const b2 = document.createElement("button");
      b2.type = "button";
      b2.className = "btn tiny secondary";
      b2.textContent = "Copiar cURL";
      b2.addEventListener("click", () => {
        void navigator.clipboard.writeText(buildCurlLine(r));
      });
      actions.append(b1, b2);
      row.append(meta, urlLine, actions);
      networkEl.appendChild(row);
    }
  }

  updateAiButtonState();
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

exportBtn.addEventListener("click", () => {
  if (!lastAgg) {
    return;
  }
  const blob = new Blob([JSON.stringify(lastAgg, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `context-analyzer-findings-${lastAgg.tabId}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
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

void loadSettingsUi();
void refreshFindings();
