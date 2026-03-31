import { requestAiSuggestion } from "../ai/client";
import { buildAiPayloadFromAggregated } from "../ai/context";
import {
  buildAggregatedFromDom,
  computeSeverityScore,
  mergeNetworkIntoFindings,
} from "../core/index";
import { loadSettings, saveSettings } from "../data/settings";
import { toNetworkPayload } from "../integration/network-observer";
import {
  isExtensionMessage,
  isTrustedSender,
  type ExtensionMessage,
} from "../shared/messages";
import type { AggregatedFindings, EndpointRef, ObservedRequest } from "../shared/types";

const SESSION_PREFIX = "ca_findings_";

/** Últimos pedidos XHR/fetch por separador (não persistido em storage). */
const requestBuffers = new Map<number, ObservedRequest[]>();
const MAX_OBSERVED = 80;

function sessionKey(tabId: number): string {
  return `${SESSION_PREFIX}${tabId}`;
}

async function readAggregated(tabId: number): Promise<AggregatedFindings | null> {
  const k = sessionKey(tabId);
  const raw = await chrome.storage.session.get(k);
  const v = raw[k] as AggregatedFindings | undefined;
  return v ?? null;
}

async function writeAggregated(data: AggregatedFindings): Promise<void> {
  const k = sessionKey(data.tabId);
  await chrome.storage.session.set({ [k]: data });
}

function dedupeFindings(list: AggregatedFindings["findings"]) {
  const m = new Map<string, (typeof list)[number]>();
  for (const f of list) {
    m.set(f.id, f);
  }
  return [...m.values()];
}

const NETWORK_FINDING_CATEGORIES = new Set([
  "CSP",
  "Clickjacking",
  "Transporte",
  "Headers",
  "Privacidade",
  "Cookies",
  "GraphQL",
]);

function newRequestId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }
}

function appendObserved(details: chrome.webRequest.WebResponseCacheDetails): void {
  const tabId = details.tabId;
  const list = requestBuffers.get(tabId) ?? [];
  const entry: ObservedRequest = {
    id: newRequestId(),
    url: details.url,
    method: details.method ?? "GET",
    type: details.type,
    statusCode: details.statusCode,
    timestamp: Date.now(),
  };
  list.unshift(entry);
  requestBuffers.set(tabId, list.slice(0, MAX_OBSERVED));
}

function dedupeEndpoints<T extends { url: string }>(list: T[]): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const e of list) {
    if (seen.has(e.url)) continue;
    seen.add(e.url);
    out.push(e);
  }
  return out;
}

function enrichForUi(agg: AggregatedFindings): AggregatedFindings {
  const buf = requestBuffers.get(agg.tabId) ?? [];
  const netEndpoints: EndpointRef[] = buf.map((r) => ({
    url: r.url,
    source: "network",
    methodGuess: r.method,
  }));
  const endpoints = dedupeEndpoints([...agg.endpoints, ...netEndpoints]);
  return {
    ...agg,
    endpoints,
    severityScore: computeSeverityScore(agg.findings),
    observedRequests: buf,
  };
}

async function updateBadge(tabId: number, agg: AggregatedFindings): Promise<void> {
  const n = agg.findings.length;
  const text = n === 0 ? "" : String(Math.min(n, 99));
  try {
    await chrome.action.setBadgeText({ tabId, text });
    if (text) {
      await chrome.action.setBadgeBackgroundColor({
        tabId,
        color: "#238636",
      });
    }
  } catch {
    /* aba inválida */
  }
}

chrome.runtime.onInstalled.addListener(() => {
  void chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
});

if (chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(() => {
    void chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
  });
}

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId < 0) return;

    if (details.type === "main_frame") {
      requestBuffers.delete(details.tabId);
      void (async () => {
        const net = toNetworkPayload(details);
        const cur = await readAggregated(details.tabId);
        const baseFindings = cur?.findings ?? [];
        const merged = mergeNetworkIntoFindings(baseFindings, net);
        const headerNames = Object.keys(net.responseHeaders);
        const observedHeaderNames = [
          ...new Set([...(cur?.observedHeaderNames ?? []), ...headerNames]),
        ].slice(0, 120);
        const baseAgg: AggregatedFindings = cur
          ? {
              ...cur,
              pageUrl: details.url,
              updatedAt: Date.now(),
              findings: dedupeFindings(merged),
              observedHeaderNames,
            }
          : {
              tabId: details.tabId,
              pageUrl: details.url,
              updatedAt: Date.now(),
              findings: dedupeFindings(merged),
              endpoints: [],
              observedHeaderNames,
            };
        const next = enrichForUi(baseAgg);
        await writeAggregated({
          ...next,
          severityScore: next.severityScore,
          observedRequests: undefined,
        });
        await broadcastFindings(next);
        await updateBadge(details.tabId, next);
      })();
      return;
    }

    if (details.type === "xmlhttprequest" || details.type === "other") {
      appendObserved(details);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"],
);

chrome.tabs.onRemoved.addListener((tabId) => {
  void chrome.storage.session.remove(sessionKey(tabId));
  requestBuffers.delete(tabId);
});

chrome.runtime.onMessage.addListener(
  (
    raw: unknown,
    sender: chrome.runtime.MessageSender,
    sendResponse: (r: unknown) => void,
  ) => {
    if (!isExtensionMessage(raw)) {
      return false;
    }
    const msg = raw as ExtensionMessage;
    if (!isTrustedSender(sender)) {
      sendResponse({ error: "untrusted" });
      return false;
    }

    void (async () => {
      try {
        if (msg.type === "PING") {
          sendResponse({ type: "PONG", requestId: msg.requestId } satisfies ExtensionMessage);
          return;
        }

        if (msg.type === "CONTENT_DOM_SCAN") {
          const tabId = sender.tab?.id;
          if (tabId === undefined) {
            sendResponse({ ok: false });
            return;
          }
          const built = buildAggregatedFromDom(tabId, msg.payload);
          const prev = await readAggregated(tabId);
          const keepFromPrev = (prev?.findings ?? []).filter((f) =>
            NETWORK_FINDING_CATEGORIES.has(f.category),
          );
          const merged: AggregatedFindings = {
            ...built,
            findings: dedupeFindings([...built.findings, ...keepFromPrev]),
            endpoints: dedupeEndpoints([...(prev?.endpoints ?? []), ...built.endpoints]),
            updatedAt: Date.now(),
            observedHeaderNames: prev?.observedHeaderNames,
          };
          const next = enrichForUi(merged);
          await writeAggregated({
            ...next,
            severityScore: next.severityScore,
            observedRequests: undefined,
          });
          await broadcastFindings(next);
          await updateBadge(tabId, next);
          sendResponse({ ok: true });
          return;
        }

        if (msg.type === "SIDEPANEL_GET_FINDINGS") {
          const tab = await getActiveTabId();
          if (tab === null) {
            sendResponse({ type: "SIDEPANEL_FINDINGS", payload: null } satisfies ExtensionMessage);
            return;
          }
          const agg = await readAggregated(tab);
          if (!agg) {
            sendResponse({
              type: "SIDEPANEL_FINDINGS",
              payload: enrichForUi({
                tabId: tab,
                pageUrl: "",
                updatedAt: Date.now(),
                findings: [],
                endpoints: [],
              }),
            } satisfies ExtensionMessage);
            return;
          }
          sendResponse({
            type: "SIDEPANEL_FINDINGS",
            payload: enrichForUi(agg),
          } satisfies ExtensionMessage);
          return;
        }

        if (msg.type === "SIDEPANEL_GET_SETTINGS") {
          const s = await loadSettings();
          sendResponse({ type: "SIDEPANEL_SETTINGS", payload: s } satisfies ExtensionMessage);
          return;
        }

        if (msg.type === "SIDEPANEL_SET_SETTINGS") {
          const s = await saveSettings(msg.payload);
          sendResponse({ type: "SIDEPANEL_SETTINGS", payload: s } satisfies ExtensionMessage);
          return;
        }

        if (msg.type === "SIDEPANEL_REQUEST_AI_SUGGESTION") {
          const settings = await loadSettings();
          if (!settings.aiEnabled || !settings.aiEndpointUrl.trim()) {
            sendResponse({
              type: "SIDEPANEL_AI_SUGGESTION_RESULT",
              payload: {
                text: "",
                error: "Ative a IA e defina um endpoint HTTPS nas definições.",
              },
            } satisfies ExtensionMessage);
            return;
          }
          const tab = await getActiveTabId();
          if (tab === null) {
            sendResponse({
              type: "SIDEPANEL_AI_SUGGESTION_RESULT",
              payload: { text: "", error: "Nenhum separador ativo." },
            } satisfies ExtensionMessage);
            return;
          }
          const agg = await readAggregated(tab);
          if (!agg) {
            sendResponse({
              type: "SIDEPANEL_AI_SUGGESTION_RESULT",
              payload: {
                text: "",
                error: "Sem achados para este separador. Recarregue a página.",
              },
            } satisfies ExtensionMessage);
            return;
          }
          const payload = buildAiPayloadFromAggregated(agg);
          const result = await requestAiSuggestion(
            settings.aiEndpointUrl,
            payload,
          );
          sendResponse({
            type: "SIDEPANEL_AI_SUGGESTION_RESULT",
            payload: result,
          } satisfies ExtensionMessage);
          return;
        }
      } catch (e) {
        sendResponse({
          error: e instanceof Error ? e.message : "erro",
        });
      }
    })();

    return true;
  },
);

async function getActiveTabId(): Promise<number | null> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const t = tabs[0];
  return t?.id ?? null;
}

chrome.tabs.onActivated.addListener((activeInfo) => {
  void (async () => {
    try {
      const tab = await chrome.tabs.get(activeInfo.tabId);
      const agg = await readAggregated(activeInfo.tabId);
      const payload =
        agg ??
        ({
          tabId: activeInfo.tabId,
          pageUrl: tab.url ?? "",
          updatedAt: Date.now(),
          findings: [],
          endpoints: [],
        } satisfies AggregatedFindings);
      const next = enrichForUi(payload);
      await broadcastFindings(next);
      await updateBadge(activeInfo.tabId, next);
    } catch {
      /* separador fechado */
    }
  })();
});

async function broadcastFindings(agg: AggregatedFindings): Promise<void> {
  const out = enrichForUi(agg);
  try {
    await chrome.runtime.sendMessage({
      type: "SIDEPANEL_FINDINGS",
      payload: out,
    } satisfies ExtensionMessage);
  } catch {
    /* nenhum subscritor */
  }
}
