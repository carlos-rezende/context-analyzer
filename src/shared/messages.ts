import type {
  AggregatedFindings,
  DomScanPayload,
  ExtensionSettings,
} from "./types";

/** Contratos de mensagem: discriminação por `type` para roteamento seguro. */
export type ExtensionMessage =
  | { type: "PING"; requestId: string }
  | { type: "PONG"; requestId: string }
  | { type: "CONTENT_DOM_SCAN"; payload: DomScanPayload }
  | { type: "SIDEPANEL_GET_FINDINGS" }
  | { type: "SIDEPANEL_FINDINGS"; payload: AggregatedFindings | null }
  | { type: "SIDEPANEL_GET_SETTINGS" }
  | { type: "SIDEPANEL_SETTINGS"; payload: ExtensionSettings }
  | { type: "SIDEPANEL_SET_SETTINGS"; payload: Partial<ExtensionSettings> }
  | { type: "SIDEPANEL_REQUEST_AI_SUGGESTION" }
  | { type: "SIDEPANEL_AI_SUGGESTION_RESULT"; payload: { text: string; error?: string } };

export function isExtensionMessage(data: unknown): data is ExtensionMessage {
  if (data === null || typeof data !== "object") return false;
  const t = (data as { type?: unknown }).type;
  return typeof t === "string" && t.length > 0 && t.length < 128;
}

/** Valida remetente de mensagens externas (painel/ content → background). */
export function isTrustedSender(
  sender: chrome.runtime.MessageSender,
): boolean {
  if (!sender.id || sender.id !== chrome.runtime.id) {
    return false;
  }
  return true;
}
