/** Tipos compartilhados entre camadas (sem estado global). */

export type Severity = "info" | "low" | "medium" | "high";

export interface Finding {
  id: string;
  category: string;
  title: string;
  detail: string;
  severity: Severity;
  evidence?: string;
}

export interface EndpointRef {
  url: string;
  methodGuess?: string;
  source: "dom" | "network";
}

export interface DomScanPayload {
  pageUrl: string;
  collectedAt: number;
  endpoints: EndpointRef[];
  numericParameters: { name: string; sample?: string }[];
  suspiciousInputs: { name: string; type: string; reason: string }[];
  idorHints: string[];
  /** Achados heurísticos gerados no content script (sem dados sensíveis). */
  domFindings: Finding[];
}

export interface NetworkScanPayload {
  tabId: number;
  url: string;
  statusCode: number;
  responseHeaders: Record<string, string>;
  setCookieHeaders: string[];
}

/** Pedido observado (somente leitura) para cópia manual tipo fetch/cURL. */
export interface ObservedRequest {
  id: string;
  url: string;
  method: string;
  type: string;
  statusCode: number;
  timestamp: number;
}

export interface AggregatedFindings {
  tabId: number;
  pageUrl: string;
  updatedAt: number;
  findings: Finding[];
  endpoints: EndpointRef[];
  dom?: DomScanPayload;
  /** Nomes de cabeçalhos observados (via webRequest, só leitura). */
  observedHeaderNames?: string[];
  /** Pontuação heurística 0–100 (maior = mais achados de maior peso). */
  severityScore?: number;
  /** Últimos pedidos XHR/fetch observados neste separador (memória no service worker). */
  observedRequests?: ObservedRequest[];
}

/** Dados permitidos para a camada de IA (nunca credenciais/HTML completo). */
export interface AiContextPayload {
  pageHost: string;
  endpointPaths: string[];
  parameterNames: string[];
  headerNames: string[];
  findingSummaries: string[];
}

export interface ExtensionSettings {
  aiEnabled: boolean;
  /** URL opcional configurada pelo utilizador; nunca enviamos segredos. */
  aiEndpointUrl: string;
  heuristicDetailLevel: "compact" | "normal";
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
  aiEnabled: false,
  aiEndpointUrl: "",
  heuristicDetailLevel: "normal",
};
