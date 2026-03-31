import type { AiContextPayload } from "../shared/types";

/**
 * Chamada opcional a um backend de IA configurado pelo utilizador.
 * Não envia cookies, tokens, HTML nem corpo de pedidos.
 */
export async function requestAiSuggestion(
  endpointUrl: string,
  payload: AiContextPayload,
): Promise<{ text: string; error?: string }> {
  const url = endpointUrl.trim();
  if (!url || !/^https:\/\//i.test(url)) {
    return {
      text: "",
      error: "Configure um URL HTTPS válido para o endpoint de IA.",
    };
  }

  const body = JSON.stringify({
    context: payload,
    source: "context-analyzer",
    version: 1,
  });

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      credentials: "omit",
      mode: "cors",
    });
    if (!res.ok) {
      return { text: "", error: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as { suggestion?: string; message?: string };
    const text = data.suggestion ?? data.message ?? "";
    return { text: String(text).slice(0, 16_000) };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Erro de rede";
    return { text: "", error: msg };
  }
}
