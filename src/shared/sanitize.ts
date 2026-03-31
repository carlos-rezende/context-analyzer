/**
 * Sanitização para exibição segura: sem interpretar HTML da página.
 * Usar sempre antes de mostrar texto vindo do DOM ou da rede.
 */
const MAX_LEN = 8_000;

export function sanitizePlainText(input: string, max = MAX_LEN): string {
  const s = String(input ?? "")
    .replace(/\u0000/g, "")
    .slice(0, max);
  return s;
}

export function sanitizeUrlForDisplay(url: string): string {
  try {
    const u = new URL(url);
    return sanitizePlainText(u.toString(), 2048);
  } catch {
    return sanitizePlainText(url, 2048);
  }
}
