import { defineConfig } from "vitest/config";

/**
 * Testes isolados em Node: sem browser, sem rede, sem binários externos.
 * Reduz falsos positivos de antivírus em relação a E2E ou ferramentas de teste de intrusão.
 */
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    globals: false,
    mockReset: true,
  },
});
