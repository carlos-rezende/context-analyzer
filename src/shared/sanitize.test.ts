import { describe, expect, it } from "vitest";
import { sanitizePlainText, sanitizeUrlForDisplay } from "./sanitize";

describe("sanitizePlainText", () => {
  it("remove bytes nulos e limita tamanho", () => {
    const long = "a".repeat(20_000);
    expect(sanitizePlainText(long).length).toBeLessThanOrEqual(8000);
    expect(sanitizePlainText("a\u0000b")).toBe("ab");
  });
});

describe("sanitizeUrlForDisplay", () => {
  it("aceita URL válida", () => {
    expect(sanitizeUrlForDisplay("https://exemplo.org/caminho")).toContain(
      "exemplo.org",
    );
  });

  it("trata string inválida sem lançar", () => {
    expect(sanitizeUrlForDisplay("não é url")).toBeTruthy();
  });
});
