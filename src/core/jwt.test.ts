import { describe, expect, it } from "vitest";
import { jwtFindingsFromStorage, looksLikeJwt } from "./jwt";

/** Storage mínimo em memória para testes. */
function mockStorage(entries: Record<string, string>): Storage {
  const map = new Map<string, string>(Object.entries(entries));
  return {
    get length() {
      return map.size;
    },
    key: (i: number) => [...map.keys()][i] ?? null,
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => {
      map.set(k, v);
    },
    removeItem: (k: string) => {
      map.delete(k);
    },
    clear: () => {
      map.clear();
    },
  } as Storage;
}

/** Três segmentos base64url com comprimentos mínimos da heurística. */
const SAMPLE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0." +
  "signaturepart1234567890123456789012";

describe("looksLikeJwt", () => {
  it("aceita padrão JWT-like", () => {
    expect(looksLikeJwt(SAMPLE_JWT)).toBe(true);
  });

  it("rejeita string curta", () => {
    expect(looksLikeJwt("a.b.c")).toBe(false);
  });

  it("rejeita sem três partes", () => {
    expect(looksLikeJwt("onlytwo.parts")).toBe(false);
  });
});

describe("jwtFindingsFromStorage", () => {
  it("cria achado quando valor parece JWT em localStorage", () => {
    const local = mockStorage({ access_token: SAMPLE_JWT });
    const session = mockStorage({});
    const f = jwtFindingsFromStorage(local, session);
    expect(f.length).toBe(1);
    expect(f[0].category).toBe("JWT");
    expect(f[0].evidence).toContain("chave:");
    expect(f[0].evidence).toContain("comprimento:");
  });

  it("não duplica a mesma chave entre storages vazios", () => {
    const empty = mockStorage({});
    expect(jwtFindingsFromStorage(empty, empty)).toEqual([]);
  });
});
