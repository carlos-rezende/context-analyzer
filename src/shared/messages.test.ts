import { describe, expect, it, beforeEach, vi } from "vitest";
import { isExtensionMessage, isTrustedSender } from "./messages";

describe("isExtensionMessage", () => {
  it("rejeita valores inválidos", () => {
    expect(isExtensionMessage(null)).toBe(false);
    expect(isExtensionMessage({})).toBe(false);
    expect(isExtensionMessage({ type: "" })).toBe(false);
  });

  it("aceita objeto com type string", () => {
    expect(isExtensionMessage({ type: "PING", requestId: "1" })).toBe(true);
  });
});

describe("isTrustedSender", () => {
  beforeEach(() => {
    vi.stubGlobal("chrome", {
      runtime: { id: "extension-teste-uuid" },
    });
  });

  it("aceita remetente com mesmo id", () => {
    expect(
      isTrustedSender({ id: "extension-teste-uuid" } as chrome.runtime.MessageSender),
    ).toBe(true);
  });

  it("rejeita id diferente", () => {
    expect(
      isTrustedSender({ id: "outro" } as chrome.runtime.MessageSender),
    ).toBe(false);
  });

  it("rejeita sem id", () => {
    expect(isTrustedSender({} as chrome.runtime.MessageSender)).toBe(false);
  });
});
