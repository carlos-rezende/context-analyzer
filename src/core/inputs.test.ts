import { describe, expect, it } from "vitest";
import { Window } from "happy-dom";
import { analyzeInputsFromForms } from "./inputs";

describe("analyzeInputsFromForms", () => {
  it("deteta nomes suspeitos", () => {
    const w = new Window({ url: "https://form.test/" });
    const doc = w.document;
    doc.body.innerHTML =
      '<form><input name="api_key" type="text" /><input name="q" /></form>';
    const r = analyzeInputsFromForms(doc);
    expect(r.suspiciousInputs.length).toBeGreaterThan(0);
    expect(r.findings.length).toBeGreaterThan(0);
    w.close();
  });
});
