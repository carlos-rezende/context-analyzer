import { describe, expect, it } from "vitest";
import { Window } from "happy-dom";
import { extractEndpointsFromPage } from "./endpoints";

describe("extractEndpointsFromPage", () => {
  it("extrai href de âncoras", () => {
    const w = new Window({ url: "https://pagina.test/" });
    const doc = w.document;
    doc.body.innerHTML =
      '<a href="/api/recurso">x</a><img src="https://cdn.test/img.png" />';
    const eps = extractEndpointsFromPage(doc, "https://pagina.test/");
    expect(eps.some((e) => e.url.includes("pagina.test"))).toBe(true);
    expect(eps.some((e) => e.url.includes("cdn.test"))).toBe(true);
    w.close();
  });
});
