import { describe, expect, it } from "vitest";
import { Window } from "happy-dom";
import {
  graphqlDomFindingsFromPage,
  graphqlFindingsFromNetwork,
} from "./graphql";
import type { NetworkScanPayload } from "../shared/types";

function net(partial: Partial<NetworkScanPayload>): NetworkScanPayload {
  return {
    tabId: 1,
    url: partial.url ?? "https://exemplo.test/",
    statusCode: 200,
    responseHeaders: partial.responseHeaders ?? {},
    setCookieHeaders: partial.setCookieHeaders ?? [],
  };
}

describe("graphqlFindingsFromNetwork", () => {
  it("deteta caminho /graphql", () => {
    const f = graphqlFindingsFromNetwork(
      net({ url: "https://api.test/v1/graphql" }),
    );
    expect(f.some((x) => x.title.includes("URL sugere"))).toBe(true);
  });

  it("deteta Content-Type graphql", () => {
    const f = graphqlFindingsFromNetwork(
      net({
        url: "https://exemplo.test/data",
        responseHeaders: {
          "Content-Type": "application/graphql-response+json",
        },
      }),
    );
    expect(f.some((x) => x.id.startsWith("gql-"))).toBe(true);
  });
});

describe("graphqlDomFindingsFromPage", () => {
  it("deteta script inline com referência Apollo (sem pedido de rede)", () => {
    const w = new Window({ url: "https://example.invalid/" });
    const doc = w.document;
    doc.body.innerHTML = "<script>const apollo = {};</script>";
    const f = graphqlDomFindingsFromPage(doc, "https://example.invalid/");
    expect(f.some((x) => x.id === "gql-inline-hint")).toBe(true);
    w.close();
  });

  it("deteta caminho /graphql na página", () => {
    const w = new Window({ url: "https://app.test/" });
    const doc = w.document;
    doc.body.innerHTML = "<p>x</p>";
    const f = graphqlDomFindingsFromPage(doc, "https://app.test/graphql");
    expect(f.some((x) => x.id === "gql-page-path")).toBe(true);
    w.close();
  });
});
