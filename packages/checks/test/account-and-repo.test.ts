import { describe, expect, it } from "vitest";
import { runChecks, type CloudflareAccountFacts, type RepoFacts } from "../src/index.js";

const NOW = "2026-11-03T00:00:00.000Z";

describe("cloudflare account checks", () => {
  const facts: CloudflareAccountFacts = {
    workers: [
      { name: "chat-api", bindings: [{ type: "ai", name: "AI" }], secretNames: ["OPENAI_API_KEY"], routes: ["app.example.com/api/*"], customDomains: [], workersDevEnabled: false, observabilityEnabled: true },
      { name: "docs-mcp", bindings: [], secretNames: [], routes: [], customDomains: ["mcp.example.com"], workersDevEnabled: true, observabilityEnabled: false },
    ],
    zones: [
      {
        id: "z1",
        name: "example.com",
        llmOperations: [{ method: "POST", host: "app.example.com", endpoint: "/api/chat" }],
        rateLimitExpressions: ['(http.request.uri.path eq "/api/login")'],
        customRuleExpressions: [],
        botFightMode: false,
      },
    ],
    accessHostnames: ["admin.example.com"],
    collectedAt: NOW,
  };
  const r = runChecks("cloudflare-account", facts);
  const by = (id: string) => r.find((x) => x.id === id)!;

  it("flags provider keys on Workers", () => expect(by("WRK-001").status).toBe("fail"));
  it("flags MCP without Access", () => {
    expect(by("WRK-004").status).toBe("fail");
    expect(by("WRK-004").evidence[0]).toContain("docs-mcp");
  });
  it("flags uncovered LLM endpoints and bare zones", () => {
    expect(by("ZONE-001").status).toBe("fail");
    expect(by("ZONE-002").status).toBe("fail");
  });
  it("passes WRK-003 when the AI Worker is on a route", () => expect(by("WRK-003").status).toBe("pass"));
  it("counts inventory", () => expect(by("ACC-001").summary).toContain("1 AI Worker"));
});

describe("repo checks", () => {
  const facts: RepoFacts = {
    root: "/tmp/app",
    files: [
      { path: "src/llm.ts", imports: ["openai"], hosts: ["api.openai.com"], hasAiRun: false, hasGatewayRef: false, hasMcpServer: false, hasAccessCheck: false },
      { path: "src/summarise.ts", imports: [], hosts: [], hasAiRun: true, hasGatewayRef: true, hasMcpServer: false, hasAccessCheck: false },
      { path: "src/mcp.ts", imports: ["@modelcontextprotocol/sdk/server/mcp.js"], hosts: [], hasAiRun: false, hasGatewayRef: false, hasMcpServer: true, hasAccessCheck: false },
    ],
    wrangler: [{ path: "wrangler.jsonc", name: "app", hasAiBinding: true, observabilityEnabled: null, secretLikeVarNames: ["OPENAI_API_KEY"], providerKeyVarNames: ["OPENAI_API_KEY"] }],
    collectedAt: NOW,
  };
  const r = runChecks("repo", facts);
  const by = (id: string) => r.find((x) => x.id === id)!;

  it("flags direct hosts, bare SDKs, plaintext secrets, unguarded MCP and missing observability", () => {
    expect(by("REPO-001").status).toBe("fail");
    expect(by("REPO-002").status).toBe("fail");
    expect(by("REPO-003").status).toBe("pass");
    expect(by("REPO-004").status).toBe("fail");
    expect(by("REPO-005").status).toBe("fail");
    expect(by("REPO-006").status).toBe("fail");
  });
});

describe("catalogue completeness", () => {
  it("every check names its source and singular summaries agree", async () => {
    const { allChecks } = await import("../src/index.js");
    for (const c of allChecks()) expect(c.source, c.id).toMatch(/\S/);
  });
  it("uses singular verbs for a count of one", () => {
    const one: RepoFacts = {
      root: "/x",
      files: [{ path: "a.ts", imports: ["openai"], hosts: [], hasAiRun: true, hasGatewayRef: false, hasMcpServer: false, hasAccessCheck: false }],
      wrangler: [],
      collectedAt: NOW,
    };
    const r = runChecks("repo", one);
    expect(r.find((x) => x.id === "REPO-002")!.summary).toBe("1 file uses a provider SDK without a gateway reference.");
    expect(r.find((x) => x.id === "REPO-003")!.summary).toBe("1 file calls Workers AI without a gateway id.");
  });
});
