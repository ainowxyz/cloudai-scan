import { describe, expect, it } from "vitest";
import { isProviderHost, PROVIDER_KEY_NAME, runChecks, type CloudflareAccountFacts, type RepoFacts } from "../src/index.js";

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
        llmOperationCount: 1,
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
  it("reports an MCP Worker without Access as needing review, not as unauthenticated", () => {
    expect(by("WRK-004").status).toBe("needs_review");
    expect(by("WRK-004").evidence[0]).toContain("docs-mcp");
    expect(by("WRK-004").summary).toMatch(/cannot be read/);
    expect(by("WRK-004").summary).not.toMatch(/unauthenticated|reachable without/i);
    expect(by("WRK-004").limits).toMatch(/OAuth/);
  });
  it("passes WRK-004 when Access covers every hostname", () => {
    const covered = runChecks("cloudflare-account", { ...facts, workers: [{ ...facts.workers![1]!, workersDevEnabled: false }], accessHostnames: ["mcp.example.com"] });
    expect(covered.find((x) => x.id === "WRK-004")?.status).toBe("pass");
  });
  it("a secret name is reported as a name match, not as proof of a bypass", () => {
    expect(by("WRK-001").summary).toMatch(/named like/);
    expect(by("WRK-001").limits).toMatch(/does not prove/);
  });
  it("never passes when Workers or zones could not be read", () => {
    for (const r of runChecks("cloudflare-account", { collectedAt: NOW })) expect(r.status, r.id).toBe("unverifiable");
  });
  it("an account with nothing relevant is not applicable", () => {
    const empty = runChecks("cloudflare-account", { workers: [], zones: [], accessHostnames: [], collectedAt: NOW });
    for (const id of ["WRK-001", "WRK-002", "WRK-003", "WRK-004", "ZONE-001", "ZONE-002"]) expect(empty.find((x) => x.id === id)?.status, id).toBe("not_applicable");
  });
  it("flags uncovered LLM endpoints and bare zones", () => {
    expect(by("ZONE-001").status).toBe("fail");
    expect(by("ZONE-002").status).toBe("fail");
  });
  it("passes WRK-003 when the AI Worker is on a route", () => expect(by("WRK-003").status).toBe("pass"));
  it("claims nothing about LLM endpoints when the labels could not be read", () => {
    const unread = runChecks("cloudflare-account", { ...facts, zones: [{ id: "z1", name: "example.com", rateLimitExpressions: [], customRuleExpressions: [], botFightMode: false }] });
    const of = (id: string) => unread.find((x) => x.id === id)!;
    expect(of("ZONE-001").status).toBe("unverifiable");
    expect(of("ZONE-002").status).toBe("unverifiable");
    expect(of("ACC-001").observed[0]).toMatch(/not readable on 1 of 1 zone/);
    expect(of("ACC-001").observed[0]).not.toMatch(/0 labelled/);
  });
  it("asks for review when Cloudflare gives a count but not the endpoints", () => {
    const counted = runChecks("cloudflare-account", { ...facts, zones: [{ id: "z1", name: "example.com", llmOperationCount: 2, rateLimitExpressions: [], customRuleExpressions: [], botFightMode: true }] });
    expect(counted.find((x) => x.id === "ZONE-001")?.status).toBe("needs_review");
  });
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

describe("provider key names", () => {
  it("matches Hugging Face keys however the words are joined", () => {
    for (const n of ["HUGGINGFACE_TOKEN", "HUGGING_FACE_API_KEY", "HF_TOKEN"]) expect(PROVIDER_KEY_NAME.test(n), n).toBe(true);
  });
});

describe("provider hosts", () => {
  it("matches a provider host and its subdomains, not a host that only contains it", () => {
    for (const h of ["api.openai.com", "myres.openai.azure.com", "bedrock-runtime.us-east-1.amazonaws.com", "openrouter.ai"]) expect(isProviderHost(h), h).toBe(true);
    for (const h of ["api.openai.com.evil.example", "notopenrouter.ai", "docs.anthropic.com"]) expect(isProviderHost(h), h).toBe(false);
  });
});
