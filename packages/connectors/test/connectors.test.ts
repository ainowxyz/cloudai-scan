import { afterEach, describe, expect, it, vi } from "vitest";
import { anthropicConnector, assertReadOnly, cloudflareAccountConnector, cloudflareAiGatewayConnector, getJson, openaiConnector, redact } from "../src/index.js";

type Handler = (url: string, init?: RequestInit) => { status?: number; body: unknown } | undefined;

function mockFetch(handler: Handler) {
  const calls: { url: string; method: string }[] = [];
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, method: init?.method ?? "GET" });
    const r = handler(url, init) ?? { status: 404, body: { error: { message: "no route" } } };
    return new Response(JSON.stringify(r.body), { status: r.status ?? 200, headers: { "content-type": "application/json" } });
  });
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

const NOW = new Date("2026-11-03T00:00:00Z");

describe("read-only allow-list", () => {
  it("allows the documented read calls", () => {
    assertReadOnly("https://api.openai.com/v1/organization/projects?limit=1");
    assertReadOnly("https://api.anthropic.com/v1/organizations/api_keys");
    assertReadOnly("https://api.cloudflare.com/client/v4/accounts/abc/ai-gateway/gateways");
    assertReadOnly("https://api.cloudflare.com/client/v4/zones?per_page=50");
    assertReadOnly("https://api.cloudflare.com/client/v4/graphql", "POST");
  });

  it("blocks writes, other hosts, inference endpoints and plain http", () => {
    for (const [url, method] of [
      ["https://api.openai.com/v1/organization/projects", "POST"],
      ["https://api.openai.com/v1/organization/projects/p/api_keys/k", "DELETE"],
      ["https://api.openai.com/v1/chat/completions", "GET"],
      ["https://api.anthropic.com/v1/messages", "POST"],
      ["https://api.cloudflare.com/client/v4/accounts/abc/ai-gateway/gateways/g", "PUT"],
      ["https://evil.example/v1/organization/projects", "GET"],
      ["http://api.openai.com/v1/organization/projects", "GET"],
      ["https://api.openai.com.evil.example/v1/organization/x", "GET"],
    ] as const)
      expect(() => assertReadOnly(url, method), `${method} ${url}`).toThrow(/Blocked request/);
  });

  it("getJson refuses a blocked request before any network call, and refuses GraphQL mutations", async () => {
    const calls = mockFetch(() => ({ body: {} }));
    await expect(getJson("https://api.openai.com/v1/organization/projects", {}, { method: "POST", body: "{}" })).rejects.toThrow(/Blocked request/);
    await expect(getJson("https://api.cloudflare.com/client/v4/graphql", {}, { method: "POST", body: JSON.stringify({ query: "mutation { x }" }) })).rejects.toThrow(/only GraphQL queries/);
    expect(calls).toEqual([]);
  });
});

describe("redaction", () => {
  it("removes the credential and key-shaped strings from error text", async () => {
    expect(redact("Incorrect API key provided: sk-admin-abc123XYZ987.", "sk-admin-abc123XYZ987")).toBe("Incorrect API key provided: [redacted].");
    expect(redact("bad key sk-proj-****************wxyz")).toBe("bad key [redacted]");
    mockFetch(() => ({ status: 401, body: { error: { message: "Incorrect API key provided: sk-admin-SECRETSECRET" } } }));
    const err = await getJson("https://api.openai.com/v1/organization/projects?limit=1", { authorization: "Bearer sk-admin-SECRETSECRET" }).catch((e: Error) => e);
    expect(String((err as Error).message)).not.toContain("SECRETSECRET");
  });
});

describe("openai connector", () => {
  const routes: Handler = (url) => {
    if (url.includes("/projects?")) return { body: { data: [{ id: "p1", name: "prod", status: "active", created_at: 1700000000 }, { id: "p0", name: "old", status: "archived", created_at: 1600000000 }], has_more: false } };
    if (url.includes("/projects/p1/api_keys")) return { body: { data: [{ id: "k1", name: "api", created_at: 1750000000, last_used_at: 1762000000, owner: { type: "service_account" } }], has_more: false } };
    if (url.includes("/projects/p1/service_accounts")) return { body: { data: [{ id: "sa1" }], has_more: false } };
    if (url.includes("/projects/p1/rate_limits")) return { body: { data: [{ id: "rl-1", model: "gpt-5.5", max_requests_per_1_minute: 500, max_tokens_per_1_minute: 30000 }], has_more: false } };
    if (url.includes("/projects/p1/spend_alerts")) return { body: { data: [{ id: "a1", threshold_amount: 10000 }], has_more: false } };
    if (url.includes("/projects/p1/spend_limit")) return { body: { object: "project.spend_limit", threshold_amount: 0, enforcement: { status: "inactive" } } };
    if (url.includes("/projects/p1/data_retention")) return { body: { object: "project.data_retention", type: "zero_data_retention" } };
    if (url.includes("/projects/p1/model_permissions")) return { status: 403, body: { error: { message: "forbidden" } } };
    if (url.includes("/users")) return { body: { data: [{ id: "u1", email: "a@b.c", role: "owner", added_at: 1700000000 }], has_more: false } };
    if (url.includes("/invites")) return { body: { data: [], has_more: false } };
    if (url.includes("/audit_logs")) return { body: { data: [{ id: "e1", effective_at: 1762000000 }] } };
    if (url.endsWith("/organization/spend_limit")) return { body: { threshold_amount: 500000 } };
    if (url.includes("/usage/completions")) return { body: { data: [{ results: [{ model: "gpt-5.5" }, { model: "gpt-5.5" }] }] } };
    if (url.includes("/usage/embeddings")) return { body: { data: [{ results: [{ model: "text-embedding-3-large" }] }] } };
    return undefined;
  };

  it("collects settings from documented endpoints with GET only, and records what it could not read", async () => {
    const calls = mockFetch(routes);
    const r = await openaiConnector.collect({ secret: "sk-admin-test" }, NOW);
    const p = r.facts.projects!.find((x) => x.id === "p1")!;
    expect(p.apiKeys![0]!.ownerType).toBe("service_account");
    expect(p.rateLimits![0]).toEqual({ model: "gpt-5.5", maxRequestsPer1Minute: 500, maxTokensPer1Minute: 30000 });
    expect(p.spendAlertCount).toBe(1);
    expect(p.spendLimitCents).toBe(0);
    expect(p.dataRetention).toBe("zero_data_retention");
    expect(p.modelPermissions).toBeUndefined();
    expect(r.facts.auditLogEvents).toBe(1);
    expect(r.facts.orgSpendLimitCents).toBe(500000);
    expect(r.facts.modelsUsed30d).toEqual(["gpt-5.5", "text-embedding-3-large"]);
    expect(r.errors.map((e) => `${e.endpoint} ${e.status}`)).toEqual(["GET /projects/p1/model_permissions 403"]);
    expect(calls.every((c) => c.method === "GET" && c.url.startsWith("https://api.openai.com/v1/organization/"))).toBe(true);
  });

  it("does not read keys of archived projects", async () => {
    const calls = mockFetch(routes);
    const r = await openaiConnector.collect({ secret: "sk-admin-test" }, NOW);
    const old = r.facts.projects!.find((x) => x.id === "p0")!;
    expect(old.status).toBe("archived");
    expect(old.apiKeys).toBeUndefined();
    expect(calls.some((c) => c.url.includes("/projects/p0/"))).toBe(false);
  });

  it("follows pagination", async () => {
    const calls = mockFetch((url) => {
      if (url.includes("/users") && !url.includes("after=")) return { body: { data: [{ id: "u1", email: "a@b.c", role: "owner", added_at: 1 }], has_more: true, last_id: "u1" } };
      if (url.includes("/users") && url.includes("after=u1")) return { body: { data: [{ id: "u2", email: "d@e.f", role: "member", added_at: 1 }], has_more: false } };
      return undefined;
    });
    const r = await openaiConnector.collect({ secret: "sk-admin-test" }, NOW);
    expect(r.facts.users!.map((u) => u.id)).toEqual(["u1", "u2"]);
    expect(calls.filter((c) => c.url.includes("/users")).length).toBe(2);
  });

  it("missing permission leaves facts undefined, never empty", async () => {
    mockFetch(() => ({ status: 403, body: { error: { message: "insufficient permissions" } } }));
    const r = await openaiConnector.collect({ secret: "sk-admin-test" }, NOW);
    expect(r.facts.projects).toBeUndefined();
    expect(r.facts.users).toBeUndefined();
    expect(r.facts.auditLogEvents).toBeUndefined();
    expect(r.facts.modelsUsed30d).toBeUndefined();
  });

  it("an empty audit log is reported as zero events, not as an error", async () => {
    mockFetch((url) => (url.includes("/audit_logs") ? { body: { data: [] } } : undefined));
    const r = await openaiConnector.collect({ secret: "sk-admin-test" }, NOW);
    expect(r.facts.auditLogEvents).toBe(0);
  });

  it("verify maps 401 to a helpful message", async () => {
    mockFetch(() => ({ status: 401, body: { error: { message: "Incorrect API key" } } }));
    const v = await openaiConnector.verify({ secret: "bad-key-value" });
    expect(v.ok).toBe(false);
    expect(v.error).toMatch(/Admin API key/);
  });
});

describe("anthropic connector", () => {
  it("collects members, workspaces, keys, spend limits and models with the right headers", async () => {
    const betas: string[] = [];
    mockFetch((url, init) => {
      const h = init?.headers as Record<string, string>;
      expect(h["x-api-key"]).toBe("sk-ant-admin-test");
      if (h["anthropic-beta"]) betas.push(`${new URL(url).pathname.split("/").pop()}:${h["anthropic-beta"]}`);
      if (url.includes("/users")) return { body: { data: [{ id: "u", email: "a@b.c", role: "admin", added_at: "2026-01-01T00:00:00Z" }], has_more: false } };
      if (url.includes("/invites")) return { body: { data: [], has_more: false } };
      if (url.includes("/workspaces")) return { body: { data: [{ id: "w1", name: "Default", archived_at: null }], has_more: false } };
      if (url.includes("/api_keys")) return { body: { data: [{ id: "k", name: "prod", status: "active", created_at: "2026-02-01T00:00:00Z", scope: { type: "workspace", workspace_id: "w1" } }, { id: "o", name: "org", status: "active", created_at: "2026-02-01T00:00:00Z", scope: { type: "organization" } }], has_more: false } };
      if (url.includes("/spend_limits")) return { body: { data: [{ id: "spl_1", amount: "50000", is_enabled: true, period: "monthly", scope: { type: "workspace", workspace_id: "w1" } }], next_page: null } };
      if (url.includes("/analytics/usage")) return { body: { data: [{ group: { model: "claude-sonnet-5-5" } }, { group: { model: null } }], has_more: false, next_page: null } };
      return undefined;
    });
    const r = await anthropicConnector.collect({ secret: "sk-ant-admin-test" }, NOW);
    expect(r.facts.workspaces![0]!.isDefault).toBe(true);
    expect(r.facts.apiKeys!.map((k) => k.workspaceId)).toEqual(["w1", null]);
    expect(r.facts.spendLimits).toEqual([{ scopeType: "workspace", hasAmount: true, enabled: true, period: "monthly" }]);
    expect(r.facts.modelsUsed30d).toEqual(["claude-sonnet-5-5"]);
    expect(betas).toEqual(["spend_limits:spend-limit-reads-2026-09-26", "usage:analytics-usage-cost-2026-08-24"]);
    expect(r.errors).toEqual([]);
  });

  it("an unreadable usage or spend endpoint stays undefined", async () => {
    mockFetch((url) => (url.includes("/users") ? { body: { data: [], has_more: false } } : { status: 403, body: { error: { message: "no access" } } }));
    const r = await anthropicConnector.collect({ secret: "sk-ant-admin-test" }, NOW);
    expect(r.facts.users).toEqual([]);
    expect(r.facts.apiKeys).toBeUndefined();
    expect(r.facts.spendLimits).toBeUndefined();
    expect(r.facts.modelsUsed30d).toBeUndefined();
  });
});

describe("cloudflare ai gateway connector", () => {
  it("reads gateway settings, stored keys and analytics", async () => {
    const calls = mockFetch((url) => {
      if (url.endsWith("/user/tokens/verify")) return { body: { result: { status: "active" } } };
      if (url.includes("/ai-gateway/gateways/gw1/provider_configs")) return { body: { success: true, result: [{ id: "b" }], result_info: { total_count: 1 } } };
      if (url.includes("/ai-gateway/gateways"))
        return { body: { success: true, result: [{ id: "gw1", authentication: true, collect_logs: true, dlp: { enabled: false }, rate_limiting_limit: 100, rate_limiting_interval: 60, byok_only: false, guardrails: { prompt: { P1: "BLOCK" }, response: {} }, spend_limits: { enabled: true, rules: [{ id: "r", enabled: true, limit: 100 }] } }] } };
      if (url.endsWith("/graphql")) return { body: { data: { viewer: { accounts: [{ aiGatewayRequestsAdaptiveGroups: [{ count: 12, dimensions: { gateway: "gw1", provider: "openai", model: "gpt-5.5" } }] }] } } } };
      return undefined;
    });
    const v = await cloudflareAiGatewayConnector.verify({ secret: "cf-token-value", accountId: "acct" });
    expect(v.ok).toBe(true);
    const r = await cloudflareAiGatewayConnector.collect({ secret: "cf-token-value", accountId: "acct" }, NOW);
    expect(r.facts.gateways![0]).toEqual({ id: "gw1", authentication: true, collectLogs: true, dlpEnabled: false, rateLimitingLimit: 100, rateLimitingInterval: 60, byokOnly: false, hasByokKeys: true, guardrailsEnabled: true, spendLimitSet: true });
    expect(r.facts.usage30d?.[0]?.requests).toBe(12);
    expect(calls.filter((c) => c.method !== "GET").map((c) => c.url)).toEqual(["https://api.cloudflare.com/client/v4/graphql"]);
  });

  it("an unreadable gateway list is undefined, an empty one is empty", async () => {
    mockFetch(() => ({ status: 403, body: { errors: [{ message: "forbidden" }] } }));
    expect((await cloudflareAiGatewayConnector.collect({ secret: "cf-token-value", accountId: "acct" }, NOW)).facts.gateways).toBeUndefined();
    mockFetch((url) => (url.includes("/ai-gateway/gateways") ? { body: { success: true, result: [] } } : undefined));
    expect((await cloudflareAiGatewayConnector.collect({ secret: "cf-token-value", accountId: "acct" }, NOW)).facts.gateways).toEqual([]);
  });
});

describe("cloudflare account connector", () => {
  it("counts only endpoints Cloudflare labelled cf-llm, and treats a missing ruleset as empty", async () => {
    mockFetch((url) => {
      if (url.includes("/workers/scripts/api/settings")) return { body: { success: true, result: { bindings: [{ type: "ai", name: "AI" }, { type: "secret_text", name: "OPENAI_API_KEY" }], observability: { enabled: true } } } };
      if (url.includes("/workers/scripts/api/subdomain")) return { body: { success: true, result: { enabled: false } } };
      if (url.includes("/workers/scripts")) return { body: { success: true, result: [{ id: "api" }] } };
      if (url.includes("/workers/domains")) return { body: { success: true, result: [] } };
      if (url.includes("/workers/routes")) return { body: { success: true, result: [{ script: "api", pattern: "app.example.com/api/*" }] } };
      if (url.includes("/api_gateway/operations")) return { body: { success: true, result: [{ method: "POST", host: "app.example.com", endpoint: "/api/chat", features: { label: { labels: ["cf-llm"] } } }, { method: "GET", host: "app.example.com", endpoint: "/health", features: { label: { labels: [] } } }] } };
      if (url.includes("/http_ratelimit/")) return { status: 404, body: { errors: [{ message: "not found" }] } };
      if (url.includes("/http_request_firewall_custom/")) return { body: { success: true, result: { rules: [{ expression: "true", enabled: false }] } } };
      if (url.includes("/bot_management")) return { body: { success: true, result: { fight_mode: true } } };
      if (url.includes("/zones?")) return { body: { success: true, result: [{ id: "z1", name: "example.com" }] } };
      if (url.includes("/access/apps")) return { body: { success: true, result: [{ domain: "admin.example.com/path" }] } };
      return undefined;
    });
    const r = await cloudflareAccountConnector.collect({ secret: "cf-token-value", accountId: "acct" }, NOW);
    expect(r.facts.workers![0]).toMatchObject({ name: "api", secretNames: ["OPENAI_API_KEY"], routes: ["app.example.com/api/*"], observabilityEnabled: true, workersDevEnabled: false });
    expect(r.facts.zones![0]!.llmOperations).toEqual([{ method: "POST", host: "app.example.com", endpoint: "/api/chat" }]);
    expect(r.facts.zones![0]!.rateLimitExpressions).toEqual([]);
    expect(r.facts.zones![0]!.customRuleExpressions).toEqual([]);
    expect(r.facts.accessHostnames).toEqual(["admin.example.com"]);
    expect(r.errors).toEqual([]);
  });
});
