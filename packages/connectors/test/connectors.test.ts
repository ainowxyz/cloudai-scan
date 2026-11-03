import { afterEach, describe, expect, it, vi } from "vitest";
import { anthropicConnector, cloudflareAiGatewayConnector, openaiConnector } from "../src/index.js";

type Handler = (url: string, init?: RequestInit) => { status?: number; body: unknown } | undefined;

function mockFetch(handler: Handler) {
  const calls: string[] = [];
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    const r = handler(url, init) ?? { status: 404, body: { error: { message: "no route" } } };
    return new Response(JSON.stringify(r.body), { status: r.status ?? 200, headers: { "content-type": "application/json" } });
  });
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

const NOW = new Date("2026-11-03T00:00:00Z");

describe("openai connector", () => {
  it("collects projects, keys, users and audit state; records unreadable endpoints", async () => {
    const calls = mockFetch((url) => {
      if (url.includes("/projects?")) return { body: { data: [{ id: "p1", name: "prod", status: "active", created_at: 1700000000 }], has_more: false } };
      if (url.includes("/projects/p1/api_keys")) return { body: { data: [{ id: "k1", name: "api", created_at: 1750000000, last_used_at: 1762000000, owner: { type: "service_account" } }], has_more: false } };
      if (url.includes("/projects/p1/service_accounts")) return { body: { data: [{ id: "sa1" }], has_more: false } };
      if (url.includes("/projects/p1/rate_limits")) return { status: 403, body: { error: { message: "forbidden" } } };
      if (url.includes("/users")) return { body: { data: [{ id: "u1", email: "a@b.c", role: "owner", added_at: 1700000000 }], has_more: false } };
      if (url.includes("/invites")) return { body: { data: [], has_more: false } };
      if (url.includes("/audit_logs")) return { body: { data: [{ id: "e1" }] } };
      if (url.includes("/usage/completions")) return { body: { data: [{ results: [{ model: "gpt-5.5" }, { model: "gpt-5.5" }] }] } };
      return undefined;
    });
    const r = await openaiConnector.collect({ secret: "sk-admin-test" }, NOW);
    expect(r.facts.projects[0]?.apiKeys[0]?.ownerType).toBe("service_account");
    expect(r.facts.projects[0]?.apiKeys[0]?.lastUsedAt).toBe("2025-11-01T12:26:40.000Z");
    expect(r.facts.projects[0]?.serviceAccountCount).toBe(1);
    expect(r.facts.projects[0]?.hasRateLimitOverrides).toBeUndefined();
    expect(r.facts.auditLogsEnabled).toBe(true);
    expect(r.facts.modelsUsed30d).toEqual(["gpt-5.5"]);
    expect(r.errors.map((e) => e.status)).toEqual([403]);
    expect(calls.some((c) => c.includes("limit=100"))).toBe(true);
  });

  it("verify maps 401 to a helpful message", async () => {
    mockFetch(() => ({ status: 401, body: { error: { message: "Incorrect API key" } } }));
    const v = await openaiConnector.verify({ secret: "bad" });
    expect(v.ok).toBe(false);
    expect(v.error).toMatch(/Admin API key/);
  });
});

describe("anthropic connector", () => {
  it("collects members, workspaces and keys with the admin headers", async () => {
    let sawHeaders = false;
    mockFetch((url, init) => {
      const h = init?.headers as Record<string, string>;
      if (h["x-api-key"] === "sk-ant-admin-test" && h["anthropic-version"]) sawHeaders = true;
      if (url.includes("/users")) return { body: { data: [{ id: "u", email: "a@b.c", role: "admin", added_at: "2026-01-01T00:00:00Z" }], has_more: false } };
      if (url.includes("/invites")) return { body: { data: [], has_more: false } };
      if (url.includes("/workspaces")) return { body: { data: [{ id: "w1", name: "Default", archived_at: null }], has_more: false } };
      if (url.includes("/api_keys")) return { body: { data: [{ id: "k", name: "prod", status: "active", created_at: "2026-02-01T00:00:00Z", workspace_id: "w1" }], has_more: false } };
      if (url.includes("/analytics/usage")) return { status: 400, body: { error: { message: "unsupported" } } };
      return undefined;
    });
    const r = await anthropicConnector.collect({ secret: "sk-ant-admin-test" }, NOW);
    expect(sawHeaders).toBe(true);
    expect(r.facts.workspaces[0]?.isDefault).toBe(true);
    expect(r.facts.apiKeys[0]?.workspaceId).toBe("w1");
    expect(r.facts.modelsUsed30d).toBeUndefined();
    expect(r.errors[0]?.endpoint).toBe("GET /analytics/usage");
  });
});

describe("cloudflare ai gateway connector", () => {
  it("reads gateway settings, byok presence and analytics", async () => {
    mockFetch((url) => {
      if (url.endsWith("/user/tokens/verify")) return { body: { result: { status: "active" } } };
      if (url.includes("/ai-gateway/gateways/gw1/byok")) return { body: { success: true, result: [{ id: "b" }], result_info: { total_count: 1 } } };
      if (url.includes("/ai-gateway/gateways")) return { body: { success: true, result: [{ id: "gw1", authentication: true, collect_logs: true, dlp: { enabled: false }, rate_limiting_limit: 100, rate_limiting_interval: 60, byok_only: false }] } };
      if (url.endsWith("/graphql")) return { body: { data: { viewer: { accounts: [{ aiGatewayRequestsAdaptiveGroups: [{ count: 12, dimensions: { gateway: "gw1", provider: "openai", model: "gpt-5.5" } }] }] } } } };
      return undefined;
    });
    const v = await cloudflareAiGatewayConnector.verify({ secret: "cf-token", accountId: "acct" });
    expect(v.ok).toBe(true);
    const r = await cloudflareAiGatewayConnector.collect({ secret: "cf-token", accountId: "acct" }, NOW);
    const g = r.facts.gateways[0]!;
    expect(g.authentication).toBe(true);
    expect(g.dlpEnabled).toBe(false);
    expect(g.hasByokKeys).toBe(true);
    expect(g.byokOnly).toBe(false);
    expect(g.spendLimitSet).toBeUndefined();
    expect(r.facts.usage30d?.[0]?.requests).toBe(12);
  });
});
