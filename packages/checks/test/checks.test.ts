import { describe, expect, it } from "vitest";
import { allChecks, genericAiAppendix, runChecks, scoreResults, type AIGatewayFacts, type AnthropicFacts, type OpenAIFacts } from "../src/index.js";

const NOW = "2026-11-03T00:00:00.000Z";

describe("catalogue integrity", () => {
  it("has unique ids and valid questionnaire references", () => {
    const ids = allChecks().map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
    const items = new Set(genericAiAppendix.map((q) => q.id));
    for (const c of allChecks()) for (const a of c.answers) if (a.framework === "generic-ai") expect(items.has(a.itemId), `${c.id} -> ${a.itemId}`).toBe(true);
  });
});

describe("openai", () => {
  const base: OpenAIFacts = {
    auditLogsEnabled: true,
    orgSpendLimitSet: true,
    projects: [
      {
        id: "p1",
        name: "prod",
        status: "active",
        createdAt: "2026-01-01T00:00:00Z",
        serviceAccountCount: 1,
        apiKeys: [{ id: "k1", name: "api", createdAt: "2026-06-01T00:00:00Z", lastUsedAt: "2026-11-02T00:00:00Z", ownerType: "service_account" }],
      },
    ],
    users: [{ id: "u1", email: "a@b.c", role: "owner", addedAt: "2026-01-01T00:00:00Z" }],
    invites: [],
    modelsUsed30d: ["gpt-5.5"],
    collectedAt: NOW,
  };

  it("passes a healthy org", () => {
    const r = runChecks("openai", base);
    expect(r.find((x) => x.id === "OAI-001")?.status).toBe("pass");
    expect(r.find((x) => x.id === "OAI-002")?.status).toBe("pass");
    expect(r.find((x) => x.id === "OAI-008")?.status).toBe("pass");
    expect(r.find((x) => x.id === "OAI-005")?.status).toBe("unverifiable");
  });

  it("flags stale and user-owned keys", () => {
    const f: OpenAIFacts = { ...base, projects: [{ ...base.projects[0]!, apiKeys: [{ id: "k2", name: "old", createdAt: "2025-01-01T00:00:00Z", lastUsedAt: "2026-01-01T00:00:00Z", ownerType: "user" }] }] };
    const r = runChecks("openai", f);
    expect(r.find((x) => x.id === "OAI-002")?.status).toBe("fail");
    expect(r.find((x) => x.id === "OAI-003")?.status).toBe("fail");
    expect(r.find((x) => x.id === "OAI-008")?.status).toBe("fail");
    expect(r.find((x) => x.id === "OAI-002")?.remediation).toBeTruthy();
  });
});

describe("anthropic", () => {
  it("flags keys in archived and default workspaces", () => {
    const f: AnthropicFacts = {
      users: [{ id: "u", email: "a@b.c", role: "admin" }],
      invites: [],
      workspaces: [
        { id: "w1", name: "Default", archivedAt: null, isDefault: true },
        { id: "w2", name: "old", archivedAt: "2026-05-01T00:00:00Z" },
      ],
      apiKeys: [
        { id: "a", name: "default-key", status: "active", createdAt: "2026-09-01T00:00:00Z", workspaceId: "w1" },
        { id: "b", name: "orphan", status: "active", createdAt: "2026-09-01T00:00:00Z", workspaceId: "w2" },
      ],
      collectedAt: NOW,
    };
    const r = runChecks("anthropic", f);
    expect(r.find((x) => x.id === "ANT-001")?.status).toBe("fail");
    expect(r.find((x) => x.id === "ANT-002")?.status).toBe("fail");
    expect(r.find((x) => x.id === "ANT-004")?.status).toBe("pass");
  });
});

describe("ai gateway", () => {
  it("scores an open gateway low", () => {
    const f: AIGatewayFacts = {
      gateways: [{ id: "default", authentication: false, collectLogs: true, dlpEnabled: false, rateLimitingLimit: 0, rateLimitingInterval: 0, hasByokKeys: false }],
      usage30d: [{ gateway: "default", provider: "openai", model: "gpt-5.5", requests: 10 }],
      collectedAt: NOW,
    };
    const r = runChecks("cloudflare-ai-gateway", f);
    expect(r.find((x) => x.id === "AIG-001")?.status).toBe("fail");
    expect(r.find((x) => x.id === "AIG-005")?.status).toBe("not_applicable");
    const s = scoreResults(r);
    expect(s.score).toBeLessThan(30);
  });
});
