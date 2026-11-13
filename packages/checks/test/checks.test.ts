import { describe, expect, it } from "vitest";
import { allChecks, genericAiAppendix, runChecks, scoreResults, type AIGatewayFacts, type AnthropicFacts, type OpenAIFacts, type OpenAIProjectFact } from "../src/index.js";

const NOW = "2026-11-03T00:00:00.000Z";

describe("catalogue integrity", () => {
  it("has unique ids and valid questionnaire references", () => {
    const ids = allChecks().map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
    const items = new Set(genericAiAppendix.map((q) => q.id));
    for (const c of allChecks()) for (const a of c.answers) if (a.framework === "generic-ai") expect(items.has(a.itemId), `${c.id} -> ${a.itemId}`).toBe(true);
  });

  it("every rule states its source and what it does not show", () => {
    for (const c of allChecks()) {
      expect(c.source.length, `${c.id} source`).toBeGreaterThan(10);
      expect(c.limits.length, `${c.id} limits`).toBeGreaterThan(20);
      if (c.provider !== "repo") expect(c.docsUrl, `${c.id} docsUrl`).toMatch(/^https:\/\//);
    }
  });

  it("API-backed rules name a provider call, not an invented field label", () => {
    for (const c of allChecks().filter((x) => x.provider !== "repo")) expect(c.source, c.id).toMatch(/\b(GET|POST) \//);
  });
});

const project = (over: Partial<OpenAIProjectFact> = {}): OpenAIProjectFact => ({
  id: "p1",
  name: "prod",
  status: "active",
  createdAt: "2026-01-01T00:00:00Z",
  serviceAccountCount: 1,
  apiKeys: [{ id: "k1", name: "api", createdAt: "2026-06-01T00:00:00Z", lastUsedAt: "2026-11-02T00:00:00Z", ownerType: "service_account" }],
  rateLimits: [{ model: "gpt-5.5", maxRequestsPer1Minute: 500, maxTokensPer1Minute: 30000 }, { model: "unused-model", maxRequestsPer1Minute: 1, maxTokensPer1Minute: 1 }],
  spendAlertCount: 1,
  spendLimitCents: 0,
  dataRetention: "zero_data_retention",
  modelPermissions: { mode: "allow_list", modelCount: 2 },
  ...over,
});

const openai = (over: Partial<OpenAIFacts> = {}): OpenAIFacts => ({
  auditLogEvents: 1,
  auditLogLatestAt: "2026-11-01T00:00:00.000Z",
  orgSpendLimitCents: 500000,
  projects: [project()],
  users: [{ id: "u1", email: "a@b.c", role: "owner", addedAt: "2026-01-01T00:00:00Z" }],
  invites: [],
  modelsUsed30d: ["gpt-5.5"],
  collectedAt: NOW,
  ...over,
});

const status = (f: OpenAIFacts, id: string) => runChecks("openai", f).find((x) => x.id === id)!;

describe("openai", () => {
  it("passes a healthy organization and publishes values, not names", () => {
    const r = runChecks("openai", openai());
    for (const id of ["OAI-001", "OAI-002", "OAI-003", "OAI-004", "OAI-005", "OAI-006", "OAI-007", "OAI-008", "OAI-011"]) expect(r.find((x) => x.id === id)?.status, id).toBe("pass");
    expect(status(openai(), "OAI-009").observed[0]).toBe("gpt-5.5: 500 requests per minute, 30,000 tokens per minute");
    expect(status(openai(), "OAI-009").observed.join(" ")).not.toContain("unused-model");
    // The table carries the same values as the sentence, one row per model, and nothing else.
    const limits = status(openai(), "OAI-009");
    expect(limits.table).toEqual({ subject: "Model", columns: ["Requests per minute", "Tokens per minute"], rows: [{ name: "gpt-5.5", values: ["500", "30,000"] }] });
    expect(limits.table!.rows.length).toBe(limits.observed.length);
    expect(status(openai(), "OAI-001").table).toBeUndefined();
    const published = r.flatMap((x) => x.observed).join(" ");
    expect(published).not.toContain("a@b.c");
    expect(published).not.toContain("prod");
    expect(published).not.toMatch(/\$|5000/);
  });

  it("flags stale and user-owned keys with remediation", () => {
    const f = openai({ projects: [project({ apiKeys: [{ id: "k2", name: "old", createdAt: "2025-01-01T00:00:00Z", lastUsedAt: "2026-01-01T00:00:00Z", ownerType: "user" }] })] });
    expect(status(f, "OAI-002").status).toBe("fail");
    expect(status(f, "OAI-003").status).toBe("fail");
    expect(status(f, "OAI-008").status).toBe("fail");
    expect(status(f, "OAI-002").remediation).toBeTruthy();
    expect(status(f, "OAI-002").evidence[0]).toBe("prod: old");
  });

  it("never passes from missing data", () => {
    const blind = openai({ auditLogEvents: undefined, orgSpendLimitCents: undefined, users: undefined, modelsUsed30d: undefined, projects: [project({ apiKeys: undefined, rateLimits: undefined, spendAlertCount: undefined, spendLimitCents: undefined, dataRetention: undefined, modelPermissions: undefined })] });
    for (const r of runChecks("openai", blind)) expect(r.status, r.id).toBe("unverifiable");
    const none = openai({ projects: undefined });
    for (const id of ["OAI-002", "OAI-003", "OAI-005", "OAI-006", "OAI-008", "OAI-009", "OAI-011"]) expect(status(none, id).status, id).toBe("unverifiable");
  });

  it("an empty audit history is a question for a person, not a pass or a fail", () => {
    const r = status(openai({ auditLogEvents: 0, auditLogLatestAt: null }), "OAI-001");
    expect(r.status).toBe("needs_review");
    expect(r.summary).toMatch(/may be off/);
  });

  it("ignores archived projects and reports no resources as not applicable", () => {
    const archivedOnly = openai({ projects: [project({ status: "archived", apiKeys: [{ id: "k", name: "ancient", createdAt: "2020-01-01T00:00:00Z", lastUsedAt: null, ownerType: "user" }] })] });
    for (const id of ["OAI-002", "OAI-003", "OAI-008"]) expect(status(archivedOnly, id).status, id).toBe("not_applicable");
    const noKeys = openai({ projects: [project({ apiKeys: [] })] });
    expect(status(noKeys, "OAI-002").status).toBe("not_applicable");
  });

  it("a spend alert does not satisfy the hard spend limit rule", () => {
    const alertsOnly = openai({ orgSpendLimitCents: 0, projects: [project({ spendAlertCount: 3, spendLimitCents: 0 })] });
    expect(status(alertsOnly, "OAI-004").status).toBe("fail");
    expect(status(alertsOnly, "OAI-011").status).toBe("pass");
    expect(status(alertsOnly, "OAI-011").limits).toMatch(/does not cap spending/);
    const projectLimit = openai({ orgSpendLimitCents: 0, projects: [project({ spendLimitCents: 20000 })] });
    expect(status(projectLimit, "OAI-004").status).toBe("pass");
  });

  it("a project without a hard limit needs review when the organization limit could not be read", () => {
    const unread = openai({ orgSpendLimitCents: undefined, projects: [project({ spendLimitCents: 0 })] });
    expect(status(unread, "OAI-004").status).toBe("needs_review");
    expect(status(openai({ orgSpendLimitCents: 0, projects: [project({ spendLimitCents: 0 })] }), "OAI-004").status).toBe("fail");
  });

  it("a partial usage read is not published as the whole model inventory", () => {
    const emptyPartial = openai({ modelsUsed30d: [], modelsUsed30dUnread: ["embeddings"] });
    expect(status(emptyPartial, "OAI-010").status).toBe("unverifiable");
    const partial = openai({ modelsUsed30d: ["gpt-5.5"], modelsUsed30dUnread: ["embeddings"] });
    expect(status(partial, "OAI-010").summary).toMatch(/embeddings usage could not be read/);
    const limits = openai({ modelsUsed30d: ["gpt-5.5"], modelsUsed30dUnread: ["embeddings"], projects: [project({ rateLimits: [{ model: "gpt-5.5", maxRequestsPer1Minute: 1 }, { model: "text-embedding-3-large", maxRequestsPer1Minute: 2 }] })] });
    expect(status(limits, "OAI-009").observed).toHaveLength(2);
  });

  it("an organization-level alert passes; a missing project alert with unread organization alerts needs review", () => {
    const orgAlert = openai({ orgSpendAlertCount: 2, projects: [project({ spendAlertCount: 0 })] });
    expect(status(orgAlert, "OAI-011").status).toBe("pass");
    const unknown = openai({ orgSpendAlertCount: undefined, projects: [project({ spendAlertCount: 0 })] });
    expect(status(unknown, "OAI-011").status).toBe("needs_review");
    const none = openai({ orgSpendAlertCount: 0, projects: [project({ spendAlertCount: 0 })] });
    expect(status(none, "OAI-011").status).toBe("fail");
  });

  it("an organization-level alert passes even when project alerts could not be read", () => {
    for (const projects of [undefined, [], [project({ spendAlertCount: undefined })]]) expect(status(openai({ orgSpendAlertCount: 2, projects }), "OAI-011").status).toBe("pass");
  });

  it("counts key age in exact time, not whole days", () => {
    const f = openai({ collectedAt: "2026-11-03T00:00:00.000Z", projects: [project({ apiKeys: [{ id: "k", name: "old", createdAt: "2025-11-02T02:00:00Z", lastUsedAt: "2026-08-04T02:00:00Z", ownerType: "service_account" }] })] });
    expect(status(f, "OAI-002").status).toBe("fail");
    expect(status(f, "OAI-003").status).toBe("fail");
  });

  it("matches rate limits to a used model and its dated snapshots only", () => {
    const f = openai({ modelsUsed30d: ["gpt-4o-mini-2024-07-18"], projects: [project({ rateLimits: [{ model: "gpt-4o", maxRequestsPer1Minute: 1 }, { model: "gpt-4o-mini", maxRequestsPer1Minute: 2 }] })] });
    expect(status(f, "OAI-009").observed).toEqual(["gpt-4o-mini: 2 requests per minute"]);
  });

  it("OpenAI saying no limit and no model permissions exist is a fail, not an unreadable setting", () => {
    const f = openai({ orgSpendLimitCents: 0, projects: [project({ spendLimitCents: 0, modelPermissions: { mode: "none", modelCount: 0 } })] });
    expect(status(f, "OAI-004").status).toBe("fail");
    expect(status(f, "OAI-005").status).toBe("fail");
  });

  it("inherited retention needs review; a deny-list is not an allow-list", () => {
    const f = openai({ projects: [project({ dataRetention: "organization_default", modelPermissions: { mode: "deny_list", modelCount: 1 } })] });
    expect(status(f, "OAI-006").status).toBe("needs_review");
    expect(status(f, "OAI-006").observed[0]).toContain("1 × organization_default");
    expect(status(f, "OAI-005").status).toBe("fail");
  });
});

describe("anthropic", () => {
  const base: AnthropicFacts = {
    users: [{ id: "u", email: "a@b.c", role: "admin" }],
    invites: [],
    workspaces: [
      { id: "w1", name: "Default", archivedAt: null, isDefault: true },
      { id: "w2", name: "old", archivedAt: "2026-05-01T00:00:00Z" },
      { id: "w3", name: "production", archivedAt: null },
    ],
    apiKeys: [
      { id: "a", name: "default-key", status: "active", createdAt: "2026-09-01T00:00:00Z", workspaceId: "w1" },
      { id: "b", name: "orphan", status: "active", createdAt: "2026-09-01T00:00:00Z", workspaceId: "w2" },
    ],
    collectedAt: NOW,
  };
  const by = (f: AnthropicFacts, id: string) => runChecks("anthropic", f).find((x) => x.id === id)!;

  it("flags keys in archived and default workspaces", () => {
    expect(by(base, "ANT-001").status).toBe("fail");
    expect(by(base, "ANT-002").status).toBe("fail");
    expect(by(base, "ANT-004").status).toBe("pass");
  });

  it("spend limits: not readable without the preview, Anthropic's tier cap is not a limit you set", () => {
    expect(by(base, "ANT-005").status).toBe("unverifiable");
    expect(by({ ...base, spendLimits: [{ scopeType: "usage_tier", hasAmount: true, enabled: true, period: "monthly" }] }, "ANT-005").status).toBe("fail");
    expect(by({ ...base, spendLimits: [{ scopeType: "workspace", hasAmount: true, enabled: true, period: "monthly" }] }, "ANT-005").status).toBe("pass");
  });

  it("no keys is not applicable; unreadable keys are not a pass", () => {
    expect(by({ ...base, apiKeys: [] }, "ANT-001").status).toBe("not_applicable");
    for (const id of ["ANT-001", "ANT-002", "ANT-003"]) expect(by({ ...base, apiKeys: undefined }, id).status, id).toBe("unverifiable");
    expect(by({ ...base, users: undefined }, "ANT-004").status).toBe("unverifiable");
  });
});

describe("ai gateway", () => {
  const gw = { id: "default", authentication: false, collectLogs: true, dlpEnabled: false, rateLimitingLimit: 0, rateLimitingInterval: 0, byokOnly: false, hasByokKeys: false, guardrailsEnabled: false, spendLimitSet: false };
  const by = (f: AIGatewayFacts, id: string) => runChecks("cloudflare-ai-gateway", f).find((x) => x.id === id)!;

  it("scores an open gateway low", () => {
    const f: AIGatewayFacts = { gateways: [gw], usage30d: [{ gateway: "default", provider: "openai", model: "gpt-5.5", requests: 10 }], collectedAt: NOW };
    expect(by(f, "AIG-001").status).toBe("fail");
    expect(by(f, "AIG-005").status).toBe("not_applicable");
    expect(scoreResults(runChecks("cloudflare-ai-gateway", f)).score).toBeLessThan(30);
  });

  it("publishes the rate limit value", () => {
    const f: AIGatewayFacts = { gateways: [{ ...gw, rateLimitingLimit: 600, rateLimitingInterval: 60 }], usage30d: [], collectedAt: NOW };
    expect(by(f, "AIG-003").observed[0]).toBe("Gateway rate limit: 600 requests per 60 seconds");
  });

  it("no gateways is not applicable, an unreadable list is not readable", () => {
    for (const r of runChecks("cloudflare-ai-gateway", { gateways: [], usage30d: [], collectedAt: NOW }).filter((x) => x.id !== "AIG-007")) expect(r.status, r.id).toBe("not_applicable");
    for (const r of runChecks("cloudflare-ai-gateway", { collectedAt: NOW })) expect(r.status, r.id).toBe("unverifiable");
  });

  it("unknown stored-key state is not readable", () => {
    expect(by({ gateways: [{ ...gw, hasByokKeys: undefined }], collectedAt: NOW }, "AIG-005").status).toBe("unverifiable");
  });
});

describe("scoring", () => {
  it("needs_review and unverifiable neither earn nor cost points", () => {
    const r = runChecks("openai", openai({ auditLogEvents: 0 }));
    const s = scoreResults(r);
    expect(s.counts.needs_review).toBe(1);
    expect(s.score).toBe(100);
  });
});
