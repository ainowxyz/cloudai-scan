import { describe, expect, it } from "vitest";
import { ANSWER_STATES, buildAnswers, completenessLine, genericAiAppendix, runChecks, type AnswerResultInput, type CheckResult, type OpenAIFacts } from "../src/index.js";

const NOW = "2026-11-03T00:00:00.000Z";
const toInput = (rs: CheckResult[], connection?: string): AnswerResultInput[] => rs.map((r) => ({ checkId: r.id, provider: r.provider, status: r.status, summary: r.summary, observed: r.observed, connection }));

const facts: OpenAIFacts = {
  auditLogEvents: 1,
  orgSpendLimitCents: 0,
  projects: [
    {
      id: "p",
      name: "prod",
      status: "active",
      createdAt: "2026-01-01T00:00:00Z",
      apiKeys: [{ id: "k", name: "jane-laptop", createdAt: "2025-01-01T00:00:00Z", lastUsedAt: "2026-11-01T00:00:00Z", ownerType: "user" }],
      rateLimits: [{ model: "gpt-5.5", maxRequestsPer1Minute: 500, maxTokensPer1Minute: 30000 }],
      spendAlertCount: 1,
      spendLimitCents: 0,
      dataRetention: "zero_data_retention",
      modelPermissions: { mode: "allow_list", modelCount: 1 },
    },
  ],
  users: [{ id: "u", email: "cto@example.com", role: "owner", addedAt: "2026-01-01T00:00:00Z" }],
  invites: [],
  modelsUsed30d: ["gpt-5.5", "text-embedding-3-large"],
  collectedAt: NOW,
};
const openai = toInput(runChecks("openai", facts));
const gateway = toInput(runChecks("cloudflare-ai-gateway", { gateways: [{ id: "g", authentication: true, collectLogs: true, dlpEnabled: true, rateLimitingLimit: 600, rateLimitingInterval: 60, byokOnly: true, hasByokKeys: true, guardrailsEnabled: false, spendLimitSet: true }], usage30d: [{ gateway: "g", provider: "openai", model: "gpt-5.5", requests: 5 }], collectedAt: NOW }));

const stmt = (itemId: string, answer: string) => ({ itemId, answer, attestedAt: "2026-10-20T00:00:00.000Z" });
const get = (b: ReturnType<typeof buildAnswers>, id: string) => b.answers.find((a) => a.id === id)!;

describe("buildAnswers", () => {
  it("returns all 25 questions in order, each with a valid state, for any input", () => {
    for (const input of [{ providers: [], results: [], statements: [] }, { providers: ["openai", "cloudflare-ai-gateway"], results: [...openai, ...gateway], statements: genericAiAppendix.map((q) => stmt(q.id, "Stated.")) }]) {
      const b = buildAnswers(input);
      expect(b.answers.map((a) => a.id)).toEqual(genericAiAppendix.map((q) => q.id));
      for (const a of b.answers) expect(ANSWER_STATES).toContain(a.state);
      expect(Object.values(b.counts).reduce((x, y) => x + y, 0)).toBe(25);
    }
  });

  it("empty data: every answer needs a statement and says what is needed", () => {
    const b = buildAnswers({ providers: [], results: [], statements: [] });
    expect(b.counts.needs_statement).toBe(25);
    expect(b.incomplete).toBe(25);
    for (const a of b.answers) {
      expect(a.observed).toEqual([]);
      expect(a.statement).toBeNull();
      expect(a.missing[0]!.length).toBeGreaterThan(20);
    }
  });

  it("GAI-02 names the connected providers instead of returning nothing", () => {
    const a = get(buildAnswers({ providers: ["openai", "anthropic", "cloudflare-ai-gateway"], results: gateway, statements: [] }), "GAI-02");
    expect(a.observed[0]!.text).toBe("Provider accounts connected and checked: OpenAI, Anthropic, Cloudflare AI Gateway.");
    expect(a.observed.some((o) => o.text.includes("Providers in gateway traffic, last 30 days: openai"))).toBe(true);
    expect(a.state).toBe("partial");
    expect(a.missing[0]).toMatch(/complete/);
  });

  it("GAI-03 separates the model inventory from the approval process", () => {
    const a = get(buildAnswers({ providers: ["openai"], results: openai, statements: [] }), "GAI-03");
    expect(a.observed[0]!.text).toContain("gpt-5.5, text-embedding-3-large");
    expect(a.state).toBe("partial");
    expect(a.missing[0]).toMatch(/approves a new model/);
    const done = get(buildAnswers({ providers: ["openai"], results: openai, statements: [stmt("GAI-03", "The CTO approves new models in a pull request.")] }), "GAI-03");
    expect(done.state).toBe("complete");
    expect(done.statement!.text).toMatch(/CTO/);
    expect(done.observed.map((o) => o.text).join(" ")).not.toMatch(/CTO/);
  });

  it("GAI-08 gives what was read and names the durations it cannot know", () => {
    const a = get(buildAnswers({ providers: ["openai", "cloudflare-ai-gateway"], results: [...openai, ...gateway], statements: [] }), "GAI-08");
    expect(a.observed.map((o) => o.text).join(" ")).toMatch(/zero_data_retention/);
    expect(a.observed.map((o) => o.text).join(" ")).toMatch(/logging is on for 1 of 1 gateway/);
    expect(a.missing[0]).toMatch(/in days at each provider and in your own systems/);
    expect(a.state).toBe("partial");
  });

  it("GAI-20 does not equate logs existing with a person reviewing them", () => {
    const a = get(buildAnswers({ providers: ["openai"], results: openai, statements: [] }), "GAI-20");
    expect(a.state).toBe("partial");
    expect(a.missing[0]).toMatch(/Who reviews the logs/);
    expect(a.observed[0]!.limits).toMatch(/does not show that anyone reviews/);
  });

  it("GAI-23 includes the limit values", () => {
    const a = get(buildAnswers({ providers: ["openai", "cloudflare-ai-gateway"], results: [...openai, ...gateway], statements: [] }), "GAI-23");
    const text = a.observed.map((o) => o.text).join(" ");
    expect(text).toContain("500 requests per minute");
    expect(text).toContain("600 requests per 60 seconds");
  });

  it("a passing check never completes an answer on its own", () => {
    const b = buildAnswers({ providers: ["openai", "cloudflare-ai-gateway"], results: [...openai, ...gateway], statements: [] });
    expect(b.counts.complete).toBe(0);
  });

  it("unknown values: unreadable checks are reported as not readable, never as evidence", () => {
    const blind = toInput(runChecks("openai", { collectedAt: NOW }));
    const a = get(buildAnswers({ providers: [], results: blind, statements: [] }), "GAI-12");
    expect(a.state).toBe("not_readable");
    expect(a.observed).toEqual([]);
    expect(a.missing.join(" ")).toMatch(/could not be read: OAI-002, OAI-008/);
    const stated = get(buildAnswers({ providers: [], results: blind, statements: [stmt("GAI-12", "Keys are issued by the platform team.")] }), "GAI-12");
    expect(stated.state).toBe("complete");
    expect(stated.missing.join(" ")).toMatch(/could not be read/);
  });

  it("multiple providers and two accounts of one provider stay distinguishable", () => {
    const b = buildAnswers({ providers: ["openai", "openai", "cloudflare-ai-gateway"], results: [...toInput(runChecks("openai", facts), "EU org"), ...toInput(runChecks("openai", facts), "US org"), ...gateway], statements: [] });
    const a = get(b, "GAI-03");
    expect(a.observed.filter((o) => o.checkId === "OAI-010").map((o) => o.text.split(":")[0])).toEqual(["OpenAI (EU org)", "OpenAI (US org)"]);
    expect(get(b, "GAI-02").observed[0]!.text).toBe("Provider accounts connected and checked: OpenAI, Cloudflare AI Gateway.");
  });

  it("conflicting statement: a statement next to a failing check is flagged for review", () => {
    const a = get(buildAnswers({ providers: ["openai"], results: openai, statements: [stmt("GAI-12", "All keys are owned by service accounts.")] }), "GAI-12");
    expect(a.state).toBe("complete");
    expect(a.flags[0]).toMatch(/OAI-008/);
    expect(a.flags[0]).toMatch(/does not contradict/);
  });

  it("a statement of 'Not applicable' sets the state", () => {
    const a = get(buildAnswers({ providers: [], results: [], statements: [stmt("GAI-25", "Not applicable: AI is the core of the product.")] }), "GAI-25");
    expect(a.state).toBe("not_applicable");
  });

  it("publishes no names, emails or amounts in observed text", () => {
    const b = buildAnswers({ providers: ["openai", "cloudflare-ai-gateway"], results: [...openai, ...gateway], statements: [] });
    const text = b.answers.flatMap((a) => a.observed.map((o) => o.text)).join(" ");
    expect(text).not.toMatch(/jane-laptop|cto@example\.com|prod\b/);
  });

  it("summarizes completeness", () => {
    const b = buildAnswers({ providers: ["openai"], results: openai, statements: [stmt("GAI-01", "Reply drafting.")] });
    expect(completenessLine(b.counts)).toMatch(/^1 complete, \d+ partial, \d+ need your statement, 0 not readable, 0 not applicable$/);
    expect(b.incomplete).toBe(24);
  });
});
