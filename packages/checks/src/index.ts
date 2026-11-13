import { aiGatewayChecks } from "./aigateway.js";
import { anthropicChecks } from "./anthropic.js";
import { cloudflareAccountChecks } from "./cloudflare-account.js";
import { openaiChecks } from "./openai.js";
import { repoChecks } from "./repo.js";
import type { CheckDefinition, CheckResult, FactsFor, Provider } from "./types.js";

export * from "./types.js";
export * from "./questionnaires.js";
export * from "./patterns.js";
export * from "./answers.js";
export { openaiChecks, anthropicChecks, aiGatewayChecks, cloudflareAccountChecks, repoChecks };

export const CHECKS_VERSION = "2026.11.5";

/** Display names for providers, used wherever a result is shown to a person. */
export const PROVIDER_LABEL: Record<Provider, string> = {
  openai: "OpenAI",
  anthropic: "Anthropic",
  "cloudflare-ai-gateway": "Cloudflare AI Gateway",
  "cloudflare-account": "Cloudflare account",
  repo: "Repository",
};

const registry: { [P in Provider]: CheckDefinition<FactsFor<P>>[] } = {
  openai: openaiChecks,
  anthropic: anthropicChecks,
  "cloudflare-ai-gateway": aiGatewayChecks,
  "cloudflare-account": cloudflareAccountChecks,
  repo: repoChecks,
};

export function checksFor<P extends Provider>(provider: P): CheckDefinition<FactsFor<P>>[] {
  return registry[provider] as CheckDefinition<FactsFor<P>>[];
}

export function allChecks(): CheckDefinition<any>[] {
  return [...openaiChecks, ...anthropicChecks, ...aiGatewayChecks, ...cloudflareAccountChecks, ...repoChecks];
}

/** Evaluate every check for a provider against collected facts. Never throws: a broken rule degrades to `unverifiable`. */
export function runChecks<P extends Provider>(provider: P, facts: FactsFor<P>): CheckResult[] {
  return checksFor(provider).map((def) => {
    try {
      const r = def.evaluate(facts);
      return {
        id: def.id,
        provider: def.provider,
        severity: def.severity,
        title: def.title,
        source: def.source,
        docsUrl: def.docsUrl,
        limits: def.limits,
        status: r.status,
        summary: r.summary,
        observed: r.observed ?? [],
        ...(r.table ? { table: r.table } : {}),
        evidence: r.evidence,
        remediation: r.status === "fail" ? def.remediation : undefined,
        answers: def.answers,
      };
    } catch (err) {
      return {
        id: def.id,
        provider: def.provider,
        severity: def.severity,
        title: def.title,
        source: def.source,
        docsUrl: def.docsUrl,
        limits: def.limits,
        status: "unverifiable",
        summary: `Check could not run: ${err instanceof Error ? err.message : String(err)}`,
        observed: [],
        evidence: [],
        answers: def.answers,
      };
    }
  });
}

export interface Score {
  score: number; // 0-100
  counts: Record<CheckResult["status"], number>;
}

const WEIGHT = { high: 3, medium: 2, low: 1, info: 0 } as const;

/** Share of weighted checks with a pass or fail result that pass. Info, not_applicable, unverifiable and needs_review are excluded. */
export function scoreResults(results: CheckResult[]): Score {
  const counts = { pass: 0, fail: 0, needs_review: 0, not_applicable: 0, unverifiable: 0 } as Record<CheckResult["status"], number>;
  let earned = 0;
  let possible = 0;
  for (const r of results) {
    counts[r.status]++;
    const w = WEIGHT[r.severity];
    if (w === 0 || r.status === "not_applicable" || r.status === "unverifiable" || r.status === "needs_review") continue;
    possible += w;
    if (r.status === "pass") earned += w;
  }
  return { score: possible === 0 ? 0 : Math.round((earned / possible) * 100), counts };
}
