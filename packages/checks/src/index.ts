import { aiGatewayChecks } from "./aigateway.js";
import { anthropicChecks } from "./anthropic.js";
import { cloudflareAccountChecks } from "./cloudflare-account.js";
import { openaiChecks } from "./openai.js";
import { repoChecks } from "./repo.js";
import type { CheckDefinition, CheckResult, FactsFor, Provider } from "./types.js";

export * from "./types.js";
export * from "./questionnaires.js";
export * from "./patterns.js";
export { openaiChecks, anthropicChecks, aiGatewayChecks, cloudflareAccountChecks, repoChecks };

export const CHECKS_VERSION = "2026.11.1";

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
        status: r.status,
        summary: r.summary,
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
        status: "unverifiable",
        summary: `Check could not run: ${err instanceof Error ? err.message : String(err)}`,
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

/** Share of weighted, verifiable checks that pass. Info and not_applicable are excluded. */
export function scoreResults(results: CheckResult[]): Score {
  const counts = { pass: 0, fail: 0, not_applicable: 0, unverifiable: 0 } as Record<CheckResult["status"], number>;
  let earned = 0;
  let possible = 0;
  for (const r of results) {
    counts[r.status]++;
    const w = WEIGHT[r.severity];
    if (w === 0 || r.status === "not_applicable" || r.status === "unverifiable") continue;
    possible += w;
    if (r.status === "pass") earned += w;
  }
  return { score: possible === 0 ? 0 : Math.round((earned / possible) * 100), counts };
}
