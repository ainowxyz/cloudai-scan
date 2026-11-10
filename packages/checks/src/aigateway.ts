import type { AIGatewayFacts, CheckDefinition } from "./types.js";
import { agree, pluralise } from "./util.js";

export const aiGatewayChecks: CheckDefinition<AIGatewayFacts>[] = [
  {
    id: "AIG-001",
    provider: "cloudflare-ai-gateway",
    title: "Gateways require authentication",
    description: "An unauthenticated gateway lets anyone who knows the URL spend your provider credits.",
    severity: "high",
    source: "GET /accounts/{id}/ai-gateway/gateways: authentication",
    remediation: "Enable Authenticated Gateway in each gateway's settings and send cf-aig-authorization from your app.",
    answers: [{ framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      const open = f.gateways.filter((g) => !g.authentication).map((g) => g.id);
      return open.length === 0
        ? { status: "pass", summary: "All gateways require authentication.", evidence: f.gateways.map((g) => g.id) }
        : { status: "fail", summary: `${pluralise(open.length, "gateway")} ${agree(open.length, "accepts", "accept")} unauthenticated requests.`, evidence: open };
    },
  },
  {
    id: "AIG-002",
    provider: "cloudflare-ai-gateway",
    title: "Prompt logging is either off or covered by DLP",
    description: "Stored prompts and responses are customer data; if kept, they should be scanned.",
    severity: "medium",
    source: "GET /accounts/{id}/ai-gateway/gateways: collect_logs, dlp.enabled",
    remediation: "Turn off log collection, or enable DLP with the predefined profiles (free on all plans).",
    answers: [{ framework: "generic-ai", itemId: "GAI-08" }, { framework: "generic-ai", itemId: "GAI-09" }],
    evaluate: (f) => {
      const risky = f.gateways.filter((g) => g.collectLogs && g.dlpEnabled === false).map((g) => g.id);
      const unknown = f.gateways.filter((g) => g.collectLogs && g.dlpEnabled === undefined);
      if (risky.length === 0 && unknown.length > 0) return { status: "unverifiable", summary: "DLP state not readable for logging gateways.", evidence: unknown.map((g) => g.id) };
      return risky.length === 0
        ? { status: "pass", summary: "No gateway stores prompts without DLP.", evidence: [] }
        : { status: "fail", summary: `${pluralise(risky.length, "gateway")} ${agree(risky.length, "stores", "store")} prompts without DLP.`, evidence: risky };
    },
  },
  {
    id: "AIG-003",
    provider: "cloudflare-ai-gateway",
    title: "Rate limiting is configured",
    description: "Per-gateway rate limits contain abuse and runaway loops.",
    severity: "medium",
    source: "GET /accounts/{id}/ai-gateway/gateways: rate_limiting_limit, rate_limiting_interval",
    remediation: "Set a rate limit and interval on each gateway.",
    answers: [{ framework: "generic-ai", itemId: "GAI-23" }],
    evaluate: (f) => {
      const none = f.gateways.filter((g) => !g.rateLimitingLimit || !g.rateLimitingInterval).map((g) => g.id);
      return none.length === 0
        ? { status: "pass", summary: "All gateways have a rate limit.", evidence: [] }
        : { status: "fail", summary: `${pluralise(none.length, "gateway")} without a rate limit.`, evidence: none };
    },
  },
  {
    id: "AIG-004",
    provider: "cloudflare-ai-gateway",
    title: "Spend limits are set for third-party providers",
    description: "Dollar-based limits stop a leaked key or a bug from producing a surprise bill.",
    severity: "medium",
    source: "GET /accounts/{id}/ai-gateway/gateways: spend limits",
    remediation: "Add a spend limit on each gateway that routes to third-party providers.",
    answers: [{ framework: "generic-ai", itemId: "GAI-22" }],
    evaluate: (f) => {
      const known = f.gateways.filter((g) => g.spendLimitSet !== undefined);
      if (known.length === 0) return { status: "unverifiable", summary: "Spend limit configuration not readable.", evidence: [] };
      const none = known.filter((g) => !g.spendLimitSet).map((g) => g.id);
      return none.length === 0
        ? { status: "pass", summary: "All gateways have a spend limit.", evidence: [] }
        : { status: "fail", summary: `${pluralise(none.length, "gateway")} without a spend limit.`, evidence: none };
    },
  },
  {
    id: "AIG-005",
    provider: "cloudflare-ai-gateway",
    title: "Stored provider keys cannot fall back to Unified Billing",
    description: "With BYOK keys stored, byok_only prevents silent billing to Cloudflare credits.",
    severity: "low",
    source: "GET /accounts/{id}/ai-gateway/gateways: byok_only; GET …/gateways/{id}/byok",
    remediation: "Enable 'Require provider credentials' (byok_only) on gateways with stored keys.",
    answers: [{ framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      const withKeys = f.gateways.filter((g) => g.hasByokKeys);
      if (withKeys.length === 0) return { status: "not_applicable", summary: "No stored provider keys.", evidence: [] };
      const lax = withKeys.filter((g) => g.byokOnly === false).map((g) => g.id);
      return lax.length === 0
        ? { status: "pass", summary: "All gateways with stored keys require provider credentials.", evidence: [] }
        : { status: "fail", summary: `${pluralise(lax.length, "gateway")} ${agree(lax.length, "allows", "allow")} Unified Billing fallback.`, evidence: lax };
    },
  },
  {
    id: "AIG-006",
    provider: "cloudflare-ai-gateway",
    title: "Guardrails are enabled",
    description: "Guardrails flag or block harmful prompts and responses across providers.",
    severity: "low",
    source: "GET /accounts/{id}/ai-gateway/gateways: guardrails",
    remediation: "Enable Guardrails on gateways serving end-user traffic (flag mode first).",
    answers: [{ framework: "generic-ai", itemId: "GAI-17" }],
    evaluate: (f) => {
      const known = f.gateways.filter((g) => g.guardrailsEnabled !== undefined);
      if (known.length === 0) return { status: "unverifiable", summary: "Guardrails configuration not readable.", evidence: [] };
      const off = known.filter((g) => !g.guardrailsEnabled).map((g) => g.id);
      return off.length === 0
        ? { status: "pass", summary: "Guardrails enabled on all gateways.", evidence: [] }
        : { status: "fail", summary: `${pluralise(off.length, "gateway")} without guardrails.`, evidence: off };
    },
  },
  {
    id: "AIG-007",
    provider: "cloudflare-ai-gateway",
    title: "Providers and models used in the last 30 days",
    description: "Inventory from AI Gateway analytics.",
    severity: "info",
    source: "GraphQL aiGatewayRequestsAdaptiveGroups: provider, model, last 30 days",
    remediation: "",
    answers: [{ framework: "generic-ai", itemId: "GAI-03" }, { framework: "generic-ai", itemId: "GAI-04" }],
    evaluate: (f) => {
      if (f.usage30d === undefined) return { status: "unverifiable", summary: "Analytics not readable.", evidence: [] };
      const pairs = [...new Set(f.usage30d.map((u) => `${u.provider}/${u.model}`))];
      return { status: "pass", summary: `${pluralise(pairs.length, "provider/model pair")} used in the last 30 days.`, evidence: pairs.slice(0, 25) };
    },
  },
];
