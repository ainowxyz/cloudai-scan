import type { AIGatewayFacts, CheckDefinition } from "./types.js";
import { agree, notApplicable, notReadable, num, pluralise, ofTotal } from "./util.js";

const API_DOCS = "https://developers.cloudflare.com/api/resources/ai_gateway/methods/get/";
const LIST = "GET /accounts/{account_id}/ai-gateway/gateways";

/** Shared guard: the gateway list must be readable and non-empty before a rule can pass or fail. */
function guard(f: AIGatewayFacts) {
  if (!f.gateways) return notReadable("AI Gateway settings could not be read with this API token.");
  if (f.gateways.length === 0) return notApplicable("No AI Gateway found in this account.");
  return null;
}

export const aiGatewayChecks: CheckDefinition<AIGatewayFacts>[] = [
  {
    id: "AIG-001",
    provider: "cloudflare-ai-gateway",
    title: "Gateways require authentication",
    description: "Reads the Authenticated Gateway setting on each gateway. Without it, anyone who knows the gateway URL can send requests through it.",
    severity: "high",
    source: `${LIST}: result[].authentication`,
    docsUrl: API_DOCS,
    limits: "Shows the gateway setting. It does not show how the gateway token is stored or who holds it.",
    remediation: "Enable Authenticated Gateway in each gateway's settings and send cf-aig-authorization from your app.",
    answers: [{ framework: "generic-ai", itemId: "GAI-04" }, { framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      const g = guard(f);
      if (g) return g;
      const open = f.gateways!.filter((x) => !x.authentication).map((x) => x.id);
      const observed = [`${ofTotal(f.gateways!.length - open.length, f.gateways!.length, "gateway", "requires", "require")} authentication`];
      return open.length === 0
        ? { status: "pass", summary: "Every gateway requires authentication.", evidence: f.gateways!.map((x) => x.id), observed }
        : { status: "fail", summary: `${pluralise(open.length, "gateway")} ${agree(open.length, "accepts", "accept")} unauthenticated requests.`, evidence: open, observed };
    },
  },
  {
    id: "AIG-002",
    provider: "cloudflare-ai-gateway",
    title: "Prompt logging is either off or covered by DLP",
    description: "Reads whether each gateway stores request and response logs, and whether Data Loss Prevention scanning is enabled on it. Stored prompts are customer data.",
    severity: "medium",
    source: `${LIST}: result[].collect_logs, result[].dlp.enabled`,
    docsUrl: API_DOCS,
    limits: "Shows whether logs are stored and whether DLP is on. It does not give a retention period in days, which DLP profiles apply, or what happens on a match.",
    remediation: "Turn off log collection, or enable DLP with the predefined profiles (free on all plans).",
    answers: [{ framework: "generic-ai", itemId: "GAI-08" }, { framework: "generic-ai", itemId: "GAI-09" }],
    evaluate: (f) => {
      const g = guard(f);
      if (g) return g;
      const logging = f.gateways!.filter((x) => x.collectLogs);
      const risky = logging.filter((x) => !x.dlpEnabled).map((x) => x.id);
      const observed = [
        `Prompt and response logging is on for ${logging.length} of ${pluralise(f.gateways!.length, "gateway")}`,
        `DLP scanning is on for ${f.gateways!.filter((x) => x.dlpEnabled).length} of ${pluralise(f.gateways!.length, "gateway")}`,
      ];
      return risky.length === 0
        ? { status: "pass", summary: logging.length === 0 ? "No gateway stores prompts or responses." : "Every gateway that stores prompts has DLP scanning on.", evidence: [], observed }
        : { status: "fail", summary: `${pluralise(risky.length, "gateway")} ${agree(risky.length, "stores", "store")} prompts without DLP scanning.`, evidence: risky, observed };
    },
  },
  {
    id: "AIG-003",
    provider: "cloudflare-ai-gateway",
    title: "Rate limiting is configured",
    description: "Reads the request limit and interval on each gateway.",
    severity: "medium",
    source: `${LIST}: result[].rate_limiting_limit, result[].rate_limiting_interval`,
    docsUrl: API_DOCS,
    limits: "This is the gateway-wide limit. It does not show per-user limits or limits on the company's own endpoints.",
    remediation: "Set a rate limit and interval on each gateway.",
    answers: [{ framework: "generic-ai", itemId: "GAI-23" }],
    evaluate: (f) => {
      const g = guard(f);
      if (g) return g;
      const none = f.gateways!.filter((x) => !x.rateLimitingLimit || !x.rateLimitingInterval).map((x) => x.id);
      const values = [...new Set(f.gateways!.filter((x) => x.rateLimitingLimit && x.rateLimitingInterval).map((x) => `${num(x.rateLimitingLimit)} requests per ${num(x.rateLimitingInterval)} seconds`))];
      const observed = [...(values.length ? [`Gateway rate limit: ${values.join("; ")}`] : []), ...(none.length ? [`${pluralise(none.length, "gateway")} with no rate limit`] : [])];
      return none.length === 0
        ? { status: "pass", summary: "Every gateway has a rate limit.", evidence: [], observed }
        : { status: "fail", summary: `${pluralise(none.length, "gateway")} ${agree(none.length, "has", "have")} no rate limit.`, evidence: none, observed };
    },
  },
  {
    id: "AIG-004",
    provider: "cloudflare-ai-gateway",
    title: "Gateway spend limits are set",
    description: "Reads the spend limit rules on each gateway. When a rule's budget is used up the gateway rejects further requests until the window resets.",
    severity: "medium",
    source: `${LIST}: result[].spend_limits.enabled, result[].spend_limits.rules[].enabled`,
    docsUrl: "https://developers.cloudflare.com/ai-gateway/features/spend-limits/",
    limits: "Shows that at least one enabled spend rule exists per gateway. Amounts are not published, and Cloudflare applies these limits only to models with known pricing.",
    remediation: "Add a spend limit on each gateway that routes to third-party providers.",
    answers: [{ framework: "generic-ai", itemId: "GAI-22" }],
    evaluate: (f) => {
      const g = guard(f);
      if (g) return g;
      const none = f.gateways!.filter((x) => !x.spendLimitSet).map((x) => x.id);
      const observed = [`${ofTotal(f.gateways!.length - none.length, f.gateways!.length, "gateway", "has", "have")} an enabled spend limit`];
      return none.length === 0
        ? { status: "pass", summary: "Every gateway has an enabled spend limit.", evidence: [], observed }
        : { status: "fail", summary: `${pluralise(none.length, "gateway")} ${agree(none.length, "has", "have")} no enabled spend limit.`, evidence: none, observed };
    },
  },
  {
    id: "AIG-005",
    provider: "cloudflare-ai-gateway",
    title: "Stored provider keys cannot fall back to Unified Billing",
    description: "For gateways that store your own provider keys, reads whether the gateway requires them. Without that setting a request can fall back to Cloudflare's Unified Billing credits.",
    severity: "low",
    source: `${LIST}: result[].byok_only; GET /accounts/{account_id}/ai-gateway/gateways/{gateway_id}/provider_configs: count`,
    docsUrl: "https://developers.cloudflare.com/ai-gateway/configuration/bring-your-own-keys/",
    limits: "Counts stored provider key configurations; key values are never read. It does not show which provider each request used.",
    remediation: "Enable 'Require provider credentials' (byok_only) on gateways with stored keys.",
    answers: [{ framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      const g = guard(f);
      if (g) return g;
      const withKeys = f.gateways!.filter((x) => x.hasByokKeys);
      const unknown = f.gateways!.filter((x) => x.hasByokKeys === undefined);
      const lax = withKeys.filter((x) => !x.byokOnly).map((x) => x.id);
      const observed = [`${pluralise(withKeys.length, "gateway")} with stored provider keys; ${withKeys.length - lax.length} require them`];
      if (lax.length > 0) return { status: "fail", summary: `${pluralise(lax.length, "gateway")} with stored keys ${agree(lax.length, "allows", "allow")} fallback to Unified Billing.`, evidence: lax, observed };
      if (unknown.length > 0) return notReadable(`Stored provider keys could not be listed for ${pluralise(unknown.length, "gateway")}.`);
      if (withKeys.length === 0) return notApplicable("No gateway stores provider keys.");
      return { status: "pass", summary: "Every gateway with stored keys requires them.", evidence: [], observed };
    },
  },
  {
    id: "AIG-006",
    provider: "cloudflare-ai-gateway",
    title: "Guardrails are configured",
    description: "Reads whether each gateway has Guardrails categories set for prompts or responses. Guardrails flag or block content in those categories.",
    severity: "low",
    source: `${LIST}: result[].guardrails.prompt, result[].guardrails.response`,
    docsUrl: "https://developers.cloudflare.com/ai-gateway/features/guardrails/",
    limits: "Shows that at least one category is configured. It does not show which categories, or whether they flag or block.",
    remediation: "Enable Guardrails on gateways serving end-user traffic (flag mode first).",
    answers: [{ framework: "generic-ai", itemId: "GAI-17" }],
    evaluate: (f) => {
      const g = guard(f);
      if (g) return g;
      const off = f.gateways!.filter((x) => !x.guardrailsEnabled).map((x) => x.id);
      const observed = [`Guardrails configured on ${f.gateways!.length - off.length} of ${pluralise(f.gateways!.length, "gateway")}`];
      return off.length === 0
        ? { status: "pass", summary: "Every gateway has Guardrails configured.", evidence: [], observed }
        : { status: "fail", summary: `${pluralise(off.length, "gateway")} ${agree(off.length, "has", "have")} no Guardrails configured.`, evidence: off, observed };
    },
  },
  {
    id: "AIG-007",
    provider: "cloudflare-ai-gateway",
    title: "Providers and models seen in gateway traffic",
    description: "Lists the providers and models in AI Gateway analytics for the last 30 days. This is an inventory, not a pass or fail rule.",
    severity: "info",
    source: "POST /client/v4/graphql (read-only query): aiGatewayRequestsAdaptiveGroups { dimensions { provider model } }, last 30 days",
    docsUrl: "https://developers.cloudflare.com/ai-gateway/observability/analytics/",
    limits: "Covers traffic that went through AI Gateway. Calls made to a provider directly do not appear here.",
    remediation: "",
    answers: [{ framework: "generic-ai", itemId: "GAI-02" }, { framework: "generic-ai", itemId: "GAI-03" }, { framework: "generic-ai", itemId: "GAI-04" }, { framework: "generic-ai", itemId: "GAI-21" }],
    evaluate: (f) => {
      if (f.usage30d === undefined) return notReadable("AI Gateway analytics could not be read with this API token.");
      const providers = [...new Set(f.usage30d.map((u) => u.provider))];
      const pairs = [...new Set(f.usage30d.map((u) => `${u.provider}/${u.model}`))];
      if (pairs.length === 0) return { status: "pass", summary: "No traffic went through AI Gateway in the last 30 days.", evidence: [], observed: ["No gateway traffic in the last 30 days"] };
      return {
        status: "pass",
        summary: `${pluralise(providers.length, "provider")} and ${pluralise(pairs.length, "model")} seen in gateway traffic in the last 30 days.`,
        evidence: [],
        observed: [`Providers in gateway traffic, last 30 days: ${providers.join(", ")}`, `Models in gateway traffic, last 30 days: ${pairs.slice(0, 25).join(", ")}`],
      };
    },
  },
];
