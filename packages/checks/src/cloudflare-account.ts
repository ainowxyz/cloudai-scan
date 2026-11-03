import { looksLikeMcp, PROVIDER_KEY_NAME } from "./patterns.js";
import type { CheckDefinition, CloudflareAccountFacts, WorkerFact } from "./types.js";
import { pluralise } from "./util.js";

const AI_BINDING_TYPES = new Set(["ai", "vectorize", "ai_search", "autorag"]);

function isAiWorker(w: WorkerFact): boolean {
  return w.bindings.some((b) => AI_BINDING_TYPES.has(b.type)) || w.secretNames.some((n) => PROVIDER_KEY_NAME.test(n));
}

function hostOf(route: string): string {
  return route.replace(/^https?:\/\//, "").split("/")[0]!.replace(/^\*\./, "");
}

export const cloudflareAccountChecks: CheckDefinition<CloudflareAccountFacts>[] = [
  {
    id: "WRK-001",
    provider: "cloudflare-account",
    title: "Workers hold provider API keys directly",
    description: "A Worker secret named like a provider key means the Worker calls the provider itself, outside AI Gateway's logging, limits and key storage.",
    severity: "medium",
    remediation: "Store the key in AI Gateway (BYOK) and call the gateway endpoint; delete the Worker secret.",
    answers: [{ framework: "generic-ai", itemId: "GAI-04" }, { framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      const hits = f.workers.flatMap((w) => w.secretNames.filter((n) => PROVIDER_KEY_NAME.test(n)).map((n) => `${w.name}: ${n}`));
      return hits.length === 0
        ? { status: "pass", summary: "No Worker secrets look like provider API keys.", evidence: [] }
        : { status: "fail", summary: `${pluralise(hits.length, "provider key secret")} on Workers.`, evidence: hits.slice(0, 15) };
    },
  },
  {
    id: "WRK-002",
    provider: "cloudflare-account",
    title: "AI Workers have observability enabled",
    description: "Without Workers Logs there is no record of what an AI Worker did when something goes wrong.",
    severity: "low",
    remediation: "Set observability.enabled = true in the Worker's configuration.",
    answers: [{ framework: "generic-ai", itemId: "GAI-20" }],
    evaluate: (f) => {
      const ai = f.workers.filter(isAiWorker);
      if (ai.length === 0) return { status: "not_applicable", summary: "No AI Workers found.", evidence: [] };
      const known = ai.filter((w) => w.observabilityEnabled !== undefined);
      if (known.length === 0) return { status: "unverifiable", summary: "Observability settings not readable.", evidence: [] };
      const off = known.filter((w) => !w.observabilityEnabled).map((w) => w.name);
      return off.length === 0
        ? { status: "pass", summary: `All ${pluralise(ai.length, "AI Worker")} have observability on.`, evidence: [] }
        : { status: "fail", summary: `${pluralise(off.length, "AI Worker")} without observability.`, evidence: off.slice(0, 15) };
    },
  },
  {
    id: "WRK-003",
    provider: "cloudflare-account",
    title: "AI Workers are not exposed only on workers.dev",
    description: "A workers.dev hostname has no zone-level WAF rules, rate limiting rules or Access policies.",
    severity: "medium",
    remediation: "Attach a custom domain or route on a zone and disable the workers.dev subdomain for the Worker.",
    answers: [{ framework: "generic-ai", itemId: "GAI-23" }],
    evaluate: (f) => {
      const ai = f.workers.filter(isAiWorker);
      if (ai.length === 0) return { status: "not_applicable", summary: "No AI Workers found.", evidence: [] };
      const known = ai.filter((w) => w.workersDevEnabled !== undefined);
      if (known.length === 0) return { status: "unverifiable", summary: "workers.dev settings not readable.", evidence: [] };
      const exposed = known.filter((w) => w.workersDevEnabled && w.routes.length === 0 && w.customDomains.length === 0).map((w) => w.name);
      return exposed.length === 0
        ? { status: "pass", summary: "AI Workers are served through zones or have workers.dev disabled.", evidence: [] }
        : { status: "fail", summary: `${pluralise(exposed.length, "AI Worker")} reachable only via workers.dev.`, evidence: exposed.slice(0, 15) };
    },
  },
  {
    id: "WRK-004",
    provider: "cloudflare-account",
    title: "MCP servers are behind Cloudflare Access",
    description: "An MCP server reachable without Access lets any client enumerate and call its tools.",
    severity: "high",
    remediation: "Create a Cloudflare Access application for the MCP hostname, or require OAuth inside the server.",
    answers: [{ framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      const mcp = f.workers.filter((w) => looksLikeMcp(w.name) || w.bindings.some((b) => looksLikeMcp(b.name)));
      if (mcp.length === 0) return { status: "not_applicable", summary: "No Workers look like MCP servers.", evidence: [] };
      if (f.accessHostnames === undefined) return { status: "unverifiable", summary: `${pluralise(mcp.length, "MCP-like Worker")} found; Access applications not readable.`, evidence: mcp.map((w) => w.name) };
      const access = new Set(f.accessHostnames.map((h) => h.toLowerCase()));
      const open = mcp.filter((w) => {
        const hosts = [...w.routes.map(hostOf), ...w.customDomains];
        if (w.workersDevEnabled) return true;
        return hosts.some((h) => !access.has(h.toLowerCase()));
      });
      return open.length === 0
        ? { status: "pass", summary: "All MCP-like Workers are behind Access.", evidence: mcp.map((w) => w.name) }
        : { status: "fail", summary: `${pluralise(open.length, "MCP-like Worker")} reachable without Access.`, evidence: open.map((w) => `${w.name}: ${[...w.routes, ...w.customDomains, ...(w.workersDevEnabled ? ["workers.dev"] : [])].join(", ")}`) };
    },
  },
  {
    id: "ZONE-001",
    provider: "cloudflare-account",
    title: "LLM endpoints have a rate limiting rule",
    description: "Cloudflare labels LLM endpoints automatically (cf-llm). Each should be covered by a rate limiting rule.",
    severity: "high",
    remediation: "Create a rate limiting rule matching the endpoint path (1 rule is included on Free, 2 on Pro, 5 on Business).",
    answers: [{ framework: "generic-ai", itemId: "GAI-23" }],
    evaluate: (f) => {
      const zones = f.zones.filter((z) => z.llmOperations.length > 0);
      if (zones.length === 0) return { status: "not_applicable", summary: "No LLM-labelled endpoints found on your zones.", evidence: [] };
      const uncovered: string[] = [];
      let unverifiable = false;
      for (const z of zones) {
        if (z.rateLimitExpressions === undefined) {
          unverifiable = true;
          continue;
        }
        for (const op of z.llmOperations) {
          const covered = z.rateLimitExpressions.some((e) => e.includes(op.endpoint) || e.includes(op.host) || /http\.request\.uri\.path/.test(e) === false && e.trim() === "true");
          if (!covered) uncovered.push(`${z.name}: ${op.method} ${op.host}${op.endpoint}`);
        }
      }
      if (uncovered.length === 0 && unverifiable) return { status: "unverifiable", summary: "Rate limiting rules not readable for some zones.", evidence: [] };
      return uncovered.length === 0
        ? { status: "pass", summary: "Every LLM endpoint matches a rate limiting rule.", evidence: [] }
        : { status: "fail", summary: `${pluralise(uncovered.length, "LLM endpoint")} without a rate limiting rule.`, evidence: uncovered.slice(0, 15) };
    },
  },
  {
    id: "ZONE-002",
    provider: "cloudflare-account",
    title: "Zones with LLM endpoints have bot protection or custom rules",
    description: "LLM endpoints attract scripted abuse; at least Bot Fight Mode or a custom rule should apply.",
    severity: "medium",
    remediation: "Enable Bot Fight Mode (Free) or Super Bot Fight Mode, or add a custom rule challenging non-browser traffic to the endpoint.",
    answers: [{ framework: "generic-ai", itemId: "GAI-23" }],
    evaluate: (f) => {
      const zones = f.zones.filter((z) => z.llmOperations.length > 0);
      if (zones.length === 0) return { status: "not_applicable", summary: "No LLM-labelled endpoints found on your zones.", evidence: [] };
      const known = zones.filter((z) => z.botFightMode !== undefined || z.customRuleExpressions !== undefined);
      if (known.length === 0) return { status: "unverifiable", summary: "Bot and custom rule settings not readable.", evidence: [] };
      const bare = known.filter((z) => !z.botFightMode && (z.customRuleExpressions?.length ?? 0) === 0).map((z) => z.name);
      return bare.length === 0
        ? { status: "pass", summary: "All zones with LLM endpoints have bot protection or custom rules.", evidence: [] }
        : { status: "fail", summary: `${pluralise(bare.length, "zone")} with LLM endpoints and no bot protection or custom rules.`, evidence: bare };
    },
  },
  {
    id: "ACC-001",
    provider: "cloudflare-account",
    title: "AI surface inventory",
    description: "Workers using AI bindings or provider keys, and zones with LLM endpoints.",
    severity: "info",
    remediation: "",
    answers: [{ framework: "generic-ai", itemId: "GAI-21" }],
    evaluate: (f) => {
      const ai = f.workers.filter(isAiWorker);
      const ops = f.zones.reduce((n, z) => n + z.llmOperations.length, 0);
      return { status: "pass", summary: `${pluralise(ai.length, "AI Worker")}, ${pluralise(ops, "LLM endpoint")} across ${pluralise(f.zones.length, "zone")}.`, evidence: ai.map((w) => w.name).slice(0, 25) };
    },
  },
];
