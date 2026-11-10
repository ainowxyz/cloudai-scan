import { looksLikeMcp, PROVIDER_KEY_NAME } from "./patterns.js";
import type { CheckDefinition, CloudflareAccountFacts, WorkerFact } from "./types.js";
import { agree, notApplicable, notReadable, pluralise } from "./util.js";

const AI_BINDING_TYPES = new Set(["ai", "vectorize", "ai_search", "autorag"]);
const SETTINGS = "GET /accounts/{account_id}/workers/scripts/{script_name}/settings";

function isAiWorker(w: WorkerFact): boolean {
  return w.bindings.some((b) => AI_BINDING_TYPES.has(b.type)) || w.secretNames.some((n) => PROVIDER_KEY_NAME.test(n));
}

function hostOf(route: string): string {
  return route.replace(/^https?:\/\//, "").split("/")[0]!.replace(/^\*\./, "");
}

const noWorkers = () => notReadable("Workers could not be read with this API token.");
const noZones = () => notReadable("Zones could not be read with this API token.");

export const cloudflareAccountChecks: CheckDefinition<CloudflareAccountFacts>[] = [
  {
    id: "WRK-001",
    provider: "cloudflare-account",
    title: "No Worker secret is named like a provider API key",
    description: "Reads the names of each Worker's secrets and flags names such as OPENAI_API_KEY. A match suggests the Worker holds a provider key and may call the provider itself instead of going through a gateway.",
    severity: "medium",
    source: `${SETTINGS}: result.bindings[] where type = secret_text, name only`,
    docsUrl: "https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/settings/",
    limits: "Matches secret names only; values are never read. A match does not prove the Worker bypasses a gateway, and no match does not prove that no Worker holds a provider key under another name.",
    remediation: "Store the key in AI Gateway (BYOK) and call the gateway endpoint; delete the Worker secret.",
    answers: [{ framework: "generic-ai", itemId: "GAI-04" }, { framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      if (!f.workers) return noWorkers();
      if (f.workers.length === 0) return notApplicable("No Workers found in this account.");
      const hits = f.workers.flatMap((w) => w.secretNames.filter((n) => PROVIDER_KEY_NAME.test(n)).map((n) => `${w.name}: ${n}`));
      const holders = new Set(hits.map((h) => h.split(":")[0])).size;
      const observed = [`${holders} of ${pluralise(f.workers.length, "Worker")} ${agree(holders, "has", "have")} a secret named like a provider API key`];
      return hits.length === 0
        ? { status: "pass", summary: "No Worker secret is named like a provider API key.", evidence: [], observed }
        : { status: "fail", summary: `${pluralise(hits.length, "Worker secret")} ${agree(hits.length, "is", "are")} named like a provider API key.`, evidence: hits.slice(0, 15), observed };
    },
  },
  {
    id: "WRK-002",
    provider: "cloudflare-account",
    title: "AI Workers have observability enabled",
    description: "For Workers with an AI binding or a provider-key secret, reads whether Workers Logs is on. Without it there is no record of what the Worker did when something goes wrong.",
    severity: "low",
    source: `${SETTINGS}: result.observability.enabled, result.bindings[].type`,
    docsUrl: "https://developers.cloudflare.com/workers/observability/logs/workers-logs/",
    limits: "Shows that logging is switched on. It does not show what is logged, how long logs are kept, or whether anyone reviews them.",
    remediation: "Set observability.enabled = true in the Worker's configuration.",
    answers: [{ framework: "generic-ai", itemId: "GAI-20" }],
    evaluate: (f) => {
      if (!f.workers) return noWorkers();
      const ai = f.workers.filter(isAiWorker);
      if (ai.length === 0) return notApplicable("No Workers with an AI binding or provider-key secret found.");
      const known = ai.filter((w) => w.observabilityEnabled !== undefined);
      const off = known.filter((w) => !w.observabilityEnabled).map((w) => w.name);
      const observed = [`Workers Logs is on for ${known.length - off.length} of ${pluralise(ai.length, "AI Worker")}`];
      if (off.length > 0) return { status: "fail", summary: `${pluralise(off.length, "AI Worker")} ${agree(off.length, "has", "have")} observability off.`, evidence: off.slice(0, 15), observed };
      if (known.length < ai.length) return notReadable(`Observability settings could not be read for ${pluralise(ai.length - known.length, "AI Worker")}.`);
      return { status: "pass", summary: ai.length === 1 ? "The AI Worker has observability on." : `All ${ai.length} AI Workers have observability on.`, evidence: [], observed };
    },
  },
  {
    id: "WRK-003",
    provider: "cloudflare-account",
    title: "AI Workers are not exposed only on workers.dev",
    description: "For AI Workers, reads whether the workers.dev hostname is enabled and whether the Worker also has a route or custom domain. A workers.dev hostname has no zone-level WAF, rate limiting rules or Access policies.",
    severity: "medium",
    source: "GET /accounts/{account_id}/workers/scripts/{script_name}/subdomain: result.enabled; GET /zones/{zone_id}/workers/routes: pattern; GET /accounts/{account_id}/workers/domains: hostname",
    docsUrl: "https://developers.cloudflare.com/workers/configuration/routing/workers-dev/",
    limits: "Shows how the Worker is reachable. It does not show authentication or limits implemented inside the Worker.",
    remediation: "Attach a custom domain or route on a zone and disable the workers.dev subdomain for the Worker.",
    answers: [{ framework: "generic-ai", itemId: "GAI-23" }],
    evaluate: (f) => {
      if (!f.workers) return noWorkers();
      const ai = f.workers.filter(isAiWorker);
      if (ai.length === 0) return notApplicable("No Workers with an AI binding or provider-key secret found.");
      const known = ai.filter((w) => w.workersDevEnabled !== undefined);
      const exposed = known.filter((w) => w.workersDevEnabled && w.routes.length === 0 && w.customDomains.length === 0).map((w) => w.name);
      const observed = [`${exposed.length} of ${pluralise(ai.length, "AI Worker")} reachable only on workers.dev`];
      if (exposed.length > 0) return { status: "fail", summary: `${pluralise(exposed.length, "AI Worker")} ${agree(exposed.length, "is", "are")} reachable only on workers.dev.`, evidence: exposed.slice(0, 15), observed };
      if (known.length < ai.length) return notReadable(`workers.dev settings could not be read for ${pluralise(ai.length - known.length, "AI Worker")}.`);
      return { status: "pass", summary: "Every AI Worker is served through a zone or has workers.dev disabled.", evidence: [], observed };
    },
  },
  {
    id: "WRK-004",
    provider: "cloudflare-account",
    title: "A Cloudflare Access application covers each MCP-like Worker",
    description: "Finds Workers whose name or bindings look like an MCP server, then checks whether every hostname they are served on belongs to a Cloudflare Access application. Access is one way to authenticate an MCP server; OAuth inside the server is another, and cannot be read from the account.",
    severity: "high",
    source: "GET /accounts/{account_id}/access/apps: result[].domain, self_hosted_domains; Workers routes, custom domains and workers.dev setting",
    docsUrl: "https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/",
    limits: "When no Access application is found, this result says exactly that. It does not mean the server is unauthenticated: a server that implements its own OAuth flow is protected without Access. Add a note to the result describing the control in use.",
    remediation: "Create a Cloudflare Access application for the MCP hostname, or require OAuth inside the server and record that in a note on this result.",
    answers: [],
    evaluate: (f) => {
      if (!f.workers) return noWorkers();
      const mcp = f.workers.filter((w) => looksLikeMcp(w.name) || w.bindings.some((b) => looksLikeMcp(b.name)));
      if (mcp.length === 0) return notApplicable("No Workers look like MCP servers.");
      if (f.accessHostnames === undefined) return notReadable(`${pluralise(mcp.length, "MCP-like Worker")} found; Access applications could not be read with this API token.`, mcp.map((w) => w.name));
      const access = new Set(f.accessHostnames.map((h) => h.toLowerCase()));
      const open = mcp.filter((w) => {
        const hosts = [...w.routes.map(hostOf), ...w.customDomains];
        if (w.workersDevEnabled) return true;
        return hosts.length === 0 || hosts.some((h) => !access.has(h.toLowerCase()));
      });
      const observed = [`A Cloudflare Access application covers ${mcp.length - open.length} of ${pluralise(mcp.length, "MCP-like Worker")}`];
      return open.length === 0
        ? { status: "pass", summary: "Every MCP-like Worker hostname belongs to a Cloudflare Access application.", evidence: mcp.map((w) => w.name), observed }
        : {
            status: "needs_review",
            summary: `No Cloudflare Access application covers ${pluralise(open.length, "MCP-like Worker")}. Authentication inside the Worker, such as OAuth, cannot be read from the account.`,
            evidence: open.map((w) => `${w.name}: ${[...w.routes, ...w.customDomains, ...(w.workersDevEnabled ? ["workers.dev"] : [])].join(", ")}`),
            observed,
          };
    },
  },
  {
    id: "ZONE-001",
    provider: "cloudflare-account",
    title: "LLM endpoints have a rate limiting rule",
    description: "Cloudflare labels endpoints that serve LLM traffic (the cf-llm label in API Shield). For each labelled endpoint this looks for an enabled rate limiting rule whose expression mentions its path or host.",
    severity: "high",
    source: "GET /zones/{zone_id}/api_gateway/operations: features/labels containing cf-llm; GET /zones/{zone_id}/rulesets/phases/http_ratelimit/entrypoint: rules[].expression, enabled",
    docsUrl: "https://developers.cloudflare.com/waf/rate-limiting-rules/",
    limits: "Covers only endpoints Cloudflare has labelled cf-llm. The match is on the rule expression text, so a rule that covers the endpoint in another way is not recognized, and rate limits implemented in your application are not read.",
    remediation: "Create a rate limiting rule matching the endpoint path (1 rule is included on Free, 2 on Pro, 5 on Business).",
    answers: [{ framework: "generic-ai", itemId: "GAI-23" }],
    evaluate: (f) => {
      if (!f.zones) return noZones();
      const zones = f.zones.filter((z) => z.llmOperations.length > 0);
      if (zones.length === 0) return notApplicable("Cloudflare has labelled no endpoints on your zones as LLM endpoints.");
      const uncovered: string[] = [];
      let total = 0;
      let unread = 0;
      for (const z of zones) {
        if (z.rateLimitExpressions === undefined) {
          unread++;
          continue;
        }
        for (const op of z.llmOperations) {
          total++;
          const covered = z.rateLimitExpressions.some((e) => e.includes(op.endpoint) || e.includes(op.host) || e.trim() === "true");
          if (!covered) uncovered.push(`${z.name}: ${op.method} ${op.host}${op.endpoint}`);
        }
      }
      const observed = total ? [`${total - uncovered.length} of ${pluralise(total, "labelled LLM endpoint")} matched by a rate limiting rule`] : [];
      if (uncovered.length > 0) return { status: "fail", summary: `${pluralise(uncovered.length, "LLM endpoint")} ${agree(uncovered.length, "is", "are")} not matched by a rate limiting rule.`, evidence: uncovered.slice(0, 15), observed };
      if (unread > 0) return notReadable(`Rate limiting rules could not be read for ${pluralise(unread, "zone")}.`);
      return { status: "pass", summary: "Every labelled LLM endpoint is matched by a rate limiting rule.", evidence: [], observed };
    },
  },
  {
    id: "ZONE-002",
    provider: "cloudflare-account",
    title: "Zones with LLM endpoints have bot protection or custom rules",
    description: "For zones with labelled LLM endpoints, reads whether Bot Fight Mode is on or at least one enabled custom WAF rule exists.",
    severity: "medium",
    source: "GET /zones/{zone_id}/bot_management: result.fight_mode, sbfm_definitely_automated; GET /zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint: rules[].enabled",
    docsUrl: "https://developers.cloudflare.com/bots/get-started/",
    limits: "Shows that some bot protection or custom rule exists on the zone. It does not show that the rule applies to the LLM endpoint.",
    remediation: "Enable Bot Fight Mode (Free) or Super Bot Fight Mode, or add a custom rule challenging non-browser traffic to the endpoint.",
    answers: [{ framework: "generic-ai", itemId: "GAI-23" }],
    evaluate: (f) => {
      if (!f.zones) return noZones();
      const zones = f.zones.filter((z) => z.llmOperations.length > 0);
      if (zones.length === 0) return notApplicable("Cloudflare has labelled no endpoints on your zones as LLM endpoints.");
      const known = zones.filter((z) => z.botFightMode !== undefined && z.customRuleExpressions !== undefined);
      const bare = known.filter((z) => !z.botFightMode && z.customRuleExpressions!.length === 0).map((z) => z.name);
      const observed = [`${known.length - bare.length} of ${pluralise(zones.length, "zone")} with LLM endpoints ${agree(known.length - bare.length, "has", "have")} bot protection or a custom rule`];
      if (bare.length > 0) return { status: "fail", summary: `${pluralise(bare.length, "zone")} with LLM endpoints ${agree(bare.length, "has", "have")} neither bot protection nor a custom rule.`, evidence: bare, observed };
      if (known.length < zones.length) return notReadable(`Bot and custom rule settings could not be read for ${pluralise(zones.length - known.length, "zone")}.`);
      return { status: "pass", summary: "Every zone with LLM endpoints has bot protection or a custom rule.", evidence: [], observed };
    },
  },
  {
    id: "ACC-001",
    provider: "cloudflare-account",
    title: "AI surface inventory",
    description: "Counts Workers with an AI binding or provider-key secret, and endpoints Cloudflare has labelled as LLM endpoints. This is an inventory, not a pass or fail rule.",
    severity: "info",
    source: `${SETTINGS}: result.bindings[].type; GET /zones/{zone_id}/api_gateway/operations: features/labels containing cf-llm`,
    docsUrl: "https://developers.cloudflare.com/api-shield/management-and-monitoring/endpoint-labels/",
    limits: "Counts what this Cloudflare account contains. AI features hosted elsewhere do not appear.",
    remediation: "",
    answers: [{ framework: "generic-ai", itemId: "GAI-21" }],
    evaluate: (f) => {
      if (!f.workers || !f.zones) return notReadable("Workers or zones could not be read with this API token.");
      const ai = f.workers.filter(isAiWorker);
      const ops = f.zones.reduce((n, z) => n + z.llmOperations.length, 0);
      const text = `${pluralise(ai.length, "AI Worker")} and ${pluralise(ops, "labelled LLM endpoint")} across ${pluralise(f.zones.length, "zone")}`;
      return { status: "pass", summary: `${text}.`, evidence: ai.map((w) => w.name).slice(0, 25), observed: [text] };
    },
  },
];
