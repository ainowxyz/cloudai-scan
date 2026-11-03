import type { CloudflareAccountFacts, WorkerFact, ZoneFact } from "@cloudaisecurity/checks";
import { getJson, ProviderHttpError, type CollectResult, type Connector, type Credentials, type VerifyResult } from "./types.js";

const API = "https://api.cloudflare.com/client/v4";
type CfList<T> = { success: boolean; result: T[]; result_info?: { total_count?: number; total_pages?: number } };
type CfOne<T> = { success: boolean; result: T };

/**
 * Inventory of AI-related surfaces in a Cloudflare account: Workers (bindings, secret names, routes),
 * zones (LLM-labelled operations, rate limiting and custom rules, Bot Fight Mode) and Access hostnames.
 * Needs: Workers Scripts Read, Workers Routes Read, Zone Read, Zone WAF Read, API Gateway Read, Access: Apps and Policies Read.
 */
export const cloudflareAccountConnector: Connector<"cloudflare-account"> = {
  provider: "cloudflare-account",
  credentialGuide: {
    label: "Cloudflare API token (read-only inventory)",
    docsUrl: "https://dash.cloudflare.com/profile/api-tokens",
    scope: "Account: Workers Scripts Read, Access: Apps and Policies Read. Zone (all zones): Zone Read, Workers Routes Read, Zone WAF Read, API Gateway Read, Zone Settings Read.",
  },

  async verify(creds: Credentials): Promise<VerifyResult> {
    if (!creds.accountId) return { ok: false, permissions: [], error: "Account ID is required." };
    const headers = { authorization: `Bearer ${creds.secret}` };
    try {
      await getJson<CfList<unknown>>(`${API}/accounts/${creds.accountId}/workers/scripts`, headers);
      return { ok: true, permissions: ["workers:read"] };
    } catch (e) {
      const status = e instanceof ProviderHttpError ? e.status : 0;
      return { ok: false, permissions: [], error: status === 403 || status === 401 ? "Token lacks Workers Scripts Read on this account." : `Cloudflare returned ${status || "a network error"}.` };
    }
  },

  async collect(creds: Credentials, now = new Date()): Promise<CollectResult<"cloudflare-account">> {
    const headers = { authorization: `Bearer ${creds.secret}` };
    const acct = creds.accountId!;
    const errors: CollectResult<"cloudflare-account">["errors"] = [];
    const endpoints: string[] = [];
    const attempt = async <T>(endpoint: string, fn: () => Promise<T>): Promise<T | undefined> => {
      endpoints.push(endpoint);
      try {
        return await fn();
      } catch (e) {
        errors.push({ endpoint, status: e instanceof ProviderHttpError ? e.status : 0, message: e instanceof Error ? e.message : String(e) });
        return undefined;
      }
    };

    // Workers
    const scripts = (await attempt("GET /workers/scripts", () => getJson<CfList<any>>(`${API}/accounts/${acct}/workers/scripts`, headers)))?.result ?? [];
    const domains = (await attempt("GET /workers/domains", () => getJson<CfList<any>>(`${API}/accounts/${acct}/workers/domains`, headers)))?.result ?? [];
    const workers: WorkerFact[] = [];
    for (const s of scripts.slice(0, 200)) {
      const settings = await attempt(`GET /workers/scripts/${s.id}/settings`, () => getJson<CfOne<any>>(`${API}/accounts/${acct}/workers/scripts/${s.id}/settings`, headers));
      const subdomain = await attempt(`GET /workers/scripts/${s.id}/subdomain`, () => getJson<CfOne<{ enabled: boolean }>>(`${API}/accounts/${acct}/workers/scripts/${s.id}/subdomain`, headers));
      const bindings: { type: string; name: string }[] = (settings?.result?.bindings ?? []).map((b: any) => ({ type: String(b.type), name: String(b.name ?? b.binding ?? "") }));
      workers.push({
        name: s.id,
        modifiedAt: s.modified_on,
        bindings: bindings.filter((b) => b.type !== "secret_text"),
        secretNames: bindings.filter((b) => b.type === "secret_text").map((b) => b.name),
        routes: [],
        customDomains: domains.filter((d: any) => d.service === s.id).map((d: any) => String(d.hostname)),
        workersDevEnabled: subdomain?.result?.enabled,
        observabilityEnabled: settings?.result?.observability === undefined ? undefined : Boolean(settings.result.observability?.enabled),
      });
    }

    // Zones
    const zonesRaw = (await attempt("GET /zones", () => getJson<CfList<any>>(`${API}/zones?per_page=50&account.id=${acct}`, headers)))?.result ?? [];
    const zones: ZoneFact[] = [];
    for (const z of zonesRaw) {
      const routes = (await attempt(`GET /zones/${z.id}/workers/routes`, () => getJson<CfList<any>>(`${API}/zones/${z.id}/workers/routes`, headers)))?.result ?? [];
      for (const r of routes) {
        const w = workers.find((x) => x.name === r.script);
        if (w) w.routes.push(String(r.pattern));
      }
      const ops = await attempt(`GET /zones/${z.id}/api_gateway/operations?label=cf-llm`, () => getJson<CfList<any>>(`${API}/zones/${z.id}/api_gateway/operations?per_page=200&feature=label&label=cf-llm`, headers));
      const llmOperations = (ops?.result ?? [])
        .filter((o: any) => o.features?.label?.labels?.includes?.("cf-llm") || (Array.isArray(o.labels) && o.labels.includes("cf-llm")) || ops?.result?.length)
        .map((o: any) => ({ method: String(o.method), host: String(o.host), endpoint: String(o.endpoint) }));
      const rl = await attempt(`GET /zones/${z.id}/rulesets/phases/http_ratelimit/entrypoint`, () => getJson<CfOne<{ rules?: { expression: string; enabled: boolean }[] }>>(`${API}/zones/${z.id}/rulesets/phases/http_ratelimit/entrypoint`, headers));
      const cr = await attempt(`GET /zones/${z.id}/rulesets/phases/http_request_firewall_custom/entrypoint`, () => getJson<CfOne<{ rules?: { expression: string; enabled: boolean }[] }>>(`${API}/zones/${z.id}/rulesets/phases/http_request_firewall_custom/entrypoint`, headers));
      const bfm = await attempt(`GET /zones/${z.id}/bot_management`, () => getJson<CfOne<{ fight_mode?: boolean; sbfm_definitely_automated?: string }>>(`${API}/zones/${z.id}/bot_management`, headers));
      // A 404 on a ruleset entrypoint means "no rules yet", which is readable and empty.
      const lastErr = () => errors.at(-1);
      const rlExpressions = rl ? (rl.result.rules ?? []).filter((r) => r.enabled !== false).map((r) => r.expression) : lastErr()?.status === 404 && lastErr()?.endpoint.includes("http_ratelimit") ? [] : undefined;
      const crExpressions = cr ? (cr.result.rules ?? []).filter((r) => r.enabled !== false).map((r) => r.expression) : lastErr()?.status === 404 && lastErr()?.endpoint.includes("firewall_custom") ? [] : undefined;
      zones.push({
        id: z.id,
        name: z.name,
        plan: z.plan?.name,
        llmOperations,
        rateLimitExpressions: rlExpressions,
        customRuleExpressions: crExpressions,
        botFightMode: bfm ? Boolean(bfm.result.fight_mode || (bfm.result.sbfm_definitely_automated && bfm.result.sbfm_definitely_automated !== "allow")) : undefined,
      });
    }

    // Access applications
    const apps = await attempt("GET /access/apps", () => getJson<CfList<any>>(`${API}/accounts/${acct}/access/apps?per_page=100`, headers));
    const accessHostnames = apps ? apps.result.flatMap((a: any) => [a.domain, ...(a.self_hosted_domains ?? [])].filter(Boolean).map((d: string) => d.split("/")[0]!)) : undefined;

    return { facts: { workers, zones, accessHostnames, collectedAt: now.toISOString() }, errors, endpoints };
  },
};
