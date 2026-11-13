import type { CloudflareAccountFacts, WorkerFact, ZoneFact } from "@cloudaisecurity/checks";
import { cloudflareListAll, getJson, ProviderHttpError, type CollectResult, type Connector, type Credentials, type VerifyResult } from "./types.js";

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
    label: "Cloudflare API token, read-only",
    docsUrl: "https://dash.cloudflare.com/profile/api-tokens",
    readOnlyByProvider: true,
    scope: "Account: Workers Scripts Read, Access: Apps and Policies Read. Zone (all zones): Zone Read, Workers Routes Read, Zone WAF Read, API Gateway Read, Bot Management Read. Cloudflare enforces these read-only permissions.",
    use: "We send only GET requests to api.cloudflare.com. Secret names are read; secret values cannot be read through this API.",
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
    const scripts = (await attempt("GET /workers/scripts", () => getJson<CfList<any>>(`${API}/accounts/${acct}/workers/scripts`, headers)))?.result;
    const domains = (await attempt("GET /workers/domains", () => getJson<CfList<any>>(`${API}/accounts/${acct}/workers/domains`, headers)))?.result ?? [];
    let workers: WorkerFact[] | undefined;
    if (scripts) {
      workers = [];
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
          observabilityEnabled: settings === undefined ? undefined : settings.result?.observability?.enabled === true,
        });
      }
    }

    // Zones
    const zonesRaw = await attempt("GET /zones", () => cloudflareListAll<any>(`${API}/zones?account.id=${acct}`, headers));
    let zones: ZoneFact[] | undefined;
    const hasLlmLabel = (o: any): boolean => {
      const labels: unknown[] = [...(Array.isArray(o.labels) ? o.labels : []), ...(Array.isArray(o.features?.label?.labels) ? o.features.label.labels : [])];
      return labels.some((l) => l === "cf-llm" || (l && typeof l === "object" && (l as { name?: string }).name === "cf-llm"));
    };
    if (zonesRaw) {
      zones = [];
      for (const z of zonesRaw) {
        const routes = (await attempt(`GET /zones/${z.id}/workers/routes`, () => getJson<CfList<any>>(`${API}/zones/${z.id}/workers/routes`, headers)))?.result ?? [];
        for (const r of routes) {
          const w = workers?.find((x) => x.name === r.script);
          if (w) w.routes.push(String(r.pattern));
        }
        // Cloudflare's own count of operations carrying the cf-llm managed label. No readable label, no claim.
        const label = await attempt(`GET /zones/${z.id}/api_gateway/labels/managed/cf-llm`, () =>
          getJson<CfOne<{ mapped_resources?: { operations?: number } }>>(`${API}/zones/${z.id}/api_gateway/labels/managed/cf-llm?with_mapped_resource_counts=true`, headers),
        );
        const counted = label?.result?.mapped_resources?.operations;
        const llmOperationCount = typeof counted === "number" ? counted : undefined;
        if (label && llmOperationCount === undefined) errors.push({ endpoint: `GET /zones/${z.id}/api_gateway/labels/managed/cf-llm`, status: 200, message: `The response carried no operation count (mapped_resources: ${label.result?.mapped_resources === undefined ? "absent" : JSON.stringify(label.result.mapped_resources).slice(0, 80)}).` });
        let llmOperations: ZoneFact["llmOperations"] = llmOperationCount === 0 ? [] : undefined;
        if (llmOperationCount && llmOperationCount > 0) {
          // The operations list does not document a label field. If it carries one, use it; otherwise the list stays unread.
          const ops = await attempt(`GET /zones/${z.id}/api_gateway/operations`, () => getJson<CfList<any>>(`${API}/zones/${z.id}/api_gateway/operations?per_page=50`, headers));
          const labelled = (ops?.result ?? []).filter(hasLlmLabel).map((o: any) => ({ method: String(o.method), host: String(o.host), endpoint: String(o.endpoint) }));
          if (labelled.length === llmOperationCount) llmOperations = labelled;
        }
        // A 404 on a ruleset entrypoint means "no rules yet", which is readable and empty.
        const ruleset = async (phase: string): Promise<string[] | undefined> => {
          const before = errors.length;
          const res = await attempt(`GET /zones/${z.id}/rulesets/phases/${phase}/entrypoint`, () => getJson<CfOne<{ rules?: { expression: string; enabled?: boolean }[] }>>(`${API}/zones/${z.id}/rulesets/phases/${phase}/entrypoint`, headers));
          if (res) return (res.result.rules ?? []).filter((r) => r.enabled !== false).map((r) => r.expression);
          if (errors[before]?.status === 404) {
            errors.splice(before, 1);
            return [];
          }
          return undefined;
        };
        const rlExpressions = await ruleset("http_ratelimit");
        const crExpressions = await ruleset("http_request_firewall_custom");
        const bfm = await attempt(`GET /zones/${z.id}/bot_management`, () => getJson<CfOne<{ fight_mode?: boolean; sbfm_definitely_automated?: string }>>(`${API}/zones/${z.id}/bot_management`, headers));
        zones.push({
          id: z.id,
          name: z.name,
          plan: z.plan?.name,
          llmOperationCount,
          llmOperations,
          rateLimitExpressions: rlExpressions,
          customRuleExpressions: crExpressions,
          botFightMode: bfm ? Boolean(bfm.result.fight_mode || (bfm.result.sbfm_definitely_automated && bfm.result.sbfm_definitely_automated !== "allow")) : undefined,
        });
      }
    }

    // Access applications
    const apps = await attempt("GET /access/apps", () => cloudflareListAll<any>(`${API}/accounts/${acct}/access/apps`, headers, 100));
    const accessHostnames = apps ? apps.flatMap((a: any) => [a.domain, ...(a.self_hosted_domains ?? [])].filter(Boolean).map((d: string) => d.split("/")[0]!)) : undefined;

    return { facts: { workers, zones, accessHostnames, collectedAt: now.toISOString() }, errors, endpoints };
  },
};
