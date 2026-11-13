import type { AIGatewayFact, AIGatewayFacts } from "@cloudaisecurity/checks";
import { cloudflareListAll, getJson, ProviderHttpError, type CollectResult, type Connector, type Credentials, type VerifyResult } from "./types.js";

const API = "https://api.cloudflare.com/client/v4";

type CfList<T> = { success: boolean; result: T[]; result_info?: { total_count?: number; page?: number; per_page?: number } };

export const cloudflareAiGatewayConnector: Connector<"cloudflare-ai-gateway"> = {
  provider: "cloudflare-ai-gateway",
  credentialGuide: {
    label: "Cloudflare API token, read-only",
    docsUrl: "https://dash.cloudflare.com/profile/api-tokens",
    readOnlyByProvider: true,
    scope: "Account: AI Gateway Read, Account Analytics Read. Nothing else. Cloudflare enforces these read-only permissions.",
    use: "We send GET requests to api.cloudflare.com, plus one read-only analytics query. The same token can also carry the Cloudflare account scopes.",
  },

  async verify(creds: Credentials): Promise<VerifyResult> {
    if (!creds.accountId) return { ok: false, permissions: [], error: "Account ID is required." };
    const headers = { authorization: `Bearer ${creds.secret}` };
    try {
      const v = await getJson<{ result: { status: string } }>(`${API}/user/tokens/verify`, headers);
      if (v.result.status !== "active") return { ok: false, permissions: [], error: `Token status is ${v.result.status}.` };
      await getJson<CfList<unknown>>(`${API}/accounts/${creds.accountId}/ai-gateway/gateways?per_page=1`, headers);
      return { ok: true, permissions: ["ai-gateway:read"] };
    } catch (e) {
      const status = e instanceof ProviderHttpError ? e.status : 0;
      return { ok: false, permissions: [], error: status === 403 ? "Token lacks AI Gateway Read on this account." : `Cloudflare returned ${status || "a network error"}.` };
    }
  },

  async collect(creds: Credentials, now = new Date()): Promise<CollectResult<"cloudflare-ai-gateway">> {
    const headers = { authorization: `Bearer ${creds.secret}` };
    const acct = creds.accountId!;
    const errors: CollectResult<"cloudflare-ai-gateway">["errors"] = [];
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

    const list = await attempt("GET /ai-gateway/gateways", () => cloudflareListAll<any>(`${API}/accounts/${acct}/ai-gateway/gateways`, headers));
    let gateways: AIGatewayFact[] | undefined;
    if (list) {
      gateways = [];
      for (const g of list) {
        const keys = await attempt(`GET /ai-gateway/gateways/${g.id}/provider_configs`, () => getJson<CfList<unknown>>(`${API}/accounts/${acct}/ai-gateway/gateways/${g.id}/provider_configs?per_page=1`, headers));
        const count = (o: unknown) => (o && typeof o === "object" ? Object.keys(o).length : 0);
        // Optional settings that are absent from the gateway object are not configured.
        gateways.push({
          id: String(g.id),
          authentication: g.authentication === true,
          collectLogs: g.collect_logs === true,
          dlpEnabled: g.dlp?.enabled === true,
          rateLimitingLimit: Number(g.rate_limiting_limit ?? 0),
          rateLimitingInterval: Number(g.rate_limiting_interval ?? 0),
          byokOnly: g.byok_only === true,
          hasByokKeys: keys === undefined ? undefined : (keys.result_info?.total_count ?? keys.result?.length ?? 0) > 0,
          guardrailsEnabled: count(g.guardrails?.prompt) + count(g.guardrails?.response) > 0,
          spendLimitSet: g.spend_limits?.enabled === true && Array.isArray(g.spend_limits?.rules) && g.spend_limits.rules.some((r: any) => r?.enabled !== false),
        });
      }
    }

    const start = new Date(now.getTime() - 30 * 86_400_000).toISOString();
    const query = `query($acct:String!,$start:Time!){viewer{accounts(filter:{accountTag:$acct}){aiGatewayRequestsAdaptiveGroups(limit:500,filter:{datetimeHour_geq:$start}){count dimensions{gateway provider model}}}}}`;
    const gql = await attempt("POST /graphql aiGatewayRequestsAdaptiveGroups", () =>
      getJson<{ data?: { viewer?: { accounts?: { aiGatewayRequestsAdaptiveGroups: { count: number; dimensions: { gateway: string; provider: string; model: string } }[] }[] } } }>(`${API}/graphql`, headers, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query, variables: { acct, start } }),
      }),
    );
    const groups = gql?.data?.viewer?.accounts?.[0]?.aiGatewayRequestsAdaptiveGroups;
    const usage30d = groups ? groups.map((g) => ({ gateway: g.dimensions.gateway, provider: g.dimensions.provider, model: g.dimensions.model, requests: g.count })) : undefined;

    return { facts: { gateways, usage30d, collectedAt: now.toISOString() }, errors, endpoints };
  },
};
