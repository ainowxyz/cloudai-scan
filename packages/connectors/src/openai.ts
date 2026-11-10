import type { OpenAIFacts, OpenAIProjectFact } from "@cloudaisecurity/checks";
import { daysAgoUnix, getJson, isoFromUnix, ProviderHttpError, type CollectResult, type Connector, type Credentials, type VerifyResult } from "./types.js";

const BASE = "https://api.openai.com/v1/organization";

type Page<T> = { data: T[]; has_more?: boolean; last_id?: string };

async function listAll<T>(path: string, headers: Record<string, string>, max = 1000): Promise<T[]> {
  const out: T[] = [];
  let after: string | undefined;
  for (let i = 0; i < 20 && out.length < max; i++) {
    const url = `${BASE}${path}${path.includes("?") ? "&" : "?"}limit=100${after ? `&after=${encodeURIComponent(after)}` : ""}`;
    const page = await getJson<Page<T>>(url, headers);
    out.push(...page.data);
    if (!page.has_more || !page.last_id) break;
    after = page.last_id;
  }
  return out;
}

export const openaiConnector: Connector<"openai"> = {
  provider: "openai",
  credentialGuide: {
    label: "OpenAI Admin API key",
    docsUrl: "https://platform.openai.com/settings/organization/admin-keys",
    readOnlyByProvider: false,
    scope: "OpenAI admin keys cover the whole organization and cannot be limited to read-only. This key could also create or delete projects, API keys and users.",
    use: "We send only GET requests to api.openai.com/v1/organization. Delete the key on the same page at any time.",
  },

  async verify(creds: Credentials): Promise<VerifyResult> {
    const headers = { authorization: `Bearer ${creds.secret}` };
    try {
      await getJson<Page<unknown>>(`${BASE}/projects?limit=1`, headers);
      return { ok: true, permissions: ["organization.projects:read", "organization.users:read", "organization.api_keys:read"] };
    } catch (e) {
      const status = e instanceof ProviderHttpError ? e.status : 0;
      return { ok: false, permissions: [], error: status === 401 ? "Key rejected. Use an Admin API key created by an organization owner." : `OpenAI returned ${status || "a network error"}.` };
    }
  },

  async collect(creds: Credentials, now = new Date()): Promise<CollectResult<"openai">> {
    const headers = { authorization: `Bearer ${creds.secret}` };
    const errors: CollectResult<"openai">["errors"] = [];
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

    const projectsRaw = await attempt("GET /projects", () => listAll<any>("/projects?include_archived=true", headers));
    let projects: OpenAIProjectFact[] | undefined;
    if (projectsRaw) {
      projects = [];
      for (const p of projectsRaw) {
        const status = p.status === "archived" || p.archived_at ? "archived" : "active";
        const base = { id: String(p.id), name: String(p.name), status, createdAt: isoFromUnix(p.created_at) ?? now.toISOString() } as const;
        // Archived projects are listed for the record but not read further: their keys no longer work.
        if (status === "archived") {
          projects.push(base);
          continue;
        }
        const at = `/projects/${p.id}`;
        const keys = await attempt(`GET ${at}/api_keys`, () => listAll<any>(`${at}/api_keys`, headers));
        const sas = await attempt(`GET ${at}/service_accounts`, () => listAll<any>(`${at}/service_accounts`, headers));
        const rl = await attempt(`GET ${at}/rate_limits`, () => listAll<any>(`${at}/rate_limits`, headers));
        const alerts = await attempt(`GET ${at}/spend_alerts`, () => listAll<any>(`${at}/spend_alerts`, headers));
        const limit = await attempt(`GET ${at}/spend_limit`, () => getJson<{ threshold_amount?: number }>(`${BASE}${at}/spend_limit`, headers));
        const retention = await attempt(`GET ${at}/data_retention`, () => getJson<{ type?: string }>(`${BASE}${at}/data_retention`, headers));
        const perms = await attempt(`GET ${at}/model_permissions`, () => getJson<{ mode?: string; model_ids?: unknown[] }>(`${BASE}${at}/model_permissions`, headers));
        projects.push({
          ...base,
          apiKeys: keys?.map((k: any) => ({
            id: String(k.id),
            name: k.name ?? null,
            createdAt: isoFromUnix(k.created_at) ?? now.toISOString(),
            lastUsedAt: isoFromUnix(k.last_used_at),
            ownerType: k.owner?.type === "service_account" ? "service_account" : k.owner?.type === "user" ? "user" : "unknown",
          })),
          serviceAccountCount: sas?.length,
          rateLimits: rl?.map((r: any) => ({
            model: String(r.model),
            maxRequestsPer1Minute: typeof r.max_requests_per_1_minute === "number" ? r.max_requests_per_1_minute : undefined,
            maxTokensPer1Minute: typeof r.max_tokens_per_1_minute === "number" ? r.max_tokens_per_1_minute : undefined,
          })),
          spendAlertCount: alerts?.length,
          spendLimitCents: typeof limit?.threshold_amount === "number" ? limit.threshold_amount : undefined,
          dataRetention: typeof retention?.type === "string" ? retention.type : undefined,
          modelPermissions: typeof perms?.mode === "string" ? { mode: perms.mode, modelCount: Array.isArray(perms.model_ids) ? perms.model_ids.length : 0 } : undefined,
        });
      }
    }

    const users = (await attempt("GET /users", () => listAll<any>("/users", headers)))?.map((u: any) => ({
      id: String(u.id),
      email: String(u.email),
      role: String(u.role),
      addedAt: isoFromUnix(u.added_at) ?? now.toISOString(),
    }));
    const invites = (await attempt("GET /invites", () => listAll<any>("/invites", headers)))?.map((i: any) => ({
      email: String(i.email),
      status: String(i.status),
      invitedAt: isoFromUnix(i.invited_at) ?? now.toISOString(),
    }));

    // One event is enough to know the log is recording. An empty list is reported as such, not as "disabled".
    const audit = await attempt("GET /audit_logs", () => getJson<Page<{ effective_at?: number }>>(`${BASE}/audit_logs?limit=1`, headers));
    const orgLimit = await attempt("GET /spend_limit", () => getJson<{ threshold_amount?: number }>(`${BASE}/spend_limit`, headers));

    const usageOf = (kind: "completions" | "embeddings") =>
      attempt(`GET /usage/${kind}`, () =>
        getJson<{ data: { results: { model?: string | null }[] }[] }>(`${BASE}/usage/${kind}?start_time=${daysAgoUnix(30, now)}&bucket_width=1d&group_by=model&limit=31`, headers),
      );
    const completions = await usageOf("completions");
    const embeddings = await usageOf("embeddings");
    const models = (u: typeof completions) => (u?.data ?? []).flatMap((b) => (b.results ?? []).map((r) => r.model).filter((m): m is string => !!m));
    const modelsUsed30d = completions ? [...new Set([...models(completions), ...models(embeddings)])] : undefined;

    return {
      facts: {
        auditLogEvents: audit ? (audit.data ?? []).length : undefined,
        auditLogLatestAt: audit ? isoFromUnix(audit.data?.[0]?.effective_at) : undefined,
        orgSpendLimitCents: typeof orgLimit?.threshold_amount === "number" ? orgLimit.threshold_amount : undefined,
        projects,
        users,
        invites,
        modelsUsed30d,
        collectedAt: now.toISOString(),
      },
      errors,
      endpoints,
    };
  },
};
