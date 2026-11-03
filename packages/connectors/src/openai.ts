import type { OpenAIFacts, OpenAIProjectFact } from "@cloudaisecurity/checks";
import { daysAgoUnix, getJson, isoFromUnix, ProviderHttpError, type CollectResult, type Connector, type Credentials, type VerifyResult } from "./types.js";

const BASE = "https://api.openai.com/v1/organization";

type Page<T> = { data: T[]; has_more?: boolean; last_id?: string };

async function listAll<T>(path: string, headers: Record<string, string>, max = 1000): Promise<T[]> {
  const out: T[] = [];
  let after: string | undefined;
  for (let i = 0; i < 20 && out.length < max; i++) {
    const url = `${BASE}${path}${path.includes("?") ? "&" : "?"}limit=100${after ? `&after=${after}` : ""}`;
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
    label: "OpenAI Admin API key (read-only use)",
    docsUrl: "https://platform.openai.com/settings/organization/admin-keys",
    scope: "Admin keys are organization-wide. We only call GET endpoints; revoke the key at any time from the same page.",
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

    const projectsRaw = (await attempt("GET /projects", () => listAll<any>("/projects?include_archived=true", headers))) ?? [];
    const projects: OpenAIProjectFact[] = [];
    for (const p of projectsRaw) {
      const keys = (await attempt(`GET /projects/${p.id}/api_keys`, () => listAll<any>(`/projects/${p.id}/api_keys`, headers))) ?? [];
      const sas = await attempt(`GET /projects/${p.id}/service_accounts`, () => listAll<any>(`/projects/${p.id}/service_accounts`, headers));
      const rl = await attempt(`GET /projects/${p.id}/rate_limits`, () => listAll<any>(`/projects/${p.id}/rate_limits`, headers));
      projects.push({
        id: p.id,
        name: p.name,
        status: p.status === "archived" || p.archived_at ? "archived" : "active",
        createdAt: isoFromUnix(p.created_at) ?? now.toISOString(),
        apiKeys: keys.map((k: any) => ({
          id: k.id,
          name: k.name ?? null,
          createdAt: isoFromUnix(k.created_at) ?? now.toISOString(),
          lastUsedAt: isoFromUnix(k.last_used_at),
          ownerType: k.owner?.type === "service_account" ? "service_account" : k.owner?.type === "user" ? "user" : "unknown",
        })),
        serviceAccountCount: sas?.length ?? 0,
        // OpenAI returns the default limits with the same shape as overrides; treat any entry whose
        // values differ from a sibling default as an override. Until we store defaults, report presence only.
        hasRateLimitOverrides: rl === undefined ? undefined : rl.length > 0 ? undefined : false,
      });
    }

    const users = ((await attempt("GET /users", () => listAll<any>("/users", headers))) ?? []).map((u: any) => ({
      id: u.id,
      email: u.email,
      role: u.role,
      addedAt: isoFromUnix(u.added_at) ?? now.toISOString(),
    }));
    const invites = ((await attempt("GET /invites", () => listAll<any>("/invites", headers))) ?? []).map((i: any) => ({
      email: i.email,
      status: i.status,
      invitedAt: isoFromUnix(i.invited_at) ?? now.toISOString(),
    }));

    const audit = await attempt("GET /audit_logs", () => getJson<Page<unknown>>(`${BASE}/audit_logs?limit=1`, headers));
    const auditLogsEnabled = audit === undefined ? (errors.at(-1)?.status === 400 ? false : undefined) : true;

    const usage = await attempt("GET /usage/completions", () =>
      getJson<{ data: { results: { model?: string }[] }[] }>(`${BASE}/usage/completions?start_time=${daysAgoUnix(30, now)}&bucket_width=1d&group_by=model&limit=31`, headers),
    );
    const modelsUsed30d = usage ? [...new Set(usage.data.flatMap((b) => b.results.map((r) => r.model).filter((m): m is string => !!m)))] : undefined;

    return {
      facts: { auditLogsEnabled, orgSpendLimitSet: undefined, projects, users, invites, modelsUsed30d, collectedAt: now.toISOString() },
      errors,
      endpoints,
    };
  },
};
