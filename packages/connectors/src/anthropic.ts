import type { AnthropicFacts } from "@cloudaisecurity/checks";
import { getJson, ProviderHttpError, type CollectResult, type Connector, type Credentials, type VerifyResult } from "./types.js";

const BASE = "https://api.anthropic.com/v1/organizations";
const VERSION = "2023-06-01";
const BETA_USAGE = "analytics-usage-cost-2026-08-24";
const BETA_SPEND = "spend-limit-reads-2026-09-26";

type Page<T> = { data: T[]; has_more?: boolean; last_id?: string | null };

function headersFor(secret: string, beta?: string): Record<string, string> {
  return { "x-api-key": secret, "anthropic-version": VERSION, ...(beta ? { "anthropic-beta": beta } : {}) };
}

async function listAll<T>(path: string, headers: Record<string, string>): Promise<T[]> {
  const out: T[] = [];
  let after: string | null | undefined;
  for (let i = 0; i < 20; i++) {
    const url = `${BASE}${path}${path.includes("?") ? "&" : "?"}limit=100${after ? `&after_id=${encodeURIComponent(after)}` : ""}`;
    const page = await getJson<Page<T>>(url, headers);
    out.push(...page.data);
    if (!page.has_more || !page.last_id) break;
    after = page.last_id;
  }
  return out;
}

/** Cursor pagination used by the analytics and spend-limit endpoints. */
async function pageAll<T>(path: string, headers: Record<string, string>): Promise<T[]> {
  const out: T[] = [];
  let page: string | null | undefined;
  for (let i = 0; i < 10; i++) {
    const res = await getJson<{ data?: T[]; next_page?: string | null; has_more?: boolean }>(`${BASE}${path}${page ? `&page=${encodeURIComponent(page)}` : ""}`, headers);
    out.push(...(res.data ?? []));
    if (!res.next_page || res.has_more === false) break;
    page = res.next_page;
  }
  return out;
}

export const anthropicConnector: Connector<"anthropic"> = {
  provider: "anthropic",
  credentialGuide: {
    label: "Anthropic Admin API key",
    docsUrl: "https://platform.claude.com/settings/admin-keys",
    readOnlyByProvider: false,
    scope: "Anthropic admin keys (sk-ant-admin…) cover the whole organization and cannot be limited to read-only. This key could also change members, workspaces and API keys.",
    use: "We send only GET requests to api.anthropic.com/v1/organizations. Delete the key on the same page at any time.",
  },

  async verify(creds: Credentials): Promise<VerifyResult> {
    try {
      await getJson(`${BASE}/me`, headersFor(creds.secret));
      return { ok: true, permissions: ["organization:read", "workspaces:read", "api_keys:read"] };
    } catch (e) {
      const status = e instanceof ProviderHttpError ? e.status : 0;
      return { ok: false, permissions: [], error: status === 401 || status === 403 ? "Key rejected. Use an Admin API key (sk-ant-admin…) from an organization admin." : `Anthropic returned ${status || "a network error"}.` };
    }
  },

  async collect(creds: Credentials, now = new Date()): Promise<CollectResult<"anthropic">> {
    const headers = headersFor(creds.secret);
    const errors: CollectResult<"anthropic">["errors"] = [];
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

    const users = (await attempt("GET /users", () => listAll<any>("/users", headers)))?.map((u: any) => ({ id: String(u.id), email: String(u.email), role: String(u.role), addedAt: u.added_at }));
    const invites = (await attempt("GET /invites", () => listAll<any>("/invites", headers)))?.map((i: any) => ({ email: String(i.email), status: String(i.status), invitedAt: i.invited_at }));
    const workspaces = (await attempt("GET /workspaces", () => listAll<any>("/workspaces?include_archived=true", headers)))?.map((w: any) => ({
      id: String(w.id),
      name: String(w.name),
      archivedAt: w.archived_at ?? null,
      isDefault: w.name === "Default" || w.is_default === true,
    }));
    const apiKeys = (await attempt("GET /api_keys", () => listAll<any>("/api_keys", headers)))?.map((k: any) => ({
      id: String(k.id),
      name: String(k.name),
      status: String(k.status),
      createdAt: String(k.created_at),
      // Current API: scope.workspace_id. Older responses carried workspace_id at the top level.
      workspaceId: (k.scope?.workspace_id ?? k.workspace_id ?? null) as string | null,
    }));

    const spend = await attempt("GET /spend_limits", () => pageAll<any>("/spend_limits?limit=1000", headersFor(creds.secret, BETA_SPEND)));
    const spendLimits = spend?.map((l: any) => ({ scopeType: String(l.scope?.type ?? "unknown"), hasAmount: l.amount !== null && l.amount !== undefined, enabled: l.is_enabled !== false, period: String(l.period ?? "") }));

    const start = new Date(now.getTime() - 30 * 86_400_000).toISOString();
    const usage = await attempt("GET /analytics/usage", () => pageAll<{ group?: { model?: string | null } }>(`/analytics/usage?starting_at=${encodeURIComponent(start)}&group_by[]=model&limit=1000`, headersFor(creds.secret, BETA_USAGE)));
    const modelsUsed30d = usage ? [...new Set(usage.map((r) => r.group?.model).filter((m): m is string => !!m))] : undefined;

    return { facts: { users, invites, workspaces, apiKeys, spendLimits, modelsUsed30d, collectedAt: now.toISOString() }, errors, endpoints };
  },
};
