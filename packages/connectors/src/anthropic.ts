import type { AnthropicFacts } from "@cloudaisecurity/checks";
import { getJson, ProviderHttpError, type CollectResult, type Connector, type Credentials, type VerifyResult } from "./types.js";

const BASE = "https://api.anthropic.com/v1/organizations";
const VERSION = "2023-06-01";

type Page<T> = { data: T[]; has_more?: boolean; last_id?: string | null };

function headersFor(secret: string): Record<string, string> {
  return { "x-api-key": secret, "anthropic-version": VERSION };
}

async function listAll<T>(path: string, headers: Record<string, string>): Promise<T[]> {
  const out: T[] = [];
  let after: string | null | undefined;
  for (let i = 0; i < 20; i++) {
    const url = `${BASE}${path}${path.includes("?") ? "&" : "?"}limit=100${after ? `&after_id=${after}` : ""}`;
    const page = await getJson<Page<T>>(url, headers);
    out.push(...page.data);
    if (!page.has_more || !page.last_id) break;
    after = page.last_id;
  }
  return out;
}

export const anthropicConnector: Connector<"anthropic"> = {
  provider: "anthropic",
  credentialGuide: {
    label: "Anthropic Admin API key",
    docsUrl: "https://platform.claude.com/settings/admin-keys",
    scope: "Admin keys (sk-ant-admin…) are organization-wide. We only read members, workspaces, keys and usage; revoke at any time.",
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

    const users = ((await attempt("GET /users", () => listAll<any>("/users", headers))) ?? []).map((u: any) => ({ id: u.id, email: u.email, role: u.role, addedAt: u.added_at }));
    const invites = ((await attempt("GET /invites", () => listAll<any>("/invites", headers))) ?? []).map((i: any) => ({ email: i.email, status: i.status, invitedAt: i.invited_at }));
    const workspaces = ((await attempt("GET /workspaces", () => listAll<any>("/workspaces?include_archived=true", headers))) ?? []).map((w: any) => ({
      id: w.id,
      name: w.name,
      archivedAt: w.archived_at ?? null,
      isDefault: w.name === "Default" || w.is_default === true,
    }));
    const apiKeys = ((await attempt("GET /api_keys", () => listAll<any>("/api_keys", headers))) ?? []).map((k: any) => ({
      id: k.id,
      name: k.name,
      status: k.status,
      createdAt: k.created_at,
      workspaceId: k.workspace_id ?? null,
    }));

    const start = new Date(now.getTime() - 30 * 86_400_000).toISOString();
    const usage = await attempt("GET /analytics/usage", () =>
      getJson<{ data?: { results?: { model?: string }[] }[] }>(`${BASE}/analytics/usage?starting_at=${encodeURIComponent(start)}&group_by[]=model&bucket_width=1d`, headers),
    );
    const modelsUsed30d = usage ? [...new Set((usage.data ?? []).flatMap((b) => (b.results ?? []).map((r) => r.model).filter((m): m is string => !!m)))] : undefined;

    return { facts: { users, invites, workspaces, apiKeys, modelsUsed30d, collectedAt: now.toISOString() }, errors, endpoints };
  },
};
