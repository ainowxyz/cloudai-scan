import type { FactsFor, Provider } from "@cloudaisecurity/checks";

export interface Credentials {
  /** The secret: an OpenAI admin key, an Anthropic admin key, or a Cloudflare API token. */
  secret: string;
  /** Cloudflare only. */
  accountId?: string;
}

export interface VerifyResult {
  ok: boolean;
  /** Human-readable capabilities confirmed (used to show coverage in the UI). */
  permissions: string[];
  /** Hint shown when ok is false. Never includes the secret. */
  error?: string;
}

export interface CollectResult<P extends Provider> {
  facts: FactsFor<P>;
  /** Endpoints that failed, with status codes. Facts those endpoints feed stay undefined => checks report `unverifiable`. */
  errors: { endpoint: string; status: number; message: string }[];
  /** Endpoints called, for provenance. */
  endpoints: string[];
}

/**
 * true when every request of a collection failed: the credential was accepted but read nothing.
 * Such a run must not be reported as a successful read of the account.
 */
export function readNothing(result: { errors: { endpoint: string }[]; endpoints: string[] }): boolean {
  if (result.endpoints.length === 0) return false;
  const failed = new Set(result.errors.map((e) => e.endpoint));
  return result.endpoints.every((e) => failed.has(e));
}

export interface CredentialGuide {
  /** The credential type, in the provider's words. */
  label: string;
  docsUrl: string;
  /**
   * true: the provider can restrict this credential to read-only, and the scope below does so.
   * false: the provider issues it with write access we cannot remove; it is only used read-only by this code.
   */
  readOnlyByProvider: boolean;
  /** The scope to grant, or what the credential can do when it cannot be restricted. */
  scope: string;
  /** What this code does with it. */
  use: string;
}

export interface Connector<P extends Provider> {
  provider: P;
  /** What the customer must create, shown wherever a credential is asked for. */
  credentialGuide: CredentialGuide;
  verify(creds: Credentials): Promise<VerifyResult>;
  collect(creds: Credentials, now?: Date): Promise<CollectResult<P>>;
}

export class ProviderHttpError extends Error {
  endpoint: string;
  status: number;
  constructor(endpoint: string, status: number, message: string) {
    super(message);
    this.endpoint = endpoint;
    this.status = status;
  }
}

/**
 * The only requests this package can send. Everything is a GET to one of three provider API hosts,
 * plus one POST: Cloudflare's GraphQL analytics endpoint, which is read-only but uses POST for queries.
 * A request outside this list throws before it leaves, so "used read-only" is enforced here, not just promised.
 */
const ALLOWED: { host: string; method: "GET" | "POST"; path: RegExp }[] = [
  { host: "api.openai.com", method: "GET", path: /^\/v1\/organization\// },
  { host: "api.anthropic.com", method: "GET", path: /^\/v1\/organizations\// },
  { host: "api.cloudflare.com", method: "GET", path: /^\/client\/v4\/(accounts|zones|user\/tokens\/verify)(\/|\?|$)/ },
  { host: "api.cloudflare.com", method: "POST", path: /^\/client\/v4\/graphql$/ },
];

export function assertReadOnly(url: string, method = "GET"): void {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error("Blocked request: not a valid URL.");
  }
  const m = method.toUpperCase();
  const ok = u.protocol === "https:" && ALLOWED.some((a) => a.host === u.hostname && a.method === m && a.path.test(u.pathname));
  if (!ok) throw new Error(`Blocked request: ${m} ${u.hostname}${u.pathname} is not on the read-only allow-list.`);
  if (m === "POST" && u.hostname === "api.cloudflare.com" && u.search !== "") throw new Error("Blocked request: unexpected query string.");
}

/** A GraphQL body is only sent if it is a query; mutations are refused. */
function assertQueryOnly(body: unknown): void {
  const text = typeof body === "string" ? body : "";
  let query = "";
  try {
    query = String((JSON.parse(text) as { query?: unknown }).query ?? "");
  } catch {
    throw new Error("Blocked request: unreadable GraphQL body.");
  }
  if (!/^\s*query\b/.test(query) || /\bmutation\b/.test(query)) throw new Error("Blocked request: only GraphQL queries are allowed.");
}

const SECRET_SHAPES = /\b(sk-[A-Za-z0-9_*.-]{6,}|sk-ant-[A-Za-z0-9_*.-]{6,}|Bearer\s+[A-Za-z0-9._~+/-]{8,}=*)/g;

/** Removes anything that looks like a credential from text that will be stored or shown. */
export function redact(text: string, secret?: string): string {
  let out = text;
  if (secret && secret.length >= 6) out = out.split(secret).join("[redacted]");
  return out.replace(SECRET_SHAPES, "[redacted]");
}

/** How long one request may take, from sending it to the end of its body. */
export const REQUEST_TIMEOUT_MS = 30_000;

/**
 * fetch wrapper: JSON in/out, allow-listed and read-only, never logs headers, maps non-2xx to ProviderHttpError with redacted text.
 * The response and its body must both arrive within `timeoutMs`; a request that takes longer fails like any other unreadable endpoint.
 */
export async function getJson<T>(url: string, headers: Record<string, string>, init?: RequestInit, timeoutMs = REQUEST_TIMEOUT_MS): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  assertReadOnly(url, method);
  if (method === "POST") assertQueryOnly(init?.body);
  const secret = (headers.authorization ?? headers["x-api-key"] ?? "").replace(/^Bearer\s+/i, "");
  const endpoint = redact(url.split("?")[0]!, secret);
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  // The race settles even when fetch or the body ignores the abort signal.
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new ProviderHttpError(endpoint, 0, `No complete response within ${timeoutMs / 1000} seconds.`));
    }, timeoutMs);
  });
  init?.signal?.addEventListener("abort", () => controller.abort(), { once: true });
  const request = async (): Promise<T> => {
    const res = await fetch(url, { ...init, method, signal: controller.signal, redirect: "manual", headers: { accept: "application/json", ...headers, ...(init?.headers as Record<string, string> | undefined) } });
    if (!res.ok) {
      let msg = res.statusText;
      try {
        const body = (await res.json()) as any;
        msg = body?.error?.message ?? body?.errors?.[0]?.message ?? body?.message ?? msg;
      } catch {
        /* ignore */
      }
      throw new ProviderHttpError(endpoint, res.status, redact(String(msg), secret).slice(0, 300));
    }
    return (await res.json()) as T;
  };
  try {
    return await Promise.race([request(), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/** A list endpoint had more items than this code reads. Returning the part read would look like the whole list. */
export function incompleteList(what: string): Error {
  return new Error(`${what} has more items than this scan reads; the list was not read rather than read in part.`);
}

/**
 * Every page of a Cloudflare v4 list endpoint (page / per_page pagination). One page is not the whole list:
 * stopping early would evaluate rules on part of the account. Stops at the last page. If more pages remain after
 * `maxPages`, or a page comes back empty before the last, it throws instead of returning part of the list.
 */
export async function cloudflareListAll<T>(url: string, headers: Record<string, string>, perPage = 50, maxPages = 20): Promise<T[]> {
  const out: T[] = [];
  for (let page = 1; page <= maxPages; page++) {
    const res = await getJson<{ result?: T[]; result_info?: { total_pages?: number; total_count?: number } }>(`${url}${url.includes("?") ? "&" : "?"}page=${page}&per_page=${perPage}`, headers);
    const items = res.result ?? [];
    out.push(...items);
    const info = res.result_info;
    const last = info?.total_pages !== undefined ? page >= info.total_pages : info?.total_count !== undefined ? out.length >= info.total_count : items.length < perPage;
    if (last) return out;
    if (items.length === 0) break;
  }
  throw incompleteList(url.replace(/^https:\/\/api\.cloudflare\.com\/client\/v4/, "").split("?")[0]!);
}

export function isoFromUnix(seconds: number | null | undefined): string | null {
  return seconds ? new Date(seconds * 1000).toISOString() : null;
}

export function daysAgoUnix(days: number, now: Date): number {
  return Math.floor((now.getTime() - days * 86_400_000) / 1000);
}
