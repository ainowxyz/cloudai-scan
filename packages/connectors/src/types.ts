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

/** fetch wrapper: JSON in/out, allow-listed and read-only, never logs headers, maps non-2xx to ProviderHttpError with redacted text. */
export async function getJson<T>(url: string, headers: Record<string, string>, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  assertReadOnly(url, method);
  if (method === "POST") assertQueryOnly(init?.body);
  const secret = (headers.authorization ?? headers["x-api-key"] ?? "").replace(/^Bearer\s+/i, "");
  const res = await fetch(url, { ...init, method, redirect: "manual", headers: { accept: "application/json", ...headers, ...(init?.headers as Record<string, string> | undefined) } });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const body = (await res.json()) as any;
      msg = body?.error?.message ?? body?.errors?.[0]?.message ?? body?.message ?? msg;
    } catch {
      /* ignore */
    }
    throw new ProviderHttpError(redact(url.split("?")[0]!, secret), res.status, redact(String(msg), secret).slice(0, 300));
  }
  return (await res.json()) as T;
}

export function isoFromUnix(seconds: number | null | undefined): string | null {
  return seconds ? new Date(seconds * 1000).toISOString() : null;
}

export function daysAgoUnix(days: number, now: Date): number {
  return Math.floor((now.getTime() - days * 86_400_000) / 1000);
}
