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

export interface Connector<P extends Provider> {
  provider: P;
  /** What the customer must create and the minimal scope, shown during onboarding. */
  credentialGuide: { label: string; docsUrl: string; scope: string };
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

/** fetch wrapper: JSON in/out, never logs headers, maps non-2xx to ProviderHttpError. */
export async function getJson<T>(url: string, headers: Record<string, string>, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...init, headers: { accept: "application/json", ...headers, ...(init?.headers as Record<string, string> | undefined) } });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const body = (await res.json()) as any;
      msg = body?.error?.message ?? body?.errors?.[0]?.message ?? body?.message ?? msg;
    } catch {
      /* ignore */
    }
    throw new ProviderHttpError(url, res.status, String(msg).slice(0, 300));
  }
  return (await res.json()) as T;
}

export function isoFromUnix(seconds: number | null | undefined): string | null {
  return seconds ? new Date(seconds * 1000).toISOString() : null;
}

export function daysAgoUnix(days: number, now: Date): number {
  return Math.floor((now.getTime() - days * 86_400_000) / 1000);
}
