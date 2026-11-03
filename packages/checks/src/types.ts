export type Provider = "openai" | "anthropic" | "cloudflare-ai-gateway" | "cloudflare-account" | "repo";

export type Severity = "high" | "medium" | "low" | "info";

export type CheckStatus = "pass" | "fail" | "not_applicable" | "unverifiable";

/** Where a fact came from. Every customer-visible fact carries this. */
export interface Provenance {
  provider: Provider;
  endpoint: string;
  collectedAt: string; // ISO 8601
}

export type QuestionnaireFramework = "generic-ai" | "caiq-ai" | "sig-ai" | "hecvat-ai";

export interface QuestionnaireRef {
  framework: QuestionnaireFramework;
  itemId: string;
}

export interface CheckResult {
  id: string;
  provider: Provider;
  status: CheckStatus;
  severity: Severity;
  title: string;
  /** One sentence a buyer can read. */
  summary: string;
  /** Short evidence lines (never secrets, never prompt content). */
  evidence: string[];
  remediation?: string;
  answers: QuestionnaireRef[];
}

export interface CheckDefinition<F> {
  id: string;
  provider: Provider;
  title: string;
  description: string;
  severity: Severity;
  remediation: string;
  answers: QuestionnaireRef[];
  evaluate: (facts: F) => Pick<CheckResult, "status" | "summary" | "evidence">;
}

/* ---------- Provider fact shapes (collected read-only by connectors) ---------- */

export interface OpenAIApiKeyFact {
  id: string;
  name: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  ownerType: "user" | "service_account" | "unknown";
}

export interface OpenAIProjectFact {
  id: string;
  name: string;
  status: "active" | "archived";
  createdAt: string;
  apiKeys: OpenAIApiKeyFact[];
  serviceAccountCount: number;
  /** undefined = endpoint not reachable with the given key, so unverifiable. */
  hasRateLimitOverrides?: boolean;
  spendAlertCount?: number;
  dataRetention?: "organization_default" | "explicit";
  modelPermissionsMode?: "allow_list" | "deny_list" | "none";
}

export interface OpenAIFacts {
  auditLogsEnabled?: boolean;
  orgSpendLimitSet?: boolean;
  projects: OpenAIProjectFact[];
  users: { id: string; email: string; role: "owner" | "reader" | string; addedAt: string }[];
  invites: { email: string; status: string; invitedAt: string }[];
  modelsUsed30d?: string[];
  collectedAt: string;
}

export interface AnthropicFacts {
  users: { id: string; email: string; role: string; addedAt?: string }[];
  invites: { email: string; status: string; invitedAt?: string }[];
  workspaces: { id: string; name: string; archivedAt: string | null; isDefault?: boolean }[];
  apiKeys: {
    id: string;
    name: string;
    status: "active" | "inactive" | "archived" | string;
    createdAt: string;
    workspaceId: string | null;
  }[];
  modelsUsed30d?: string[];
  collectedAt: string;
}

export interface AIGatewayFact {
  id: string;
  authentication: boolean;
  collectLogs: boolean;
  dlpEnabled?: boolean;
  rateLimitingLimit: number;
  rateLimitingInterval: number;
  byokOnly?: boolean;
  hasByokKeys?: boolean;
  guardrailsEnabled?: boolean;
  spendLimitSet?: boolean;
}

export interface AIGatewayFacts {
  gateways: AIGatewayFact[];
  usage30d?: { gateway: string; provider: string; model: string; requests: number }[];
  collectedAt: string;
}

/* ---------- Cloudflare account inventory (Workers, zones, Access) ---------- */

export interface WorkerFact {
  name: string;
  modifiedAt?: string;
  /** Binding types as reported by the settings API, e.g. ai, vectorize, ai_search, secret_text, kv_namespace. */
  bindings: { type: string; name: string }[];
  /** Names only. Values are never read. */
  secretNames: string[];
  routes: string[];
  customDomains: string[];
  workersDevEnabled?: boolean;
  observabilityEnabled?: boolean;
}

export interface ZoneFact {
  id: string;
  name: string;
  plan?: string;
  /** Operations Cloudflare labelled as LLM endpoints (cf-llm managed label). */
  llmOperations: { method: string; host: string; endpoint: string }[];
  /** Rule expressions in the http_ratelimit phase. undefined = not readable. */
  rateLimitExpressions?: string[];
  /** Rule expressions in the http_request_firewall_custom phase. undefined = not readable. */
  customRuleExpressions?: string[];
  botFightMode?: boolean;
}

export interface CloudflareAccountFacts {
  workers: WorkerFact[];
  zones: ZoneFact[];
  /** Hostnames protected by Cloudflare Access applications. undefined = not readable. */
  accessHostnames?: string[];
  collectedAt: string;
}

/* ---------- Local repository scan (no credentials) ---------- */

export interface RepoFileFact {
  path: string;
  /** Imported module specifiers. */
  imports: string[];
  /** Hostnames found in string literals. */
  hosts: string[];
  hasAiRun: boolean;
  hasGatewayRef: boolean;
  hasMcpServer: boolean;
  hasAccessCheck: boolean;
}

export interface WranglerConfigFact {
  path: string;
  name: string | null;
  hasAiBinding: boolean;
  observabilityEnabled: boolean | null;
  /** Plain vars whose value looks like a provider secret. Names only. */
  secretLikeVarNames: string[];
  /** Var names that look like provider key names, regardless of value. */
  providerKeyVarNames: string[];
}

export interface RepoFacts {
  root: string;
  files: RepoFileFact[];
  wrangler: WranglerConfigFact[];
  collectedAt: string;
}

export type FactsFor<P extends Provider> = P extends "openai"
  ? OpenAIFacts
  : P extends "anthropic"
    ? AnthropicFacts
    : P extends "cloudflare-ai-gateway"
      ? AIGatewayFacts
      : P extends "cloudflare-account"
        ? CloudflareAccountFacts
        : RepoFacts;
