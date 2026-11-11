export type Provider = "openai" | "anthropic" | "cloudflare-ai-gateway" | "cloudflare-account" | "repo";

export type Severity = "high" | "medium" | "low" | "info";

/**
 * pass / fail: the rule was evaluated against values read from the provider.
 * needs_review: something was read, but it cannot settle the rule on its own (for example, no Cloudflare Access
 *   application was found, which does not prove a server has no authentication). A person has to answer.
 * unverifiable: the values could not be read. Shown as "not readable". Never treated as a pass.
 * not_applicable: nothing exists for the rule to apply to.
 */
export type CheckStatus = "pass" | "fail" | "needs_review" | "not_applicable" | "unverifiable";

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
  /** The provider API call(s) and field path(s) read, in the provider's own names. */
  source: string;
  /** Provider documentation for that call. */
  docsUrl?: string;
  /** What this result does not show. Printed next to every result so it is not over-read. */
  limits: string;
  /** One sentence a buyer can read: the bounded observation, not a wider conclusion. */
  summary: string;
  /**
   * Values read from the provider that are safe to publish: counts, model names, limit values, setting names.
   * Never people, email addresses, key or project names, amounts of money, or secrets.
   */
  observed: string[];
  /**
   * The same values as `observed`, as rows and named columns, when a rule reads several measurements per subject
   * (for example a model with its request and token limits). Present only for such rules. It adds nothing that
   * `observed` does not say; it exists so a reader does not have to take a sentence apart.
   */
  table?: ObservedTable;
  /** Internal detail for the account owner (project, key and Worker names). Never published. Never secrets or prompt content. */
  evidence: string[];
  remediation?: string;
  answers: QuestionnaireRef[];
}

/** Publishable values laid out as one row per subject. A null value was not returned by the provider. */
export interface ObservedTable {
  /** What each row is, for example "Model". */
  subject: string;
  /** What each value is, for example "Requests per minute". */
  columns: string[];
  rows: { name: string; values: (string | null)[] }[];
}

export interface CheckDefinition<F> {
  id: string;
  provider: Provider;
  title: string;
  description: string;
  severity: Severity;
  /** The provider API call(s) and field path(s) this check reads, in the provider's own names. Shown next to every result. */
  source: string;
  /** Provider documentation for that call. */
  docsUrl?: string;
  /** What a result of this check does not show. */
  limits: string;
  remediation: string;
  answers: QuestionnaireRef[];
  evaluate: (facts: F) => Pick<CheckResult, "status" | "summary" | "evidence"> & { observed?: string[]; table?: ObservedTable };
}

/* ---------- Provider fact shapes (collected read-only by connectors) ---------- */

export interface OpenAIApiKeyFact {
  id: string;
  name: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  ownerType: "user" | "service_account" | "unknown";
}

/** In every fact shape, `undefined` means "the endpoint could not be read", which is different from an empty list. */
export interface OpenAIProjectFact {
  id: string;
  name: string;
  status: "active" | "archived";
  createdAt: string;
  apiKeys?: OpenAIApiKeyFact[];
  serviceAccountCount?: number;
  /** GET …/rate_limits: one entry per model. */
  rateLimits?: { model: string; maxRequestsPer1Minute?: number; maxTokensPer1Minute?: number }[];
  /** GET …/spend_alerts: number of alerts. Alerts notify; they do not stop usage. */
  spendAlertCount?: number;
  /** GET …/spend_limit: threshold_amount in cents. 0 means no hard limit. */
  spendLimitCents?: number;
  /** GET …/data_retention: type, as OpenAI names it (organization_default, none, zero_data_retention, …). */
  dataRetention?: string;
  /** GET …/model_permissions: mode and number of model ids. mode "none" = OpenAI reported that no permissions are set. */
  modelPermissions?: { mode: "allow_list" | "deny_list" | string; modelCount: number };
}

export interface OpenAIFacts {
  /** Number of events GET /audit_logs?limit=1 returned (0 or 1). */
  auditLogEvents?: number;
  /** effective_at of the most recent audit event, if one was returned. */
  auditLogLatestAt?: string | null;
  /** GET /organization/spend_limit: threshold_amount in cents. 0 means no hard limit. */
  orgSpendLimitCents?: number;
  /** GET /organization/spend_alerts: number of organization-level alerts. undefined = not readable. */
  orgSpendAlertCount?: number;
  projects?: OpenAIProjectFact[];
  users?: { id: string; email: string; role: "owner" | "member" | string; addedAt: string }[];
  invites?: { email: string; status: string; invitedAt: string }[];
  modelsUsed30d?: string[];
  collectedAt: string;
}

export interface AnthropicFacts {
  users?: { id: string; email: string; role: string; addedAt?: string }[];
  invites?: { email: string; status: string; invitedAt?: string }[];
  workspaces?: { id: string; name: string; archivedAt: string | null; isDefault?: boolean }[];
  apiKeys?: {
    id: string;
    name: string;
    status: "active" | "inactive" | "archived" | "expired" | string;
    createdAt: string;
    /** scope.workspace_id; null for an organization-scoped key or the default workspace. */
    workspaceId: string | null;
  }[];
  /** GET /v1/organizations/spend_limits. For Console organizations this endpoint is an early-access preview. */
  spendLimits?: { scopeType: string; hasAmount: boolean; enabled: boolean; period: string }[];
  modelsUsed30d?: string[];
  collectedAt: string;
}

export interface AIGatewayFact {
  id: string;
  authentication: boolean;
  collectLogs: boolean;
  dlpEnabled: boolean;
  rateLimitingLimit: number;
  rateLimitingInterval: number;
  byokOnly: boolean;
  /** undefined = stored provider keys could not be listed. */
  hasByokKeys?: boolean;
  guardrailsEnabled: boolean;
  /** spend_limits.enabled with at least one enabled rule. */
  spendLimitSet: boolean;
}

export interface AIGatewayFacts {
  gateways?: AIGatewayFact[];
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
  /**
   * How many operations carry Cloudflare's cf-llm managed label on this zone.
   * undefined = the label could not be read, which is different from zero.
   */
  llmOperationCount?: number;
  /** The labelled operations themselves, when the API returned them. undefined = the list could not be read. */
  llmOperations?: { method: string; host: string; endpoint: string }[];
  /** Rule expressions in the http_ratelimit phase. undefined = not readable. */
  rateLimitExpressions?: string[];
  /** Rule expressions in the http_request_firewall_custom phase. undefined = not readable. */
  customRuleExpressions?: string[];
  botFightMode?: boolean;
}

export interface CloudflareAccountFacts {
  workers?: WorkerFact[];
  zones?: ZoneFact[];
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
