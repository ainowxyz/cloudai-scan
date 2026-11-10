import type { AnthropicFacts, CheckDefinition } from "./types.js";
import { agree, daysBetween, notApplicable, notReadable, num, olderThanDays, pluralise } from "./util.js";

const OLD_KEY_DAYS = 365;
const STALE_INVITE_DAYS = 30;
const MAX_ADMINS = 3;
const ADMIN_ROLES = new Set(["admin", "owner", "primary_owner"]);
const DOCS = "https://platform.claude.com/docs/en/manage-claude/admin-api";

const activeKeys = (f: AnthropicFacts) => f.apiKeys?.filter((k) => k.status === "active");

export const anthropicChecks: CheckDefinition<AnthropicFacts>[] = [
  {
    id: "ANT-001",
    provider: "anthropic",
    title: "No active API key in an archived workspace",
    description: "Compares each active API key's workspace with the list of archived workspaces. A key that outlives its workspace is a forgotten credential.",
    severity: "medium",
    source: "GET /v1/organizations/api_keys: status, scope.workspace_id; GET /v1/organizations/workspaces: archived_at",
    docsUrl: DOCS,
    limits: "Shows where active keys live. It does not show what each key is used for.",
    remediation: "Deactivate keys belonging to archived workspaces in the Claude Console.",
    answers: [{ framework: "generic-ai", itemId: "GAI-12" }],
    evaluate: (f) => {
      const keys = activeKeys(f);
      if (!keys || !f.workspaces) return notReadable("API keys or workspaces could not be read with this admin key.");
      if (keys.length === 0) return notApplicable("No active API keys found.");
      const archived = new Set(f.workspaces.filter((w) => w.archivedAt).map((w) => w.id));
      const orphans = keys.filter((k) => k.workspaceId && archived.has(k.workspaceId));
      const observed = [`${orphans.length} of ${pluralise(keys.length, "active API key")} in archived workspaces`];
      return orphans.length === 0
        ? { status: "pass", summary: "No active key belongs to an archived workspace.", evidence: [], observed }
        : { status: "fail", summary: `${pluralise(orphans.length, "active key")} ${agree(orphans.length, "belongs", "belong")} to an archived workspace.`, evidence: orphans.slice(0, 10).map((k) => k.name), observed };
    },
  },
  {
    id: "ANT-002",
    provider: "anthropic",
    title: "Active keys live in a dedicated workspace",
    description: "Reads the workspace of each active API key. Keys in the default workspace, or scoped to the whole organization, cannot be limited or reported separately from everything else.",
    severity: "medium",
    source: "GET /v1/organizations/api_keys: status, scope.type, scope.workspace_id; GET /v1/organizations/workspaces: name",
    docsUrl: DOCS,
    limits: "Shows which workspace each key is in. It does not show which workspace serves production, or how environments are separated beyond workspaces.",
    remediation: "Create a workspace per environment and issue keys there; deactivate default-workspace keys.",
    answers: [{ framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      const keys = activeKeys(f);
      if (!keys || !f.workspaces) return notReadable("API keys or workspaces could not be read with this admin key.");
      if (keys.length === 0) return notApplicable("No active API keys found.");
      const inDefault = keys.filter((k) => k.workspaceId === null || f.workspaces!.find((w) => w.id === k.workspaceId)?.isDefault);
      const observed = [`${keys.length - inDefault.length} of ${pluralise(keys.length, "active API key")} in a dedicated workspace`];
      return inDefault.length === 0
        ? { status: "pass", summary: "Every active key is in a dedicated workspace.", evidence: [], observed }
        : { status: "fail", summary: `${pluralise(inDefault.length, "active key")} ${agree(inDefault.length, "is", "are")} in the default workspace or scoped to the whole organization.`, evidence: inDefault.slice(0, 10).map((k) => k.name), observed };
    },
  },
  {
    id: "ANT-003",
    provider: "anthropic",
    title: `No active key older than ${OLD_KEY_DAYS} days`,
    description: "Compares each active API key's creation date with today. Long-lived keys should be rotated.",
    severity: "low",
    source: "GET /v1/organizations/api_keys: status, created_at",
    docsUrl: DOCS,
    limits: "Shows key age only. It does not show your rotation policy or when keys were last rotated.",
    remediation: "Rotate keys older than a year.",
    answers: [{ framework: "generic-ai", itemId: "GAI-13" }],
    evaluate: (f) => {
      const keys = activeKeys(f);
      if (!keys) return notReadable("API keys could not be read with this admin key.");
      if (keys.length === 0) return notApplicable("No active API keys found.");
      const old = keys.filter((k) => olderThanDays(k.createdAt, OLD_KEY_DAYS, f.collectedAt));
      const oldest = keys.reduce((m, k) => Math.max(m, daysBetween(k.createdAt, f.collectedAt)), 0);
      const observed = [`Oldest active API key: ${num(oldest)} days`, `${old.length} of ${pluralise(keys.length, "active key")} older than ${OLD_KEY_DAYS} days`];
      return old.length === 0
        ? { status: "pass", summary: `No active key is older than ${OLD_KEY_DAYS} days.`, evidence: [], observed }
        : { status: "fail", summary: `${pluralise(old.length, "active key")} older than ${OLD_KEY_DAYS} days.`, evidence: old.slice(0, 10).map((k) => k.name), observed };
    },
  },
  {
    id: "ANT-004",
    provider: "anthropic",
    title: "Admin count is small and invites are not stale",
    description: `Counts organization admins and owners, and pending invitations older than ${STALE_INVITE_DAYS} days. Names and email addresses are never published.`,
    severity: "low",
    source: "GET /v1/organizations/users: role; GET /v1/organizations/invites: status, invited_at",
    docsUrl: DOCS,
    limits: "Counts only. It does not show who the admins are, whether they use single sign-on, or how access is reviewed.",
    remediation: `Keep admins to ${MAX_ADMINS} or fewer and revoke invitations older than ${STALE_INVITE_DAYS} days.`,
    answers: [{ framework: "generic-ai", itemId: "GAI-11" }],
    evaluate: (f) => {
      if (!f.users || !f.invites) return notReadable("Organization users or invitations could not be read with this admin key.");
      const admins = f.users.filter((u) => ADMIN_ROLES.has(u.role)).length;
      const stale = f.invites.filter((i) => i.status === "pending" && i.invitedAt && olderThanDays(i.invitedAt, STALE_INVITE_DAYS, f.collectedAt)).length;
      const observed = [pluralise(admins, "organization admin"), `${pluralise(stale, "pending invitation")} older than ${STALE_INVITE_DAYS} days`];
      return admins <= MAX_ADMINS && stale === 0
        ? { status: "pass", summary: `${pluralise(admins, "admin")} and no stale invitations.`, evidence: [], observed }
        : { status: "fail", summary: `${pluralise(admins, "admin")} and ${pluralise(stale, "stale invitation")}; the rule allows up to ${MAX_ADMINS} admins and none stale.`, evidence: [], observed };
    },
  },
  {
    id: "ANT-005",
    provider: "anthropic",
    title: "A spend limit is set",
    description: "Reads the organization's spend limits. Passes when you have set a limit with an amount on the organization or on a workspace. Anthropic's own usage-tier cap does not count as a limit you set.",
    severity: "medium",
    source: "GET /v1/organizations/spend_limits (beta spend-limit-reads-2026-09-26): data[].scope.type, amount, is_enabled, period",
    docsUrl: "https://platform.claude.com/docs/en/manage-claude/spend-limits-api",
    limits: "For Claude Console organizations Anthropic offers this endpoint as an early-access preview, so it is often not readable. The amount is not published.",
    remediation: "Set a monthly spend limit on the organization or on each production workspace in the Claude Console.",
    answers: [{ framework: "generic-ai", itemId: "GAI-22" }],
    evaluate: (f) => {
      if (!f.spendLimits) return notReadable("Spend limits could not be read. For Claude Console organizations, Anthropic offers this API as an early-access preview.");
      const own = f.spendLimits.filter((l) => (l.scopeType === "organization" || l.scopeType === "workspace") && l.hasAmount && l.enabled);
      const tier = f.spendLimits.some((l) => l.scopeType === "usage_tier");
      const observed = [`${pluralise(own.length, "organization or workspace spend limit")} set`, ...(tier ? ["Anthropic's usage-tier cap also applies"] : [])];
      return own.length > 0
        ? { status: "pass", summary: `${pluralise(own.length, "spend limit")} ${agree(own.length, "is", "are")} set on the organization or its workspaces.`, evidence: [], observed }
        : { status: "fail", summary: `No organization or workspace spend limit is set${tier ? "; only Anthropic's usage-tier cap applies" : ""}.`, evidence: [], observed };
    },
  },
  {
    id: "ANT-006",
    provider: "anthropic",
    title: "Models used in the last 30 days",
    description: "Lists the models that appear in the organization's usage data for the last 30 days. This is an inventory, not a pass or fail rule.",
    severity: "info",
    source: "GET /v1/organizations/analytics/usage?group_by[]=model (beta analytics-usage-cost-2026-08-24): data[].group.model, last 30 days",
    docsUrl: "https://platform.claude.com/docs/en/api/beta/organization/analytics/usage/list",
    limits: "Anthropic refreshes this data about every four hours. A model enabled but unused in the period does not appear.",
    remediation: "",
    answers: [{ framework: "generic-ai", itemId: "GAI-03" }, { framework: "generic-ai", itemId: "GAI-21" }],
    evaluate: (f) => {
      if (f.modelsUsed30d === undefined) return notReadable("Usage data could not be read with this admin key.");
      if (f.modelsUsed30d.length === 0) return { status: "pass", summary: "No model usage was recorded in the last 30 days.", evidence: [], observed: ["No models called in the last 30 days"] };
      return { status: "pass", summary: `${pluralise(f.modelsUsed30d.length, "model")} used in the last 30 days.`, evidence: [], observed: [`Models called in the last 30 days: ${f.modelsUsed30d.slice(0, 25).join(", ")}`] };
    },
  },
];
