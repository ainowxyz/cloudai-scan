import type { CheckDefinition, OpenAIFacts } from "./types.js";
import { olderThanDays, pluralise } from "./util.js";

const UNUSED_DAYS = 90;
const OLD_KEY_DAYS = 365;
const STALE_INVITE_DAYS = 30;
const MAX_OWNERS = 3;

export const openaiChecks: CheckDefinition<OpenAIFacts>[] = [
  {
    id: "OAI-001",
    provider: "openai",
    title: "Audit logging is enabled",
    description: "The OpenAI organization records API key, project, user and login lifecycle events.",
    severity: "high",
    remediation: "In OpenAI platform settings, open Organization > General and enable audit logging. Once on it cannot be turned off.",
    answers: [{ framework: "generic-ai", itemId: "GAI-20" }],
    evaluate: (f) => {
      if (f.auditLogsEnabled === undefined)
        return { status: "unverifiable", summary: "Audit log endpoint not reachable with the provided admin key.", evidence: [] };
      return f.auditLogsEnabled
        ? { status: "pass", summary: "Organization audit logging is enabled.", evidence: ["GET /v1/organization/audit_logs returned events"] }
        : { status: "fail", summary: "Organization audit logging is not enabled.", evidence: ["GET /v1/organization/audit_logs returned no data or 400"] };
    },
  },
  {
    id: "OAI-002",
    provider: "openai",
    title: `No API key unused for ${UNUSED_DAYS}+ days`,
    description: "Stale keys are the most common path to silent credential leaks.",
    severity: "medium",
    remediation: "Delete keys that have not been used in 90 days from each project's API keys page.",
    answers: [{ framework: "generic-ai", itemId: "GAI-12" }],
    evaluate: (f) => {
      const stale = f.projects.flatMap((p) =>
        p.apiKeys
          .filter((k) => (k.lastUsedAt ? olderThanDays(k.lastUsedAt, UNUSED_DAYS, f.collectedAt) : olderThanDays(k.createdAt, UNUSED_DAYS, f.collectedAt)))
          .map((k) => `${p.name}: ${k.name ?? k.id}`),
      );
      return stale.length === 0
        ? { status: "pass", summary: `All project API keys were used within the last ${UNUSED_DAYS} days.`, evidence: [] }
        : { status: "fail", summary: `${pluralise(stale.length, "API key")} unused for ${UNUSED_DAYS}+ days.`, evidence: stale.slice(0, 10) };
    },
  },
  {
    id: "OAI-003",
    provider: "openai",
    title: `No API key older than ${OLD_KEY_DAYS} days`,
    description: "Long-lived keys should be rotated.",
    severity: "low",
    remediation: "Rotate keys older than a year: create a replacement, deploy it, then delete the old key.",
    answers: [{ framework: "generic-ai", itemId: "GAI-13" }],
    evaluate: (f) => {
      const old = f.projects.flatMap((p) => p.apiKeys.filter((k) => olderThanDays(k.createdAt, OLD_KEY_DAYS, f.collectedAt)).map((k) => `${p.name}: ${k.name ?? k.id}`));
      return old.length === 0
        ? { status: "pass", summary: "All API keys are younger than a year.", evidence: [] }
        : { status: "fail", summary: `${pluralise(old.length, "API key")} older than ${OLD_KEY_DAYS} days.`, evidence: old.slice(0, 10) };
    },
  },
  {
    id: "OAI-004",
    provider: "openai",
    title: "Spend controls are configured",
    description: "An organization spend limit or per-project spend alerts cap runaway usage.",
    severity: "medium",
    remediation: "Set an organization monthly spend limit, or add spend alerts on every active project.",
    answers: [{ framework: "generic-ai", itemId: "GAI-22" }],
    evaluate: (f) => {
      const alertsKnown = f.projects.some((p) => p.spendAlertCount !== undefined);
      if (f.orgSpendLimitSet === undefined && !alertsKnown)
        return { status: "unverifiable", summary: "Spend limit and spend alert endpoints not reachable.", evidence: [] };
      if (f.orgSpendLimitSet) return { status: "pass", summary: "An organization spend limit is set.", evidence: ["POST/GET /v1/organization/spend_limit"] };
      const without = f.projects.filter((p) => p.status === "active" && (p.spendAlertCount ?? 0) === 0).map((p) => p.name);
      return without.length === 0
        ? { status: "pass", summary: "Every active project has at least one spend alert.", evidence: [] }
        : { status: "fail", summary: `${pluralise(without.length, "active project")} without spend limit or alert.`, evidence: without.slice(0, 10) };
    },
  },
  {
    id: "OAI-005",
    provider: "openai",
    title: "Production projects restrict usable models",
    description: "An allow-list prevents accidental use of unapproved models.",
    severity: "low",
    remediation: "Set model permissions to an allow-list on each production project.",
    answers: [{ framework: "generic-ai", itemId: "GAI-05" }],
    evaluate: (f) => {
      const known = f.projects.filter((p) => p.modelPermissionsMode !== undefined);
      if (known.length === 0) return { status: "unverifiable", summary: "Model permissions not readable with the provided key.", evidence: [] };
      const open = known.filter((p) => p.status === "active" && p.modelPermissionsMode !== "allow_list").map((p) => p.name);
      return open.length === 0
        ? { status: "pass", summary: "All active projects use a model allow-list.", evidence: [] }
        : { status: "fail", summary: `${pluralise(open.length, "active project")} without a model allow-list.`, evidence: open.slice(0, 10) };
    },
  },
  {
    id: "OAI-006",
    provider: "openai",
    title: "Data retention is set explicitly per project",
    description: "Projects inheriting an unstated organization default make retention answers ambiguous.",
    severity: "medium",
    remediation: "Set an explicit retention policy on each production project.",
    answers: [{ framework: "generic-ai", itemId: "GAI-08" }],
    evaluate: (f) => {
      const known = f.projects.filter((p) => p.dataRetention !== undefined);
      if (known.length === 0) return { status: "unverifiable", summary: "Data retention settings not readable with the provided key.", evidence: [] };
      const inherited = known.filter((p) => p.status === "active" && p.dataRetention === "organization_default").map((p) => p.name);
      return inherited.length === 0
        ? { status: "pass", summary: "All active projects set retention explicitly.", evidence: [] }
        : { status: "fail", summary: `${pluralise(inherited.length, "active project")} inherit the organization default retention.`, evidence: inherited.slice(0, 10) };
    },
  },
  {
    id: "OAI-007",
    provider: "openai",
    title: "Owner count is small and invites are not stale",
    description: "Few owners and no lingering invitations limit account takeover exposure.",
    severity: "low",
    remediation: `Keep owners to ${MAX_OWNERS} or fewer and revoke invitations older than ${STALE_INVITE_DAYS} days.`,
    answers: [{ framework: "generic-ai", itemId: "GAI-11" }],
    evaluate: (f) => {
      const owners = f.users.filter((u) => u.role === "owner").length;
      const stale = f.invites.filter((i) => i.status === "pending" && olderThanDays(i.invitedAt, STALE_INVITE_DAYS, f.collectedAt)).length;
      const evidence = [`${pluralise(owners, "owner")}`, `${pluralise(stale, "stale pending invite")}`];
      return owners <= MAX_OWNERS && stale === 0
        ? { status: "pass", summary: "Owner count and invitations are within policy.", evidence }
        : { status: "fail", summary: `${owners} owners and ${stale} stale invites.`, evidence };
    },
  },
  {
    id: "OAI-008",
    provider: "openai",
    title: "Production keys belong to service accounts",
    description: "Keys owned by individual users disappear or leak when people leave.",
    severity: "medium",
    remediation: "Create a service account per workload and move production traffic to its keys.",
    answers: [{ framework: "generic-ai", itemId: "GAI-12" }],
    evaluate: (f) => {
      const userOwned = f.projects.flatMap((p) => p.apiKeys.filter((k) => k.ownerType === "user").map((k) => `${p.name}: ${k.name ?? k.id}`));
      return userOwned.length === 0
        ? { status: "pass", summary: "All API keys are owned by service accounts.", evidence: [] }
        : { status: "fail", summary: `${pluralise(userOwned.length, "API key")} owned by individual users.`, evidence: userOwned.slice(0, 10) };
    },
  },
  {
    id: "OAI-009",
    provider: "openai",
    title: "Rate limits are tuned on active projects",
    description: "Project-level rate limits below the organization default contain abuse and bugs.",
    severity: "low",
    remediation: "Lower rate limits on projects serving public traffic.",
    answers: [{ framework: "generic-ai", itemId: "GAI-23" }],
    evaluate: (f) => {
      const known = f.projects.filter((p) => p.hasRateLimitOverrides !== undefined);
      if (known.length === 0) return { status: "unverifiable", summary: "Rate limit settings not readable.", evidence: [] };
      const untuned = known.filter((p) => p.status === "active" && !p.hasRateLimitOverrides).map((p) => p.name);
      return untuned.length === 0
        ? { status: "pass", summary: "All active projects override default rate limits.", evidence: [] }
        : { status: "fail", summary: `${pluralise(untuned.length, "active project")} on default rate limits.`, evidence: untuned.slice(0, 10) };
    },
  },
  {
    id: "OAI-010",
    provider: "openai",
    title: "Models used in the last 30 days",
    description: "Inventory of models actually called, from usage data.",
    severity: "info",
    remediation: "",
    answers: [{ framework: "generic-ai", itemId: "GAI-03" }],
    evaluate: (f) =>
      f.modelsUsed30d === undefined
        ? { status: "unverifiable", summary: "Usage endpoint not reachable.", evidence: [] }
        : { status: "pass", summary: `${pluralise(f.modelsUsed30d.length, "model")} used in the last 30 days.`, evidence: f.modelsUsed30d.slice(0, 25) },
  },
];
