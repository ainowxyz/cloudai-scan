import type { CheckDefinition, OpenAIApiKeyFact, OpenAIFacts, OpenAIProjectFact } from "./types.js";
import { agree, daysBetween, notApplicable, notReadable, num, olderThanDays, pluralise, tally, ofTotal } from "./util.js";

const UNUSED_DAYS = 90;
const OLD_KEY_DAYS = 365;
const STALE_INVITE_DAYS = 30;
const MAX_OWNERS = 3;
const DOCS = "https://developers.openai.com/api/docs/guides/admin-apis";

/** Active projects only: keys in archived projects no longer work. */
function active(f: OpenAIFacts): OpenAIProjectFact[] | undefined {
  return f.projects?.filter((p) => p.status === "active");
}

/** Keys of active projects, plus how many active projects' keys could not be read. */
function keysOf(f: OpenAIFacts): { keys: { project: string; key: OpenAIApiKeyFact }[]; unread: number } | undefined {
  const projects = active(f);
  if (!projects) return undefined;
  return {
    keys: projects.flatMap((p) => (p.apiKeys ?? []).map((key) => ({ project: p.name, key }))),
    unread: projects.filter((p) => p.apiKeys === undefined).length,
  };
}

const label = (k: { project: string; key: OpenAIApiKeyFact }) => `${k.project}: ${k.key.name ?? k.key.id}`;

export const openaiChecks: CheckDefinition<OpenAIFacts>[] = [
  {
    id: "OAI-001",
    provider: "openai",
    title: "The audit log returns events",
    description: "Reads one event from the organization audit log. If an event comes back, the organization is recording admin activity such as key, project, user and login changes.",
    severity: "high",
    source: "GET /v1/organization/audit_logs?limit=1: data[].effective_at",
    docsUrl: DOCS,
    limits: "Shows that admin events are being recorded. It does not show that anyone reviews them, or how long they are kept.",
    remediation: "In OpenAI platform settings, open Organization > General and enable audit logging. Once on it cannot be turned off.",
    answers: [{ framework: "generic-ai", itemId: "GAI-20" }],
    evaluate: (f) => {
      if (f.auditLogEvents === undefined) return notReadable("The audit log could not be read with this admin key.");
      if (f.auditLogEvents === 0)
        return {
          status: "needs_review",
          summary: "The audit log returned no events. Audit logging may be off, or nothing has been logged yet.",
          evidence: ["GET /v1/organization/audit_logs returned an empty list"],
          observed: ["The audit log returned no events"],
        };
      const when = f.auditLogLatestAt ? ` The most recent is dated ${f.auditLogLatestAt.slice(0, 10)}.` : "";
      return { status: "pass", summary: `The audit log returned events, so admin activity is being recorded.${when}`, evidence: [], observed: ["Audit log events are being recorded"] };
    },
  },
  {
    id: "OAI-002",
    provider: "openai",
    title: `No API key unused for ${UNUSED_DAYS}+ days`,
    description: "Compares each project API key's last use with today. A key nobody uses is a credential nobody is watching.",
    severity: "medium",
    source: "GET /v1/organization/projects/{project_id}/api_keys: last_used_at, created_at",
    docsUrl: DOCS,
    limits: "Covers project API keys in active projects. It does not show what a key is used for or where it is stored.",
    remediation: "Delete keys that have not been used in 90 days from each project's API keys page.",
    answers: [{ framework: "generic-ai", itemId: "GAI-12" }],
    evaluate: (f) => {
      const k = keysOf(f);
      if (!k) return notReadable("Projects could not be read with this admin key.");
      const stale = k.keys.filter(({ key }) => olderThanDays(key.lastUsedAt ?? key.createdAt, UNUSED_DAYS, f.collectedAt));
      const observed = [`${stale.length} of ${pluralise(k.keys.length, "project API key")} unused for ${UNUSED_DAYS}+ days`];
      if (stale.length > 0) return { status: "fail", summary: `${pluralise(stale.length, "API key")} unused for ${UNUSED_DAYS}+ days.`, evidence: stale.slice(0, 10).map(label), observed };
      if (k.unread > 0) return notReadable(`API keys could not be read for ${pluralise(k.unread, "active project")}.`);
      if (k.keys.length === 0) return notApplicable("No project API keys found in active projects.");
      return { status: "pass", summary: k.keys.length === 1 ? `The project API key was used within the last ${UNUSED_DAYS} days.` : `All ${k.keys.length} project API keys were used within the last ${UNUSED_DAYS} days.`, evidence: [], observed };
    },
  },
  {
    id: "OAI-003",
    provider: "openai",
    title: `No API key older than ${OLD_KEY_DAYS} days`,
    description: "Compares each project API key's creation date with today. Long-lived keys should be rotated.",
    severity: "low",
    source: "GET /v1/organization/projects/{project_id}/api_keys: created_at",
    docsUrl: DOCS,
    limits: "Shows key age only. It does not show the rotation policy or when keys were last rotated.",
    remediation: "Rotate keys older than a year: create a replacement, deploy it, then delete the old key.",
    answers: [{ framework: "generic-ai", itemId: "GAI-13" }],
    evaluate: (f) => {
      const k = keysOf(f);
      if (!k) return notReadable("Projects could not be read with this admin key.");
      const old = k.keys.filter(({ key }) => olderThanDays(key.createdAt, OLD_KEY_DAYS, f.collectedAt));
      const oldest = k.keys.reduce((m, { key }) => Math.max(m, daysBetween(key.createdAt, f.collectedAt)), 0);
      const observed = k.keys.length ? [`Oldest project API key: ${num(oldest)} days`, `${old.length} of ${pluralise(k.keys.length, "key")} older than ${OLD_KEY_DAYS} days`] : [];
      if (old.length > 0) return { status: "fail", summary: `${pluralise(old.length, "API key")} older than ${OLD_KEY_DAYS} days.`, evidence: old.slice(0, 10).map(label), observed };
      if (k.unread > 0) return notReadable(`API keys could not be read for ${pluralise(k.unread, "active project")}.`);
      if (k.keys.length === 0) return notApplicable("No project API keys found in active projects.");
      return { status: "pass", summary: `No project API key is older than ${OLD_KEY_DAYS} days.`, evidence: [], observed };
    },
  },
  {
    id: "OAI-004",
    provider: "openai",
    title: "A hard spend limit is set",
    description: "Reads the organization spend limit and each active project's spend limit. A hard limit is the control that stops spending; an alert only sends an email (see OAI-011).",
    severity: "medium",
    source: "GET /v1/organization/spend_limit: threshold_amount; GET /v1/organization/projects/{project_id}/spend_limit: threshold_amount, enforcement.status",
    docsUrl: DOCS,
    limits: "Shows whether a hard limit is configured. The amount is not published, and whether it is low enough for the organization's usage is a judgment this check cannot make.",
    remediation: "Set an organization monthly spend limit, or a spend limit on every active project.",
    answers: [{ framework: "generic-ai", itemId: "GAI-22" }],
    evaluate: (f) => {
      const projects = active(f);
      if (f.orgSpendLimitCents !== undefined && f.orgSpendLimitCents > 0)
        return { status: "pass", summary: "A hard monthly spend limit is set for the organization.", evidence: [], observed: ["Hard monthly spend limit set at organization level"] };
      if (!projects) return notReadable("Spend limits could not be read with this admin key.");
      const known = projects.filter((p) => p.spendLimitCents !== undefined);
      const without = known.filter((p) => (p.spendLimitCents ?? 0) === 0);
      const observed = [`${ofTotal(known.length - without.length, known.length, "active project", "has", "have")} a hard spend limit`];
      if (without.length > 0) {
        const org = f.orgSpendLimitCents === undefined ? "the organization limit could not be read" : "no organization limit is set";
        return { status: "fail", summary: `${pluralise(without.length, "active project")} ${agree(without.length, "has", "have")} no hard spend limit, and ${org}.`, evidence: without.slice(0, 10).map((p) => p.name), observed };
      }
      if (known.length < projects.length || known.length === 0) return notReadable("Spend limits could not be read with this admin key.");
      return { status: "pass", summary: "Every active project has a hard spend limit.", evidence: [], observed };
    },
  },
  {
    id: "OAI-005",
    provider: "openai",
    title: "Active projects restrict models with an allow-list",
    description: "Reads each active project's model permissions. An allow-list means only the listed models can be called from that project.",
    severity: "low",
    source: "GET /v1/organization/projects/{project_id}/model_permissions: mode, model_ids",
    docsUrl: DOCS,
    limits: "Reads the project setting. It does not show who approves a new model or how the list is reviewed.",
    remediation: "Set model permissions to an allow-list on each production project.",
    answers: [{ framework: "generic-ai", itemId: "GAI-05" }],
    evaluate: (f) => {
      const projects = active(f);
      if (!projects) return notReadable("Projects could not be read with this admin key.");
      const known = projects.filter((p) => p.modelPermissions !== undefined);
      if (known.length === 0) return projects.length === 0 ? notApplicable("No active projects found.") : notReadable("Model permissions could not be read with this admin key.");
      const open = known.filter((p) => p.modelPermissions?.mode !== "allow_list");
      const observed = [`${ofTotal(known.length - open.length, known.length, "active project", "uses", "use")} a model allow-list`];
      if (open.length > 0) return { status: "fail", summary: `${pluralise(open.length, "active project")} ${agree(open.length, "does", "do")} not use a model allow-list.`, evidence: open.slice(0, 10).map((p) => `${p.name}: ${p.modelPermissions?.mode ?? "none"}`), observed };
      if (known.length < projects.length) return notReadable(`Model permissions could not be read for ${pluralise(projects.length - known.length, "active project")}.`);
      return { status: "pass", summary: "Every active project uses a model allow-list.", evidence: [], observed };
    },
  },
  {
    id: "OAI-006",
    provider: "openai",
    title: "Data retention is set per project",
    description: "Reads the data retention type OpenAI reports for each active project. A project on “organization_default” inherits a setting this API does not state, so the retention answer has to come from you.",
    severity: "low",
    source: "GET /v1/organization/projects/{project_id}/data_retention: type",
    docsUrl: DOCS,
    limits: "Reports OpenAI's retention type per project, in OpenAI's own terms. It gives no number of days and does not cover retention in the company's own systems or at other providers.",
    remediation: "Set an explicit retention type on each production project, or state the organization default in your retention statement.",
    answers: [{ framework: "generic-ai", itemId: "GAI-08" }],
    evaluate: (f) => {
      const projects = active(f);
      if (!projects) return notReadable("Projects could not be read with this admin key.");
      const known = projects.filter((p) => p.dataRetention !== undefined);
      if (known.length === 0) return projects.length === 0 ? notApplicable("No active projects found.") : notReadable("Data retention settings could not be read with this admin key.");
      const observed = [`OpenAI data retention type across ${pluralise(known.length, "active project")}: ${tally(known.map((p) => p.dataRetention!))}`];
      const inherited = known.filter((p) => p.dataRetention === "organization_default");
      if (inherited.length > 0)
        return {
          status: "needs_review",
          summary: `${pluralise(inherited.length, "active project")} ${agree(inherited.length, "inherits", "inherit")} the organization default retention, which this API does not state.`,
          evidence: inherited.slice(0, 10).map((p) => p.name),
          observed,
        };
      if (known.length < projects.length) return notReadable(`Data retention could not be read for ${pluralise(projects.length - known.length, "active project")}.`);
      return { status: "pass", summary: "Every active project has its own data retention type.", evidence: known.slice(0, 10).map((p) => `${p.name}: ${p.dataRetention}`), observed };
    },
  },
  {
    id: "OAI-007",
    provider: "openai",
    title: "Owner count is small and invites are not stale",
    description: `Counts organization owners and pending invitations older than ${STALE_INVITE_DAYS} days. Names and email addresses are never published.`,
    severity: "low",
    source: "GET /v1/organization/users: role; GET /v1/organization/invites: status, invited_at",
    docsUrl: DOCS,
    limits: "Counts only. It does not show who the owners are, whether they use single sign-on or multi-factor authentication, or how access is reviewed.",
    remediation: `Keep owners to ${MAX_OWNERS} or fewer and revoke invitations older than ${STALE_INVITE_DAYS} days.`,
    answers: [{ framework: "generic-ai", itemId: "GAI-11" }],
    evaluate: (f) => {
      if (!f.users || !f.invites) return notReadable("Organization users or invitations could not be read with this admin key.");
      const owners = f.users.filter((u) => u.role === "owner").length;
      const stale = f.invites.filter((i) => i.status === "pending" && olderThanDays(i.invitedAt, STALE_INVITE_DAYS, f.collectedAt)).length;
      const observed = [pluralise(owners, "organization owner"), `${pluralise(stale, "pending invitation")} older than ${STALE_INVITE_DAYS} days`];
      return owners <= MAX_OWNERS && stale === 0
        ? { status: "pass", summary: `${pluralise(owners, "owner")} and no stale invitations.`, evidence: [], observed }
        : { status: "fail", summary: `${pluralise(owners, "owner")} and ${pluralise(stale, "stale invitation")}; the rule allows up to ${MAX_OWNERS} owners and none stale.`, evidence: [], observed };
    },
  },
  {
    id: "OAI-008",
    provider: "openai",
    title: "Project API keys belong to service accounts",
    description: "Reads the owner type of each project API key. A key owned by a person stops working, or lingers, when that person leaves.",
    severity: "medium",
    source: "GET /v1/organization/projects/{project_id}/api_keys: owner.type",
    docsUrl: DOCS,
    limits: "Shows the owner type of each key. It does not show which keys serve production traffic.",
    remediation: "Create a service account per workload and move production traffic to its keys.",
    answers: [{ framework: "generic-ai", itemId: "GAI-12" }, { framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      const k = keysOf(f);
      if (!k) return notReadable("Projects could not be read with this admin key.");
      const userOwned = k.keys.filter(({ key }) => key.ownerType === "user");
      const service = k.keys.filter(({ key }) => key.ownerType === "service_account").length;
      const observed = [`${service} of ${pluralise(k.keys.length, "project API key")} owned by service accounts, ${userOwned.length} by individual users`];
      if (userOwned.length > 0)
        return { status: "fail", summary: `${pluralise(userOwned.length, "API key")} ${agree(userOwned.length, "is owned by an individual user", "are owned by individual users")}.`, evidence: userOwned.slice(0, 10).map(label), observed };
      if (k.unread > 0) return notReadable(`API keys could not be read for ${pluralise(k.unread, "active project")}.`);
      if (k.keys.length === 0) return notApplicable("No project API keys found in active projects.");
      if (service < k.keys.length) return notReadable("The owner type was not returned for some project API keys.");
      return { status: "pass", summary: "Every project API key is owned by a service account.", evidence: [], observed };
    },
  },
  {
    id: "OAI-009",
    provider: "openai",
    title: "Rate limits OpenAI applies to the models in use",
    description: "Lists the per-minute request and token limits OpenAI applies in active projects, for the models called in the last 30 days. This is an inventory, not a pass or fail rule.",
    severity: "info",
    source: "GET /v1/organization/projects/{project_id}/rate_limits: model, max_requests_per_1_minute, max_tokens_per_1_minute",
    docsUrl: DOCS,
    limits: "These are OpenAI's limits on the organization's projects. Whether they were lowered from the defaults cannot be read, and they do not limit requests to the company's own endpoints.",
    remediation: "",
    answers: [{ framework: "generic-ai", itemId: "GAI-23" }],
    evaluate: (f) => {
      const projects = active(f);
      if (!projects) return notReadable("Projects could not be read with this admin key.");
      const limits = projects.flatMap((p) => p.rateLimits ?? []);
      if (limits.length === 0) return projects.some((p) => p.rateLimits === undefined) ? notReadable("Project rate limits could not be read with this admin key.") : notApplicable("No project rate limits were returned.");
      const used = f.modelsUsed30d;
      const models = [...new Set(limits.map((l) => l.model))].filter((m) => !used || used.some((u) => u === m || u.startsWith(`${m}-`) || m.startsWith(`${u}-`)));
      const range = (xs: number[]) => (xs.length === 0 ? null : Math.min(...xs) === Math.max(...xs) ? num(xs[0]!) : `${num(Math.min(...xs))} to ${num(Math.max(...xs))}`);
      const observed = models.slice(0, 12).map((m) => {
        const rows = limits.filter((l) => l.model === m);
        const rpm = range(rows.map((r) => r.maxRequestsPer1Minute).filter((x): x is number => typeof x === "number"));
        const tpm = range(rows.map((r) => r.maxTokensPer1Minute).filter((x): x is number => typeof x === "number"));
        return `${m}: ${[rpm && `${rpm} requests per minute`, tpm && `${tpm} tokens per minute`].filter(Boolean).join(", ")}`;
      });
      if (observed.length === 0) return notApplicable("No rate limits were returned for the models used in the last 30 days.");
      return { status: "pass", summary: `Read the rate limits for ${pluralise(observed.length, "model")} ${used ? "used in the last 30 days" : "configured in active projects"}.`, evidence: [], observed };
    },
  },
  {
    id: "OAI-010",
    provider: "openai",
    title: "Models used in the last 30 days",
    description: "Lists the models that appear in the organization's usage data for the last 30 days. This is an inventory, not a pass or fail rule.",
    severity: "info",
    source: "GET /v1/organization/usage/completions and /usage/embeddings, group_by=model: data[].results[].model, last 30 days",
    docsUrl: DOCS,
    limits: "Covers text completions and embeddings usage. Image, audio and other usage types are not read, and a model enabled but unused in the period does not appear.",
    remediation: "",
    answers: [{ framework: "generic-ai", itemId: "GAI-03" }, { framework: "generic-ai", itemId: "GAI-21" }],
    evaluate: (f) => {
      if (f.modelsUsed30d === undefined) return notReadable("Usage data could not be read with this admin key.");
      if (f.modelsUsed30d.length === 0) return { status: "pass", summary: "No model usage was recorded in the last 30 days.", evidence: [], observed: ["No models called in the last 30 days"] };
      return { status: "pass", summary: `${pluralise(f.modelsUsed30d.length, "model")} used in the last 30 days.`, evidence: [], observed: [`Models called in the last 30 days: ${f.modelsUsed30d.slice(0, 25).join(", ")}`] };
    },
  },
  {
    id: "OAI-011",
    provider: "openai",
    title: "Spend alerts are configured",
    description: "Counts the spend alerts set for the organization and on each active project. An alert emails the listed recipients when monthly spend passes a threshold. It does not stop usage.",
    severity: "low",
    source: "GET /v1/organization/spend_alerts and GET /v1/organization/projects/{project_id}/spend_alerts: number of alerts",
    docsUrl: DOCS,
    limits: "An alert notifies; it does not cap spending. For the control that stops spending, see OAI-004. Where organization-level alerts cannot be read, the result is Needs review rather than Fail.",
    remediation: "Add a spend alert for the organization or on every active project, addressed to a monitored mailbox.",
    answers: [{ framework: "generic-ai", itemId: "GAI-22" }],
    evaluate: (f) => {
      const projects = active(f);
      if (!projects) return notReadable("Projects could not be read with this admin key.");
      const known = projects.filter((p) => p.spendAlertCount !== undefined);
      if (known.length === 0) return projects.length === 0 ? notApplicable("No active projects found.") : notReadable("Spend alerts could not be read with this admin key.");
      const without = known.filter((p) => p.spendAlertCount === 0);
      const orgCount = f.orgSpendAlertCount;
      const observed = [
        ...(orgCount !== undefined ? [`${pluralise(orgCount, "organization-level spend alert")}`] : []),
        `${ofTotal(known.length - without.length, known.length, "active project", "has", "have")} a spend alert`,
      ];
      if (orgCount !== undefined && orgCount > 0)
        return { status: "pass", summary: `${pluralise(orgCount, "spend alert")} ${agree(orgCount, "is", "are")} set for the whole organization.`, evidence: [], observed };
      if (without.length > 0) {
        // Alerts can also be set for the whole organization. If that could not be read, a missing project alert settles nothing.
        if (orgCount === undefined)
          return {
            status: "needs_review",
            summary: `${pluralise(without.length, "active project")} ${agree(without.length, "has", "have")} no spend alert of ${agree(without.length, "its", "their")} own. Organization-level alerts could not be read, so check the organization's alerts in the OpenAI dashboard.`,
            evidence: without.slice(0, 10).map((p) => p.name),
            observed,
          };
        return { status: "fail", summary: `${pluralise(without.length, "active project")} ${agree(without.length, "has", "have")} no spend alert, and none is set for the organization.`, evidence: without.slice(0, 10).map((p) => p.name), observed };
      }
      if (known.length < projects.length) return notReadable(`Spend alerts could not be read for ${pluralise(projects.length - known.length, "active project")}.`);
      return { status: "pass", summary: "Every active project has at least one spend alert.", evidence: [], observed };
    },
  },
];
