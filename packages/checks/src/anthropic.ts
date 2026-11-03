import type { AnthropicFacts, CheckDefinition } from "./types.js";
import { olderThanDays, pluralise } from "./util.js";

const OLD_KEY_DAYS = 365;
const STALE_INVITE_DAYS = 30;
const MAX_ADMINS = 3;
const ADMIN_ROLES = new Set(["admin", "owner", "primary_owner"]);

export const anthropicChecks: CheckDefinition<AnthropicFacts>[] = [
  {
    id: "ANT-001",
    provider: "anthropic",
    title: "No active API key in an archived workspace",
    description: "Keys that outlive their workspace are forgotten credentials.",
    severity: "medium",
    remediation: "Deactivate keys belonging to archived workspaces in the Claude Console.",
    answers: [{ framework: "generic-ai", itemId: "GAI-12" }],
    evaluate: (f) => {
      const archived = new Set(f.workspaces.filter((w) => w.archivedAt).map((w) => w.id));
      const orphans = f.apiKeys.filter((k) => k.status === "active" && k.workspaceId && archived.has(k.workspaceId)).map((k) => k.name);
      return orphans.length === 0
        ? { status: "pass", summary: "No active keys in archived workspaces.", evidence: [] }
        : { status: "fail", summary: `${pluralise(orphans.length, "active key")} in archived workspaces.`, evidence: orphans.slice(0, 10) };
    },
  },
  {
    id: "ANT-002",
    provider: "anthropic",
    title: "Production keys live in a dedicated workspace",
    description: "Keys in the default workspace cannot be scoped, limited or reported separately.",
    severity: "medium",
    remediation: "Create a workspace per environment and issue keys there; deactivate default-workspace keys.",
    answers: [{ framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      const inDefault = f.apiKeys.filter((k) => k.status === "active" && (k.workspaceId === null || f.workspaces.find((w) => w.id === k.workspaceId)?.isDefault)).map((k) => k.name);
      return inDefault.length === 0
        ? { status: "pass", summary: "All active keys are scoped to a non-default workspace.", evidence: [] }
        : { status: "fail", summary: `${pluralise(inDefault.length, "active key")} in the default workspace.`, evidence: inDefault.slice(0, 10) };
    },
  },
  {
    id: "ANT-003",
    provider: "anthropic",
    title: `No active key older than ${OLD_KEY_DAYS} days`,
    description: "Long-lived keys should be rotated.",
    severity: "low",
    remediation: "Rotate keys older than a year.",
    answers: [{ framework: "generic-ai", itemId: "GAI-13" }],
    evaluate: (f) => {
      const old = f.apiKeys.filter((k) => k.status === "active" && olderThanDays(k.createdAt, OLD_KEY_DAYS, f.collectedAt)).map((k) => k.name);
      return old.length === 0
        ? { status: "pass", summary: "All active keys are younger than a year.", evidence: [] }
        : { status: "fail", summary: `${pluralise(old.length, "active key")} older than ${OLD_KEY_DAYS} days.`, evidence: old.slice(0, 10) };
    },
  },
  {
    id: "ANT-004",
    provider: "anthropic",
    title: "Admin count is small and invites are not stale",
    description: "Few admins and no lingering invitations limit account takeover exposure.",
    severity: "low",
    remediation: `Keep admins to ${MAX_ADMINS} or fewer and revoke invitations older than ${STALE_INVITE_DAYS} days.`,
    answers: [{ framework: "generic-ai", itemId: "GAI-11" }],
    evaluate: (f) => {
      const admins = f.users.filter((u) => ADMIN_ROLES.has(u.role)).length;
      const stale = f.invites.filter((i) => i.status === "pending" && i.invitedAt && olderThanDays(i.invitedAt, STALE_INVITE_DAYS, f.collectedAt)).length;
      const evidence = [`${pluralise(admins, "admin/owner")}`, `${pluralise(stale, "stale pending invite")}`];
      return admins <= MAX_ADMINS && stale === 0
        ? { status: "pass", summary: "Admin count and invitations are within policy.", evidence }
        : { status: "fail", summary: `${admins} admins and ${stale} stale invites.`, evidence };
    },
  },
  {
    id: "ANT-005",
    provider: "anthropic",
    title: "Workspace spend limits",
    description: "Workspace spend limits cap runaway usage. Readable only on plans that expose them.",
    severity: "medium",
    remediation: "Set a monthly spend limit on each production workspace in the Claude Console.",
    answers: [{ framework: "generic-ai", itemId: "GAI-22" }],
    evaluate: () => ({ status: "unverifiable", summary: "Workspace spend limits are not exposed by the Admin API for this organization.", evidence: [] }),
  },
  {
    id: "ANT-006",
    provider: "anthropic",
    title: "Models used in the last 30 days",
    description: "Inventory of models actually called, from the usage analytics API.",
    severity: "info",
    remediation: "",
    answers: [{ framework: "generic-ai", itemId: "GAI-03" }],
    evaluate: (f) =>
      f.modelsUsed30d === undefined
        ? { status: "unverifiable", summary: "Usage analytics endpoint not reachable.", evidence: [] }
        : { status: "pass", summary: `${pluralise(f.modelsUsed30d.length, "model")} used in the last 30 days.`, evidence: f.modelsUsed30d.slice(0, 25) },
  },
];
