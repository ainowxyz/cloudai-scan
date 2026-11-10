import { anthropicChecks } from "./anthropic.js";
import { aiGatewayChecks } from "./aigateway.js";
import { cloudflareAccountChecks } from "./cloudflare-account.js";
import { openaiChecks } from "./openai.js";
import { genericAiAppendix } from "./questionnaires.js";
import { repoChecks } from "./repo.js";
import type { CheckStatus, Provider } from "./types.js";

/**
 * How finished one answer is. This is a mechanical state: it says which parts are present.
 * It never means that anyone has verified a statement, and it is separate from a rule's pass or fail.
 * complete: the required statement has been supplied (provider evidence, where it exists, is attached to it).
 * partial: provider settings were read, but the part only you can state is missing.
 * needs_statement: nothing was read for this question and you have not stated an answer.
 * not_readable: checks exist for this question but none could be read, and you have not stated an answer.
 * not_applicable: you stated that the question does not apply.
 */
export type AnswerState = "complete" | "partial" | "needs_statement" | "not_readable" | "not_applicable";

export const ANSWER_STATES: AnswerState[] = ["complete", "partial", "needs_statement", "not_readable", "not_applicable"];

export const ANSWER_STATE_LABEL: Record<AnswerState, string> = {
  complete: "Statement supplied",
  partial: "Partial: statement needed",
  needs_statement: "Needs your statement",
  not_readable: "Not readable",
  not_applicable: "Not applicable",
};

/**
 * The same states in the words a buyer reads. "Your statement" on a page sent to a buyer reads as the buyer's own,
 * so anything shown outside the owner's screens uses these.
 */
export const ANSWER_STATE_LABEL_READER: Record<AnswerState, string> = {
  complete: "Statement supplied",
  partial: "Partial: no statement supplied",
  needs_statement: "No statement supplied",
  not_readable: "Not readable, no statement",
  not_applicable: "Not applicable",
};

export interface AnswerResultInput {
  checkId: string;
  provider: Provider | string;
  status: CheckStatus | string;
  summary: string;
  observed: string[];
  /** Optional label when one organization connects two accounts of the same provider. */
  connection?: string | null;
  /** When this result was read from the provider (ISO 8601). */
  checkedAt?: string | null;
}

export interface AnswerInput {
  /** Providers with a connected account, whether or not their checks were readable. */
  providers: (Provider | string)[];
  results: AnswerResultInput[];
  statements: { itemId: string; answer: string; attestedAt: string }[];
}

export interface ObservedLine {
  checkId: string | null;
  provider: Provider | string | null;
  status: CheckStatus | string;
  /** What was read, in one line a buyer can check. */
  text: string;
  /** The provider API call and fields behind it. */
  source: string;
  /** What the observation does not show. */
  limits: string;
  /**
   * Where the line comes from. "provider_api": read from the provider's API by a rule.
   * "configuration": derived from what is configured in the product, such as the list of connected accounts.
   */
  origin: "provider_api" | "configuration";
  /** When it was read from the provider, if known. */
  checkedAt: string | null;
}

export interface BuiltAnswer {
  id: string;
  question: string;
  state: AnswerState;
  /** Read from provider settings. Never includes anything you stated. */
  observed: ObservedLine[];
  /** What you stated, and when you attested it. Never includes anything read from a provider. */
  statement: { text: string; attestedAt: string } | null;
  /** What is still needed before this answer is complete. */
  missing: string[];
  /** Things to look at before sending, such as a statement next to a failing check. */
  flags: string[];
}

export interface BuiltAnswers {
  answers: BuiltAnswer[];
  counts: Record<AnswerState, number>;
  /** Answers that are neither complete nor not applicable. */
  incomplete: number;
}

const LABEL: Record<string, string> = { openai: "OpenAI", anthropic: "Anthropic", "cloudflare-ai-gateway": "Cloudflare AI Gateway", "cloudflare-account": "Cloudflare account", repo: "Repository" };
const CATALOGUE = new Map([...openaiChecks, ...anthropicChecks, ...aiGatewayChecks, ...cloudflareAccountChecks, ...repoChecks].map((c) => [c.id, c] as const));
const READ = new Set(["pass", "fail", "needs_review"]);
const NOT_APPLICABLE = /^\s*(n\/a|n\.a\.|not applicable)\b/i;

/**
 * Builds the 25 answers from what was read and what was stated, keeping the two apart.
 * A passing check never completes an answer on its own: every question asks for more than a setting.
 */
export function buildAnswers(input: AnswerInput): BuiltAnswers {
  const statements = new Map(input.statements.filter((s) => s.answer.trim() !== "").map((s) => [s.itemId, s] as const));
  const counts = { complete: 0, partial: 0, needs_statement: 0, not_readable: 0, not_applicable: 0 } as Record<AnswerState, number>;

  const answers = genericAiAppendix.map((q): BuiltAnswer => {
    const mapped = input.results.filter((r) => CATALOGUE.get(r.checkId)?.answers.some((a) => a.framework === "generic-ai" && a.itemId === q.id));
    const read = mapped.filter((r) => READ.has(r.status));
    const unreadable = mapped.filter((r) => r.status === "unverifiable");

    const observed: ObservedLine[] = read.map((r) => {
      const def = CATALOGUE.get(r.checkId)!;
      const who = `${LABEL[r.provider] ?? r.provider}${r.connection ? ` (${r.connection})` : ""}`;
      const text = r.observed.length ? r.observed.join("; ") : r.summary.replace(/\.$/, "");
      return { checkId: r.checkId, provider: r.provider, status: r.status, text: `${who}: ${text}.`, source: def.source, limits: def.limits, origin: "provider_api", checkedAt: r.checkedAt ?? null };
    });

    // The list of connected accounts comes from the product's own configuration, not from a provider API,
    // so it is labelled as an inventory and never as an API observation.
    if (q.id === "GAI-02" && input.providers.length > 0) {
      const names = [...new Set(input.providers.map((p) => LABEL[p] ?? p))];
      observed.unshift({
        checkId: null,
        provider: null,
        status: "pass",
        text: `Connected for checking: ${names.join(", ")}.`,
        source: "Connections configured in Cloud AI Security",
        limits: "Lists what is connected for checking. A provider in use but not connected does not appear.",
        origin: "configuration",
        checkedAt: null,
      });
    }

    const s = statements.get(q.id) ?? null;
    let state: AnswerState;
    if (s && NOT_APPLICABLE.test(s.answer)) state = "not_applicable";
    else if (s) state = "complete";
    else if (observed.length > 0) state = "partial";
    else if (unreadable.length > 0) state = "not_readable";
    else state = "needs_statement";

    const missing: string[] = [];
    if (!s) missing.push(q.statementNeeded);
    if (unreadable.length > 0 && state !== "not_applicable") missing.push(`Provider settings that could not be read: ${[...new Set(unreadable.map((r) => r.checkId))].join(", ")}.`);

    const flags: string[] = [];
    const failing = read.filter((r) => r.status === "fail");
    const review = read.filter((r) => r.status === "needs_review");
    if (s && failing.length > 0) flags.push(`${failing.length === 1 ? "A checked control" : `${failing.length} checked controls`} for this question currently ${failing.length === 1 ? "fails" : "fail"} (${failing.map((r) => r.checkId).join(", ")}). The statement should not contradict ${failing.length === 1 ? "it" : "them"}.`);
    if (review.length > 0) flags.push(`${review.map((r) => r.checkId).join(", ")} ${review.length === 1 ? "needs" : "need"} review: the setting was read but cannot settle the question on its own.`);

    counts[state]++;
    return { id: q.id, question: q.question, state, observed, statement: s ? { text: s.answer.trim(), attestedAt: s.attestedAt } : null, missing, flags };
  });

  return { answers, counts, incomplete: answers.filter((a) => a.state !== "complete" && a.state !== "not_applicable").length };
}

/** "9 with a statement supplied, 8 partial, 6 needing your statement, 2 not readable, 0 not applicable" */
export function completenessLine(counts: Record<AnswerState, number>, audience: "owner" | "reader" = "owner"): string {
  return [
    `${counts.complete} with a statement supplied`,
    `${counts.partial} partial`,
    audience === "owner" ? `${counts.needs_statement} needing your statement` : `${counts.needs_statement} with no statement supplied`,
    `${counts.not_readable} not readable`,
    `${counts.not_applicable} not applicable`,
  ].join(", ");
}
