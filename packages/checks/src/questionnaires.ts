import type { QuestionnaireFramework } from "./types.js";

export interface QuestionnaireItem {
  id: string;
  question: string;
  /** Which kind of input answers it: verified checks, customer statements, or both. */
  source: "checks" | "statement" | "both";
}

/**
 * The generic AI appendix: the ~25 questions that recur across enterprise AI
 * security reviews. Published openly as a template. Framework-specific mappings
 * (CAIQ-AI, SIG-AI, HECVAT-AI) are added in Milestone 2.
 */
export const genericAiAppendix: QuestionnaireItem[] = [
  { id: "GAI-01", question: "Describe the AI/ML features in your product and their purpose.", source: "statement" },
  { id: "GAI-02", question: "Which third-party AI providers do you use?", source: "both" },
  { id: "GAI-03", question: "Which models are in use, and how are new models approved?", source: "both" },
  { id: "GAI-04", question: "Do you route AI traffic through a gateway or proxy with central controls?", source: "both" },
  { id: "GAI-05", question: "How do you restrict which models your systems may call?", source: "both" },
  { id: "GAI-06", question: "Is customer data used to train or fine-tune any model, by you or your providers?", source: "statement" },
  { id: "GAI-07", question: "What contractual terms (DPA, zero data retention) are in place with AI providers?", source: "statement" },
  { id: "GAI-08", question: "What is the retention period for prompts and outputs at each provider and in your systems?", source: "both" },
  { id: "GAI-09", question: "Do you scan prompts or outputs for sensitive data (DLP)?", source: "both" },
  { id: "GAI-10", question: "Where is AI data processed and stored (regions)?", source: "statement" },
  { id: "GAI-11", question: "Who administers your AI provider accounts, and how is access reviewed?", source: "both" },
  { id: "GAI-12", question: "How are AI provider API keys issued, owned, reviewed and revoked?", source: "both" },
  { id: "GAI-13", question: "How often are AI provider credentials rotated?", source: "both" },
  { id: "GAI-14", question: "How are production AI credentials segregated from development and from individuals?", source: "both" },
  { id: "GAI-15", question: "Is there a human in the loop for AI outputs that affect customers?", source: "statement" },
  { id: "GAI-16", question: "How do you prevent and detect prompt injection?", source: "statement" },
  { id: "GAI-17", question: "What content safety controls or guardrails are applied to prompts and outputs?", source: "both" },
  { id: "GAI-18", question: "How are AI-related incidents detected, handled and communicated?", source: "statement" },
  { id: "GAI-19", question: "List all subprocessors involved in AI features.", source: "statement" },
  { id: "GAI-20", question: "Is administrative activity on AI provider accounts logged and reviewed?", source: "both" },
  { id: "GAI-21", question: "Do you maintain an inventory (AI bill of materials) of models and providers?", source: "both" },
  { id: "GAI-22", question: "What cost and usage limits protect against abuse or runaway consumption?", source: "both" },
  { id: "GAI-23", question: "What rate limits apply to AI endpoints?", source: "both" },
  { id: "GAI-24", question: "Which AI governance frameworks do you align to (ISO 42001, NIST AI RMF)?", source: "statement" },
  { id: "GAI-25", question: "Can customers opt out of AI features?", source: "statement" },
];

export const frameworks: Record<QuestionnaireFramework, { name: string; available: boolean }> = {
  "generic-ai": { name: "Generic AI security appendix", available: true },
  "caiq-ai": { name: "CSA AI-CAIQ", available: false },
  "sig-ai": { name: "Shared Assessments SIG 2026 — AI Governance", available: false },
  "hecvat-ai": { name: "EDUCAUSE HECVAT 4 — AI", available: false },
};
