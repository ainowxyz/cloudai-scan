import type { QuestionnaireFramework } from "./types.js";

export interface QuestionnaireItem {
  id: string;
  question: string;
  /** Which kind of input answers it: your statement alone, or provider settings plus your statement. */
  source: "statement" | "both";
  /** What provider settings can show for this question. Absent when nothing is observable. */
  observable?: string;
  /** What only you can state. No question is complete without it, because every question asks about more than a setting. */
  statementNeeded: string;
}

/**
 * The generic AI appendix: the 25 questions that recur across enterprise AI security reviews.
 * Published openly as a template. It is our own list, not a copy of any framework's questionnaire.
 */
export const genericAiAppendix: QuestionnaireItem[] = [
  { id: "GAI-01", question: "Describe the AI/ML features in your product and their purpose.", source: "statement", statementNeeded: "Each AI feature, the data it sends to a model, and who sees the output." },
  { id: "GAI-02", question: "Which third-party AI providers do you use?", source: "both", observable: "The provider accounts connected for checking, and providers seen in gateway traffic.", statementNeeded: "Confirmation that the list is complete, including any provider reached through a vendor or not connected here." },
  { id: "GAI-03", question: "Which models are in use, and how are new models approved?", source: "both", observable: "Models called in the last 30 days.", statementNeeded: "Who approves a new model, and where that approval is recorded." },
  { id: "GAI-04", question: "Do you route AI traffic through a gateway or proxy with central controls?", source: "both", observable: "Gateway settings and traffic, and Worker secrets named like provider keys.", statementNeeded: "Whether all model traffic passes through the gateway, and any exceptions." },
  { id: "GAI-05", question: "How do you restrict which models your systems may call?", source: "both", observable: "OpenAI project model permissions.", statementNeeded: "How model restrictions are enforced at other providers, and who can change them." },
  { id: "GAI-06", question: "Is customer data used to train or fine-tune any model, by you or your providers?", source: "statement", statementNeeded: "Whether customer data trains or fine-tunes any model, and the provider terms you rely on." },
  { id: "GAI-07", question: "What contractual terms (DPA, zero data retention) are in place with AI providers?", source: "statement", statementNeeded: "The agreements in place with each provider and the date each was signed." },
  { id: "GAI-08", question: "What is the retention period for prompts and outputs at each provider and in your systems?", source: "both", observable: "OpenAI project retention type, and whether the gateway stores prompts.", statementNeeded: "The retention period in days at each provider and in your own systems." },
  { id: "GAI-09", question: "Do you scan prompts or outputs for sensitive data (DLP)?", source: "both", observable: "Whether DLP scanning is on at the gateway.", statementNeeded: "What is scanned for, and what happens on a match." },
  { id: "GAI-10", question: "Where is AI data processed and stored (regions)?", source: "statement", statementNeeded: "The regions where prompts are processed and where you store them." },
  { id: "GAI-11", question: "Who administers your AI provider accounts, and how is access reviewed?", source: "both", observable: "Owner and admin counts, and stale invitations.", statementNeeded: "The roles that administer provider accounts, and how often access is reviewed." },
  { id: "GAI-12", question: "How are AI provider API keys issued, owned, reviewed and revoked?", source: "both", observable: "Key ownership, last use and workspace.", statementNeeded: "Who issues keys, and how a departing employee's keys are revoked." },
  { id: "GAI-13", question: "How often are AI provider credentials rotated?", source: "both", observable: "The age of the oldest key.", statementNeeded: "The rotation interval and the date keys were last rotated." },
  { id: "GAI-14", question: "How are production AI credentials segregated from development and from individuals?", source: "both", observable: "Key ownership, workspace separation and gateway authentication.", statementNeeded: "How production keys are separated from development and from individual people." },
  { id: "GAI-15", question: "Is there a human in the loop for AI outputs that affect customers?", source: "statement", statementNeeded: "Which outputs reach customers without human review, if any." },
  { id: "GAI-16", question: "How do you prevent and detect prompt injection?", source: "statement", statementNeeded: "Input handling, tool permissions and monitoring that limit prompt injection." },
  { id: "GAI-17", question: "What content safety controls or guardrails are applied to prompts and outputs?", source: "both", observable: "Whether gateway Guardrails are configured.", statementNeeded: "Which categories are filtered, and what happens on a match." },
  { id: "GAI-18", question: "How are AI-related incidents detected, handled and communicated?", source: "statement", statementNeeded: "Your incident process, and how an AI-related incident is reported to customers." },
  { id: "GAI-19", question: "List all subprocessors involved in AI features.", source: "statement", statementNeeded: "Every subprocessor in the AI data path, including gateways and hosting." },
  { id: "GAI-20", question: "Is administrative activity on AI provider accounts logged and reviewed?", source: "both", observable: "Whether the provider audit log returns events, and Worker logging.", statementNeeded: "Who reviews the logs, and how often." },
  { id: "GAI-21", question: "Do you maintain an inventory (AI bill of materials) of models and providers?", source: "both", observable: "Models, providers and AI Workers found in the connected accounts.", statementNeeded: "Whether you maintain the inventory yourselves, who owns it, and when it was last updated." },
  { id: "GAI-22", question: "What cost and usage limits protect against abuse or runaway consumption?", source: "both", observable: "Hard spend limits and spend alerts at the provider and the gateway.", statementNeeded: "What happens when a limit is reached, and who is notified." },
  { id: "GAI-23", question: "What rate limits apply to AI endpoints?", source: "both", observable: "Provider and gateway rate limit values, and rate limiting rules on labelled LLM endpoints.", statementNeeded: "The limits on your own AI endpoints, and how abuse is detected." },
  { id: "GAI-24", question: "Which AI governance frameworks do you align to (ISO 42001, NIST AI RMF)?", source: "statement", statementNeeded: "The frameworks you align to, and any certification held or planned." },
  { id: "GAI-25", question: "Can customers opt out of AI features?", source: "statement", statementNeeded: "Whether customers can switch AI features off, and at what level." },
];

/** Framework-specific mappings are planned. Only the generic appendix ships today. */
export const frameworks: Record<QuestionnaireFramework, { name: string; available: boolean }> = {
  "generic-ai": { name: "Generic AI security appendix", available: true },
  "caiq-ai": { name: "CSA AI-CAIQ", available: false },
  "sig-ai": { name: "Shared Assessments SIG 2026 — AI Governance", available: false },
  "hecvat-ai": { name: "EDUCAUSE HECVAT 4 — AI", available: false },
};
