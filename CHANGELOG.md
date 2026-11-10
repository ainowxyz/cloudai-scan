# Changelog

## 0.2.2 — 2026-11-10

- Answers: the list of connected accounts is labelled as product configuration (`origin: "configuration"`), not as an API observation.
- The `complete` answer state is labelled "Statement supplied": it is a mechanical state, not verification.

## 0.2.1 — 2026-11-10

- Display name is now Cloud AI Security. Package names, the `cloudai-scan` command and rule IDs are unchanged.
- README explains the difference between the local scanner and the hosted product.

## 0.2.0 — 2026-11-10

Rules version 2026.11.3. Results now say only what was read.

- New result state `needs_review` for observations that cannot settle a rule alone. WRK-004 (no Cloudflare Access application on an MCP-like Worker) and OAI-001 with an empty audit log use it instead of `fail`.
- No pass from missing data: facts are `undefined` when an endpoint could not be read and checks report `unverifiable`; an account with nothing relevant reports `not_applicable`.
- Every rule declares `limits` (what the result does not show) and `docsUrl`. Results carry `observed`: publishable values such as rate limits and model names, never names, emails or amounts.
- OpenAI: hard spend limits (OAI-004) are separated from spend alerts (new OAI-011). Model permissions, data retention, spend limits and rate limits are read from their documented endpoints. Archived projects are ignored.
- Anthropic: models come from `/analytics/usage`; spend limits from `/spend_limits` where readable; key workspace from `scope.workspace_id`.
- AI Gateway: guardrails, DLP, spend limits and stored keys read from the documented gateway fields.
- Cloudflare account: only operations Cloudflare labelled `cf-llm` count as LLM endpoints. WRK-001 is described as a name match, not proof of a bypass.
- Connectors enforce a read-only allow-list and redact credentials from error text.
- `buildAnswers` turns results and statements into the 25 questionnaire answers with a state each: complete, partial, needs statement, not readable, not applicable.

## 0.1.1 — 2026-11-10

- Every check declares `source`: the provider API call and fields it reads. Results carry it and the CLI prints it under each failure.
- Summaries agree in number ("1 file uses…", "2 files use…"); owner and admin counts use proper plurals.
- Rules version 2026.11.2.

## 0.1.0 — 2026-11-03

- First release: `cloudai-scan repo` (7 rules) and `cloudai-scan account` (14 rules across AI Gateway, Workers, zones and Access).
- `@cloudaisecurity/checks` 2026.11.1: adds `cloudflare-account` and `repo` providers to the OpenAI, Anthropic and AI Gateway rules.
- `@cloudaisecurity/connectors` 0.1.0: read-only collectors for OpenAI, Anthropic, Cloudflare AI Gateway and Cloudflare account inventory.
