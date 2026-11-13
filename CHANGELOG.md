# Changelog

## Unreleased

Fixes from a code review (#1). Rule outcomes change for OAI-002, OAI-003, ANT-003, ANT-004, OAI-009, OAI-011 and REPO-001; the rules version is not bumped here.

- CLI: an option's value was taken as the command or the repository path, so `repo --fail-on medium` scanned a directory named `medium` and reported it clean. Values of `--fail-on`, `--token` and `--account` are no longer positional.
- CLI: an unknown `--fail-on` value exits 2 instead of never failing, and `repo <path>` exits with an error when the path is not a directory.
- Repository scan: a plaintext key in top-level wrangler `vars` is found even when an `env` overrides the same name.
- REPO-001 matches a provider host and its subdomains only; `api.openai.com.evil.example` is no longer a direct provider call.
- `HUGGING_FACE_*` variable and secret names are recognised as provider key names.
- Cloudflare: the AI Gateway, zone and Access application lists read every page instead of the first 50 (100 for Access).
- OAI-011: an organization-level spend alert passes even when project alerts or projects could not be read.
- Key and invitation age rules compare exact elapsed time instead of whole days.
- OAI-009 matches a used model to its own limits and dated snapshots only (`gpt-4o-mini` no longer counts `gpt-4o` as used), and its summary counts every model, not only the 12 listed.
- Answers: a statement of `N.A.` is read as not applicable.

Fixes from the whole-codebase review (#3, #4). Rule outcomes change for WRK-001 to WRK-004, ZONE-001, ZONE-002, ACC-001, OAI-004, OAI-009, OAI-010 and REPO-001 to REPO-006; the rules version is not bumped here.

- Cloudflare account: a Worker whose settings could not be read is marked `settingsReadable: false`. WRK-001 to WRK-004 no longer pass, or call themselves not applicable, on its empty bindings and secrets, and ACC-001 says how many Workers could not be classified.
- Cloudflare account: every Worker is listed. Settings are still read for the first 200 only; the rest are marked unread and an error says so, instead of being dropped from the account.
- Cloudflare account: Access application domains keep their path. WRK-004 counts only an application for the whole host (`host` or `host/*`) as covering it.
- ZONE-001 reads rate limiting rule expressions for the endpoint's path, host and method, with `not`, `and`, `xor` and `or` in Cloudflare's precedence and its case-sensitive comparisons, instead of looking for the path as text. A rule that excludes the endpoint, or is limited to another host or method, no longer counts; an expression it cannot settle is Needs review.
- ZONE-001 and ZONE-002 do not pass when the LLM labels of some zone could not be read.
- OAI-004: a project without a hard limit is Needs review, not Fail, when the organization limit could not be read.
- OpenAI: models from embeddings usage are kept when completions usage cannot be read, and the reverse. `modelsUsed30dUnread` names the usage type not read; OAI-010 says the list may be incomplete and OAI-009 does not narrow its list on a partial read.
- Connectors: every request must complete, body included, within 30 seconds; one that does not fails like any unreadable endpoint and the collection goes on.
- Connectors: a list longer than the page bound, or one that says more remain without giving a cursor, is reported as not readable instead of returned in part (Cloudflare, OpenAI and Anthropic).
- Repository scan: only source and wrangler files count toward the 5,000-file limit. Files too large, unreadable files and directories, unparsable wrangler files and the limit itself are listed in `notScanned`; REPO-001 to REPO-004 and REPO-006 do not pass or call themselves not applicable when anything was left out. REPO-005 is not applicable only on a complete scan; its pass, which rests on an MCP server and an Access or OAuth check both seen in the files read, can still come from a partial scan.
- REPO-006 pairs each environment's AI binding with the observability setting that applies to it (its own, else the top-level one).

## 0.2.5 — 2026-11-11

- OAI-009 also returns its values as a table (`table`: one row per model, with requests and tokens per minute as named columns). `observed` is unchanged and says the same thing; the table is for display, so a reader does not have to take a sentence apart. Answers carry it through as `ObservedLine.table`, with `who` naming the account.
- No rule changed. Rules version stays 2026.11.4.

## 0.2.4 — 2026-11-10

- Cloudflare account: when the cf-llm label response carries no operation count, the recorded reason now states what the count field contained, so the cause can be diagnosed. The result stays "not readable"; a missing count is never read as zero.

## 0.2.3 — 2026-11-10

Rules version 2026.11.4. Found by testing against live accounts.

- OpenAI: a 404 that says no spend limit or no model permissions are configured is a readable answer ("none"), so OAI-004 and OAI-005 now fail instead of reporting "not readable". Any other 404 stays unreadable.
- OpenAI: OAI-011 reads organization-level spend alerts as well as project alerts. If the organization alerts cannot be read and a project has none, the result is `needs_review`, not `fail`.
- Cloudflare account: LLM endpoint labels are read from `GET /zones/{zone_id}/api_gateway/labels/managed/cf-llm`. The previous request sent an unsupported `feature` parameter and failed, yet rules reported "no labelled endpoints". When the label cannot be read, ZONE-001 and ZONE-002 are `unverifiable` and ACC-001 says the labels were not readable instead of counting zero.
- Anthropic: `verify` now tests an endpoint the rules need (`/users`) instead of `/me`, and refuses a key that cannot read organization settings, with the reason. Individual organizations have no Admin API.
- New `readNothing(result)`: true when every request of a collection failed.
- Answers: `ANSWER_STATE_LABEL_READER` and `completenessLine(counts, "reader")` give buyer-facing wording; "still needed" lines no longer say "you".
- WRK-001 no longer feeds GAI-04 and WRK-003 no longer feeds GAI-23: neither setting answers those questions.
- Grammar: "0 of 1 gateway has", not "have".

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
