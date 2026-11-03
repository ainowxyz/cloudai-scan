# cloudai-scan

Find ungoverned AI usage on Cloudflare, from your terminal or CI. No account needed for the repository scan; a read-only API token for the account scan. Nothing is uploaded anywhere.

```
$ cloudai-scan repo .

Repository /work/app (14 relevant files, 1 wrangler configs)  score 40/100  (2 pass, 3 fail, 0 unverifiable, 2 n/a)
  fail          REPO-001  high   2 direct provider calls in source.
      - src/llm.ts: api.openai.com
      fix: Point the SDK's base URL at your AI Gateway …
  fail          REPO-004  high   1 plaintext secret in wrangler configuration.
      - wrangler.jsonc: OPENAI_API_KEY
      fix: Remove the value from wrangler configuration, rotate the key …
```

## What it checks

**Repository (`cloudai-scan repo [path]`)** — source and `wrangler.{toml,json,jsonc}`:

| Rule | Severity | Finds |
|---|---|---|
| REPO-001 | high | direct calls to `api.openai.com`, `api.anthropic.com`, Gemini, Mistral, Cohere, OpenRouter, Groq… that bypass AI Gateway |
| REPO-002 | medium | provider SDKs (`openai`, `@anthropic-ai/sdk`, `@google/genai`…) with no gateway base URL in the file |
| REPO-003 | low | `env.AI.run()` without a gateway id |
| REPO-004 | high | provider keys committed as plaintext `vars` |
| REPO-005 | medium | MCP server code with no Access or OAuth check anywhere in the repo |
| REPO-006 | low | AI Workers with observability off |
| REPO-007 | info | provider key variable names (inventory) |

**Account (`cloudai-scan account`)** — Workers, AI Gateway, zones and Access:

| Rule | Severity | Finds |
|---|---|---|
| AIG-001…007 | high→info | unauthenticated gateways, prompt logging without DLP, no rate or spend limits, BYOK fallback, guardrails off, provider/model inventory |
| WRK-001 | medium | Workers holding provider API keys as secrets (names only; values are never read) |
| WRK-002 | low | AI Workers without observability |
| WRK-003 | medium | AI Workers reachable only on `workers.dev` |
| WRK-004 | high | MCP-looking Workers reachable without a Cloudflare Access application |
| ZONE-001 | high | endpoints Cloudflare labelled `cf-llm` with no rate limiting rule |
| ZONE-002 | medium | zones with LLM endpoints and neither Bot Fight Mode nor custom rules |
| ACC-001 | info | AI surface inventory |

Rules live in [`packages/checks`](packages/checks) (`@cloudaisecurity/checks`, MIT) and are the same code that powers [cloudaisecurity.com](https://cloudaisecurity.com/checks). A rule that cannot be evaluated reports `unverifiable`, never `pass`.

## Install

Until the packages are on npm, run from a clone:

```bash
git clone https://github.com/ainowxyz/cloudai-scan && cd cloudai-scan
pnpm install && pnpm -r build
node packages/cli/bin/cloudai-scan.mjs repo /path/to/your/worker
```

Account scan:

```bash
export CLOUDFLARE_API_TOKEN=…   # read-only token, scope below
export CLOUDFLARE_ACCOUNT_ID=…
node packages/cli/bin/cloudai-scan.mjs account
```

Token scope (all read): **Account** Workers Scripts, AI Gateway, Account Analytics, Access: Apps and Policies. **Zone (all zones)** Zone, Workers Routes, Zone WAF, API Gateway, Bot Management. Anything the token cannot read shows up as *unverifiable* with the endpoint named.

## CI

```yaml
- run: npx --yes github:ainowxyz/cloudai-scan repo . --fail-on high
```

`--fail-on high|medium|low|none` sets the exit-code threshold; `--json` prints machine-readable output.

## Why

AI Gateway, Access, rate limiting and Workers Logs are all free. Most AI incidents on Workers are a Worker that calls a provider directly with a key in a secret, an MCP server nobody put behind Access, or an LLM endpoint with no rate limit. This tool finds those in a minute.

Want the same checks on a trust page your enterprise buyers can read, plus OpenAI and Anthropic organisation checks? That is [cloudaisecurity.com](https://cloudaisecurity.com).

MIT © AINOW Group OÜ
