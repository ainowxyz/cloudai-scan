# Changelog

## 0.1.1 — 2026-11-10

- Every check declares `source`: the provider API call and fields it reads. Results carry it and the CLI prints it under each failure.
- Summaries agree in number ("1 file uses…", "2 files use…"); owner and admin counts use proper plurals.
- Rules version 2026.11.2.

## 0.1.0 — 2026-11-03

- First release: `cloudai-scan repo` (7 rules) and `cloudai-scan account` (14 rules across AI Gateway, Workers, zones and Access).
- `@cloudaisecurity/checks` 2026.11.1: adds `cloudflare-account` and `repo` providers to the OpenAI, Anthropic and AI Gateway rules.
- `@cloudaisecurity/connectors` 0.1.0: read-only collectors for OpenAI, Anthropic, Cloudflare AI Gateway and Cloudflare account inventory.
