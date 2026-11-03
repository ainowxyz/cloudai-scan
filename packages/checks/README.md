# @cloudaisecurity/checks

Deterministic, versioned checks over AI provider configuration, used by [cloudaisecurity.com](https://cloudaisecurity.com) to produce verified AI trust pages, and by the `cloudai-scan` CLI.

- Checks are pure functions over **facts** collected read-only from a provider's admin API. No prompt or response content is ever read.
- Every check declares a severity, a remediation, and the questionnaire items it answers (generic AI appendix now; CAIQ-AI, SIG-AI and HECVAT-AI mappings to follow).
- A check that cannot be evaluated degrades to `unverifiable`, never to a wrong answer.

Providers: OpenAI (`OAI-*`), Anthropic (`ANT-*`), Cloudflare AI Gateway (`AIG-*`).

MIT licensed. Changes to a check's logic bump `CHECKS_VERSION` and are listed in `CHANGELOG.md`.
