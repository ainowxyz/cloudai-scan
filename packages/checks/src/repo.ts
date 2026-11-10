import { GATEWAY_HOSTS, MCP_PACKAGES, PROVIDER_HOSTS, PROVIDER_SDKS } from "./patterns.js";
import type { CheckDefinition, RepoFacts } from "./types.js";
import { agree, pluralise } from "./util.js";

export const repoChecks: CheckDefinition<RepoFacts>[] = [
  {
    id: "REPO-001",
    provider: "repo",
    title: "No direct calls to model-provider hosts",
    description: "Source code that targets api.openai.com, api.anthropic.com and similar bypasses any gateway, so those calls have no central logging, limits or key management.",
    severity: "high",
    source: "Source files: URLs in string literals",
    remediation: "Point the SDK's base URL at your AI Gateway (gateway.ai.cloudflare.com/v1/<account>/<gateway>/<provider>) or use the unified /ai/v1 endpoints.",
    answers: [{ framework: "generic-ai", itemId: "GAI-04" }],
    evaluate: (f) => {
      const hits = f.files.flatMap((file) => file.hosts.filter((h) => PROVIDER_HOSTS.some((p) => h.includes(p))).map((h) => `${file.path}: ${h}`));
      return hits.length === 0
        ? { status: "pass", summary: "No direct provider hosts found in source.", evidence: [] }
        : { status: "fail", summary: `${pluralise(hits.length, "direct provider call")} in source.`, evidence: hits.slice(0, 20) };
    },
  },
  {
    id: "REPO-002",
    provider: "repo",
    title: "Provider SDKs are configured through a gateway",
    description: "A provider SDK with no gateway reference in the same file is almost certainly calling the provider directly.",
    severity: "medium",
    source: "Source files: import statements and gateway references",
    remediation: "Pass baseURL pointing at AI Gateway when constructing the client, or route through the AI binding with a gateway id.",
    answers: [{ framework: "generic-ai", itemId: "GAI-04" }],
    evaluate: (f) => {
      const sdkFiles = f.files.filter((file) => file.imports.some((i) => PROVIDER_SDKS.includes(i)));
      if (sdkFiles.length === 0) return { status: "not_applicable", summary: "No provider SDK imports found.", evidence: [] };
      const direct = sdkFiles.filter((file) => !file.hasGatewayRef && !file.hosts.some((h) => GATEWAY_HOSTS.some((g) => h.includes(g)))).map((file) => file.path);
      return direct.length === 0
        ? { status: "pass", summary: "Every file using a provider SDK references a gateway.", evidence: [] }
        : { status: "fail", summary: `${pluralise(direct.length, "file")} ${agree(direct.length, "uses", "use")} a provider SDK without a gateway reference.`, evidence: direct.slice(0, 20) };
    },
  },
  {
    id: "REPO-003",
    provider: "repo",
    title: "Workers AI calls go through a gateway",
    description: "env.AI.run without a gateway id has no logs, caching, rate limits or spend limits.",
    severity: "low",
    source: "Source files: env.AI.run calls and gateway options",
    remediation: "Add { gateway: { id: \"<gateway>\" } } as the options argument to env.AI.run, or use the default gateway.",
    answers: [{ framework: "generic-ai", itemId: "GAI-04" }],
    evaluate: (f) => {
      const aiFiles = f.files.filter((file) => file.hasAiRun);
      if (aiFiles.length === 0) return { status: "not_applicable", summary: "No env.AI.run calls found.", evidence: [] };
      const bare = aiFiles.filter((file) => !file.hasGatewayRef).map((file) => file.path);
      return bare.length === 0
        ? { status: "pass", summary: "All Workers AI calls reference a gateway.", evidence: [] }
        : { status: "fail", summary: `${pluralise(bare.length, "file")} ${agree(bare.length, "calls", "call")} Workers AI without a gateway id.`, evidence: bare.slice(0, 20) };
    },
  },
  {
    id: "REPO-004",
    provider: "repo",
    title: "No provider secrets in plaintext configuration",
    description: "Wrangler vars are committed in plaintext; provider keys belong in secrets or AI Gateway BYOK.",
    severity: "high",
    source: "wrangler.toml / wrangler.json(c): vars values",
    remediation: "Remove the value from wrangler configuration, rotate the key, and store it with `wrangler secret put` or as a BYOK key on the gateway.",
    answers: [{ framework: "generic-ai", itemId: "GAI-12" }],
    evaluate: (f) => {
      const hits = f.wrangler.flatMap((w) => w.secretLikeVarNames.map((n) => `${w.path}: ${n}`));
      return hits.length === 0
        ? { status: "pass", summary: "No plaintext provider secrets in wrangler configuration.", evidence: [] }
        : { status: "fail", summary: `${pluralise(hits.length, "plaintext secret")} in wrangler configuration.`, evidence: hits };
    },
  },
  {
    id: "REPO-005",
    provider: "repo",
    title: "MCP servers verify callers",
    description: "An MCP server without an Access or OAuth check will serve any client that finds the URL.",
    severity: "medium",
    source: "Source files: MCP server code and Access or OAuth checks",
    remediation: "Validate the Cf-Access-Jwt-Assertion header, or use the OAuth provider from the Agents SDK, before serving tools.",
    answers: [{ framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      const mcp = f.files.filter((file) => file.hasMcpServer || file.imports.some((i) => MCP_PACKAGES.some((m) => i === m || i.startsWith(m + "/"))));
      if (mcp.length === 0) return { status: "not_applicable", summary: "No MCP server code found.", evidence: [] };
      const anyAccess = f.files.some((file) => file.hasAccessCheck);
      return anyAccess
        ? { status: "pass", summary: "MCP server code is present alongside an Access or OAuth check.", evidence: mcp.map((m) => m.path).slice(0, 10) }
        : { status: "fail", summary: `${pluralise(mcp.length, "MCP server file")} and no Access or OAuth check found in the repository.`, evidence: mcp.map((m) => m.path).slice(0, 10) };
    },
  },
  {
    id: "REPO-006",
    provider: "repo",
    title: "AI Workers enable observability in configuration",
    description: "Workers Logs should be on for any Worker with an AI binding.",
    severity: "low",
    source: "wrangler.toml / wrangler.json(c): ai binding, observability.enabled",
    remediation: "Add \"observability\": { \"enabled\": true } to the wrangler configuration.",
    answers: [{ framework: "generic-ai", itemId: "GAI-20" }],
    evaluate: (f) => {
      const ai = f.wrangler.filter((w) => w.hasAiBinding);
      if (ai.length === 0) return { status: "not_applicable", summary: "No wrangler configuration with an AI binding.", evidence: [] };
      const off = ai.filter((w) => w.observabilityEnabled !== true).map((w) => `${w.path}${w.name ? ` (${w.name})` : ""}`);
      return off.length === 0
        ? { status: "pass", summary: "All AI Workers enable observability.", evidence: [] }
        : { status: "fail", summary: `${pluralise(off.length, "AI Worker config")} without observability.`, evidence: off };
    },
  },
  {
    id: "REPO-007",
    provider: "repo",
    title: "Provider key variable names",
    description: "Inventory of configuration variables that look like provider keys (names only).",
    severity: "info",
    source: "wrangler.toml / wrangler.json(c): vars names",
    remediation: "",
    answers: [{ framework: "generic-ai", itemId: "GAI-21" }],
    evaluate: (f) => {
      const names = f.wrangler.flatMap((w) => w.providerKeyVarNames.map((n) => `${w.path}: ${n}`));
      return { status: "pass", summary: `${pluralise(names.length, "provider key variable")} referenced in configuration.`, evidence: names.slice(0, 20) };
    },
  },
];
