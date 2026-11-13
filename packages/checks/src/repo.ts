import { GATEWAY_HOSTS, isProviderHost, MCP_PACKAGES, PROVIDER_SDKS } from "./patterns.js";
import type { CheckDefinition, RepoFacts } from "./types.js";
import { agree, notReadable, pluralise } from "./util.js";

type Outcome = ReturnType<CheckDefinition<RepoFacts>["evaluate"]>;

/** A pass or not applicable says nothing was found, which holds only if everything was scanned. Findings stand either way. */
function scanned(f: RepoFacts, outcome: Outcome): Outcome {
  const skipped = f.notScanned ?? [];
  if (skipped.length === 0 || (outcome.status !== "pass" && outcome.status !== "not_applicable")) return outcome;
  return notReadable(`Part of the repository was not scanned (${pluralise(skipped.length, "item")}), so this cannot be settled.`, skipped.slice(0, 20));
}

/** Rules whose pass or not applicable is a claim that something is absent from the whole repository. */
const ABSENCE_RULES = new Set(["REPO-001", "REPO-002", "REPO-003", "REPO-004", "REPO-006"]);

const rules: CheckDefinition<RepoFacts>[] = [
  {
    id: "REPO-001",
    provider: "repo",
    title: "No direct calls to model-provider hosts",
    description: "Source code that targets api.openai.com, api.anthropic.com and similar bypasses any gateway, so those calls have no central logging, limits or key management.",
    severity: "high",
    source: "Source files: URLs in string literals",
    limits: "Matches provider hostnames in string literals. A hostname in a comment or test also matches, and a hostname built at run time does not.",
    remediation: "Point the SDK's base URL at your AI Gateway (gateway.ai.cloudflare.com/v1/<account>/<gateway>/<provider>) or use the unified /ai/v1 endpoints.",
    answers: [{ framework: "generic-ai", itemId: "GAI-04" }],
    evaluate: (f) => {
      const hits = f.files.flatMap((file) => file.hosts.filter(isProviderHost).map((h) => `${file.path}: ${h}`));
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
    limits: "Looks for a gateway reference in the same file as the SDK import. A gateway configured in another file is not recognized.",
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
    limits: "Looks for a gateway option in the same file as the env.AI.run call. A gateway configured elsewhere is not recognized.",
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
    limits: "Matches values shaped like provider keys in wrangler vars. Secrets in other files are not scanned.",
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
    limits: "Looks for any Access or OAuth check anywhere in the repository. It does not prove that check protects the MCP routes, and authentication applied outside the repository is not seen.",
    remediation: "Validate the Cf-Access-Jwt-Assertion header, or use the OAuth provider from the Agents SDK, before serving tools.",
    answers: [{ framework: "generic-ai", itemId: "GAI-14" }],
    evaluate: (f) => {
      const mcp = f.files.filter((file) => file.hasMcpServer || file.imports.some((i) => MCP_PACKAGES.some((m) => i === m || i.startsWith(m + "/"))));
      // A pass here rests on a check that was found. "None found", of MCP code or of a check, depends on the whole repository.
      if (mcp.length === 0) return scanned(f, { status: "not_applicable", summary: "No MCP server code found.", evidence: [] });
      const anyAccess = f.files.some((file) => file.hasAccessCheck);
      const skipped = f.notScanned ?? [];
      // The check may be in a file that was left out, so its absence from the files read settles nothing.
      if (!anyAccess && skipped.length > 0)
        return notReadable(`${pluralise(mcp.length, "MCP server file")} found, and no Access or OAuth check in the files scanned. Part of the repository was not scanned (${pluralise(skipped.length, "item")}), so this cannot be settled.`, skipped.slice(0, 20));
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
    source: "wrangler.toml / wrangler.json(c): ai binding and observability.enabled, top level and each env",
    limits: "Reads the wrangler configuration in the repository. The deployed Worker may differ.",
    remediation: "Add \"observability\": { \"enabled\": true } to the wrangler configuration.",
    answers: [{ framework: "generic-ai", itemId: "GAI-20" }],
    evaluate: (f) => {
      const ai = f.wrangler.filter((w) => w.aiEnvironments.length > 0);
      if (ai.length === 0) return { status: "not_applicable", summary: "No wrangler configuration with an AI binding.", evidence: [] };
      // Each environment's AI binding is paired with the observability setting that applies to that environment.
      const off = ai.flatMap((w) => w.aiEnvironments.filter((e) => e.observabilityEnabled !== true).map((e) => `${w.path}${w.name ? ` (${w.name})` : ""}${e.env ? `, env ${e.env}` : ""}`));
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
    limits: "Lists variable names only. Values are never reported.",
    remediation: "",
    answers: [{ framework: "generic-ai", itemId: "GAI-21" }],
    evaluate: (f) => {
      const names = f.wrangler.flatMap((w) => w.providerKeyVarNames.map((n) => `${w.path}: ${n}`));
      return { status: "pass", summary: `${pluralise(names.length, "provider key variable")} referenced in configuration.`, evidence: names.slice(0, 20) };
    },
  },
];

export const repoChecks: CheckDefinition<RepoFacts>[] = rules.map((c) => (ABSENCE_RULES.has(c.id) ? { ...c, evaluate: (f: RepoFacts) => scanned(f, c.evaluate(f)) } : c));
