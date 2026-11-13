import { describe, expect, it } from "vitest";
import { expressionMatches } from "../src/cloudflare-account.js";
import { isProviderHost, PROVIDER_KEY_NAME, runChecks, type CloudflareAccountFacts, type RepoFacts } from "../src/index.js";

const NOW = "2026-11-03T00:00:00.000Z";

describe("cloudflare account checks", () => {
  const facts: CloudflareAccountFacts = {
    workers: [
      { name: "chat-api", bindings: [{ type: "ai", name: "AI" }], secretNames: ["OPENAI_API_KEY"], routes: ["app.example.com/api/*"], customDomains: [], workersDevEnabled: false, observabilityEnabled: true },
      { name: "docs-mcp", bindings: [], secretNames: [], routes: [], customDomains: ["mcp.example.com"], workersDevEnabled: true, observabilityEnabled: false },
    ],
    zones: [
      {
        id: "z1",
        name: "example.com",
        llmOperationCount: 1,
        llmOperations: [{ method: "POST", host: "app.example.com", endpoint: "/api/chat" }],
        rateLimitExpressions: ['(http.request.uri.path eq "/api/login")'],
        customRuleExpressions: [],
        botFightMode: false,
      },
    ],
    accessHostnames: ["admin.example.com"],
    collectedAt: NOW,
  };
  const r = runChecks("cloudflare-account", facts);
  const by = (id: string) => r.find((x) => x.id === id)!;

  it("flags provider keys on Workers", () => expect(by("WRK-001").status).toBe("fail"));
  it("reports an MCP Worker without Access as needing review, not as unauthenticated", () => {
    expect(by("WRK-004").status).toBe("needs_review");
    expect(by("WRK-004").evidence[0]).toContain("docs-mcp");
    expect(by("WRK-004").summary).toMatch(/cannot be read/);
    expect(by("WRK-004").summary).not.toMatch(/unauthenticated|reachable without/i);
    expect(by("WRK-004").limits).toMatch(/OAuth/);
  });
  it("passes WRK-004 when Access covers every hostname", () => {
    const covered = runChecks("cloudflare-account", { ...facts, workers: [{ ...facts.workers![1]!, workersDevEnabled: false }], accessHostnames: ["mcp.example.com"] });
    expect(covered.find((x) => x.id === "WRK-004")?.status).toBe("pass");
  });
  it("a secret name is reported as a name match, not as proof of a bypass", () => {
    expect(by("WRK-001").summary).toMatch(/named like/);
    expect(by("WRK-001").limits).toMatch(/does not prove/);
  });
  it("never passes when Workers or zones could not be read", () => {
    for (const r of runChecks("cloudflare-account", { collectedAt: NOW })) expect(r.status, r.id).toBe("unverifiable");
  });
  it("an account with nothing relevant is not applicable", () => {
    const empty = runChecks("cloudflare-account", { workers: [], zones: [], accessHostnames: [], collectedAt: NOW });
    for (const id of ["WRK-001", "WRK-002", "WRK-003", "WRK-004", "ZONE-001", "ZONE-002"]) expect(empty.find((x) => x.id === id)?.status, id).toBe("not_applicable");
  });
  it("flags uncovered LLM endpoints and bare zones", () => {
    expect(by("ZONE-001").status).toBe("fail");
    expect(by("ZONE-002").status).toBe("fail");
  });
  it("passes WRK-003 when the AI Worker is on a route", () => expect(by("WRK-003").status).toBe("pass"));
  it("claims nothing about LLM endpoints when the labels could not be read", () => {
    const unread = runChecks("cloudflare-account", { ...facts, zones: [{ id: "z1", name: "example.com", rateLimitExpressions: [], customRuleExpressions: [], botFightMode: false }] });
    const of = (id: string) => unread.find((x) => x.id === id)!;
    expect(of("ZONE-001").status).toBe("unverifiable");
    expect(of("ZONE-002").status).toBe("unverifiable");
    expect(of("ACC-001").observed[0]).toMatch(/not readable on 1 of 1 zone/);
    expect(of("ACC-001").observed[0]).not.toMatch(/0 labelled/);
  });
  it("asks for review when Cloudflare gives a count but not the endpoints", () => {
    const counted = runChecks("cloudflare-account", { ...facts, zones: [{ id: "z1", name: "example.com", llmOperationCount: 2, rateLimitExpressions: [], customRuleExpressions: [], botFightMode: true }] });
    expect(counted.find((x) => x.id === "ZONE-001")?.status).toBe("needs_review");
  });
  it("counts inventory", () => expect(by("ACC-001").summary).toContain("1 AI Worker"));

  const unreadWorker = { name: "unread", bindings: [], secretNames: [], routes: [], customDomains: [], settingsReadable: false };
  it("a Worker whose settings could not be read is not counted as having no secrets or bindings", () => {
    const blind = runChecks("cloudflare-account", { ...facts, workers: [unreadWorker], zones: [] });
    for (const id of ["WRK-001", "WRK-002", "WRK-003", "WRK-004"]) expect(blind.find((x) => x.id === id)?.status, id).toBe("unverifiable");
    expect(blind.find((x) => x.id === "ACC-001")?.observed[0]).toMatch(/settings not readable for 1 of 1 Worker/);
    const mixed = runChecks("cloudflare-account", { ...facts, workers: [{ ...facts.workers![0]!, secretNames: [] }, unreadWorker] });
    expect(mixed.find((x) => x.id === "WRK-001")?.status).toBe("unverifiable");
    expect(mixed.find((x) => x.id === "WRK-003")?.status).toBe("unverifiable");
    const failing = runChecks("cloudflare-account", { ...facts, workers: [...facts.workers!, unreadWorker] });
    expect(failing.find((x) => x.id === "WRK-001")?.status).toBe("fail");
  });

  it("an Access application limited to a path does not cover the whole host", () => {
    const mcp = [{ ...facts.workers![1]!, workersDevEnabled: false }];
    const scoped = runChecks("cloudflare-account", { ...facts, workers: mcp, accessHostnames: ["mcp.example.com/admin/*"] });
    expect(scoped.find((x) => x.id === "WRK-004")?.status).toBe("needs_review");
    const whole = runChecks("cloudflare-account", { ...facts, workers: mcp, accessHostnames: ["MCP.example.com/*"] });
    expect(whole.find((x) => x.id === "WRK-004")?.status).toBe("pass");
  });

  it("an Access application for the root path alone does not cover the whole host, and the result says it is there", () => {
    const mcp = [{ ...facts.workers![1]!, workersDevEnabled: false }];
    const root = runChecks("cloudflare-account", { ...facts, workers: mcp, accessHostnames: ["mcp.example.com/"] }).find((x) => x.id === "WRK-004")!;
    expect(root.status).toBe("needs_review");
    expect(root.evidence[0]).toMatch(/only the root path of mcp\.example\.com/);
    const bare = runChecks("cloudflare-account", { ...facts, workers: mcp, accessHostnames: ["mcp.example.com"] }).find((x) => x.id === "WRK-004")!;
    expect(bare.status).toBe("pass");
    // A path-limited application is not described as a root-path one.
    const scoped = runChecks("cloudflare-account", { ...facts, workers: mcp, accessHostnames: ["mcp.example.com/admin/"] }).find((x) => x.id === "WRK-004")!;
    expect(scoped.status).toBe("needs_review");
    expect(scoped.evidence[0]).not.toMatch(/root path/);
  });

  const zone = (rateLimitExpressions: string[]) => ({ ...facts.zones![0]!, rateLimitExpressions, botFightMode: true });
  const zone001 = (rateLimitExpressions: string[]) => runChecks("cloudflare-account", { ...facts, zones: [zone(rateLimitExpressions)] }).find((x) => x.id === "ZONE-001")!.status;
  it("ZONE-001 passes only on a rule that matches the endpoint, never on one that excludes it", () => {
    expect(zone001(['(http.request.uri.path eq "/api/chat")'])).toBe("pass");
    expect(zone001(['not (http.request.uri.path eq "/api/chat")'])).toBe("fail");
    expect(zone001(['(http.request.uri.path eq "/api/chat" and http.host eq "other.example.com")'])).toBe("fail");
    expect(zone001(['(http.request.uri.path eq "/api/chat" and http.request.method eq "GET")'])).toBe("fail");
    expect(zone001(['(http.request.uri.path matches "^/api/chat$")'])).toBe("needs_review");
    expect(zone001(["true"])).toBe("pass");
  });

  it("an unread label on one zone keeps ZONE-001 and ZONE-002 from passing for every zone", () => {
    const mixed = runChecks("cloudflare-account", {
      ...facts,
      zones: [zone(['(http.request.uri.path eq "/api/chat")']), { id: "z2", name: "other.example", rateLimitExpressions: [], customRuleExpressions: [], botFightMode: false }],
    });
    expect(mixed.find((x) => x.id === "ZONE-001")?.status).toBe("unverifiable");
    expect(mixed.find((x) => x.id === "ZONE-002")?.status).toBe("unverifiable");
  });
});

describe("rule expressions", () => {
  const op = { method: "POST", host: "app.example.com", endpoint: "/api/chat" };
  it("reads path, host and method conditions with and, or and not", () => {
    expect(expressionMatches('http.request.uri.path in {"/api/chat" "/api/complete"}', op)).toBe(true);
    expect(expressionMatches('starts_with(http.request.uri.path, "/api/")', op)).toBe(true);
    expect(expressionMatches('http.request.uri.path contains "/chat" && http.host == "app.example.com"', op)).toBe(true);
    expect(expressionMatches('(http.request.uri.path eq "/other") or (http.request.method eq "POST")', op)).toBe(true);
    expect(expressionMatches('http.request.uri.path ne "/api/chat"', op)).toBe(false);
    expect(expressionMatches('http.request.method in {"GET" "HEAD"}', op)).toBe(false);
  });
  it("compares literals with Cloudflare's case: a lower-case method is another method, an upper-case host cannot be told", () => {
    expect(expressionMatches('http.request.method eq "post"', op)).toBe(false);
    expect(expressionMatches('http.request.method in {"post" "get"}', op)).toBe(false);
    expect(expressionMatches('http.request.method ne "post"', op)).toBe(true);
    expect(expressionMatches('http.host eq "APP.example.com"', op)).toBeUndefined();
    expect(expressionMatches('http.host in {"APP.example.com"}', op)).toBeUndefined();
    expect(expressionMatches('http.host in {"app.example.com" "APP.example.com"}', op)).toBe(true);
    expect(expressionMatches('ends_with(http.host, ".EXAMPLE.com")', op)).toBeUndefined();
    expect(expressionMatches('starts_with(http.request.uri.path, "/API/")', op)).toBe(false);
  });
  it("gives xor precedence over or, and and over xor", () => {
    expect(expressionMatches('http.request.uri.path eq "/api/chat" or http.host eq "other.example.com" xor http.request.method eq "POST"', op)).toBe(true);
    expect(expressionMatches('not (http.request.uri.path eq "/api/chat" or http.host eq "other.example.com" xor http.request.method eq "POST")', op)).toBe(false);
    expect(expressionMatches('http.request.method eq "POST" xor http.request.uri.path eq "/api/chat" or http.host eq "other.example.com"', op)).toBe(false);
    expect(expressionMatches('http.request.method eq "POST" xor http.host eq "other.example.com" and http.request.uri.path eq "/api/chat"', op)).toBe(true);
  });
  it("cannot settle what it does not read", () => {
    expect(expressionMatches('http.request.uri.path eq "/api/chat" and cf.threat_score gt 10', op)).toBeUndefined();
    expect(expressionMatches('lower(http.request.uri.path) eq "/api/chat"', op)).toBeUndefined();
    expect(expressionMatches("http.request.uri.path in $llm_paths", op)).toBeUndefined();
    expect(expressionMatches('http.request.uri.path eq "/api/chat" and', op)).toBeUndefined();
    expect(expressionMatches('http.request.uri.path eq "/x" or ip.src in {10.0.0.0/8}', op)).toBeUndefined();
    expect(expressionMatches('http.request.uri.path eq "/x" and ip.src in {10.0.0.0/8}', op)).toBe(false);
  });
});

describe("repo checks", () => {
  const facts: RepoFacts = {
    root: "/tmp/app",
    files: [
      { path: "src/llm.ts", imports: ["openai"], hosts: ["api.openai.com"], hasAiRun: false, hasGatewayRef: false, hasMcpServer: false, hasAccessCheck: false },
      { path: "src/summarise.ts", imports: [], hosts: [], hasAiRun: true, hasGatewayRef: true, hasMcpServer: false, hasAccessCheck: false },
      { path: "src/mcp.ts", imports: ["@modelcontextprotocol/sdk/server/mcp.js"], hosts: [], hasAiRun: false, hasGatewayRef: false, hasMcpServer: true, hasAccessCheck: false },
    ],
    wrangler: [{ path: "wrangler.jsonc", name: "app", hasAiBinding: true, observabilityEnabled: null, aiEnvironments: [{ env: null, observabilityEnabled: null }], secretLikeVarNames: ["OPENAI_API_KEY"], providerKeyVarNames: ["OPENAI_API_KEY"] }],
    collectedAt: NOW,
  };
  const r = runChecks("repo", facts);
  const by = (id: string) => r.find((x) => x.id === id)!;

  it("flags direct hosts, bare SDKs, plaintext secrets, unguarded MCP and missing observability", () => {
    expect(by("REPO-001").status).toBe("fail");
    expect(by("REPO-002").status).toBe("fail");
    expect(by("REPO-003").status).toBe("pass");
    expect(by("REPO-004").status).toBe("fail");
    expect(by("REPO-005").status).toBe("fail");
    expect(by("REPO-006").status).toBe("fail");
  });

  it("a scan that left part of the repository out does not pass or call a rule not applicable", () => {
    const partial = runChecks("repo", { root: "/tmp/app", files: [], wrangler: [], notScanned: ["src/big.js: larger than 512 KB"], collectedAt: NOW });
    for (const id of ["REPO-001", "REPO-002", "REPO-003", "REPO-004", "REPO-005", "REPO-006"]) expect(partial.find((x) => x.id === id)?.status, id).toBe("unverifiable");
    expect(runChecks("repo", { ...facts, notScanned: ["src/big.js: larger than 512 KB"] }).find((x) => x.id === "REPO-001")?.status).toBe("fail");
  });

  it("REPO-005 does not fail for a missing Access or OAuth check when part of the repository was not scanned", () => {
    const notScanned = ["src/auth.js: larger than 512 KB"];
    const partial = runChecks("repo", { ...facts, notScanned }).find((x) => x.id === "REPO-005")!;
    expect(partial.status).toBe("unverifiable");
    expect(partial.evidence).toEqual(notScanned);
    // A check that was found still passes, and a complete scan without one still fails.
    const found = { ...facts, files: facts.files.map((file) => (file.path === "src/llm.ts" ? { ...file, hasAccessCheck: true } : file)) };
    expect(runChecks("repo", { ...found, notScanned }).find((x) => x.id === "REPO-005")?.status).toBe("pass");
    expect(runChecks("repo", { ...facts, notScanned: [] }).find((x) => x.id === "REPO-005")?.status).toBe("fail");
  });

  it("REPO-006 pairs each environment's AI binding with the logging setting that applies to it", () => {
    const wrangler = (aiEnvironments: RepoFacts["wrangler"][number]["aiEnvironments"]) => runChecks("repo", { ...facts, wrangler: [{ ...facts.wrangler[0]!, aiEnvironments }] }).find((x) => x.id === "REPO-006")!;
    const off = wrangler([{ env: "production", observabilityEnabled: false }]);
    expect(off.status).toBe("fail");
    expect(off.evidence).toEqual(["wrangler.jsonc (app), env production"]);
    expect(wrangler([{ env: "production", observabilityEnabled: true }]).status).toBe("pass");
  });
});

describe("catalogue completeness", () => {
  it("every check names its source and singular summaries agree", async () => {
    const { allChecks } = await import("../src/index.js");
    for (const c of allChecks()) expect(c.source, c.id).toMatch(/\S/);
  });
  it("uses singular verbs for a count of one", () => {
    const one: RepoFacts = {
      root: "/x",
      files: [{ path: "a.ts", imports: ["openai"], hosts: [], hasAiRun: true, hasGatewayRef: false, hasMcpServer: false, hasAccessCheck: false }],
      wrangler: [],
      collectedAt: NOW,
    };
    const r = runChecks("repo", one);
    expect(r.find((x) => x.id === "REPO-002")!.summary).toBe("1 file uses a provider SDK without a gateway reference.");
    expect(r.find((x) => x.id === "REPO-003")!.summary).toBe("1 file calls Workers AI without a gateway id.");
  });
});

describe("provider key names", () => {
  it("matches Hugging Face keys however the words are joined", () => {
    for (const n of ["HUGGINGFACE_TOKEN", "HUGGING_FACE_API_KEY", "HF_TOKEN"]) expect(PROVIDER_KEY_NAME.test(n), n).toBe(true);
  });
});

describe("provider hosts", () => {
  it("matches a provider host and its subdomains, not a host that only contains it", () => {
    for (const h of ["api.openai.com", "myres.openai.azure.com", "bedrock-runtime.us-east-1.amazonaws.com", "openrouter.ai"]) expect(isProviderHost(h), h).toBe(true);
    for (const h of ["api.openai.com.evil.example", "notopenrouter.ai", "docs.anthropic.com"]) expect(isProviderHost(h), h).toBe(false);
  });
});
