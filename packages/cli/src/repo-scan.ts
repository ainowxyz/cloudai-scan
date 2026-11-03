import { PROVIDER_KEY_NAME, SECRET_VALUE, type RepoFacts, type RepoFileFact, type WranglerConfigFact } from "@cloudaisecurity/checks";
import { parse as parseJsonc } from "jsonc-parser";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { parse as parseToml } from "smol-toml";

const SOURCE_EXT = new Set([".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx", ".py", ".go", ".rs"]);
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".wrangler", ".react-router", "coverage", ".next", "vendor", ".venv", "target"]);
const MAX_FILES = 5000;
const MAX_BYTES = 512 * 1024;

const IMPORT_RE = /(?:^|\n)\s*(?:import\s+(?:[^'"]*?\s+from\s+)?|export\s+[^'"]*?\s+from\s+)['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)|^\s*(?:from|import)\s+([A-Za-z_][\w.]*)/gm;
const HOST_RE = /https?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/gi;
const AI_RUN_RE = /\b(?:env|ctx\.env|c\.env|this\.env)\.AI\.run\s*\(/;
const GATEWAY_RE = /gateway\s*:\s*\{|gateway\.ai\.cloudflare\.com|cf-aig-|\/ai-gateway\/|gatewayId|createAI\(|aiGateway|AI_GATEWAY/i;
const MCP_RE = /McpServer|McpAgent|@modelcontextprotocol|createMcpHandler|agents\/mcp|workers-mcp/;
const ACCESS_RE = /cf-access-jwt-assertion|Cf-Access-Jwt-Assertion|cloudflareaccess\.com|OAuthProvider|workers-oauth-provider|requireAccess|access\.jwt|aud\s*:\s*env\.(ACCESS|POLICY)_AUD/i;

async function walk(root: string, out: string[]): Promise<void> {
  const stack = [root];
  while (stack.length && out.length < MAX_FILES) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) stack.push(full);
      } else if (e.isFile()) {
        out.push(full);
      }
    }
  }
}

async function scanSource(root: string, file: string): Promise<RepoFileFact | null> {
  const s = await stat(file);
  if (s.size > MAX_BYTES) return null;
  const text = await readFile(file, "utf8");
  const imports = new Set<string>();
  for (const m of text.matchAll(IMPORT_RE)) {
    const spec = m[1] ?? m[2] ?? m[3];
    if (spec) imports.add(spec);
  }
  const hosts = new Set<string>();
  for (const m of text.matchAll(HOST_RE)) hosts.add(m[1]!.toLowerCase());
  return {
    path: path.relative(root, file),
    imports: [...imports],
    hosts: [...hosts],
    hasAiRun: AI_RUN_RE.test(text),
    hasGatewayRef: GATEWAY_RE.test(text),
    hasMcpServer: MCP_RE.test(text),
    hasAccessCheck: ACCESS_RE.test(text),
  };
}

function collectWrangler(root: string, file: string, config: any): WranglerConfigFact {
  const envs = [config, ...Object.values(config?.env ?? {})];
  const vars: Record<string, unknown> = Object.assign({}, ...envs.map((e: any) => e?.vars ?? {}));
  const hasAiBinding = envs.some((e: any) => e?.ai?.binding);
  const obs = config?.observability?.enabled;
  const names = Object.keys(vars);
  return {
    path: path.relative(root, file),
    name: typeof config?.name === "string" ? config.name : null,
    hasAiBinding,
    observabilityEnabled: typeof obs === "boolean" ? obs : null,
    secretLikeVarNames: names.filter((n) => typeof vars[n] === "string" && SECRET_VALUE.test(String(vars[n]).trim())),
    providerKeyVarNames: names.filter((n) => PROVIDER_KEY_NAME.test(n)),
  };
}

export async function scanRepo(root: string): Promise<RepoFacts> {
  root = path.resolve(root);
  const files: string[] = [];
  await walk(root, files);
  const facts: RepoFileFact[] = [];
  const wrangler: WranglerConfigFact[] = [];
  for (const f of files) {
    const base = path.basename(f);
    if (/^wrangler\.(toml|json|jsonc)$/.test(base)) {
      try {
        const text = await readFile(f, "utf8");
        const cfg = base.endsWith(".toml") ? parseToml(text) : parseJsonc(text);
        wrangler.push(collectWrangler(root, f, cfg));
      } catch {
        /* unparsable config: skip */
      }
      continue;
    }
    if (!SOURCE_EXT.has(path.extname(f))) continue;
    const r = await scanSource(root, f).catch(() => null);
    if (r && (r.imports.length || r.hosts.length || r.hasAiRun || r.hasMcpServer || r.hasAccessCheck)) facts.push(r);
  }
  return { root, files: facts, wrangler, collectedAt: new Date().toISOString() };
}
