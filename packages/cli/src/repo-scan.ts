import { PROVIDER_KEY_NAME, SECRET_VALUE, type RepoFacts, type RepoFileFact, type WranglerConfigFact } from "@cloudaisecurity/checks";
import { parse as parseJsonc, type ParseError } from "jsonc-parser";
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

const WRANGLER_RE = /^wrangler\.(toml|json|jsonc)$/;
const relevant = (name: string) => SOURCE_EXT.has(path.extname(name)) || WRANGLER_RE.test(name);

/** Collects source and wrangler files. Only those count toward MAX_FILES; anything left out is named in `notScanned`. */
async function walk(root: string, out: string[], notScanned: string[]): Promise<void> {
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      notScanned.push(`${path.relative(root, dir) || "."}: directory could not be read`);
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) stack.push(full);
      } else if (e.isFile() && relevant(e.name)) {
        if (out.length >= MAX_FILES) {
          notScanned.push(`stopped after ${MAX_FILES} source and configuration files; the rest of the repository was not scanned`);
          return;
        }
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
  // Every environment's vars are committed, so each is read on its own: an override in one env does not hide a value in another.
  const vars: [string, unknown][] = envs.flatMap((e: any) => Object.entries(e?.vars ?? {}));
  const flag = (v: unknown) => (typeof v === "boolean" ? v : null);
  const obs = flag(config?.observability?.enabled);
  // The ai binding is not inherited by environments; observability is, unless the environment sets its own.
  const scopes: [string | null, any][] = [[null, config], ...Object.entries<any>(config?.env ?? {})];
  const aiEnvironments = scopes.filter(([, e]) => e?.ai?.binding).map(([env, e]) => ({ env, observabilityEnabled: flag(e?.observability?.enabled) ?? obs }));
  const names = [...new Set(vars.map(([n]) => n))];
  return {
    path: path.relative(root, file),
    name: typeof config?.name === "string" ? config.name : null,
    hasAiBinding: aiEnvironments.length > 0,
    observabilityEnabled: obs,
    aiEnvironments,
    secretLikeVarNames: [...new Set(vars.filter(([, v]) => typeof v === "string" && SECRET_VALUE.test(v.trim())).map(([n]) => n))],
    providerKeyVarNames: names.filter((n) => PROVIDER_KEY_NAME.test(n)),
  };
}

/**
 * A wrangler configuration, parsed. Throws on a syntax error: the JSON parser recovers from one and returns what it
 * could read, and a configuration read in part must not count as read. Comments and trailing commas are not errors,
 * as wrangler accepts both.
 */
function parseWrangler(file: string, text: string): unknown {
  if (file.endsWith(".toml")) return parseToml(text);
  const errors: ParseError[] = [];
  const config = parseJsonc(text, errors, { allowTrailingComma: true });
  if (errors.length > 0) throw new Error(`${errors.length} syntax error(s)`);
  return config;
}

export async function scanRepo(root: string): Promise<RepoFacts> {
  root = path.resolve(root);
  const s = await stat(root).catch(() => null);
  if (!s?.isDirectory()) throw new Error(`Not a directory: ${root}`);
  const files: string[] = [];
  const notScanned: string[] = [];
  await walk(root, files, notScanned);
  const facts: RepoFileFact[] = [];
  const wrangler: WranglerConfigFact[] = [];
  for (const f of files) {
    const rel = path.relative(root, f);
    if (WRANGLER_RE.test(path.basename(f))) {
      try {
        const text = await readFile(f, "utf8");
        wrangler.push(collectWrangler(root, f, parseWrangler(f, text)));
      } catch {
        notScanned.push(`${rel}: could not be read or parsed`);
      }
      continue;
    }
    const r = await scanSource(root, f).catch(() => undefined);
    if (r === undefined) notScanned.push(`${rel}: could not be read`);
    else if (r === null) notScanned.push(`${rel}: larger than ${MAX_BYTES / 1024} KB`);
    else if (r.imports.length || r.hosts.length || r.hasAiRun || r.hasMcpServer || r.hasAccessCheck) facts.push(r);
  }
  return { root, files: facts, wrangler, notScanned, collectedAt: new Date().toISOString() };
}
