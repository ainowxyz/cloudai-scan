import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/index.js";
import { scanRepo } from "../src/repo-scan.js";

let dir: string;
let out: string;
let err: string;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "cloudai-scan-"));
  out = "";
  err = "";
  vi.spyOn(process.stdout, "write").mockImplementation((s) => ((out += String(s)), true));
  vi.spyOn(process.stderr, "write").mockImplementation((s) => ((err += String(s)), true));
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(dir, { recursive: true, force: true });
});

describe("arguments", () => {
  it("does not take an option's value for the command or the path", async () => {
    await writeFile(path.join(dir, "llm.ts"), `fetch("https://api.openai.com/v1/chat/completions")`);
    expect(await main(["--fail-on", "medium", "repo", dir, "--json"])).toBe(1);
    expect(JSON.parse(out).sections[0].title).toContain(dir);
  });

  it("refuses an unknown --fail-on value instead of never failing", async () => {
    expect(await main(["repo", dir, "--fail-on", "critical"])).toBe(2);
    expect(err).toMatch(/Unknown --fail-on value: critical/);
  });

  it("refuses a path that is not a directory instead of reporting it clean", async () => {
    await expect(main(["repo", path.join(dir, "missing")])).rejects.toThrow(/Not a directory/);
  });
});

describe("wrangler configuration", () => {
  it("finds a plaintext key in the top-level vars when an env overrides it", async () => {
    await writeFile(path.join(dir, "wrangler.jsonc"), JSON.stringify({ name: "app", vars: { OPENAI_API_KEY: "sk-abcdefghijklmnopqrstuvwx" }, env: { production: { vars: { OPENAI_API_KEY: "" } } } }));
    const facts = await scanRepo(dir);
    expect(facts.wrangler[0]!.secretLikeVarNames).toEqual(["OPENAI_API_KEY"]);
    expect(facts.wrangler[0]!.providerKeyVarNames).toEqual(["OPENAI_API_KEY"]);
  });
});

describe("coverage", () => {
  it("names an oversized source file as not scanned, so nothing passes on it", async () => {
    await writeFile(path.join(dir, "big.ts"), `fetch("https://api.openai.com/v1")\n${"x".repeat(600 * 1024)}`);
    const facts = await scanRepo(dir);
    expect(facts.notScanned).toEqual(["big.ts: larger than 512 KB"]);
    expect(await main(["repo", dir, "--json"])).toBe(0);
    const results = JSON.parse(out).sections[0].results as { id: string; status: string }[];
    expect(results.find((r) => r.id === "REPO-001")?.status).toBe("unverifiable");
  });

  it("does not count irrelevant files toward the file limit", async () => {
    await mkdir(path.join(dir, "assets"));
    await Promise.all(Array.from({ length: 5001 }, (_, i) => writeFile(path.join(dir, "assets", `${i}.png`), "")));
    await writeFile(path.join(dir, "llm.ts"), `fetch("https://api.openai.com/v1")`);
    const facts = await scanRepo(dir);
    expect(facts.notScanned).toEqual([]);
    expect(facts.files.map((f) => f.path)).toEqual(["llm.ts"]);
  });

  it("names a wrangler file it could not parse", async () => {
    await writeFile(path.join(dir, "wrangler.toml"), "name = ");
    expect((await scanRepo(dir)).notScanned).toEqual(["wrangler.toml: could not be read or parsed"]);
  });

  it("names a wrangler.jsonc with a syntax error instead of reading the part that parsed", async () => {
    // The JSON parser recovers from the missing comma and would return the name and the AI binding alone.
    await writeFile(path.join(dir, "wrangler.jsonc"), `{ "name": "app", "ai": { "binding": "AI" } "observability": { "enabled": false } }`);
    const facts = await scanRepo(dir);
    expect(facts.wrangler).toEqual([]);
    expect(facts.notScanned).toEqual(["wrangler.jsonc: could not be read or parsed"]);
  });

  it("reads a wrangler.jsonc with comments and trailing commas, as wrangler does", async () => {
    await writeFile(path.join(dir, "wrangler.jsonc"), `{\n  // the app\n  "name": "app",\n  "ai": { "binding": "AI", },\n}\n`);
    const facts = await scanRepo(dir);
    expect(facts.notScanned).toEqual([]);
    expect(facts.wrangler.map((w) => [w.name, w.hasAiBinding])).toEqual([["app", true]]);
  });
});

describe("wrangler environments", () => {
  it("applies each environment's own logging setting to its AI binding, and inherits the top-level one otherwise", async () => {
    await writeFile(
      path.join(dir, "wrangler.jsonc"),
      JSON.stringify({ name: "app", observability: { enabled: true }, env: { production: { ai: { binding: "AI" }, observability: { enabled: false } }, staging: { ai: { binding: "AI" } } } }),
    );
    const w = (await scanRepo(dir)).wrangler[0]!;
    expect(w.aiEnvironments).toEqual([
      { env: "production", observabilityEnabled: false },
      { env: "staging", observabilityEnabled: true },
    ]);
  });
});
