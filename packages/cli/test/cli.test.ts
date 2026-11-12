import { mkdtemp, rm, writeFile } from "node:fs/promises";
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
