import { CHECKS_VERSION, runChecks, type Severity } from "@cloudaisecurity/checks";
import { cloudflareAccountConnector, cloudflareAiGatewayConnector } from "@cloudaisecurity/connectors";
import { renderJson, renderText, worstFailure, type Section } from "./report.js";
import { scanRepo } from "./repo-scan.js";

const HELP = `cloudai-scan — find ungoverned AI usage on Cloudflare

Usage:
  cloudai-scan repo [path]            Scan a Workers repository (no credentials). Default: current directory.
  cloudai-scan account                Scan a Cloudflare account. Needs CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID
                                      (or --token / --account).
  cloudai-scan rules                  Print the rule catalogue.

Options:
  --json                              JSON output
  --fail-on <high|medium|low|none>    Exit 1 when a failing check is at least this severe (default: high)
  --only-gateway                      Account mode: only AI Gateway checks
  --token <t> --account <id>          Credentials for account mode

Token scope for account mode (read-only):
  Account: Workers Scripts Read, AI Gateway Read, Account Analytics Read, Access: Apps and Policies Read
  Zone (all zones): Zone Read, Workers Routes Read, Zone WAF Read, API Gateway Read, Bot Management Read

Nothing is uploaded anywhere. Credentials are used only against api.cloudflare.com.
`;

const SEVERITY_RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };

function arg(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

export async function main(argv: string[]): Promise<number> {
  const cmd = argv.find((a) => !a.startsWith("-")) ?? "help";
  const json = argv.includes("--json");
  const failOn = (arg(argv, "--fail-on") ?? "high") as Severity | "none";
  const sections: Section[] = [];

  if (cmd === "help" || argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(HELP);
    return 0;
  }

  if (cmd === "rules") {
    const { allChecks } = await import("@cloudaisecurity/checks");
    const rows = allChecks().map(({ evaluate: _e, ...c }) => c);
    process.stdout.write(json ? JSON.stringify({ version: CHECKS_VERSION, checks: rows }, null, 2) + "\n" : rows.map((c) => `${c.id.padEnd(9)} ${c.severity.padEnd(6)} ${c.provider.padEnd(21)} ${c.title}`).join("\n") + "\n");
    return 0;
  }

  if (cmd === "repo") {
    const target = argv.filter((a) => !a.startsWith("-"))[1] ?? process.cwd();
    const facts = await scanRepo(target);
    sections.push({ title: `Repository ${facts.root} (${facts.files.length} relevant files, ${facts.wrangler.length} wrangler configs)`, results: runChecks("repo", facts) });
  } else if (cmd === "account") {
    const secret = arg(argv, "--token") ?? process.env.CLOUDFLARE_API_TOKEN;
    const accountId = arg(argv, "--account") ?? process.env.CLOUDFLARE_ACCOUNT_ID;
    if (!secret || !accountId) {
      process.stderr.write("Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID (or pass --token and --account).\n");
      return 2;
    }
    const creds = { secret, accountId };
    const gw = await cloudflareAiGatewayConnector.verify(creds);
    if (gw.ok) {
      const c = await cloudflareAiGatewayConnector.collect(creds);
      sections.push({ title: `AI Gateway (${c.facts.gateways.length} gateways)`, results: runChecks("cloudflare-ai-gateway", c.facts), errors: c.errors });
    } else {
      sections.push({ title: "AI Gateway", results: [], errors: [{ endpoint: "verify", status: 0, message: gw.error ?? "not readable" }] });
    }
    if (!argv.includes("--only-gateway")) {
      const acc = await cloudflareAccountConnector.verify(creds);
      if (acc.ok) {
        const c = await cloudflareAccountConnector.collect(creds);
        sections.push({ title: `Account inventory (${c.facts.workers.length} Workers, ${c.facts.zones.length} zones)`, results: runChecks("cloudflare-account", c.facts), errors: c.errors });
      } else {
        sections.push({ title: "Account inventory", results: [], errors: [{ endpoint: "verify", status: 0, message: acc.error ?? "not readable" }] });
      }
    }
  } else {
    process.stderr.write(`Unknown command: ${cmd}\n\n${HELP}`);
    return 2;
  }

  process.stdout.write((json ? renderJson(sections, CHECKS_VERSION) : renderText(sections, CHECKS_VERSION)) + "\n");
  const worst = worstFailure(sections);
  if (failOn !== "none" && worst && SEVERITY_RANK[worst] <= SEVERITY_RANK[failOn]) return 1;
  return 0;
}
