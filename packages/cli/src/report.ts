import { scoreResults, type CheckResult, type Severity } from "@cloudaisecurity/checks";

const ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };
const color = (code: number, s: string) => (process.stdout.isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);
const paint: Record<string, (s: string) => string> = {
  pass: (s) => color(32, s),
  fail: (s) => color(31, s),
  unverifiable: (s) => color(33, s),
  not_applicable: (s) => color(90, s),
};

export interface Section {
  title: string;
  results: CheckResult[];
  errors?: { endpoint: string; status: number; message: string }[];
}

export function renderText(sections: Section[], version: string): string {
  const lines: string[] = [];
  for (const s of sections) {
    const score = scoreResults(s.results);
    lines.push("", color(1, s.title) + `  score ${score.score}/100  (${score.counts.pass} pass, ${score.counts.fail} fail, ${score.counts.unverifiable} unverifiable, ${score.counts.not_applicable} n/a)`);
    const sorted = [...s.results].sort((a, b) => (a.status === b.status ? ORDER[a.severity] - ORDER[b.severity] : a.status === "fail" ? -1 : b.status === "fail" ? 1 : 0));
    for (const r of sorted) {
      const tag = paint[r.status]?.(r.status.replace("_", " ").padEnd(13)) ?? r.status;
      lines.push(`  ${tag} ${r.id.padEnd(9)} ${r.severity.padEnd(6)} ${r.summary}`);
      if (r.status === "fail") {
        for (const e of r.evidence.slice(0, 8)) lines.push(`      - ${e}`);
        if (r.evidence.length > 8) lines.push(`      … ${r.evidence.length - 8} more`);
        lines.push(color(90, `      source: ${r.source}`));
        if (r.remediation) lines.push(color(36, `      fix: ${r.remediation}`));
      }
    }
    if (s.errors?.length) {
      lines.push(color(90, `  ${s.errors.length} endpoint(s) not readable with this token (checks depending on them are unverifiable):`));
      for (const e of s.errors.slice(0, 6)) lines.push(color(90, `      ${e.endpoint}: ${e.status || "network"} ${e.message}`));
    }
  }
  lines.push("", color(90, `cloudai-scan · rules ${version} · https://cloudaisecurity.com/checks`), "");
  return lines.join("\n");
}

export function renderJson(sections: Section[], version: string): string {
  return JSON.stringify({ version, generatedAt: new Date().toISOString(), sections: sections.map((s) => ({ title: s.title, score: scoreResults(s.results), results: s.results, errors: s.errors ?? [] })) }, null, 2);
}

/** Highest failing severity across sections, or null when nothing fails. */
export function worstFailure(sections: Section[]): Severity | null {
  let worst: Severity | null = null;
  for (const s of sections) for (const r of s.results) if (r.status === "fail" && (worst === null || ORDER[r.severity] < ORDER[worst])) worst = r.severity;
  return worst;
}
