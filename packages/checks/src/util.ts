export const DAY_MS = 86_400_000;

export function daysBetween(fromIso: string, toIso: string): number {
  return Math.floor((Date.parse(toIso) - Date.parse(fromIso)) / DAY_MS);
}

/** Exact elapsed time, not whole days: a key last used 90.9 days ago is older than 90 days. */
export function olderThanDays(iso: string | null | undefined, days: number, now: string): boolean {
  if (!iso) return false;
  return (Date.parse(now) - Date.parse(iso)) / DAY_MS > days;
}

/** Picks the verb form that agrees with a count: agree(1, "is", "are") === "is". */
export function agree(n: number, singular: string, plural: string): string {
  return n === 1 ? singular : plural;
}

/** "0 of 1 gateway has", "1 of 2 gateways have": after "X of N things" the verb follows the N things. */
export function ofTotal(count: number, total: number, word: string, singular: string, plural: string): string {
  return `${count} of ${pluralise(total, word)} ${agree(total, singular, plural)}`;
}

export function pluralise(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

type Outcome = { status: "pass" | "fail" | "needs_review" | "not_applicable" | "unverifiable"; summary: string; evidence: string[]; observed?: string[] };

/** The values the rule needs could not be read. Never a pass. */
export function notReadable(summary: string, evidence: string[] = []): Outcome {
  return { status: "unverifiable", summary, evidence };
}

/** Nothing exists for the rule to apply to. */
export function notApplicable(summary: string): Outcome {
  return { status: "not_applicable", summary, evidence: [] };
}

/** "1,000" */
export function num(n: number): string {
  return n.toLocaleString("en-US");
}

/** Counts values: tally(["a","b","a"]) -> "2 × a, 1 × b" */
export function tally(values: string[]): string {
  const counts = new Map<string, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([v, n]) => `${n} × ${v}`).join(", ");
}
