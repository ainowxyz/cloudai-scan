export const DAY_MS = 86_400_000;

export function daysBetween(fromIso: string, toIso: string): number {
  return Math.floor((Date.parse(toIso) - Date.parse(fromIso)) / DAY_MS);
}

export function olderThanDays(iso: string | null | undefined, days: number, now: string): boolean {
  if (!iso) return false;
  return daysBetween(iso, now) > days;
}

export function pluralise(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}
