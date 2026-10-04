export function percent(value: number): string {
  return `${(value * 100).toFixed(0)} %`;
}

export function milliseconds(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return value >= 1000 ? `${(value / 1000).toFixed(1)} s` : `${Math.round(value)} ms`;
}

export function truncate(text: string, length: number): string {
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

// The stored reason ends with the raw regular expressions that matched, which
// are useful for debugging but unreadable: keep the sentence, the signals, the
// risk and the policy. Older records put them inside parentheses instead.
export function cleanReason(reason: string | null | undefined): string {
  if (!reason) return "";

  const parts = reason
    .split(" | ")
    .filter((part) => !part.startsWith("matched:"));

  parts[0] = parts[0].replace(/\s*\(matched:[\s\S]*$/, "");

  return parts.join(" | ");
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Erreur inconnue.";
}

export function dateTime(value: string): string {
  return new Date(value).toLocaleString("fr-FR");
}

export function signedPoints(delta: number): string {
  const points = delta * 100;
  return `${points > 0 ? "+" : ""}${points.toFixed(0)} pts`;
}