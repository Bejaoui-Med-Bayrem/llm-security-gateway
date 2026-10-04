const STYLES: Record<string, string> = {
  ALLOW: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  FLAG: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  BLOCK: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
};

export default function ActionBadge({ action }: { action: string | null }) {
  if (!action) {
    return <span className="text-zinc-400">—</span>;
  }

  const key = action.toUpperCase().startsWith("BLOCK") ? "BLOCK" : action.toUpperCase();
  const style = STYLES[key] ?? "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";

  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${style}`}>
      {key}
    </span>
  );
}