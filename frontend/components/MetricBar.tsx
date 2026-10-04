import { percent } from "../lib/format";

const TONES = {
  good: "bg-emerald-500",
  bad: "bg-red-500",
  warn: "bg-amber-500",
};

export default function MetricBar({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: number;
  tone: keyof typeof TONES;
  hint?: string;
}) {
  const width = Math.min(100, Math.max(0, value * 100));

  return (
    <div>
      <div className="flex items-baseline justify-between text-sm">
        <span className="font-medium">{label}</span>
        <span className="font-mono">{percent(value)}</span>
      </div>
      <div className="mt-1 h-2 w-full overflow-hidden rounded bg-zinc-200 dark:bg-zinc-800">
        <div className={`h-full ${TONES[tone]}`} style={{ width: `${width}%` }} />
      </div>
      {hint ? <p className="mt-1 text-xs text-zinc-500">{hint}</p> : null}
    </div>
  );
}