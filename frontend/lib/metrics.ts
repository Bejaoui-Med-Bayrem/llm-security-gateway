import type { AttackExecution } from "./api";
import type { Row, Run } from "./campaignData";

export type Mode = "on" | "off";

export type ModeMetrics = {
  mode: Mode;
  attacks: number;
  blocked: number;
  detected: number;
  successful: number;
  benign: number;
  falsePositives: number;
  detectionRate: number;
  attackSuccessRate: number;
  falsePositiveRate: number;
  averageLatencyMs: number;
};

// A decision recorded with the "none" detector means the defense was off.
function modeOf(run: Run): Mode | null {
  if (!run.decision) return null;
  return run.decision.detector === "none" ? "off" : "on";
}

function isBlocked(execution: AttackExecution): boolean {
  return (execution.gateway_action ?? "").toUpperCase().startsWith("BLOCK");
}

// Same rule as the backend: the Gateway decided and, if the message was
// forwarded, the target answered.
function isCompleted(run: Run): boolean {
  const action = run.execution.gateway_action;

  if (!action || !run.decision) return false;

  return isBlocked(run.execution) || run.execution.response !== null;
}

function latestRun(row: Row, mode: Mode): Run | null {
  const candidates = row.history
    .filter((run) => modeOf(run) === mode && isCompleted(run))
    .sort((a, b) => b.execution.executed_at.localeCompare(a.execution.executed_at));

  return candidates[0] ?? null;
}

// Metrics of the latest run of each attack in the given mode, or null when
// nothing was executed in that mode.
export function metricsFor(rows: Row[], mode: Mode): ModeMetrics | null {
  const attacks: AttackExecution[] = [];
  const benign: AttackExecution[] = [];

  for (const row of rows) {
    const run = latestRun(row, mode);

    if (!run) continue;

    (row.attack.category === "benign" ? benign : attacks).push(run.execution);
  }

  if (attacks.length === 0 && benign.length === 0) return null;

  const detected = attacks.filter((item) => item.gateway_action !== "ALLOW").length;
  const successful = attacks.filter((item) => item.attack_success).length;
  const falsePositives = benign.filter((item) => item.gateway_action !== "ALLOW").length;
  const latencies = [...attacks, ...benign]
    .map((item) => item.latency_ms)
    .filter((value): value is number => value !== null);

  return {
    mode,
    attacks: attacks.length,
    blocked: attacks.filter(isBlocked).length,
    detected,
    successful,
    benign: benign.length,
    falsePositives,
    detectionRate: attacks.length ? detected / attacks.length : 0,
    attackSuccessRate: attacks.length ? successful / attacks.length : 0,
    falsePositiveRate: benign.length ? falsePositives / benign.length : 0,
    averageLatencyMs: latencies.length
      ? latencies.reduce((sum, value) => sum + value, 0) / latencies.length
      : 0,
  };
}