import {
  getCampaign,
  listApplications,
  listAttacks,
  listDecisions,
  listEvaluations,
  listExecutionsByAttack,
  type Application,
  type Attack,
  type AttackExecution,
  type Campaign,
  type Evaluation,
  type GatewayDecision,
} from "./api";

export type Run = {
  execution: AttackExecution;
  decision: GatewayDecision | null;
};

export type Row = {
  attack: Attack;
  execution: AttackExecution | null;
  decision: GatewayDecision | null;
  history: Run[];
};

export type CampaignData = {
  campaign: Campaign;
  application: Application | null;
  evaluation: Evaluation | null;
  evaluations: Evaluation[];
  rows: Row[];
};

function latest(executions: AttackExecution[]): AttackExecution | null {
  if (executions.length === 0) return null;

  return [...executions].sort((a, b) =>
    b.executed_at.localeCompare(a.executed_at),
  )[0];
}

export async function loadCampaignData(id: string): Promise<CampaignData> {
  const [campaign, evaluations, attacks, decisions, applications] =
    await Promise.all([
      getCampaign(id),
      listEvaluations(),
      listAttacks(id),
      listDecisions(),
      listApplications(),
    ]);

  const executions = await Promise.all(
    attacks.map((attack) => listExecutionsByAttack(attack.id)),
  );

  const decisionByExecution = new Map(
    decisions.map((decision) => [decision.execution_id, decision]),
  );

  const rows = attacks.map((attack, index): Row => {
    const execution = latest(executions[index]);

    return {
      attack,
      execution,
      decision: execution ? (decisionByExecution.get(execution.id) ?? null) : null,
      history: executions[index].map((item) => ({
        execution: item,
        decision: decisionByExecution.get(item.id) ?? null,
      })),
    };
  });

  return {
    campaign,
    application:
      applications.find((item) => item.id === campaign.application_id) ?? null,
    evaluation: evaluations.find((item) => item.campaign_id === id) ?? null,
    evaluations,
    rows,
  };
}