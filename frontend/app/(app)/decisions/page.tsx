"use client";

import { useState } from "react";

import ActionBadge from "../../../components/ActionBadge";
import {
  Banner,
  Empty,
  Loading,
  PageHeader,
  Select,
  ROW,
  TABLE_WRAP,
  TD,
  TH,
} from "../../../components/ui";
import { listDecisions, listExecutions } from "../../../lib/api";
import { cleanReason, dateTime, milliseconds, truncate } from "../../../lib/format";
import { useLoad } from "../../../lib/useLoad";

export default function DecisionsPage() {
  const { data, error, loading } = useLoad(async () => {
    const [decisions, executions] = await Promise.all([listDecisions(), listExecutions()]);
    return { decisions, executions };
  });
  const [filter, setFilter] = useState("ALL");

  if (loading) return <Loading />;
  if (error && !data) return <Banner kind="error">{error}</Banner>;
  if (!data) return null;

  const executionById = new Map(data.executions.map((item) => [item.id, item]));

  const decisions = [...data.decisions]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .filter((item) => filter === "ALL" || item.action.toUpperCase() === filter);

  return (
    <>
      <PageHeader
        title="Décisions du Gateway"
        subtitle="Chaque message analysé : ce qui a été autorisé, bloqué ou signalé, et pourquoi."
        actions={
          <Select value={filter} onChange={(event) => setFilter(event.target.value)}>
            <option value="ALL">Toutes</option>
            <option value="ALLOW">Autorisées</option>
            <option value="FLAG">Flaggées</option>
            <option value="BLOCK">Bloquées</option>
          </Select>
        }
      />

      {decisions.length === 0 ? (
        <Empty>Aucune décision pour ce filtre.</Empty>
      ) : (
        <div className={TABLE_WRAP}>
          <table className="w-full text-left text-sm">
            <thead>
              <tr>
                <th className={TH}>Date</th>
                <th className={TH}>Décision</th>
                <th className={`${TH} text-right`}>Score</th>
                <th className={TH}>Règle</th>
                <th className={TH}>Message</th>
                <th className={`${TH} text-right`}>Traitement</th>
              </tr>
            </thead>
            <tbody>
              {decisions.map((decision) => {
                const execution = executionById.get(decision.execution_id);

                return (
                  <tr key={decision.id} className={ROW}>
                    <td className={`${TD} whitespace-nowrap text-xs text-zinc-500`}>{dateTime(decision.created_at)}</td>
                    <td className={TD}><ActionBadge action={decision.action} /></td>
                    <td className={`${TD} text-right font-mono`}>{decision.risk_score}</td>
                    <td className={`${TD} font-mono text-xs`}>{decision.matched_rule ?? "—"}</td>
                    <td className={`${TD} max-w-md`}>
                      <div title={execution?.request}>{execution ? truncate(execution.request, 80) : "—"}</div>
                      {decision.reason ? (
                        <div className="text-xs text-zinc-500" title={decision.reason}>
                          {truncate(cleanReason(decision.reason), 140)}
                        </div>
                      ) : null}
                    </td>
                    <td className={`${TD} text-right font-mono`}>{milliseconds(decision.processing_time_ms)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}