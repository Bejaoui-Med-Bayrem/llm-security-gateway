"use client";

import Link from "next/link";

import ActionBadge from "../../components/ActionBadge";
import { Banner, Card, Empty, KpiCard, Loading, PageHeader } from "../../components/ui";
import {
  listApplications,
  listCampaigns,
  listDecisions,
  listEvaluations,
} from "../../lib/api";
import { dateTime, percent, truncate } from "../../lib/format";
import { useLoad } from "../../lib/useLoad";

function Bar({ value, color }: { value: number; color: string }) {
  return (
    <div className="h-2 w-full overflow-hidden rounded bg-zinc-200 dark:bg-zinc-800">
      <div
        className={`h-full ${color}`}
        style={{ width: `${Math.min(100, Math.max(0, value * 100))}%` }}
      />
    </div>
  );
}

export default function HomePage() {
  const { data, error, loading } = useLoad(async () => {
    const [applications, campaigns, evaluations, decisions] = await Promise.all([
      listApplications(),
      listCampaigns(),
      listEvaluations(),
      listDecisions(),
    ]);

    return { applications, campaigns, evaluations, decisions };
  });

  if (loading) return <Loading />;
  if (error && !data) return <Banner kind="error">{error}</Banner>;
  if (!data) return null;

  const { applications, campaigns, evaluations, decisions } = data;

  const totalAttacks = evaluations.reduce((sum, item) => sum + item.total_attacks, 0);
  const detected = evaluations.reduce((sum, item) => sum + item.detected_attacks, 0);
  const successful = evaluations.reduce((sum, item) => sum + item.successful_attacks, 0);
  const falsePositives = evaluations.reduce((sum, item) => sum + item.false_positives, 0);

  const detectionRate = totalAttacks ? detected / totalAttacks : 0;
  const successRate = totalAttacks ? successful / totalAttacks : 0;

  const evaluationByCampaign = new Map(evaluations.map((item) => [item.campaign_id, item]));
  const evaluatedCampaigns = campaigns.filter((item) => evaluationByCampaign.has(item.id));

  const counts = { ALLOW: 0, FLAG: 0, BLOCK: 0 };
  for (const decision of decisions) {
    const key = decision.action.toUpperCase() as keyof typeof counts;
    if (key in counts) counts[key] += 1;
  }

  const recent = [...decisions]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .slice(0, 6);

  if (applications.length === 0) {
    return (
      <>
        <PageHeader title="Bienvenue" subtitle="Commence par déclarer l'application LLM à tester." />
        <Empty>
          Aucune application pour l&apos;instant.{" "}
          <Link href="/applications" className="font-medium text-indigo-600 hover:underline">
            Ajouter une application
          </Link>
        </Empty>
      </>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Tableau de bord"
        subtitle="Vue d'ensemble de tes campagnes de red teaming et du Gateway."
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard label="Applications" value={String(applications.length)} />
        <KpiCard label="Campagnes" value={String(campaigns.length)} hint={`${evaluatedCampaigns.length} évaluée(s)`} />
        <KpiCard
          label="Détection"
          value={totalAttacks ? percent(detectionRate) : "—"}
          tone="good"
          hint={`${detected} / ${totalAttacks} attaques bloquées ou flaggées`}
        />
        <KpiCard
          label="Attaques réussies (ASR)"
          value={totalAttacks ? percent(successRate) : "—"}
          tone="bad"
          hint="Borne haute (voir le juge de réponses)"
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <Card title="Résultats par campagne" className="lg:col-span-3">
          {evaluatedCampaigns.length === 0 ? (
            <p className="text-sm text-zinc-500">
              Aucune campagne évaluée. Ouvre une campagne et calcule son évaluation.
            </p>
          ) : (
            <div className="space-y-5">
              {evaluatedCampaigns.slice(0, 8).map((campaign) => {
                const evaluation = evaluationByCampaign.get(campaign.id)!;

                return (
                  <div key={campaign.id} className="space-y-1.5">
                    <Link
                      href={`/campaigns/${campaign.id}`}
                      className="text-sm font-medium hover:underline"
                    >
                      {campaign.name}
                    </Link>
                    <div className="grid grid-cols-[6rem_1fr_3rem] items-center gap-2 text-xs">
                      <span className="text-zinc-500">Détection</span>
                      <Bar value={evaluation.detection_rate} color="bg-emerald-500" />
                      <span className="text-right font-mono">{percent(evaluation.detection_rate)}</span>
                      <span className="text-zinc-500">ASR</span>
                      <Bar value={evaluation.attack_success_rate} color="bg-red-500" />
                      <span className="text-right font-mono">{percent(evaluation.attack_success_rate)}</span>
                      <span className="text-zinc-500">Faux positifs</span>
                      <Bar value={evaluation.false_positive_rate} color="bg-amber-500" />
                      <span className="text-right font-mono">{percent(evaluation.false_positive_rate)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        <div className="space-y-6 lg:col-span-2">
          <Card title="Décisions du Gateway">
            {decisions.length === 0 ? (
              <p className="text-sm text-zinc-500">Aucune décision enregistrée.</p>
            ) : (
              <div className="space-y-3">
                <div className="flex h-3 w-full overflow-hidden rounded">
                  <div className="bg-emerald-500" style={{ width: `${(counts.ALLOW / decisions.length) * 100}%` }} />
                  <div className="bg-amber-500" style={{ width: `${(counts.FLAG / decisions.length) * 100}%` }} />
                  <div className="bg-red-500" style={{ width: `${(counts.BLOCK / decisions.length) * 100}%` }} />
                </div>
                <div className="flex justify-between text-sm">
                  <span>Autorisées <strong>{counts.ALLOW}</strong></span>
                  <span>Flaggées <strong>{counts.FLAG}</strong></span>
                  <span>Bloquées <strong>{counts.BLOCK}</strong></span>
                </div>
                <p className="text-xs text-zinc-500">
                  {falsePositives} faux positif(s) sur l&apos;ensemble des campagnes évaluées.
                </p>
              </div>
            )}
          </Card>

          <Card title="Dernières décisions">
            {recent.length === 0 ? (
              <p className="text-sm text-zinc-500">Rien pour l&apos;instant.</p>
            ) : (
              <ul className="space-y-3">
                {recent.map((decision) => (
                  <li key={decision.id} className="flex items-start gap-3 text-sm">
                    <ActionBadge action={decision.action} />
                    <div className="min-w-0">
                      <p className="truncate font-mono text-xs">
                        {decision.matched_rule ?? "—"} · score {decision.risk_score}
                      </p>
                      <p className="truncate text-xs text-zinc-500">
                        {dateTime(decision.created_at)} — {truncate(decision.reason ?? "", 60)}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <Link href="/decisions" className="mt-3 inline-block text-sm text-indigo-600 hover:underline">
              Tout voir →
            </Link>
          </Card>
        </div>
      </div>
    </div>
  );
}