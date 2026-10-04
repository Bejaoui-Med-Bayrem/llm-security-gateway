"use client";

import { use } from "react";
import Link from "next/link";

import ActionBadge from "../../../../../components/ActionBadge";
import MetricBar from "../../../../../components/MetricBar";
import { Banner, Button, Loading, ROW, TD, TH } from "../../../../../components/ui";
import { loadCampaignData } from "../../../../../lib/campaignData";
import { dateTime, milliseconds, percent, truncate } from "../../../../../lib/format";
import { useLoad } from "../../../../../lib/useLoad";

export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data, error, loading } = useLoad(() => loadCampaignData(id), id);

  if (loading) return <Loading />;
  if (!data) return <Banner kind="error">{error ?? "Campagne introuvable."}</Banner>;

  const { campaign, application, evaluation, rows } = data;
  const generatedAt = new Date();

  function downloadJson() {
    const report = {
      generated_at: generatedAt.toISOString(),
      campaign,
      application,
      evaluation,
      results: rows.map(({ attack, execution, decision }) => ({
        category: attack.category,
        severity: attack.severity,
        language: attack.language,
        message: attack.payload,
        action: execution?.gateway_action ?? null,
        risk_score: execution?.risk_score ?? null,
        attack_success: execution?.attack_success ?? null,
        latency_ms: execution?.latency_ms ?? null,
        detector: decision?.detector ?? null,
        matched_rule: decision?.matched_rule ?? null,
        reason: decision?.reason ?? null,
      })),
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `rapport-${campaign.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <article className="mx-auto max-w-4xl space-y-6 print:max-w-none">
      <div className="flex items-center justify-between print:hidden">
        <Link href={`/campaigns/${id}`} className="text-sm text-zinc-500 hover:underline">
          ← Retour à la campagne
        </Link>
        <div className="flex gap-2">
          <Button onClick={downloadJson}>Télécharger JSON</Button>
          <Button variant="primary" onClick={() => window.print()}>Imprimer / PDF</Button>
        </div>
      </div>

      <header className="border-b border-zinc-200 pb-4 dark:border-zinc-800">
        <p className="text-xs uppercase tracking-wide text-zinc-500">Rapport de campagne</p>
        <h1 className="text-3xl font-semibold tracking-tight">{campaign.name}</h1>
        <p className="mt-1 text-sm text-zinc-500">
          Application : {application?.name ?? "—"} ({application?.model_name ?? "—"}) · statut {campaign.status} · généré le{" "}
          {generatedAt.toLocaleString("fr-FR")}
        </p>
        {campaign.description ? <p className="mt-2 text-sm">{campaign.description}</p> : null}
      </header>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Résultats</h2>
        {evaluation ? (
          <>
            <div className="grid gap-6 sm:grid-cols-3">
              <MetricBar label="Détection" value={evaluation.detection_rate} tone="good" hint={`${evaluation.detected_attacks} / ${evaluation.total_attacks} attaques`} />
              <MetricBar label="ASR" value={evaluation.attack_success_rate} tone="bad" hint={`${evaluation.successful_attacks} attaque(s) réussie(s)`} />
              <MetricBar label="Faux positifs" value={evaluation.false_positive_rate} tone="warn" hint={`${evaluation.false_positives} message(s) légitime(s) touché(s)`} />
            </div>
            <p className="text-sm">
              Sur {evaluation.total_attacks} attaque(s) : {evaluation.blocked_attacks} bloquée(s), détection {percent(evaluation.detection_rate)}, attaques réussies {percent(evaluation.attack_success_rate)}. Latence moyenne {milliseconds(evaluation.average_latency_ms)}. Évaluation du {dateTime(evaluation.created_at)}.
            </p>
          </>
        ) : (
          <p className="text-sm text-zinc-500">Cette campagne n&apos;a pas encore été évaluée.</p>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Détail des {rows.length} message(s)</h2>
        <table className="w-full text-left text-xs">
          <thead>
            <tr>
              <th className={TH}>Catégorie</th>
              <th className={TH}>Message</th>
              <th className={TH}>Décision</th>
              <th className={`${TH} text-right`}>Score</th>
              <th className={TH}>Règle</th>
              <th className={`${TH} text-right`}>Réussie</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ attack, execution, decision }) => (
              <tr key={attack.id} className={ROW}>
                <td className={TD}>{attack.category === "benign" ? "légitime" : attack.category}</td>
                <td className={TD}>{truncate(attack.payload, 120)}</td>
                <td className={TD}><ActionBadge action={execution?.gateway_action ?? null} /></td>
                <td className={`${TD} text-right font-mono`}>{execution?.risk_score ?? "—"}</td>
                <td className={TD}>{decision?.matched_rule ?? "—"}</td>
                <td className={`${TD} text-right`}>
                  {attack.category === "benign" || !execution ? "—" : execution.attack_success ? "Oui" : "Non"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <footer className="border-t border-zinc-200 pt-3 text-xs text-zinc-500 dark:border-zinc-800">
        L&apos;ASR est une borne haute : le juge de réponses compte comme succès toute réponse qui n&apos;est pas un refus.
        La détection mesure ce que le Gateway bloque ou signale, pas ce qu&apos;il laisse passer sans signal.
      </footer>
    </article>
  );
}