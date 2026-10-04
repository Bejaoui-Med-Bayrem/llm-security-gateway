"use client";

import { Fragment, use, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import ActionBadge from "../../../../components/ActionBadge";
import MetricBar from "../../../../components/MetricBar";
import {
  Banner,
  Button,
  Card,
  Empty,
  Field,
  Input,
  Loading,
  PageHeader,
  Select,
  Tag,
  Textarea,
  ROW,
  TABLE_WRAP,
  TD,
  TH,
} from "../../../../components/ui";
import {
  cloneCampaign,
  compareEvaluations,
  computeEvaluation,
  createAttack,
  deleteAttack,
  deleteCampaign,
  executeAttack,
  listCampaigns,
  type Comparison,
  type DefenseMode,
} from "../../../../lib/api";
import { loadCampaignData } from "../../../../lib/campaignData";
import {
  cleanReason,
  errorMessage,
  milliseconds,
  percent,
  signedPoints,
  truncate,
} from "../../../../lib/format";
import { CATEGORIES, LANGUAGES, SEVERITIES } from "../../../../lib/labels";
import { metricsFor, type ModeMetrics } from "../../../../lib/metrics";
import { useLoad } from "../../../../lib/useLoad";

type Notice = { kind: "error" | "success" | "info"; text: string };

type CompareRow = {
  key: string;
  label: string;
  kind: "rate" | "ms" | "count";
  better: "up" | "down" | null;
};

const COMPARE_ROWS: CompareRow[] = [
  { key: "detection_rate", label: "Détection", kind: "rate", better: "up" },
  { key: "attack_success_rate", label: "ASR (attaques réussies)", kind: "rate", better: "down" },
  { key: "false_positive_rate", label: "Faux positifs", kind: "rate", better: "down" },
  { key: "average_latency_ms", label: "Latence moyenne", kind: "ms", better: "down" },
  { key: "total_attacks", label: "Attaques", kind: "count", better: null },
  { key: "blocked_attacks", label: "Bloquées", kind: "count", better: null },
  { key: "successful_attacks", label: "Réussies", kind: "count", better: null },
];

function formatValue(kind: CompareRow["kind"], value: number): string {
  if (kind === "rate") return percent(value);
  if (kind === "ms") return milliseconds(value);
  return String(value);
}

function formatDelta(kind: CompareRow["kind"], delta: number): string {
  if (kind === "rate") return signedPoints(delta);
  if (kind === "ms") return `${delta > 0 ? "+" : ""}${milliseconds(delta)}`;
  return `${delta > 0 ? "+" : ""}${delta}`;
}

function deltaColor(better: CompareRow["better"], delta: number): string {
  if (delta === 0 || better === null) return "text-zinc-500";
  const improved = better === "up" ? delta > 0 : delta < 0;
  return improved ? "text-emerald-600" : "text-red-600";
}

const DELTA_ROWS: {
  key: keyof ModeMetrics;
  label: string;
  kind: CompareRow["kind"];
  better: CompareRow["better"];
}[] = [
  { key: "detectionRate", label: "Détection", kind: "rate", better: "up" },
  { key: "attackSuccessRate", label: "ASR (attaques réussies)", kind: "rate", better: "down" },
  { key: "falsePositiveRate", label: "Faux positifs", kind: "rate", better: "down" },
  { key: "averageLatencyMs", label: "Latence moyenne", kind: "ms", better: "down" },
];

function ResultPanel({
  title,
  metrics,
  empty,
}: {
  title: string;
  metrics: ModeMetrics | null;
  empty: string;
}) {
  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold">{title}</h3>

      {metrics ? (
        <>
          <MetricBar
            label="Détection"
            value={metrics.detectionRate}
            tone="good"
            hint={`${metrics.detected} / ${metrics.attacks} attaques bloquées ou flaggées`}
          />
          <MetricBar
            label="ASR (attaques réussies)"
            value={metrics.attackSuccessRate}
            tone="bad"
            hint={`${metrics.successful} / ${metrics.attacks} · borne haute : toute réponse qui n'est pas un refus compte comme un succès`}
          />
          <MetricBar
            label="Faux positifs"
            value={metrics.falsePositiveRate}
            tone="warn"
            hint={`${metrics.falsePositives} / ${metrics.benign} message(s) légitime(s) bloqué(s) ou flaggé(s)`}
          />
          <p className="text-xs text-zinc-500">
            Latence moyenne {milliseconds(metrics.averageLatencyMs)} (inclut le temps du LLM)
          </p>
        </>
      ) : (
        <p className="text-sm text-zinc-500">{empty}</p>
      )}
    </div>
  );
}

export default function CampaignDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);

  return <CampaignDetail key={id} id={id} />;
}

function CampaignDetail({ id }: { id: string }) {
  const router = useRouter();

  const { data, error, loading, reload } = useLoad(async () => {
    const [detail, campaigns] = await Promise.all([
      loadCampaignData(id),
      listCampaigns(),
    ]);

    let result = detail;

    if (!detail.evaluation && detail.rows.some((row) => row.execution)) {
      try {
        const fresh = await computeEvaluation(id);
        result = {
          ...detail,
          evaluation: fresh,
          evaluations: [...detail.evaluations, fresh],
        };
      } catch {
        // the results shown below do not depend on the stored evaluation
      }
    }

    return { ...result, campaigns };
  }, id);

  const [defenseMode, setDefenseMode] = useState<DefenseMode>("on");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [category, setCategory] = useState("prompt_injection");
  const [technique, setTechnique] = useState("manual");
  const [payload, setPayload] = useState("");
  const [language, setLanguage] = useState("en");
  const [severity, setSeverity] = useState("medium");
  const [baselineId, setBaselineId] = useState("");
  const [comparison, setComparison] = useState<Comparison | null>(null);

  if (loading) return <Loading />;

  if (!data) {
    return (
      <div className="space-y-3">
        <Link href="/campaigns" className="text-sm underline">← Campagnes</Link>
        <Banner kind="error">{error ?? "Campagne introuvable."}</Banner>
      </div>
    );
  }

  const { campaign, application, evaluation, rows, campaigns, evaluations } = data;

  const evaluationByCampaign = new Map(evaluations.map((item) => [item.campaign_id, item]));
  const candidates = campaigns.filter(
    (item) => item.id !== campaign.id && evaluationByCampaign.has(item.id),
  );

  async function run(label: string, action: () => Promise<void>) {
    setBusy(label);
    setNotice(null);

    try {
      await action();
    } catch (caught) {
      setNotice({ kind: "error", text: errorMessage(caught) });
    } finally {
      setBusy(null);
    }
  }

  async function refreshEvaluation(): Promise<boolean> {
    try {
      await computeEvaluation(id);
      return true;
    } catch (caught) {
      setNotice({
        kind: "error",
        text: `Résultats enregistrés, mais l'évaluation n'a pas pu être mise à jour : ${errorMessage(caught)}`,
      });
      return false;
    }
  }

  const executeOne = (attackId: string) =>
    run(`exec:${attackId}`, async () => {
      await executeAttack(attackId, defenseMode);
      await refreshEvaluation();
      reload();
    });

  const executeAll = () =>
    run("exec-all", async () => {
      let done = 0;

      for (const row of rows) {
        setBusy(`exec-all (${done + 1}/${rows.length})`);
        await executeAttack(row.attack.id, defenseMode);
        done += 1;
      }

      const refreshed = await refreshEvaluation();

      if (refreshed) {
        setNotice({ kind: "success", text: `${done} exécution(s) terminée(s).` });
      }

      reload();
    });

  const clone = () =>
    run("clone", async () => {
      const copy = await cloneCampaign(id);
      router.push(`/campaigns/${copy.id}`);
    });

  const removeAttack = (attackId: string, text: string) => {
    if (!window.confirm(`Supprimer cette attaque ?\n\n${truncate(text, 120)}`)) return;

    return run(`delete:${attackId}`, async () => {
      await deleteAttack(attackId);
      await refreshEvaluation();
      reload();
    });
  };

  const remove = () => {
    if (!window.confirm(`Supprimer la campagne « ${campaign.name} » et tous ses résultats ?`)) return;

    return run("delete", async () => {
      await deleteCampaign(id);
      router.push("/campaigns");
    });
  };

  async function addAttack(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    await run("add", async () => {
      await createAttack({
        campaign_id: id,
        category,
        technique,
        payload,
        language,
        generation_method: "manual",
        severity,
      });
      setPayload("");
      setShowForm(false);
      reload();
    });
  }

  async function compare(selectedCampaignId: string) {
    setBaselineId(selectedCampaignId);
    setComparison(null);

    const baseline = evaluationByCampaign.get(selectedCampaignId);

    if (!baseline || !evaluation) return;

    await run("compare", async () => {
      setComparison(await compareEvaluations(baseline.id, evaluation.id));
    });
  }

  const executing = busy !== null && busy.startsWith("exec");
  const withDefense = metricsFor(rows, "on");
  const withoutDefense = metricsFor(rows, "off");

  return (
    <div className="space-y-6">
      <div>
        <Link href="/campaigns" className="text-sm text-zinc-500 hover:underline">← Campagnes</Link>
        <PageHeader
          title={campaign.name}
          subtitle={`${application?.name ?? "Application inconnue"} · statut ${campaign.status}${campaign.description ? ` · ${campaign.description}` : ""}`}
          actions={
            <>
              <Link
                href={`/campaigns/${id}/report`}
                className="rounded-lg border border-zinc-300 px-3 py-1.5 text-sm font-medium hover:bg-zinc-50 dark:border-zinc-700 dark:hover:bg-zinc-900"
              >
                Rapport
              </Link>
              <Button disabled={busy !== null} onClick={clone}>Cloner</Button>
              <Button variant="danger" disabled={busy !== null} onClick={remove}>Supprimer</Button>
            </>
          }
        />
      </div>

      {notice ? <Banner kind={notice.kind}>{notice.text}</Banner> : null}
      {error ? <Banner kind="error">{error}</Banner> : null}
      {busy !== null ? <Banner kind="info">En cours : {busy}… Les messages autorisés attendent le LLM, cela peut prendre du temps.</Banner> : null}

      <Card title="Résultats">
        {withDefense === null && withoutDefense === null ? (
          <p className="text-sm text-zinc-500">
            Aucune exécution pour l&apos;instant. Clique sur « Tout exécuter » : les résultats s&apos;affichent ici automatiquement.
          </p>
        ) : (
          <div className="space-y-6">
            <div className="grid gap-8 lg:grid-cols-2">
              <ResultPanel
                title="Avec défense (Gateway)"
                metrics={withDefense}
                empty="Pas encore exécuté avec la défense activée."
              />
              <ResultPanel
                title="Sans défense"
                metrics={withoutDefense}
                empty="Pas encore exécuté sans défense. Choisis « sans défense » dans « Exécuter avec », puis « Tout exécuter », pour comparer."
              />
            </div>

            {withDefense && withoutDefense ? (
              <div className="space-y-2">
                <h3 className="text-sm font-semibold">Écart : avec défense par rapport à sans défense</h3>
                <div className={TABLE_WRAP}>
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr>
                        <th className={TH}>Mesure</th>
                        <th className={`${TH} text-right`}>Sans défense</th>
                        <th className={`${TH} text-right`}>Avec défense</th>
                        <th className={`${TH} text-right`}>Écart</th>
                      </tr>
                    </thead>
                    <tbody>
                      {DELTA_ROWS.map((item) => {
                        const before = withoutDefense[item.key] as number;
                        const after = withDefense[item.key] as number;
                        const delta = after - before;

                        return (
                          <tr key={item.key} className={ROW}>
                            <td className={TD}>{item.label}</td>
                            <td className={`${TD} text-right font-mono`}>{formatValue(item.kind, before)}</td>
                            <td className={`${TD} text-right font-mono`}>{formatValue(item.kind, after)}</td>
                            <td className={`${TD} text-right font-mono ${deltaColor(item.better, delta)}`}>
                              {formatDelta(item.kind, delta)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}

            <p className="text-xs text-zinc-500">
              Calculé automatiquement après chaque exécution. Chaque attaque compte avec son dernier résultat dans chaque mode.
              Les messages de catégorie <code>benign</code> sont exclus des taux d&apos;attaque.
            </p>
          </div>
        )}
      </Card>

      <Card title="Comparer avec une autre campagne">
        {!evaluation ? (
          <p className="text-sm text-zinc-500">Exécute d&apos;abord les attaques de cette campagne.</p>
        ) : candidates.length === 0 ? (
          <p className="text-sm text-zinc-500">
            Aucune autre campagne évaluée. Pour comparer deux versions, clone cette campagne puis exécute la copie.
          </p>
        ) : (
          <div className="space-y-4">
            <Field label="Campagne de référence (« avant »)" hint="Cette campagne sert d'« après ».">
              <Select value={baselineId} onChange={(event) => compare(event.target.value)}>
                <option value="">Choisir…</option>
                {candidates.map((item) => (
                  <option key={item.id} value={item.id}>{item.name}</option>
                ))}
              </Select>
            </Field>

            {comparison ? (
              <div className="space-y-2">
                {!comparison.comparable ? (
                  <Banner kind="info">
                    Les deux campagnes n&apos;ont pas le même nombre d&apos;attaques : la comparaison est approximative.
                  </Banner>
                ) : null}
                <div className={TABLE_WRAP}>
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr>
                        <th className={TH}>Mesure</th>
                        <th className={`${TH} text-right`}>Avant</th>
                        <th className={`${TH} text-right`}>Après</th>
                        <th className={`${TH} text-right`}>Écart</th>
                      </tr>
                    </thead>
                    <tbody>
                      {COMPARE_ROWS.map((item) => {
                        const before = comparison.before[item.key as keyof typeof comparison.before] as number;
                        const after = comparison.after[item.key as keyof typeof comparison.after] as number;
                        const delta = comparison.differences[item.key] ?? after - before;

                        return (
                          <tr key={item.key} className={ROW}>
                            <td className={TD}>{item.label}</td>
                            <td className={`${TD} text-right font-mono`}>{formatValue(item.kind, before)}</td>
                            <td className={`${TD} text-right font-mono`}>{formatValue(item.kind, after)}</td>
                            <td className={`${TD} text-right font-mono ${deltaColor(item.better, delta)}`}>
                              {formatDelta(item.kind, delta)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}
          </div>
        )}
      </Card>

      <div className="space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <h2 className="text-lg font-semibold">Attaques ({rows.length})</h2>
          <div className="flex flex-wrap items-end gap-2">
            <label className="text-sm">
              <span className="mr-2 text-zinc-500">Exécuter avec</span>
              <select
                value={defenseMode}
                onChange={(event) => setDefenseMode(event.target.value as DefenseMode)}
                className="rounded-lg border border-zinc-300 bg-white px-2 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-950"
              >
                <option value="on">défense activée</option>
                <option value="off">sans défense</option>
              </select>
            </label>
            <Button variant="primary" disabled={busy !== null || rows.length === 0} onClick={executeAll}>
              Tout exécuter
            </Button>
            <Button disabled={busy !== null} onClick={() => setShowForm((value) => !value)}>
              {showForm ? "Annuler" : "Ajouter une attaque"}
            </Button>
          </div>
        </div>

        {showForm ? (
          <Card title="Nouvelle attaque ou message légitime">
            <form onSubmit={addAttack} className="grid gap-4 sm:grid-cols-4">
              <Field label="Catégorie" hint="« benign » = message légitime (sert aux faux positifs)">
                <Select value={category} onChange={(event) => setCategory(event.target.value)}>
                  {CATEGORIES.map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </Select>
              </Field>
              <Field label="Technique">
                <Input required value={technique} onChange={(event) => setTechnique(event.target.value)} />
              </Field>
              <Field label="Langue">
                <Select value={language} onChange={(event) => setLanguage(event.target.value)}>
                  {LANGUAGES.map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </Select>
              </Field>
              <Field label="Sévérité">
                <Select value={severity} onChange={(event) => setSeverity(event.target.value)}>
                  {SEVERITIES.map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </Select>
              </Field>
              <div className="sm:col-span-4">
                <Field label="Message">
                  <Textarea required rows={3} value={payload} onChange={(event) => setPayload(event.target.value)} />
                </Field>
              </div>
              <div className="sm:col-span-4">
                <Button type="submit" variant="primary" disabled={busy !== null}>Ajouter</Button>
              </div>
            </form>
          </Card>
        ) : null}

        {rows.length === 0 ? (
          <Empty>Aucune attaque. Ajoute-en une avec le bouton ci-dessus.</Empty>
        ) : (
          <div className={TABLE_WRAP}>
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  <th className={TH}>Catégorie</th>
                  <th className={TH}>Message</th>
                  <th className={TH}>Décision</th>
                  <th className={`${TH} text-right`}>Score</th>
                  <th className={`${TH} text-right`}>Réussie</th>
                  <th className={`${TH} text-right`}>Latence</th>
                  <th className={TH} />
                </tr>
              </thead>
              <tbody>
                {rows.map(({ attack, execution, decision }) => {
                  const benign = attack.category === "benign";

                  return (
                    <Fragment key={attack.id}>
                      <tr className={ROW}>
                        <td className={TD}>
                          {benign ? <Tag>légitime</Tag> : attack.category}
                          <div className="text-xs text-zinc-500">{attack.severity} · {attack.language}</div>
                        </td>
                        <td className={`${TD} max-w-md`} title={attack.payload}>
                          {truncate(attack.payload, 90)}
                        </td>
                        <td className={TD}><ActionBadge action={execution?.gateway_action ?? null} /></td>
                        <td className={`${TD} text-right font-mono`}>{execution?.risk_score ?? "—"}</td>
                        <td className={`${TD} text-right`}>
                          {benign || !execution ? "—" : execution.attack_success ? "Oui" : "Non"}
                        </td>
                        <td className={`${TD} text-right font-mono`}>{milliseconds(execution?.latency_ms)}</td>
                        <td className={`${TD} whitespace-nowrap text-right`}>
                          <Button disabled={busy !== null} onClick={() => executeOne(attack.id)}>
                            {executing && busy === `exec:${attack.id}` ? "…" : "Exécuter"}
                          </Button>{" "}
                          <Button
                            variant="danger"
                            disabled={busy !== null}
                            onClick={() => removeAttack(attack.id, attack.payload)}
                          >
                            Supprimer
                          </Button>
                        </td>
                      </tr>
                      {decision?.reason ? (
                        <tr>
                          <td />
                          <td colSpan={6} className="px-3 pb-2 text-xs text-zinc-500" title={decision.reason}>
                            {truncate(cleanReason(decision.reason), 200)}
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}