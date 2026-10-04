"use client";

import { useState } from "react";

import ActionBadge from "../../../components/ActionBadge";
import {
  Banner,
  Button,
  Card,
  Empty,
  Field,
  Loading,
  PageHeader,
  Select,
  Tag,
  Textarea,
} from "../../../components/ui";
import {
  createAttack,
  createCampaign,
  executeAttack,
  listApplications,
  listCampaigns,
  type DefenseMode,
  type ExecuteResult,
} from "../../../lib/api";
import { cleanReason, errorMessage, milliseconds } from "../../../lib/format";
import { CATEGORIES, SAMPLES, SEVERITIES, TESTER_CAMPAIGN } from "../../../lib/labels";
import { useLoad } from "../../../lib/useLoad";

type Turn = { message: string; category: string; defense: DefenseMode; result: ExecuteResult };

export default function TesterPage() {
  const { data: applications, error, loading } = useLoad(listApplications);
  const [applicationId, setApplicationId] = useState("");
  const [message, setMessage] = useState("");
  const [category, setCategory] = useState("prompt_injection");
  const [severity, setSeverity] = useState("medium");
  const [defense, setDefense] = useState<DefenseMode>("on");
  const [sameConversation, setSameConversation] = useState(false);
  const [conversationId, setConversationId] = useState<string>(() => crypto.randomUUID());
  const [turns, setTurns] = useState<Turn[]>([]);
  const [sending, setSending] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  if (loading) return <Loading />;
  if (error && !applications) return <Banner kind="error">{error}</Banner>;

  if (!applications || applications.length === 0) {
    return (
      <>
        <PageHeader title="Testeur" />
        <Empty>Ajoute d&apos;abord une application pour pouvoir lui envoyer des messages.</Empty>
      </>
    );
  }

  const selectedApplication = applicationId || applications[0].id;

  async function send(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSending(true);
    setFailure(null);

    try {
      const campaigns = await listCampaigns();

      const campaign =
        campaigns.find(
          (item) => item.name === TESTER_CAMPAIGN && item.application_id === selectedApplication,
        ) ??
        (await createCampaign({
          name: TESTER_CAMPAIGN,
          description: "Messages envoyés depuis le testeur interactif",
          status: "pending",
          application_id: selectedApplication,
        }));

      const attack = await createAttack({
        campaign_id: campaign.id,
        category,
        technique: "interactive",
        payload: message,
        language: "en",
        generation_method: "manual",
        severity,
      });

      const result = await executeAttack(
        attack.id,
        defense,
        sameConversation ? conversationId : undefined,
      );

      setTurns((previous) => [{ message, category, defense, result }, ...previous]);
      setMessage("");
    } catch (caught) {
      setFailure(errorMessage(caught));
    } finally {
      setSending(false);
    }
  }

  function newConversation() {
    setConversationId(crypto.randomUUID());
    setTurns([]);
  }

  return (
    <>
      <PageHeader
        title="Testeur"
        subtitle="Envoie un message à l'application et vois ce que le Gateway décide, en direct."
      />

      <div className="grid gap-6 lg:grid-cols-5">
        <Card title="Message" className="lg:col-span-2">
          <form onSubmit={send} className="space-y-4">
            <Field label="Application cible">
              <Select value={selectedApplication} onChange={(event) => setApplicationId(event.target.value)}>
                {applications.map((application) => (
                  <option key={application.id} value={application.id}>{application.name}</option>
                ))}
              </Select>
            </Field>

            <div>
              <p className="mb-1 text-sm font-medium">Exemples</p>
              <div className="flex flex-wrap gap-1.5">
                {SAMPLES.map((sample) => (
                  <button
                    key={sample.label}
                    type="button"
                    onClick={() => {
                      setMessage(sample.text);
                      setCategory(sample.category);
                    }}
                    className="rounded-full border border-zinc-300 px-2.5 py-1 text-xs hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-900"
                  >
                    {sample.label}
                  </button>
                ))}
              </div>
            </div>

            <Field label="Message">
              <Textarea required rows={4} value={message} onChange={(event) => setMessage(event.target.value)} />
            </Field>

            <div className="grid grid-cols-2 gap-3">
              <Field label="Catégorie" hint="« benign » = message légitime">
                <Select value={category} onChange={(event) => setCategory(event.target.value)}>
                  {CATEGORIES.map((item) => (
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
            </div>

            <Field label="Défense">
              <Select value={defense} onChange={(event) => setDefense(event.target.value as DefenseMode)}>
                <option value="on">Activée (Gateway)</option>
                <option value="off">Désactivée (envoi direct à la cible)</option>
              </Select>
            </Field>

            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                checked={sameConversation}
                onChange={(event) => setSameConversation(event.target.checked)}
                className="mt-1"
              />
              <span>
                Même conversation
                <span className="block text-xs text-zinc-500">
                  Active le suivi de session : plusieurs messages suspects de suite font escalader la session.
                </span>
              </span>
            </label>

            {failure ? <Banner kind="error">{failure}</Banner> : null}

            <div className="flex gap-2">
              <Button type="submit" variant="primary" disabled={sending}>
                {sending ? "Envoi…" : "Envoyer"}
              </Button>
              <Button disabled={sending || turns.length === 0} onClick={newConversation}>
                Nouvelle conversation
              </Button>
            </div>
            <p className="text-xs text-zinc-500">
              Chaque message est enregistré dans la campagne « {TESTER_CAMPAIGN} » de l&apos;application, avec sa décision.
            </p>
          </form>
        </Card>

        <div className="space-y-4 lg:col-span-3">
          {turns.length === 0 ? (
            <Empty>Les résultats apparaîtront ici. Choisis un exemple et envoie-le.</Empty>
          ) : (
            turns.map((turn, index) => {
              const { execution, decision, response } = turn.result;

              return (
                <Card key={execution.id}>
                  <div className="flex flex-wrap items-center gap-2">
                    <ActionBadge action={decision.action} />
                    <Tag>{turn.category === "benign" ? "légitime" : turn.category}</Tag>
                    <Tag>{turn.defense === "on" ? "défense activée" : "sans défense"}</Tag>
                    {index === 0 ? <span className="text-xs text-zinc-500">dernier envoi</span> : null}
                  </div>

                  <p className="mt-3 whitespace-pre-wrap wrap-break-word rounded-lg bg-zinc-50 p-3 text-sm dark:bg-zinc-900">
                    {turn.message}
                  </p>

                  <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-sm sm:grid-cols-4">
                    <div><dt className="text-xs text-zinc-500">Score</dt><dd className="font-mono">{decision.risk_score}</dd></div>
                    <div><dt className="text-xs text-zinc-500">Règle</dt><dd className="font-mono">{decision.matched_rule ?? "—"}</dd></div>
                    <div><dt className="text-xs text-zinc-500">Détecteur</dt><dd className="truncate font-mono text-xs" title={decision.detector}>{decision.detector}</dd></div>
                    <div><dt className="text-xs text-zinc-500">Latence</dt><dd className="font-mono">{milliseconds(execution.latency_ms)}</dd></div>
                  </dl>

                  {decision.reason ? (
                    <details className="mt-3 text-xs text-zinc-500">
                      <summary className="cursor-pointer">{cleanReason(decision.reason)}</summary>
                      <p className="mt-2 break-all font-mono">{decision.reason}</p>
                    </details>
                  ) : null}

                  {response?.reply ? (
                    <div className="mt-3 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                      <p className="mb-1 text-xs font-medium uppercase text-zinc-500">
                        Réponse de l&apos;application
                        {turn.category !== "benign" ? ` · ${execution.attack_success ? "attaque réussie" : "refus détecté"}` : ""}
                      </p>
                      <p className="whitespace-pre-wrap wrap-break-word text-sm">{response.reply}</p>
                    </div>
                  ) : (
                    <p className="mt-3 text-sm text-zinc-500">
                      Message bloqué : l&apos;application n&apos;a rien reçu.
                    </p>
                  )}
                </Card>
              );
            })
          )}
        </div>
      </div>
    </>
  );
}