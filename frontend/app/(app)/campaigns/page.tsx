"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

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
  Textarea,
  ROW,
  TABLE_WRAP,
  TD,
  TH,
} from "../../../components/ui";
import {
  createCampaign,
  listApplications,
  listCampaigns,
  listEvaluations,
} from "../../../lib/api";
import { errorMessage, percent } from "../../../lib/format";
import { useLoad } from "../../../lib/useLoad";

export default function CampaignsPage() {
  const router = useRouter();
  const { data, error, loading } = useLoad(async () => {
    const [campaigns, evaluations, applications] = await Promise.all([
      listCampaigns(),
      listEvaluations(),
      listApplications(),
    ]);

    return { campaigns, evaluations, applications };
  });

  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [applicationId, setApplicationId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  if (loading) return <Loading />;
  if (error && !data) return <Banner kind="error">{error}</Banner>;
  if (!data) return null;

  const { campaigns, evaluations, applications } = data;
  const evaluationByCampaign = new Map(evaluations.map((item) => [item.campaign_id, item]));
  const applicationName = new Map(applications.map((item) => [item.id, item.name]));
  const selectedApplication = applicationId || applications[0]?.id || "";

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setMessage(null);

    try {
      const campaign = await createCampaign({
        name,
        description: description || null,
        status: "pending",
        application_id: selectedApplication,
      });
      router.push(`/campaigns/${campaign.id}`);
    } catch (caught) {
      setMessage(errorMessage(caught));
      setSubmitting(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Campagnes"
        subtitle="Un jeu d'attaques rejouable contre une application."
        actions={
          <Button variant="primary" onClick={() => setShowForm((value) => !value)}>
            {showForm ? "Annuler" : "Nouvelle campagne"}
          </Button>
        }
      />

      <div className="space-y-4">
        {showForm ? (
          applications.length === 0 ? (
            <Banner kind="info">
              Il faut d&apos;abord <Link href="/applications" className="font-medium underline">créer une application</Link>.
            </Banner>
          ) : (
            <Card title="Nouvelle campagne">
              <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2">
                <Field label="Nom">
                  <Input required value={name} onChange={(event) => setName(event.target.value)} placeholder="Injection v1" />
                </Field>
                <Field label="Application">
                  <Select value={selectedApplication} onChange={(event) => setApplicationId(event.target.value)}>
                    {applications.map((application) => (
                      <option key={application.id} value={application.id}>{application.name}</option>
                    ))}
                  </Select>
                </Field>
                <div className="sm:col-span-2">
                  <Field label="Description (facultatif)">
                    <Textarea rows={2} value={description} onChange={(event) => setDescription(event.target.value)} />
                  </Field>
                </div>
                {message ? <div className="sm:col-span-2"><Banner kind="error">{message}</Banner></div> : null}
                <div className="sm:col-span-2">
                  <Button type="submit" variant="primary" disabled={submitting}>
                    {submitting ? "Création…" : "Créer la campagne"}
                  </Button>
                </div>
              </form>
            </Card>
          )
        ) : null}

        {campaigns.length === 0 ? (
          <Empty>Aucune campagne. Crée-en une, ajoute des attaques, puis exécute-les.</Empty>
        ) : (
          <div className={TABLE_WRAP}>
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  <th className={TH}>Nom</th>
                  <th className={TH}>Application</th>
                  <th className={TH}>Statut</th>
                  <th className={`${TH} text-right`}>Attaques</th>
                  <th className={`${TH} text-right`}>Détection</th>
                  <th className={`${TH} text-right`}>ASR</th>
                  <th className={`${TH} text-right`}>Faux positifs</th>
                </tr>
              </thead>
              <tbody>
                {campaigns.map((campaign) => {
                  const evaluation = evaluationByCampaign.get(campaign.id);

                  return (
                    <tr key={campaign.id} className={ROW}>
                      <td className={TD}>
                        <Link href={`/campaigns/${campaign.id}`} className="font-medium hover:underline">
                          {campaign.name}
                        </Link>
                      </td>
                      <td className={TD}>{applicationName.get(campaign.application_id) ?? "—"}</td>
                      <td className={TD}>{campaign.status}</td>
                      <td className={`${TD} text-right font-mono`}>{evaluation ? evaluation.total_attacks : "—"}</td>
                      <td className={`${TD} text-right font-mono`}>{evaluation ? percent(evaluation.detection_rate) : "—"}</td>
                      <td className={`${TD} text-right font-mono`}>{evaluation ? percent(evaluation.attack_success_rate) : "—"}</td>
                      <td className={`${TD} text-right font-mono`}>{evaluation ? percent(evaluation.false_positive_rate) : "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}