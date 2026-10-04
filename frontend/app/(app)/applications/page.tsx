"use client";

import { useState } from "react";

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
} from "../../../components/ui";
import {
  createApplication,
  deleteApplication,
  listApplications,
  updateApplication,
  type Application,
} from "../../../lib/api";
import { errorMessage } from "../../../lib/format";
import { APPLICATION_TYPES } from "../../../lib/labels";
import { useLoad } from "../../../lib/useLoad";

const EMPTY_FORM = {
  name: "",
  description: "",
  endpoint_url: "http://127.0.0.1:8001",
  model_name: "mistral",
  application_type: "vulnerable_testing",
};

export default function ApplicationsPage() {
  const { data, error, loading, reload } = useLoad(listApplications);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  function field(name: keyof typeof EMPTY_FORM) {
    return {
      value: form[name],
      onChange: (
        event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>,
      ) => setForm((previous) => ({ ...previous, [name]: event.target.value })),
    };
  }

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("create");
    setMessage(null);

    try {
      await createApplication({
        name: form.name,
        description: form.description || null,
        endpoint_url: form.endpoint_url,
        model_name: form.model_name,
        application_type: form.application_type,
        is_active: true,
      });
      setForm(EMPTY_FORM);
      setShowForm(false);
      reload();
    } catch (caught) {
      setMessage(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function toggle(application: Application) {
    setBusy(application.id);
    setMessage(null);

    try {
      await updateApplication(application.id, { is_active: !application.is_active });
      reload();
    } catch (caught) {
      setMessage(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function remove(application: Application) {
    const confirmed = window.confirm(
      `Supprimer « ${application.name} » ?\n\nToutes ses campagnes, attaques, exécutions et évaluations seront supprimées. Cette action est définitive.`,
    );

    if (!confirmed) return;

    setBusy(application.id);
    setMessage(null);

    try {
      await deleteApplication(application.id);
      reload();
    } catch (caught) {
      setMessage(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Applications"
        subtitle="Les applications LLM cibles que le Gateway teste et protège."
        actions={
          <Button variant="primary" onClick={() => setShowForm((value) => !value)}>
            {showForm ? "Annuler" : "Nouvelle application"}
          </Button>
        }
      />

      <div className="space-y-4">
        {message ? <Banner kind="error">{message}</Banner> : null}
        {error ? <Banner kind="error">{error}</Banner> : null}

        {showForm ? (
          <Card title="Nouvelle application">
            <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2">
              <Field label="Nom">
                <Input required {...field("name")} placeholder="AI Goat" />
              </Field>
              <Field label="Type">
                <Select {...field("application_type")}>
                  {APPLICATION_TYPES.map((type) => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </Select>
              </Field>
              <Field label="URL de la cible" hint="URL de base en http(s), sans chemin d'API. Ex. http://127.0.0.1:8001">
                <Input required {...field("endpoint_url")} />
              </Field>
              <Field label="Modèle">
                <Input required {...field("model_name")} />
              </Field>
              <div className="sm:col-span-2">
                <Field label="Description (facultatif)">
                  <Textarea rows={2} {...field("description")} />
                </Field>
              </div>
              <div className="sm:col-span-2">
                <Button type="submit" variant="primary" disabled={busy === "create"}>
                  {busy === "create" ? "Création…" : "Créer l'application"}
                </Button>
              </div>
            </form>
          </Card>
        ) : null}

        {loading ? (
          <Loading />
        ) : !data || data.length === 0 ? (
          <Empty>Aucune application. Crée-en une pour pouvoir lancer des campagnes.</Empty>
        ) : (
          <div className={TABLE_WRAP}>
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  <th className={TH}>Nom</th>
                  <th className={TH}>Type</th>
                  <th className={TH}>Modèle</th>
                  <th className={TH}>URL</th>
                  <th className={TH}>Statut</th>
                  <th className={TH} />
                </tr>
              </thead>
              <tbody>
                {data.map((application) => (
                  <tr key={application.id} className={ROW}>
                    <td className={TD}>
                      <div className="font-medium">{application.name}</div>
                      {application.description ? (
                        <div className="text-xs text-zinc-500">{application.description}</div>
                      ) : null}
                    </td>
                    <td className={TD}><Tag>{application.application_type}</Tag></td>
                    <td className={TD}>{application.model_name}</td>
                    <td className={`${TD} font-mono text-xs`}>{application.endpoint_url}</td>
                    <td className={TD}>
                      {application.is_active ? (
                        <span className="text-emerald-600">Active</span>
                      ) : (
                        <span className="text-zinc-500">Inactive</span>
                      )}
                    </td>
                    <td className={`${TD} whitespace-nowrap text-right`}>
                      <Button disabled={busy === application.id} onClick={() => toggle(application)}>
                        {application.is_active ? "Désactiver" : "Activer"}
                      </Button>{" "}
                      <Button variant="danger" disabled={busy === application.id} onClick={() => remove(application)}>
                        Supprimer
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}