"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import AuthCard from "../../components/AuthCard";
import { Banner, Button, Field, Input } from "../../components/ui";
import { login, register } from "../../lib/api";
import { setToken } from "../../lib/auth";
import { errorMessage } from "../../lib/format";

export default function RegisterPage() {
  const router = useRouter();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (password !== confirmation) {
      setError("Les deux mots de passe ne correspondent pas.");
      return;
    }

    setSubmitting(true);

    try {
      await register(email, fullName, password);
      setToken(await login(email, password));
      router.replace("/");
    } catch (caught) {
      setError(errorMessage(caught));
      setSubmitting(false);
    }
  }

  return (
    <AuthCard
      title="Créer un compte"
      subtitle="Un compte te donne ton propre espace : applications, campagnes et résultats."
      footer={{ text: "Déjà inscrit ?", href: "/login", label: "Se connecter" }}
    >
      <form onSubmit={submit} className="space-y-4">
        <Field label="Nom complet">
          <Input
            required
            autoComplete="name"
            value={fullName}
            onChange={(event) => setFullName(event.target.value)}
          />
        </Field>
        <Field label="Email">
          <Input
            type="email"
            required
            autoComplete="username"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </Field>
        <Field label="Mot de passe" hint="Entre 8 et 128 caractères.">
          <Input
            type="password"
            required
            minLength={8}
            maxLength={128}
            autoComplete="new-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </Field>
        <Field label="Confirmer le mot de passe">
          <Input
            type="password"
            required
            minLength={8}
            maxLength={128}
            autoComplete="new-password"
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
          />
        </Field>
        {error ? <Banner kind="error">{error}</Banner> : null}
        <Button type="submit" variant="primary" disabled={submitting} className="w-full py-2">
          {submitting ? "Création…" : "Créer mon compte"}
        </Button>
      </form>
    </AuthCard>
  );
}