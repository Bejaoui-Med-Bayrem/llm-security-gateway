"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import AuthCard from "../../components/AuthCard";
import { Banner, Button, Field, Input } from "../../components/ui";
import { login } from "../../lib/api";
import { setToken } from "../../lib/auth";
import { errorMessage } from "../../lib/format";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      setToken(await login(email, password));
      router.replace("/");
    } catch (caught) {
      setError(errorMessage(caught));
      setSubmitting(false);
    }
  }

  return (
    <AuthCard
      title="Connexion"
      subtitle="Plateforme de red teaming et de défense des applications LLM"
      footer={{ text: "Pas encore de compte ?", href: "/register", label: "S'inscrire" }}
    >
      <form onSubmit={submit} className="space-y-4">
        <Field label="Email">
          <Input
            type="email"
            required
            autoComplete="username"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </Field>
        <Field label="Mot de passe">
          <Input
            type="password"
            required
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </Field>
        {error ? <Banner kind="error">{error}</Banner> : null}
        <Button type="submit" variant="primary" disabled={submitting} className="w-full py-2">
          {submitting ? "Connexion…" : "Se connecter"}
        </Button>
      </form>
    </AuthCard>
  );
}