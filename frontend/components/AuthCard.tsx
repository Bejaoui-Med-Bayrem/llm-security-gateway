"use client";

import { useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { useToken } from "../lib/auth";
import { Loading } from "./ui";

// Sign-in and sign-up pages are only for visitors who are signed out: a
// signed-in user is sent to the dashboard instead.
export default function AuthCard({
  title,
  subtitle,
  footer,
  children,
}: {
  title: string;
  subtitle: string;
  footer: { text: string; href: string; label: string };
  children: React.ReactNode;
}) {
  const token = useToken();
  const router = useRouter();

  useEffect(() => {
    if (typeof token === "string") router.replace("/");
  }, [token, router]);

  if (token !== null) {
    return <Loading />;
  }

  return (
    <div className="flex flex-1 items-center justify-center bg-linear-to-b from-indigo-50 to-white px-4 py-10 dark:from-zinc-950 dark:to-black">
      <div className="w-full max-w-md space-y-6">
        <div className="text-center">
          <span className="mx-auto mb-3 block h-10 w-10 rounded-xl bg-indigo-600" />
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          <p className="mt-1 text-sm text-zinc-500">{subtitle}</p>
        </div>
        <div className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-950">
          {children}
        </div>
        <p className="text-center text-sm text-zinc-500">
          {footer.text}{" "}
          <Link href={footer.href} className="font-medium text-indigo-600 hover:underline">
            {footer.label}
          </Link>
        </p>
      </div>
    </div>
  );
}