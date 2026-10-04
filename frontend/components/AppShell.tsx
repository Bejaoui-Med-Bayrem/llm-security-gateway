"use client";

import { useEffect } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";

import { clearToken, decodeClaims, useToken } from "../lib/auth";
import { Loading } from "./ui";

const NAV = [
  { href: "/", label: "Accueil" },
  { href: "/applications", label: "Applications" },
  { href: "/campaigns", label: "Campagnes" },
  { href: "/tester", label: "Testeur" },
  { href: "/decisions", label: "Décisions" },
];

function isActive(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname.startsWith(href);
}

export default function AppShell({ children }: { children: React.ReactNode }) {
  const token = useToken();
  const router = useRouter();
  const pathname = usePathname();
  const claims = decodeClaims(token);

  useEffect(() => {
    if (token === null) router.replace("/login");
  }, [token, router]);

  if (typeof token !== "string") {
    return <Loading />;
  }

  return (
    <>
      <header className="border-b border-zinc-200 bg-white/80 backdrop-blur dark:border-zinc-800 dark:bg-zinc-950/80 print:hidden">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2 font-semibold">
              <span className="inline-block h-6 w-6 rounded-md bg-indigo-600" />
              LLM Security Gateway
            </Link>
            <nav className="flex flex-wrap gap-1">
              {NAV.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`rounded-md px-3 py-1.5 text-sm ${
                    isActive(pathname, item.href)
                      ? "bg-indigo-50 font-medium text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300"
                      : "text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-900"
                  }`}
                >
                  {item.label}
                </Link>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <span className="text-zinc-500">
              {claims.email ?? "connecté"}
              {claims.role ? ` · ${claims.role}` : ""}
            </span>
            <button
              type="button"
              onClick={() => clearToken()}
              className="rounded-lg border border-zinc-300 px-3 py-1.5 hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-900"
            >
              Déconnexion
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 print:max-w-none print:p-0">
        {children}
      </main>
    </>
  );
}