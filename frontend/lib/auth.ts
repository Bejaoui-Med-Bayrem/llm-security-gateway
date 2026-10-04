import { useSyncExternalStore } from "react";

const TOKEN_KEY = "gateway_token";
const listeners = new Set<() => void>();

function emit(): void {
  listeners.forEach((listener) => listener());
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  window.sessionStorage.setItem(TOKEN_KEY, token);
  emit();
}

export function clearToken(): void {
  window.sessionStorage.removeItem(TOKEN_KEY);
  emit();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

// undefined: not known yet (server render / hydration); null: signed out.
export function useToken(): string | null | undefined {
  return useSyncExternalStore<string | null | undefined>(
    subscribe,
    getToken,
    () => undefined,
  );
}

// Reaching the app again with the browser's Back or Forward buttons, after
// having left it, must not restore a session: signing in is the only way in.
// Back and Forward inside the app are client-side and do not reload the page,
// so they are not affected. A reload (F5) keeps the session.
if (typeof window !== "undefined") {
  const guarded = window as Window & { __gatewayHistoryGuard?: boolean };

  if (!guarded.__gatewayHistoryGuard) {
    guarded.__gatewayHistoryGuard = true;

    const navigation = performance.getEntriesByType("navigation")[0] as
      | PerformanceNavigationTiming
      | undefined;

    if (navigation?.type === "back_forward") {
      window.sessionStorage.removeItem(TOKEN_KEY);
    }

    // The page was restored from the browser's back/forward cache.
    window.addEventListener("pageshow", (event) => {
      if (event.persisted) clearToken();
    });
  }
}

export type Claims = { email?: string; role?: string };

// Display only: the signature is verified by the backend, never here.
export function decodeClaims(token: string | null | undefined): Claims {
  if (!token) return {};

  try {
    const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload)) as Claims;
  } catch {
    return {};
  }
}