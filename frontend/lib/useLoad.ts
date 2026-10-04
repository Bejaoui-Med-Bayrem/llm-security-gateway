"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";

import { ApiError } from "./api";
import { errorMessage } from "./format";

type Loaded<T> = { key: string; data: T | null; error: string | null; loading: boolean };

// Runs `loader` on mount and whenever `key` changes; `reload()` runs it again.
export function useLoad<T>(loader: () => Promise<T>, key: string = "") {
  const router = useRouter();
  const loaderRef = useRef(loader);
  const [version, setVersion] = useState(0);
  const [state, setState] = useState<Loaded<T>>({
    key,
    data: null,
    error: null,
    loading: true,
  });

  useEffect(() => {
    loaderRef.current = loader;
  });

  useEffect(() => {
    let cancelled = false;

    async function run() {
      try {
        const data = await loaderRef.current();
        if (!cancelled) setState({ key, data, error: null, loading: false });
      } catch (caught) {
        if (caught instanceof ApiError && caught.status === 401) {
          router.replace("/login");
          return;
        }

        if (!cancelled) {
          setState((previous) => ({
            key,
            data: previous.key === key ? previous.data : null,
            error: errorMessage(caught),
            loading: false,
          }));
        }
      }
    }

    run();

    return () => {
      cancelled = true;
    };
  }, [key, version, router]);

  const reload = useCallback(() => setVersion((value) => value + 1), []);

  // A different key means the data on screen belongs to another resource.
  const stale = state.key !== key;

  return {
    data: stale ? null : state.data,
    error: stale ? null : state.error,
    loading: stale || state.loading,
    reload,
  };
}