"use client";

import { useCallback, useEffect, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { getStoredJobId, setStoredJobId } from "@/lib/selected-job";

/**
 * Keeps selected analysis job in sync with `?job=` and localStorage so sidebar
 * navigation (Dashboard, Alerts, Timeline, AI Investigate) preserves the same job.
 */
export function useJobSelection() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const jobParam = searchParams.get("job");

  const [selectedJob, setSelectedJobState] = useState(() => {
    if (typeof window === "undefined") return "";
    const fromUrl = new URLSearchParams(window.location.search).get("job");
    return fromUrl || getStoredJobId() || "";
  });

  useEffect(() => {
    if (jobParam) {
      setSelectedJobState(jobParam);
      setStoredJobId(jobParam);
      return;
    }
    const stored = getStoredJobId();
    if (stored) {
      setSelectedJobState(stored);
      router.replace(`${pathname}?job=${encodeURIComponent(stored)}`, { scroll: false });
    } else {
      setSelectedJobState("");
    }
  }, [jobParam, pathname, router]);

  const setSelectedJob = useCallback(
    (id: string) => {
      setSelectedJobState(id);
      if (id) {
        setStoredJobId(id);
        router.replace(`${pathname}?job=${encodeURIComponent(id)}`, { scroll: false });
      } else {
        setStoredJobId(null);
        router.replace(pathname, { scroll: false });
      }
    },
    [pathname, router]
  );

  return { selectedJob, setSelectedJob };
}
