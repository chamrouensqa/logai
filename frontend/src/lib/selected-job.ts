/** Persist last selected analysis job per signed-in user. */
import { getStoredUser } from "./auth";

function keyForCurrentUser(): string {
  const uid = getStoredUser()?.id || "anon";
  return `logai_selected_job:${uid}`;
}

export function getStoredJobId(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return localStorage.getItem(keyForCurrentUser());
  } catch {
    return null;
  }
}

export function setStoredJobId(id: string | null): void {
  if (typeof window === "undefined") return;
  try {
    if (id) {
      localStorage.setItem(keyForCurrentUser(), id);
    } else {
      localStorage.removeItem(keyForCurrentUser());
    }
    window.dispatchEvent(new Event("logai-job-change"));
  } catch {
    /* ignore quota / private mode */
  }
}
