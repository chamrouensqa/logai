"use client";

import { clsx } from "clsx";
import type { Severity } from "@/lib/api";

const classes: Record<string, string> = {
  critical: "badge-critical",
  high: "badge-high",
  medium: "badge-medium",
  low: "badge-low",
  info: "badge-info",
};

export default function SeverityBadge({ severity }: { severity: Severity | string | null }) {
  const sev = (severity || "info").toLowerCase();
  return <span className={clsx(classes[sev] || classes.info)}>{sev.toUpperCase()}</span>;
}
