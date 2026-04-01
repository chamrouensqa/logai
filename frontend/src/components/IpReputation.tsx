"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { getIpReputation, type IpReputationResponse } from "@/lib/api";

function Modal({
  ip,
  onClose,
}: {
  ip: string;
  onClose: () => void;
}) {
  const [data, setData] = useState<IpReputationResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setFetchError(null);
    getIpReputation(ip)
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e: Error) => {
        if (!cancelled) setFetchError(e.message || "Request failed");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [ip]);

  const panel = (
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center bg-slate-950/90 p-4 backdrop-blur-sm"
      onClick={onClose}
      role="presentation"
    >
      <div
        className="max-h-[min(90vh,720px)] w-full max-w-lg overflow-y-auto rounded-xl border border-slate-600 bg-slate-900 p-6 shadow-2xl ring-1 ring-slate-700/80"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-labelledby="ip-reputation-title"
        aria-modal="true"
      >
        <div className="flex items-start justify-between gap-3 mb-4">
          <div>
            <h2 id="ip-reputation-title" className="text-lg font-semibold text-white">
              IP reputation
            </h2>
            <p className="font-mono text-sm text-blue-300 mt-0.5">{ip}</p>
          </div>
          <button
            type="button"
            className="text-slate-400 hover:text-white text-sm shrink-0"
            onClick={onClose}
          >
            Close
          </button>
        </div>

        {loading && <p className="text-slate-400 text-sm py-8 text-center">Loading…</p>}

        {fetchError && (
          <div className="rounded-lg bg-red-500/10 border border-red-500/30 px-3 py-2 text-sm text-red-300">
            {fetchError}
          </div>
        )}

        {!loading && data && (
          <div className="space-y-4 text-sm">
            {data.cached && (
              <p className="text-xs text-slate-500">Cached result (same IP checked within the last hour).</p>
            )}

            {data.errors.length > 0 && (
              <ul className="space-y-1 rounded-lg bg-amber-500/10 border border-amber-500/25 px-3 py-2 text-amber-200/90">
                {data.errors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            )}

            {!data.configured_abuseipdb && !data.configured_virustotal && (
              <p className="text-slate-400">
                Add <code className="text-slate-300">ABUSEIPDB_API_KEY</code> and/or{" "}
                <code className="text-slate-300">VIRUSTOTAL_API_KEY</code> to the backend{" "}
                <code className="text-slate-300">.env</code>, then restart the API.
              </p>
            )}

            {data.abuseipdb && (
              <div className="rounded-lg border border-slate-700 bg-slate-800 p-3">
                <h3 className="text-slate-200 font-medium mb-2 flex items-center gap-2">
                  AbuseIPDB
                  <span
                    className={`text-xs px-2 py-0.5 rounded ${
                      data.abuseipdb.abuse_confidence_score >= 75
                        ? "bg-red-500/20 text-red-300"
                        : data.abuseipdb.abuse_confidence_score >= 25
                          ? "bg-amber-500/20 text-amber-200"
                          : "bg-emerald-500/15 text-emerald-300"
                    }`}
                  >
                    score {data.abuseipdb.abuse_confidence_score}
                  </span>
                </h3>
                <dl className="grid grid-cols-1 gap-1 text-slate-400">
                  <div>
                    <dt className="inline text-slate-500">Reports: </dt>
                    <dd className="inline text-slate-300">{data.abuseipdb.total_reports}</dd>
                  </div>
                  {data.abuseipdb.country_code && (
                    <div>
                      <dt className="inline text-slate-500">Country: </dt>
                      <dd className="inline text-slate-300">{data.abuseipdb.country_code}</dd>
                    </div>
                  )}
                  {data.abuseipdb.isp && (
                    <div>
                      <dt className="inline text-slate-500">ISP: </dt>
                      <dd className="inline text-slate-300 break-all">{data.abuseipdb.isp}</dd>
                    </div>
                  )}
                  {data.abuseipdb.usage_type && (
                    <div>
                      <dt className="inline text-slate-500">Usage: </dt>
                      <dd className="inline text-slate-300">{data.abuseipdb.usage_type}</dd>
                    </div>
                  )}
                  {data.abuseipdb.last_reported_at && (
                    <div>
                      <dt className="inline text-slate-500">Last reported: </dt>
                      <dd className="inline text-slate-300">{data.abuseipdb.last_reported_at}</dd>
                    </div>
                  )}
                </dl>
                {data.abuseipdb.report_url && (
                  <a
                    href={data.abuseipdb.report_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-block mt-2 text-xs text-blue-400 hover:text-blue-300"
                  >
                    Open on AbuseIPDB →
                  </a>
                )}
              </div>
            )}

            {data.virustotal && (
              <div className="rounded-lg border border-slate-700 bg-slate-800 p-3">
                <h3 className="text-slate-200 font-medium mb-2">VirusTotal</h3>
                <div className="flex flex-wrap gap-2 text-xs mb-2">
                  <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300">
                    harmless {data.virustotal.harmless}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-red-500/15 text-red-300">
                    malicious {data.virustotal.malicious}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-amber-500/15 text-amber-200">
                    suspicious {data.virustotal.suspicious}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-600/50 text-slate-300">
                    undetected {data.virustotal.undetected}
                  </span>
                </div>
                {(data.virustotal.country || data.virustotal.as_owner) && (
                  <p className="text-slate-400 text-xs mb-2">
                    {data.virustotal.country && <span>{data.virustotal.country} · </span>}
                    {data.virustotal.as_owner}
                  </p>
                )}
                {data.virustotal.reputation != null && (
                  <p className="text-slate-400 text-xs mb-2">
                    Reputation: <span className="text-slate-200">{data.virustotal.reputation}</span>
                  </p>
                )}
                {data.virustotal.analysis_url && (
                  <a
                    href={data.virustotal.analysis_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-block text-xs text-blue-400 hover:text-blue-300"
                  >
                    Open in VirusTotal →
                  </a>
                )}
              </div>
            )}

            <p className="text-[11px] text-slate-500 leading-relaxed">
              Third-party data may be incomplete or stale. Use as enrichment alongside your own logs and policies.
            </p>
          </div>
        )}
      </div>
    </div>
  );

  if (typeof document === "undefined") {
    return null;
  }
  return createPortal(panel, document.body);
}

export function IpReputationButton({ ip }: { ip: string }) {
  const [open, setOpen] = useState(false);
  const [modalKey, setModalKey] = useState(0);
  if (!ip?.trim()) return null;
  return (
    <>
      <button
        type="button"
        className="ml-2 inline-flex items-center rounded-md border border-slate-600 bg-slate-800/80 px-2 py-0.5 text-[11px] font-medium text-slate-300 hover:bg-slate-700 hover:text-white"
        onClick={(e) => {
          e.stopPropagation();
          e.preventDefault();
          setModalKey((k) => k + 1);
          setOpen(true);
        }}
      >
        Check IP
      </button>
      {open && <Modal key={modalKey} ip={ip.trim()} onClose={() => setOpen(false)} />}
    </>
  );
}

export function IpReputationLookupCard() {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [submitted, setSubmitted] = useState<string | null>(null);
  const [lookupKey, setLookupKey] = useState(0);

  const run = () => {
    const q = query.trim();
    if (!q) return;
    setSubmitted(q);
    setLookupKey((k) => k + 1);
    setOpen(true);
  };

  return (
    <div className="card border border-slate-700/80">
      <h3 className="font-semibold text-white mb-2">IP reputation lookup</h3>
      <p className="text-sm text-slate-400 mb-3">
        Check a public IP against AbuseIPDB and VirusTotal.
      </p>
      <div className="flex flex-wrap gap-2">
        <input
          className="input flex-1 min-w-[200px]"
          placeholder="e.g. 203.0.113.10"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
        />
        <button type="button" className="btn-primary" onClick={run}>
          Lookup
        </button>
      </div>
      {open && submitted && (
        <Modal key={lookupKey} ip={submitted} onClose={() => setOpen(false)} />
      )}
    </div>
  );
}
