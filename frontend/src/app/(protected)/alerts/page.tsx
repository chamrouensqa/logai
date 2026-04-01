"use client";

import { Suspense, useEffect, useState } from "react";
import { getJobAlerts, listJobs, type Alert, type Job } from "@/lib/api";
import { useJobSelection } from "@/hooks/useJobSelection";
import SeverityBadge from "@/components/SeverityBadge";
import { IpReputationButton } from "@/components/IpReputation";

export default function AlertsPage() {
  return <Suspense fallback={<div className="px-6 py-20 text-center text-slate-400">Loading...</div>}><AlertsContent /></Suspense>;
}

function AlertsContent() {
  const { selectedJob, setSelectedJob } = useJobSelection();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    listJobs().then((d) => setJobs(d.jobs)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedJob) return;
    setLoading(true);
    getJobAlerts(selectedJob)
      .then((d) => setAlerts(d.alerts))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [selectedJob]);

  const filtered = alerts.filter(
    (a) => !filter || a.severity === filter || a.alert_type.includes(filter)
  );

  return (
    <div className="px-6 py-10">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Alerts</h1>
          <p className="mt-1 text-slate-400">Threats and suspicious activity detected by the engine</p>
        </div>
        <div className="flex gap-3">
          <select className="input w-48" value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select className="input w-64" value={selectedJob} onChange={(e) => setSelectedJob(e.target.value)}>
            <option value="">Select job...</option>
            {jobs.map((j) => <option key={j.id} value={j.id}>{j.filename}</option>)}
          </select>
        </div>
      </div>

      {loading && <div className="text-center py-20 text-slate-400">Loading alerts...</div>}

      {/* Alert Cards */}
      <div className="space-y-4">
        {filtered.map((alert) => (
          <div
            key={alert.id}
            className={`card cursor-pointer transition-all hover:ring-1 hover:ring-slate-600 ${
              expanded === alert.id ? "ring-1 ring-blue-500/50" : ""
            }`}
            onClick={() => setExpanded(expanded === alert.id ? null : alert.id)}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-3">
                <SeverityBadge severity={alert.severity} />
                <div>
                  <h3 className="font-semibold text-white">{alert.title}</h3>
                  <p className="text-sm text-slate-400 mt-1">{alert.description}</p>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-xs text-slate-500">
                    {alert.source_ip && (
                      <span className="inline-flex items-center">
                        IP: <span className="text-slate-300 font-mono ml-1">{alert.source_ip}</span>
                        <IpReputationButton ip={alert.source_ip} />
                      </span>
                    )}
                    {alert.target_account && <span>Account: <span className="text-slate-300 font-mono">{alert.target_account}</span></span>}
                    <span>Type: <span className="text-slate-300">{alert.alert_type.replace(/_/g, " ")}</span></span>
                  </div>
                </div>
              </div>
              <span className="text-xs text-slate-500 shrink-0">
                {new Date(alert.created_at).toLocaleTimeString()}
              </span>
            </div>

            {/* Expanded details */}
            {expanded === alert.id && (
              <div className="mt-4 border-t border-slate-700 pt-4 space-y-4">
                {alert.evidence && (
                  <div>
                    <h4 className="text-sm font-medium text-slate-400 mb-2">Evidence</h4>
                    <pre className="text-xs bg-slate-900/50 rounded-lg p-4 overflow-x-auto text-slate-300">
                      {JSON.stringify(alert.evidence, null, 2)}
                    </pre>
                  </div>
                )}
                {alert.recommended_actions && alert.recommended_actions.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-slate-400 mb-2">Recommended Actions</h4>
                    <ul className="space-y-1.5">
                      {alert.recommended_actions.map((action, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                          <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-blue-500" />
                          {action}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {!loading && filtered.length === 0 && selectedJob && (
        <div className="text-center py-16">
          <p className="text-slate-400">No alerts detected for this analysis</p>
        </div>
      )}

      {!selectedJob && (
        <div className="text-center py-20">
          <p className="text-slate-400 text-lg">Select an analysis job to view alerts</p>
          <a href="/" className="btn-primary mt-4 inline-flex">Upload a Log File</a>
        </div>
      )}
    </div>
  );
}
