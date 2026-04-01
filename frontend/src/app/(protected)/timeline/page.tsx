"use client";

import { Suspense, useEffect, useState } from "react";
import { getTimeline, listJobs, type TimelineEvent, type Job } from "@/lib/api";
import { useJobSelection } from "@/hooks/useJobSelection";
import SeverityBadge from "@/components/SeverityBadge";
import { IpReputationButton } from "@/components/IpReputation";

export default function TimelinePage() {
  return <Suspense fallback={<div className="px-6 py-20 text-center text-slate-400">Loading...</div>}><TimelineContent /></Suspense>;
}

function TimelineContent() {
  const { selectedJob, setSelectedJob } = useJobSelection();
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(false);
  const [typeFilter, setTypeFilter] = useState("");

  useEffect(() => {
    listJobs().then((d) => setJobs(d.jobs)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedJob) return;
    setLoading(true);
    getTimeline(selectedJob, 500)
      .then((d) => setEvents(d.events))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [selectedJob]);

  const eventTypes = [...new Set(events.map((e) => e.event_type))].sort();
  const filtered = events.filter((e) => !typeFilter || e.event_type === typeFilter);

  const severityColor = (sev: string | null) => {
    switch (sev) {
      case "critical": return "bg-red-500";
      case "high": return "bg-orange-500";
      case "medium": return "bg-yellow-500";
      case "low": return "bg-blue-500";
      default: return "bg-slate-500";
    }
  };

  return (
    <div className="px-6 py-10">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white">Event Timeline</h1>
          <p className="mt-1 text-slate-400">Chronological view of security events</p>
        </div>
        <div className="flex gap-3">
          <select className="input w-48" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
            <option value="">All Events</option>
            {eventTypes.map((t) => <option key={t} value={t}>{t.replace(/_/g, " ")}</option>)}
          </select>
          <select className="input w-64" value={selectedJob} onChange={(e) => setSelectedJob(e.target.value)}>
            <option value="">Select job...</option>
            {jobs.map((j) => <option key={j.id} value={j.id}>{j.filename}</option>)}
          </select>
        </div>
      </div>

      {loading && <div className="text-center py-20 text-slate-400">Loading timeline...</div>}

      {/* Timeline */}
      <div className="relative ml-6">
        <div className="absolute left-0 top-0 bottom-0 w-px bg-slate-700" />
        <div className="space-y-1">
          {filtered.map((event, i) => (
            <div key={i} className="relative flex items-start gap-4 pl-8 py-2 group">
              <div className={`absolute left-[-4px] top-3 h-2.5 w-2.5 rounded-full ${severityColor(event.severity)} ring-4 ring-slate-900`} />
              <div className="flex-1 rounded-lg bg-slate-800/30 px-4 py-3 transition-colors group-hover:bg-slate-800/60">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-slate-500">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </span>
                    <span className="badge bg-slate-700/50 text-slate-300 text-xs">
                      {event.event_type.replace(/_/g, " ")}
                    </span>
                    {event.severity && <SeverityBadge severity={event.severity} />}
                  </div>
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    {event.source_ip && (
                      <span className="inline-flex items-center font-mono">
                        {event.source_ip}
                        <IpReputationButton ip={event.source_ip} />
                      </span>
                    )}
                    {event.username && <span className="font-mono">{event.username}</span>}
                  </div>
                </div>
                <p className="mt-1 text-sm text-slate-300">{event.description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {!loading && filtered.length === 0 && selectedJob && (
        <div className="text-center py-16"><p className="text-slate-400">No timeline events found</p></div>
      )}

      {!selectedJob && (
        <div className="text-center py-20">
          <p className="text-slate-400 text-lg">Select an analysis job to view the timeline</p>
          <a href="/" className="btn-primary mt-4 inline-flex">Upload a Log File</a>
        </div>
      )}
    </div>
  );
}
