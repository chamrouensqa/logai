"use client";

import { Suspense, useEffect, useState } from "react";
import { getDashboard, getJob, listJobs, type DashboardStats, type Job } from "@/lib/api";
import { useJobSelection } from "@/hooks/useJobSelection";
import StatCard from "@/components/StatCard";
import SeverityBadge from "@/components/SeverityBadge";
import { IpReputationLookupCard } from "@/components/IpReputation";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area, Legend,
} from "recharts";

const COLORS = ["#dc2626", "#ea580c", "#d97706", "#2563eb", "#6b7280"];
const WAF_ACTION_COLORS: Record<string, string> = {
  BLOCK: "#dc2626",
  ALLOW: "#16a34a",
  COUNT: "#ca8a04",
};

export default function DashboardPage() {
  return <Suspense fallback={<div className="px-6 py-20 text-center text-slate-400">Loading...</div>}><DashboardContent /></Suspense>;
}

function DashboardContent() {
  const { selectedJob, setSelectedJob } = useJobSelection();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    listJobs().then((data) => setJobs(data.jobs)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedJob) return;
    setLoading(true);
    setError("");
    Promise.all([getDashboard(selectedJob), getJob(selectedJob)])
      .then(([s, j]) => { setStats(s); setJob(j); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [selectedJob]);

  return (
    <div className="px-6 py-10">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
          <p className="mt-1 text-slate-400">Real-time security overview of analyzed logs</p>
        </div>
        <select className="input w-64" value={selectedJob} onChange={(e) => setSelectedJob(e.target.value)}>
          <option value="">Select analysis job...</option>
          {jobs.map((j) => (
            <option key={j.id} value={j.id}>{j.filename} ({j.status})</option>
          ))}
        </select>
      </div>

      {error && <div className="card border-red-500/30 bg-red-500/10 mb-6"><p className="text-red-400">{error}</p></div>}
      {loading && <div className="text-center py-20 text-slate-400">Loading dashboard...</div>}

      {stats && job && (
        <div className="space-y-6">
          {/* Risk Banner */}
          {job.ai_risk_level && (
            <div className={`card border-l-4 ${
              job.ai_risk_level === "critical" ? "border-l-red-500 bg-red-500/5" :
              job.ai_risk_level === "high" ? "border-l-orange-500 bg-orange-500/5" :
              "border-l-blue-500 bg-blue-500/5"
            }`}>
              <div className="flex items-center gap-4">
                <SeverityBadge severity={job.ai_risk_level} />
                <div>
                  <h3 className="font-semibold text-white">{job.filename}</h3>
                  <p className="text-sm text-slate-400">{job.ai_summary?.split("\n")[0]}</p>
                </div>
              </div>
            </div>
          )}

          {/* Stat Cards */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            <StatCard label="Total Events" value={stats.total_events} />
            <StatCard label="Alerts Detected" value={stats.total_alerts} className={stats.total_alerts > 0 ? "ring-1 ring-orange-500/30" : ""} />
            <StatCard label="Unique IPs" value={stats.unique_ips} />
            <StatCard label="Failed Logins" value={stats.failed_logins} />
            <StatCard label="Error Rate" value={`${stats.error_rate}%`} />
          </div>

          <IpReputationLookupCard />

          {/* Charts Row */}
          <div className="grid md:grid-cols-2 gap-6">
            {/* Events by Hour */}
            <div className="card">
              <h3 className="font-semibold text-white mb-4">Events by Hour</h3>
              {stats.events_by_hour.length === 0 ? (
                <p className="text-sm text-slate-500 py-16 text-center">
                  No timestamps in parsed rows (e.g. unparsed CSV/JSON lines). Re-upload after parser support or use a log format with timestamps.
                </p>
              ) : (
                <ResponsiveContainer width="100%" height={250}>
                  <AreaChart data={stats.events_by_hour} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                    <XAxis dataKey="hour" stroke="#64748b" fontSize={12} tickFormatter={(h) => `${h}:00`} />
                    <YAxis stroke="#64748b" fontSize={12} />
                    <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, color: "#f1f5f9" }} />
                    <Area type="monotone" dataKey="count" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.2} strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>

            {/* Severity Distribution */}
            <div className="card">
              <h3 className="font-semibold text-white mb-4">Alert Severity Distribution</h3>
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie data={stats.severity_distribution.filter(s => s.count > 0)} cx="50%" cy="50%" innerRadius={60} outerRadius={90} dataKey="count" nameKey="severity" label={({ severity, count }) => `${severity}: ${count}`}>
                    {stats.severity_distribution.filter(s => s.count > 0).map((_, i) => (
                      <Cell key={i} fill={COLORS[i % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, color: "#f1f5f9" }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* WAF (AWS WAF CSV / compatible) */}
          {stats.waf_has_data && stats.waf_action_counts && stats.waf_action_counts.length > 0 && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold text-slate-200 border-b border-slate-700 pb-2">
                WAF traffic
              </h2>
              <div className="grid md:grid-cols-2 gap-6">
                <div className="card">
                  <h3 className="font-semibold text-white mb-4">Action mix</h3>
                  <ResponsiveContainer width="100%" height={260}>
                    <PieChart>
                      <Pie
                        data={stats.waf_action_counts}
                        cx="50%"
                        cy="50%"
                        innerRadius={56}
                        outerRadius={92}
                        dataKey="count"
                        nameKey="action"
                        label={({ action, count }) => `${action}: ${count}`}
                      >
                        {stats.waf_action_counts.map((entry, i) => (
                          <Cell
                            key={i}
                            fill={WAF_ACTION_COLORS[entry.action] ?? COLORS[i % COLORS.length]}
                          />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          background: "#1e293b",
                          border: "1px solid #334155",
                          borderRadius: 8,
                          color: "#f1f5f9",
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="card">
                  <h3 className="font-semibold text-white mb-4">WAF events by hour</h3>
                  {stats.waf_events_by_hour && stats.waf_events_by_hour.length > 0 ? (
                    <ResponsiveContainer width="100%" height={260}>
                      <AreaChart
                        data={stats.waf_events_by_hour}
                        margin={{ top: 8, right: 8, left: 0, bottom: 0 }}
                      >
                        <XAxis
                          dataKey="hour"
                          stroke="#64748b"
                          fontSize={12}
                          tickFormatter={(h) => `${h}:00`}
                        />
                        <YAxis stroke="#64748b" fontSize={12} />
                        <Tooltip
                          contentStyle={{
                            background: "#1e293b",
                            border: "1px solid #334155",
                            borderRadius: 8,
                            color: "#f1f5f9",
                          }}
                        />
                        <Legend />
                        <Area
                          type="monotone"
                          dataKey="blocked"
                          stackId="waf"
                          stroke="#dc2626"
                          fill="#dc2626"
                          fillOpacity={0.35}
                        />
                        <Area
                          type="monotone"
                          dataKey="allowed"
                          stackId="waf"
                          stroke="#16a34a"
                          fill="#16a34a"
                          fillOpacity={0.35}
                        />
                        <Area
                          type="monotone"
                          dataKey="counted"
                          stackId="waf"
                          stroke="#ca8a04"
                          fill="#ca8a04"
                          fillOpacity={0.35}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  ) : (
                    <p className="text-sm text-slate-500 py-16 text-center">No hourly WAF data.</p>
                  )}
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-6">
                <div className="card">
                  <h3 className="font-semibold text-white mb-4">Top blocked IPs</h3>
                  {(stats.top_blocked_ips?.length ?? 0) === 0 ? (
                    <p className="text-sm text-slate-500 py-16 text-center">No blocked events with IPs.</p>
                  ) : (
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart
                        data={stats.top_blocked_ips!.slice(0, 8)}
                        layout="vertical"
                        margin={{ top: 4, right: 16, left: 4, bottom: 4 }}
                      >
                        <XAxis type="number" stroke="#64748b" fontSize={12} />
                        <YAxis
                          dataKey="ip"
                          type="category"
                          stroke="#64748b"
                          fontSize={11}
                          width={120}
                          tick={{ fill: "#94a3b8" }}
                        />
                        <Tooltip
                          contentStyle={{
                            background: "#1e293b",
                            border: "1px solid #334155",
                            borderRadius: 8,
                            color: "#f1f5f9",
                          }}
                        />
                        <Bar
                          dataKey="count"
                          fill="#dc2626"
                          radius={[0, 4, 4, 0]}
                          maxBarSize={28}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  )}
                </div>
                <div className="card">
                  <h3 className="font-semibold text-white mb-4">Top blocked endpoints</h3>
                  {(stats.top_blocked_endpoints?.length ?? 0) === 0 ? (
                    <p className="text-sm text-slate-500 py-16 text-center">No blocked events with paths.</p>
                  ) : (
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart
                        data={stats.top_blocked_endpoints!.slice(0, 8)}
                        layout="vertical"
                        margin={{ top: 4, right: 16, left: 4, bottom: 4 }}
                      >
                        <XAxis type="number" stroke="#64748b" fontSize={12} />
                        <YAxis
                          dataKey="endpoint"
                          type="category"
                          stroke="#64748b"
                          fontSize={10}
                          width={160}
                          tick={{ fill: "#94a3b8" }}
                        />
                        <Tooltip
                          contentStyle={{
                            background: "#1e293b",
                            border: "1px solid #334155",
                            borderRadius: 8,
                            color: "#f1f5f9",
                          }}
                        />
                        <Bar
                          dataKey="count"
                          fill="#b91c1c"
                          radius={[0, 4, 4, 0]}
                          maxBarSize={28}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  )}
                </div>
              </div>

              {(stats.top_terminating_rules?.length ?? 0) > 0 && (
                <div className="card">
                  <h3 className="font-semibold text-white mb-4">Terminating rules</h3>
                  <ResponsiveContainer width="100%" height={Math.min(420, 40 + (stats.top_terminating_rules!.length * 28))}>
                    <BarChart
                      data={stats.top_terminating_rules}
                      layout="vertical"
                      margin={{ top: 4, right: 16, left: 8, bottom: 4 }}
                    >
                      <XAxis type="number" stroke="#64748b" fontSize={12} />
                      <YAxis
                        dataKey="rule"
                        type="category"
                        stroke="#64748b"
                        fontSize={10}
                        width={220}
                        tick={{ fill: "#94a3b8" }}
                        tickFormatter={(v) =>
                          String(v).length > 48 ? `${String(v).slice(0, 46)}…` : String(v)
                        }
                      />
                      <Tooltip
                        contentStyle={{
                          background: "#1e293b",
                          border: "1px solid #334155",
                          borderRadius: 8,
                          color: "#f1f5f9",
                        }}
                        formatter={(value: number) => [value, "events"]}
                        labelFormatter={(label) => String(label)}
                      />
                      <Bar dataKey="count" fill="#7c3aed" radius={[0, 4, 4, 0]} maxBarSize={26} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          )}

          {/* Top IPs & Endpoints */}
          <div className="grid md:grid-cols-2 gap-6">
            <div className="card">
              <h3 className="font-semibold text-white mb-4">Top Source IPs</h3>
              {stats.top_source_ips.length === 0 ? (
                <p className="text-sm text-slate-500 py-16 text-center">No source IP field in parsed events (check log format / parser).</p>
              ) : (
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={stats.top_source_ips.slice(0, 8)} layout="vertical" margin={{ top: 4, right: 16, left: 4, bottom: 4 }}>
                    <XAxis type="number" stroke="#64748b" fontSize={12} />
                    <YAxis dataKey="ip" type="category" stroke="#64748b" fontSize={11} width={120} tick={{ fill: "#94a3b8" }} />
                    <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, color: "#f1f5f9" }} />
                    <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} maxBarSize={28} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="card">
              <h3 className="font-semibold text-white mb-4">Top Endpoints</h3>
              {stats.top_endpoints.length === 0 ? (
                <p className="text-sm text-slate-500 py-16 text-center">No endpoint/path field in parsed events.</p>
              ) : (
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={stats.top_endpoints.slice(0, 8)} layout="vertical" margin={{ top: 4, right: 16, left: 4, bottom: 4 }}>
                    <XAxis type="number" stroke="#64748b" fontSize={12} />
                    <YAxis dataKey="endpoint" type="category" stroke="#64748b" fontSize={10} width={160} tick={{ fill: "#94a3b8" }} />
                    <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, color: "#f1f5f9" }} />
                    <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} maxBarSize={28} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Alerts by Type */}
          {stats.alerts_by_type.length > 0 && (
            <div className="card">
              <h3 className="font-semibold text-white mb-4">Alerts by Type</h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart
                  data={stats.alerts_by_type}
                  margin={{ top: 12, right: 16, left: 8, bottom: 48 }}
                >
                  <XAxis
                    dataKey="type"
                    type="category"
                    stroke="#64748b"
                    fontSize={10}
                    interval={0}
                    tick={{ fill: "#94a3b8" }}
                    tickFormatter={(v) => String(v).replace(/_/g, " ")}
                    angle={stats.alerts_by_type.length > 3 ? -25 : 0}
                    textAnchor={stats.alerts_by_type.length > 3 ? "end" : "middle"}
                    height={stats.alerts_by_type.length > 3 ? 50 : 30}
                  />
                  <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, color: "#f1f5f9" }} />
                  <Bar dataKey="count" fill="#f59e0b" radius={[4, 4, 0, 0]} maxBarSize={72} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Top Usernames */}
          {stats.top_usernames.length > 0 && (
            <div className="card">
              <h3 className="font-semibold text-white mb-4">Top Targeted Accounts</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-700">
                      <th className="text-left py-2 text-slate-400 font-medium">Username</th>
                      <th className="text-right py-2 text-slate-400 font-medium">Events</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.top_usernames.map((u, i) => (
                      <tr key={i} className="border-b border-slate-700/50">
                        <td className="py-2 text-slate-200 font-mono">{u.username}</td>
                        <td className="py-2 text-right text-slate-300">{u.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {!stats && !loading && !error && (
        <div className="text-center py-20">
          <p className="text-slate-400 text-lg">Select an analysis job to view the dashboard</p>
          <a href="/" className="btn-primary mt-4 inline-flex">Upload a Log File</a>
        </div>
      )}
    </div>
  );
}
