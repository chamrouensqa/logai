"use client";

import { useState, useCallback } from "react";
import { uploadLog, uploadAndAnalyzeSync, type Job } from "@/lib/api";
import { setStoredJobId } from "@/lib/selected-job";

export default function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [logType, setLogType] = useState("");
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<Job | null>(null);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"async" | "sync">("sync");

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) setFile(dropped);
  }, []);

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError("");
    setResult(null);

    try {
      const job = mode === "sync"
        ? await uploadAndAnalyzeSync(file, logType || undefined, false)
        : await uploadLog(file, logType || undefined);
      setResult(job);
      setStoredJobId(job.id);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="mx-auto max-w-4xl px-6 py-10">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Upload Log File</h1>
        <p className="mt-2 text-slate-400">
          Drag and drop a log file to start AI-powered security analysis
        </p>
      </div>

      {/* Drop Zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={`card cursor-pointer border-2 border-dashed transition-all ${
          dragging ? "border-blue-500 bg-blue-500/10" : "border-slate-600 hover:border-slate-500"
        }`}
      >
        <label className="flex flex-col items-center gap-4 py-12 cursor-pointer">
          <svg className="h-16 w-16 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
          </svg>
          {file ? (
            <div className="text-center">
              <p className="text-lg font-medium text-white">{file.name}</p>
              <p className="text-sm text-slate-400">{(file.size / 1024).toFixed(1)} KB</p>
            </div>
          ) : (
            <div className="text-center">
              <p className="text-lg font-medium text-slate-300">Drop log file here or click to browse</p>
              <p className="text-sm text-slate-500 mt-1">Supports .log, .txt, .json, .jsonl, .csv</p>
            </div>
          )}
          <input
            type="file"
            className="hidden"
            accept=".log,.txt,.json,.jsonl,.csv"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />
        </label>
      </div>

      {/* Options */}
      <div className="mt-6 flex flex-wrap items-end gap-4">
        <div className="flex-1 min-w-[200px]">
          <label className="block text-sm text-slate-400 mb-1.5">Log Type (optional)</label>
          <select
            className="input"
            value={logType}
            onChange={(e) => setLogType(e.target.value)}
          >
            <option value="">Auto-detect</option>
            <option value="aws_waf">AWS WAF (CSV export)</option>
            <option value="auth">Auth / Syslog</option>
            <option value="nginx">Nginx / Apache Access</option>
            <option value="nginx_error">Nginx Error</option>
            <option value="json">JSON / JSONL</option>
            <option value="firewall">Firewall (iptables/UFW)</option>
          </select>
        </div>

        <div className="flex-1 min-w-[200px]">
          <label className="block text-sm text-slate-400 mb-1.5">Processing Mode</label>
          <select className="input" value={mode} onChange={(e) => setMode(e.target.value as "async" | "sync")}>
            <option value="sync">Instant (no Redis needed)</option>
            <option value="async">Background (requires Celery)</option>
          </select>
        </div>

        <button
          onClick={handleUpload}
          disabled={!file || uploading}
          className="btn-primary h-[46px] px-8"
        >
          {uploading ? (
            <>
              <svg className="h-5 w-5 animate-spin" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Analyzing...
            </>
          ) : (
            "Analyze Log"
          )}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="mt-6 card border-red-500/30 bg-red-500/10">
          <p className="text-red-400 font-medium">Error</p>
          <p className="text-sm text-red-300 mt-1">{error}</p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="mt-8 space-y-6">
          <div className="card border-green-500/30 bg-green-500/5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-green-400">Analysis Complete</h3>
                <p className="text-sm text-slate-400 mt-1">{result.filename} — {result.total_lines} entries parsed</p>
              </div>
              <div className="flex gap-2">
                {result.ai_risk_level && (
                  <span className={`badge-${result.ai_risk_level}`}>{result.ai_risk_level.toUpperCase()} RISK</span>
                )}
                {result.alert_count != null && result.alert_count > 0 && (
                  <span className="badge-high">{result.alert_count} Alert{result.alert_count > 1 ? "s" : ""}</span>
                )}
              </div>
            </div>
          </div>

          {/* Status Info */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="card text-center">
              <p className="text-2xl font-bold text-white">{result.total_lines}</p>
              <p className="text-xs text-slate-400 mt-1">Total Lines</p>
            </div>
            <div className="card text-center">
              <p className="text-2xl font-bold text-white">{result.parsed_lines}</p>
              <p className="text-xs text-slate-400 mt-1">Parsed</p>
            </div>
            <div className="card text-center">
              <p className="text-2xl font-bold text-white">{result.alert_count || 0}</p>
              <p className="text-xs text-slate-400 mt-1">Alerts</p>
            </div>
            <div className="card text-center">
              <p className="text-2xl font-bold text-white">{result.log_type || "N/A"}</p>
              <p className="text-xs text-slate-400 mt-1">Log Type</p>
            </div>
          </div>

          {/* AI Summary */}
          {result.ai_summary && (
            <div className="card">
              <h3 className="font-semibold text-white mb-3">AI Security Summary</h3>
              <div className="prose prose-invert prose-sm max-w-none">
                <p className="text-slate-300 whitespace-pre-line">{result.ai_summary}</p>
              </div>
            </div>
          )}

          {/* Recommendations */}
          {result.ai_recommendations && result.ai_recommendations.length > 0 && (
            <div className="card">
              <h3 className="font-semibold text-white mb-3">Recommended Actions</h3>
              <ul className="space-y-2">
                {result.ai_recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                    <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-blue-500" />
                    {rec}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Navigation */}
          <div className="flex gap-3">
            <a href={`/dashboard?job=${result.id}`} className="btn-primary">View Dashboard</a>
            <a href={`/alerts?job=${result.id}`} className="btn-secondary">View Alerts</a>
            <a href={`/timeline?job=${result.id}`} className="btn-secondary">View Timeline</a>
            <a href={`/investigation?job=${result.id}`} className="btn-secondary">AI Investigate</a>
          </div>
        </div>
      )}
    </div>
  );
}
