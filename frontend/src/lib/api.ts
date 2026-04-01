import { clearSession, getToken } from "./auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

// Direct backend URL for large file uploads (bypasses Next.js proxy size limits)
const BACKEND_DIRECT = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

const API_UNAVAILABLE =
  "Cannot reach the Log AI API. Start the backend (from the backend folder: uvicorn app.main:app --reload --host 127.0.0.1 --port 8000) and keep that terminal open.";

function bearerHeaders(extra?: Record<string, string>): Record<string, string> {
  const t = typeof window !== "undefined" ? getToken() : null;
  return {
    ...extra,
    ...(t ? { Authorization: `Bearer ${t}` } : {}),
  };
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const isForm = options?.body instanceof FormData;
  const headers: Record<string, string> = {
    ...(!isForm ? { "Content-Type": "application/json" } : {}),
    ...(options?.headers as Record<string, string> | undefined),
  };
  const t = getToken();
  if (t) headers.Authorization = `Bearer ${t}`;

  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api${path}`, {
      ...options,
      headers,
    });
  } catch {
    throw new Error(API_UNAVAILABLE);
  }

  if (res.status === 502 || res.status === 503 || res.status === 504) {
    throw new Error(API_UNAVAILABLE);
  }

  if (res.status === 401) {
    clearSession();
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = `/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`;
    }
    throw new Error("Session expired");
  }

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }));
    const detail = error.detail;
    const msg = Array.isArray(detail)
      ? detail.map((d: { msg?: string }) => d.msg || "").join(", ")
      : typeof detail === "string"
        ? detail
        : `API error: ${res.status}`;
    throw new Error(msg || `API error: ${res.status}`);
  }

  return res.json();
}

// ─── Types ──────────────────────────────────────────────

export type JobStatus = "pending" | "parsing" | "detecting" | "analyzing" | "completed" | "failed";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface UserPublic {
  id: string;
  username: string;
  role: string;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: UserPublic;
}

export interface Job {
  id: string;
  filename: string;
  file_size: number | null;
  log_type: string | null;
  status: JobStatus;
  progress: number;
  total_lines: number;
  parsed_lines: number;
  error_message: string | null;
  ai_summary: string | null;
  ai_risk_level: Severity | null;
  ai_recommendations: string[] | null;
  created_at: string;
  updated_at: string | null;
  completed_at: string | null;
  alert_count?: number;
}

export interface LogEntry {
  id: string;
  line_number: number | null;
  timestamp: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  username: string | null;
  endpoint: string | null;
  method: string | null;
  status_code: number | null;
  response_size: number | null;
  event_type: string | null;
  message: string | null;
  raw_line: string | null;
}

export interface Alert {
  id: string;
  job_id: string;
  alert_type: string;
  severity: Severity;
  title: string;
  description: string | null;
  source_ip: string | null;
  target_account: string | null;
  evidence: Record<string, unknown> | null;
  recommended_actions: string[] | null;
  is_resolved: boolean;
  created_at: string;
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  source_ip: string | null;
  username: string | null;
  description: string;
  severity: Severity | null;
}

export interface DashboardStats {
  total_events: number;
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  unique_ips: number;
  failed_logins: number;
  successful_logins: number;
  error_rate: number;
  top_source_ips: { ip: string; count: number }[];
  top_endpoints: { endpoint: string; count: number }[];
  top_usernames: { username: string; count: number }[];
  events_by_hour: { hour: number; count: number }[];
  alerts_by_type: { type: string; count: number }[];
  severity_distribution: { severity: string; count: number }[];
  waf_has_data?: boolean;
  waf_action_counts?: { action: string; count: number }[];
  waf_events_by_hour?: {
    hour: number;
    total: number;
    blocked: number;
    allowed: number;
    counted: number;
  }[];
  top_blocked_ips?: { ip: string; count: number }[];
  top_blocked_endpoints?: { endpoint: string; count: number }[];
  top_terminating_rules?: { rule: string; count: number }[];
}

export interface IpReputationResponse {
  ip: string;
  cached: boolean;
  configured_abuseipdb: boolean;
  configured_virustotal: boolean;
  abuseipdb: {
    abuse_confidence_score: number;
    total_reports: number;
    country_code: string | null;
    isp: string | null;
    usage_type: string | null;
    last_reported_at: string | null;
    is_whitelisted: boolean;
    report_url: string;
  } | null;
  virustotal: {
    harmless: number;
    malicious: number;
    suspicious: number;
    undetected: number;
    timeout: number;
    reputation: number | null;
    country: string | null;
    as_owner: string | null;
    analysis_url: string;
  } | null;
  errors: string[];
}

// ─── Auth (no bearer on login) ───────────────────────────

export async function login(username: string, password: string): Promise<TokenResponse> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
  } catch {
    throw new Error(API_UNAVAILABLE);
  }
  if (res.status === 502 || res.status === 503 || res.status === 504) {
    throw new Error(API_UNAVAILABLE);
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Login failed");
  }
  return res.json();
}

export const getMe = () => request<UserPublic>("/auth/me");

export const listUsers = () => request<UserPublic[]>("/users");

export const createUser = (username: string, password: string) =>
  request<UserPublic>("/users", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

export const deleteUser = (userId: string) =>
  request<{ message: string }>(`/users/${userId}`, {
    method: "DELETE",
  });

export const changePassword = (currentPassword: string, newPassword: string) =>
  request<{ message: string }>("/auth/change-password", {
    method: "POST",
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
    }),
  });

// ─── API Functions ──────────────────────────────────────

export async function uploadLog(file: File, logType?: string): Promise<Job> {
  const form = new FormData();
  form.append("file", file);
  if (logType) form.append("log_type", logType);

  let res: Response;
  try {
    res = await fetch(`${BACKEND_DIRECT}/api/upload-log`, {
      method: "POST",
      headers: bearerHeaders(),
      body: form,
    });
  } catch {
    throw new Error(API_UNAVAILABLE);
  }
  if (res.status === 502 || res.status === 503 || res.status === 504) {
    throw new Error(API_UNAVAILABLE);
  }
  if (res.status === 401) {
    clearSession();
    if (typeof window !== "undefined") {
      window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
    }
    throw new Error("Session expired");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Upload failed: ${res.status}`);
  }
  return res.json();
}

export async function uploadAndAnalyzeSync(file: File, logType?: string, skipAi = false): Promise<Job> {
  const form = new FormData();
  form.append("file", file);
  if (logType) form.append("log_type", logType);
  form.append("skip_ai", String(skipAi));

  let res: Response;
  try {
    res = await fetch(`${BACKEND_DIRECT}/api/dev/analyze`, {
      method: "POST",
      headers: bearerHeaders(),
      body: form,
    });
  } catch {
    throw new Error(API_UNAVAILABLE);
  }
  if (res.status === 502 || res.status === 503 || res.status === 504) {
    throw new Error(API_UNAVAILABLE);
  }
  if (res.status === 401) {
    clearSession();
    if (typeof window !== "undefined") {
      window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
    }
    throw new Error("Session expired");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Analysis failed: ${res.status}`);
  }
  return res.json();
}

export const getJob = (id: string) => request<Job>(`/analysis/${id}`);

export const listJobs = (page = 1, pageSize = 20) =>
  request<{ jobs: Job[]; total: number }>(`/jobs?page=${page}&page_size=${pageSize}`);

export const getLogEntries = (jobId: string, params?: Record<string, string>) => {
  const qs = new URLSearchParams(params).toString();
  return request<{ entries: LogEntry[]; total: number; page: number; page_size: number }>(
    `/logs/${jobId}${qs ? `?${qs}` : ""}`
  );
};

export const getAlerts = (jobId?: string, severity?: string) => {
  const params = new URLSearchParams();
  if (jobId) params.set("job_id", jobId);
  if (severity) params.set("severity", severity);
  const qs = params.toString();
  return request<{ alerts: Alert[]; total: number }>(`/alerts${qs ? `?${qs}` : ""}`);
};

export const getJobAlerts = (jobId: string) =>
  request<{ alerts: Alert[]; total: number }>(`/alerts/${jobId}`);

export const getTimeline = (jobId: string, limit = 200) =>
  request<{ events: TimelineEvent[]; total: number }>(`/timeline/${jobId}?limit=${limit}`);

export const getDashboard = (jobId: string) => request<DashboardStats>(`/dashboard/${jobId}`);

export const getIpReputation = (ip: string) => {
  const q = new URLSearchParams({ ip }).toString();
  return request<IpReputationResponse>(`/ip-reputation?${q}`);
};

export const askAI = (jobId: string, question: string) =>
  request<{ answer: string; sources?: Record<string, unknown>[] }>("/investigate/ask-ai", {
    method: "POST",
    body: JSON.stringify({ job_id: jobId, question }),
  });

export const getChatHistory = (jobId: string) =>
  request<{ messages: { role: string; content: string; timestamp: string }[] }>(
    `/investigate/chat-history/${jobId}`
  );
