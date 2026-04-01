"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { login } from "@/lib/api";
import { getToken, setSession } from "@/lib/auth";

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-400">
          <div className="flex items-center gap-3 text-sm">
            <span className="h-5 w-5 animate-spin rounded-full border-2 border-slate-600 border-t-blue-500" />
            Loading…
          </div>
        </div>
      }
    >
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const next = searchParams.get("next") || "/";

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (getToken()) {
      router.replace(next.startsWith("/") ? next : "/");
    }
  }, [next, router]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await login(username.trim(), password);
      setSession(data.access_token, {
        id: data.user.id,
        username: data.user.username,
        role: data.user.role as "admin" | "user",
      });
      router.replace(next.startsWith("/") ? next : "/");
      router.refresh();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-slate-950">
      {/* Background */}
      <div
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_120%_80%_at_50%_-20%,rgba(59,130,246,0.18),transparent)]"
        aria-hidden
      />
      <div
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_100%_50%,rgba(99,102,241,0.08),transparent)]"
        aria-hidden
      />
      <div className="absolute inset-0 bg-[url('data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2248%22%20height%3D%2248%22%3E%3Cg%20fill%3D%22none%22%20stroke%3D%22%23334155%22%20stroke-width%3D%220.35%22%3E%3Cpath%20d%3D%22M0%20.5h48M0%2012h48M0%2024h48M0%2036h48M.5%200v48M12%200v48M24%200v48M36%200v48%22%2F%3E%3C%2Fg%3E%3C%2Fsvg%3E')] opacity-[0.35]" aria-hidden />

      <div className="relative flex min-h-screen flex-col items-center justify-center px-4 py-12 sm:px-6">
        <div className="w-full max-w-[420px]">
          {/* Card — explicit utilities so layout holds even if @layer components fail */}
          <div className="rounded-2xl border border-slate-700/80 bg-slate-900/80 p-8 shadow-2xl shadow-black/40 ring-1 ring-white/5 backdrop-blur-sm">
            <div className="mb-8 text-center">
              <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-700 text-lg font-bold text-white shadow-lg shadow-blue-900/40">
                LA
              </div>
              <h1 className="text-2xl font-semibold tracking-tight text-white">Log AI</h1>
              <p className="mt-2 text-sm leading-relaxed text-slate-400">
                Security intelligence — sign in to upload logs and review alerts.
              </p>
            </div>

            <form onSubmit={submit} className="flex flex-col gap-5">
              {error && (
                <div
                  role="alert"
                  className="rounded-xl border border-red-500/35 bg-red-950/50 px-4 py-3 text-sm text-red-200"
                >
                  {error}
                </div>
              )}

              <div className="flex flex-col gap-2">
                <label htmlFor="login-username" className="text-sm font-medium text-slate-300">
                  Username
                </label>
                <input
                  id="login-username"
                  name="username"
                  type="text"
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  className="w-full rounded-xl border border-slate-600 bg-slate-950/50 px-4 py-3 text-[15px] text-slate-100 placeholder:text-slate-600 outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/25"
                  placeholder="Your username"
                />
              </div>

              <div className="flex flex-col gap-2">
                <label htmlFor="login-password" className="text-sm font-medium text-slate-300">
                  Password
                </label>
                <input
                  id="login-password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className="w-full rounded-xl border border-slate-600 bg-slate-950/50 px-4 py-3 text-[15px] text-slate-100 outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-500/25"
                  placeholder="••••••••"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="mt-1 flex w-full items-center justify-center rounded-xl bg-blue-600 py-3.5 text-sm font-semibold text-white shadow-lg shadow-blue-900/30 transition hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-400/40 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                    Signing in…
                  </span>
                ) : (
                  "Sign in"
                )}
              </button>
            </form>

            <p className="mt-8 text-center text-xs leading-relaxed text-slate-500">
              Default admin is set on first server start. Change credentials in production.
            </p>
          </div>

          <p className="mt-8 text-center text-xs text-slate-600">Log AI — AI-powered log investigation</p>
        </div>
      </div>
    </div>
  );
}
