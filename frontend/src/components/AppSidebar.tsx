"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { clearSession, getStoredUser } from "@/lib/auth";
import { getStoredJobId } from "@/lib/selected-job";

const links = [
  { href: "/", label: "Upload", icon: "M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12", adminOnly: false },
  { href: "/dashboard", label: "Dashboard", icon: "M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z", adminOnly: false },
  { href: "/alerts", label: "Alerts", icon: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z", adminOnly: false },
  { href: "/timeline", label: "Timeline", icon: "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z", adminOnly: false },
  { href: "/investigation", label: "AI Investigate", icon: "M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z", adminOnly: false },
  { href: "/account", label: "Account", icon: "M15.75 9V5.25A2.25 2.25 0 0013.5 3h-3A2.25 2.25 0 008.25 5.25V9m-1.5 0h10.5A2.25 2.25 0 0119.5 11.25v7.5A2.25 2.25 0 0117.25 21h-10.5A2.25 2.25 0 014.5 18.75v-7.5A2.25 2.25 0 016.75 9z", adminOnly: false },
  { href: "/users", label: "Users", icon: "M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z", adminOnly: true },
];

export default function AppSidebar() {
  const pathname = usePathname();
  const [jobId, setJobId] = useState("");
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    const sync = () => setJobId(getStoredJobId() || "");
    sync();
    window.addEventListener("logai-job-change", sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener("logai-job-change", sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  useEffect(() => {
    const sync = () => setIsAdmin(getStoredUser()?.role === "admin");
    sync();
    window.addEventListener("logai-auth-change", sync);
    return () => window.removeEventListener("logai-auth-change", sync);
  }, []);

  const withJob = (base: string) => {
    if (!jobId || base === "/" || base === "/users" || base === "/account") return base;
    return `${base}?job=${encodeURIComponent(jobId)}`;
  };

  const signOut = () => {
    clearSession();
    window.location.href = "/login";
  };

  return (
    <nav className="hidden md:flex w-64 flex-col border-r border-slate-700/50 bg-slate-900/50 backdrop-blur-sm">
      <div className="flex items-center gap-3 border-b border-slate-700/50 px-6 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 font-bold text-white">
          LA
        </div>
        <div>
          <h1 className="font-bold text-white text-lg leading-none">Log AI</h1>
          <p className="text-xs text-slate-400 mt-0.5">Security Intelligence</p>
        </div>
      </div>
      <div className="flex-1 px-3 py-4 space-y-1">
        {links
          .filter((link) => !link.adminOnly || isAdmin)
          .map((link) => {
            const href = withJob(link.href);
            const active =
              link.href === "/"
                ? pathname === "/"
                : pathname.startsWith(link.href);
            return (
              <Link
                key={link.href}
                href={href}
                className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors hover:bg-slate-800 hover:text-white ${
                  active ? "bg-slate-800 text-white" : "text-slate-300"
                }`}
              >
                <svg className="h-5 w-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d={link.icon} />
                </svg>
                {link.label}
              </Link>
            );
          })}
      </div>
      <div className="border-t border-slate-700/50 px-6 py-4 space-y-2">
        <button
          type="button"
          onClick={signOut}
          className="w-full text-left rounded-lg px-3 py-2 text-sm text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
        >
          Sign out
        </button>
        <p className="text-xs text-slate-500">Log AI v1.0.0</p>
      </div>
    </nav>
  );
}
