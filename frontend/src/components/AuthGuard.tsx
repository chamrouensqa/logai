"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { getToken } from "@/lib/auth";

export default function AuthGuard({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [state, setState] = useState<"checking" | "allowed">("checking");

  useEffect(() => {
    const token = getToken();
    if (!token) {
      const target = `/login?next=${encodeURIComponent(pathname || "/")}`;
      router.replace(target);
      setTimeout(() => {
        if (typeof window !== "undefined" && window.location.pathname !== "/login") {
          window.location.href = target;
        }
      }, 250);
      return;
    }
    setState("allowed");
  }, [pathname, router]);

  if (state !== "allowed") {
    return (
      <div className="flex min-h-screen items-center justify-center text-slate-400">
        Checking session…
      </div>
    );
  }

  return <>{children}</>;
}
