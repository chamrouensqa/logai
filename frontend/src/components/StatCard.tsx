"use client";

import { clsx } from "clsx";

interface StatCardProps {
  label: string;
  value: string | number;
  icon?: React.ReactNode;
  trend?: string;
  className?: string;
}

export default function StatCard({ label, value, icon, trend, className }: StatCardProps) {
  return (
    <div className={clsx("card flex items-start gap-4", className)}>
      {icon && (
        <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-lg bg-slate-700/50">
          {icon}
        </div>
      )}
      <div>
        <p className="text-sm text-slate-400">{label}</p>
        <p className="mt-1 text-2xl font-bold text-white">{typeof value === "number" ? value.toLocaleString() : value}</p>
        {trend && <p className="mt-1 text-xs text-slate-500">{trend}</p>}
      </div>
    </div>
  );
}
