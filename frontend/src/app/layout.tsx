import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Log AI — AI-Powered Log Investigation",
  description: "Upload logs, detect threats, get AI-driven security analysis",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-slate-950 text-slate-100 antialiased">{children}</body>
    </html>
  );
}
