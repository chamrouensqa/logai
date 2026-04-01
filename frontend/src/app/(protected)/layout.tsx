import AppSidebar from "@/components/AppSidebar";
import AuthGuard from "@/components/AuthGuard";

export default function ProtectedLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <div className="flex min-h-screen">
        <AppSidebar />
        <main className="flex-1 overflow-auto">{children}</main>
      </div>
    </AuthGuard>
  );
}
