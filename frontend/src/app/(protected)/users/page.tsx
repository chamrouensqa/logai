"use client";

import { useEffect, useState } from "react";
import { createUser, deleteUser, listUsers, type UserPublic } from "@/lib/api";
import { getStoredUser } from "@/lib/auth";
import { useRouter } from "next/navigation";

export default function UsersPage() {
  const router = useRouter();
  const [users, setUsers] = useState<UserPublic[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [creating, setCreating] = useState(false);
  const [deletingUserId, setDeletingUserId] = useState<string | null>(null);
  const currentUser = getStoredUser();

  useEffect(() => {
    if (getStoredUser()?.role !== "admin") {
      router.replace("/");
      return;
    }
    listUsers()
      .then(setUsers)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [router]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setCreating(true);
    try {
      const u = await createUser(username.trim(), password);
      setUsers((prev) => [...prev, u].sort((a, b) => a.username.localeCompare(b.username)));
      setUsername("");
      setPassword("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create user");
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (userId: string) => {
    setError("");
    setDeletingUserId(userId);
    try {
      await deleteUser(userId);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to delete user");
    } finally {
      setDeletingUserId(null);
    }
  };

  return (
    <div className="px-6 py-10 max-w-2xl">
      <h1 className="text-3xl font-bold text-white">Team users</h1>
      <p className="mt-1 text-slate-400 text-sm">
        Create accounts for your team. Everyone has the same access to log data and features; only
        admin can add users here.
      </p>

      {loading && <p className="mt-8 text-slate-500">Loading…</p>}

      {error && !loading && (
        <div className="mt-6 card border-red-500/30 bg-red-500/10 text-red-300 text-sm">{error}</div>
      )}

      {!loading && (
        <>
          <form onSubmit={handleCreate} className="mt-8 card space-y-4">
            <h2 className="font-semibold text-white">Add user</h2>
            <div className="grid sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Username</label>
                <input
                  className="input"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  minLength={2}
                  required
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Password (min 8 characters)</label>
                <input
                  type="password"
                  className="input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  minLength={8}
                  required
                />
              </div>
            </div>
            <button type="submit" className="btn-primary" disabled={creating}>
              {creating ? "Creating…" : "Create user"}
            </button>
          </form>

          <div className="mt-8">
            <h2 className="font-semibold text-white mb-3">All users</h2>
            <div className="card overflow-hidden p-0">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-left text-slate-400">
                    <th className="px-4 py-3 font-medium">Username</th>
                    <th className="px-4 py-3 font-medium">Role</th>
                    <th className="px-4 py-3 font-medium">Created</th>
                    <th className="px-4 py-3 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id} className="border-b border-slate-800/80">
                      <td className="px-4 py-3 text-slate-200 font-mono">{u.username}</td>
                      <td className="px-4 py-3 text-slate-300 capitalize">{u.role}</td>
                      <td className="px-4 py-3 text-slate-500">
                        {new Date(u.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {u.id !== currentUser?.id ? (
                          <button
                            type="button"
                            onClick={() => handleDelete(u.id)}
                            disabled={deletingUserId === u.id}
                            className="text-xs rounded-md border border-red-600/50 px-2.5 py-1 text-red-300 hover:bg-red-500/10 disabled:opacity-50"
                          >
                            {deletingUserId === u.id ? "Deleting…" : "Delete"}
                          </button>
                        ) : (
                          <span className="text-xs text-slate-500">Current user</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
