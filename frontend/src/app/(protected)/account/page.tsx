"use client";

import { useState } from "react";
import { changePassword } from "@/lib/api";

export default function AccountPage() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    if (newPassword !== confirmPassword) {
      setError("New password and confirmation do not match");
      return;
    }
    setSaving(true);
    try {
      const res = await changePassword(currentPassword, newPassword);
      setSuccess(res.message);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to update password");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="px-6 py-10 max-w-xl">
      <h1 className="text-3xl font-bold text-white">Account Settings</h1>
      <p className="mt-1 text-slate-400 text-sm">Update your password.</p>

      <form onSubmit={onSubmit} className="mt-6 card space-y-4">
        <h2 className="font-semibold text-white">Change password</h2>

        {error && (
          <div className="rounded-lg bg-red-500/10 border border-red-500/30 px-3 py-2 text-sm text-red-300">
            {error}
          </div>
        )}
        {success && (
          <div className="rounded-lg bg-green-500/10 border border-green-500/30 px-3 py-2 text-sm text-green-300">
            {success}
          </div>
        )}

        <div>
          <label className="block text-xs text-slate-400 mb-1">Current password</label>
          <input
            type="password"
            className="input"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
          />
        </div>
        <div>
          <label className="block text-xs text-slate-400 mb-1">New password (min 8 chars)</label>
          <input
            type="password"
            className="input"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            minLength={8}
            required
          />
        </div>
        <div>
          <label className="block text-xs text-slate-400 mb-1">Confirm new password</label>
          <input
            type="password"
            className="input"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            minLength={8}
            required
          />
        </div>

        <button type="submit" className="btn-primary" disabled={saving}>
          {saving ? "Updating…" : "Update password"}
        </button>
      </form>
    </div>
  );
}
