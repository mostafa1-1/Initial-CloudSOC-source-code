import React, { useEffect, useState } from 'react';
import { apiRequest, formatTimestamp } from '../api';
import { StatusTag } from '../components/StatusBadge';
import type { User } from '../types';

interface ProfilePageProps {
  user: User;
  onUserUpdated: (user: User) => void;
}

export const ProfilePage: React.FC<ProfilePageProps> = ({ user, onUserUpdated }) => {
  const [fullName, setFullName] = useState(user.full_name);
  const [email, setEmail] = useState(user.email);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [audit, setAudit] = useState<Array<{ id: number; action: string; details: string; created_at: string }>>([]);
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    apiRequest<{
      user: User;
      recentAudit: Array<{ id: number; action: string; details: string; created_at: string }>;
    }>('/api/auth/me')
      .then((d) => setAudit(d.recentAudit))
      .catch(() => {});
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setBanner(null);
    try {
      const res = await apiRequest<{ user: User }>('/api/auth/profile', {
        method: 'PATCH',
        body: JSON.stringify({
          full_name: fullName.trim(),
          email: email.trim(),
          current_password: currentPassword || undefined,
          new_password: newPassword || undefined,
        }),
      });
      onUserUpdated(res.user);
      setCurrentPassword('');
      setNewPassword('');
      setBanner({ type: 'success', text: 'Profile and security preferences updated.' });
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Update failed.' });
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-lg font-semibold text-white">User Profile &amp; Credentials</h2>
        <p className="text-sm text-slate-400">
          Manage your account details, password rotation, and personal security audit history.
        </p>
      </div>

      {banner && (
        <div
          role="status"
          className={`p-3.5 rounded-md border text-sm ${
            banner.type === 'success'
              ? 'bg-emerald-950/50 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-950/50 border-rose-500/40 text-rose-200'
          }`}
        >
          {banner.text}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <form onSubmit={handleSave} className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-white">Account Settings</h3>
            <StatusTag label={user.role} variant="info" />
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Username</label>
            <input
              type="text"
              value={user.username}
              disabled
              className="w-full px-3 py-2 rounded bg-[#080d1a]/60 border border-slate-800 text-xs font-mono text-slate-400"
            />
          </div>

          <div>
            <label className="block text-xs text-slate-300 mb-1">Full Name</label>
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
              required
            />
          </div>

          <div>
            <label className="block text-xs text-slate-300 mb-1">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={user.auth_provider === 'firebase'}
              className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white disabled:opacity-60"
              required
            />
          </div>

          {user.auth_provider === 'firebase' ? (
            <div className="pt-3 border-t border-slate-800 text-xs text-slate-400">
              Your email and password are managed securely by Firebase Authentication. Use “Forgot password?” on the sign-in page to reset your password.
            </div>
          ) : (
            <div className="pt-3 border-t border-slate-800 space-y-3">
              <p className="text-xs font-medium text-slate-300">Change Password (Optional)</p>
              <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Current password" className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white" />
              <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="New strong password" className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white" />
            </div>
          )}

          <button
            type="submit"
            className="w-full py-2.5 rounded-md bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white"
          >
            Save Profile Changes
          </button>
        </form>

        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5 space-y-3">
          <h3 className="text-sm font-semibold text-white border-b border-slate-800 pb-3">
            Recent Personal Activity
          </h3>
          <div className="space-y-2.5 max-h-96 overflow-y-auto">
            {audit.length === 0 ? (
              <p className="text-xs text-slate-400">No recent personal activity logged.</p>
            ) : (
              audit.map((entry) => (
                <div key={entry.id} className="p-3 rounded bg-[#080d1a] border border-slate-800 text-xs space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-cyan-300">{entry.action}</span>
                    <span className="font-mono text-slate-500">{formatTimestamp(entry.created_at)}</span>
                  </div>
                  <p className="text-slate-300">{entry.details}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
