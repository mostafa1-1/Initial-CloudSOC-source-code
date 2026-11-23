import React, { useEffect, useState } from 'react';
import { Plus, X } from 'lucide-react';
import { apiRequest, formatTimestamp } from '../api';
import { StatusTag } from '../components/StatusBadge';
import type { RoleName, User } from '../types';

export const UsersPage: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<RoleName>('SECURITY_ANALYST');

  const loadUsers = async () => {
    setLoading(true);
    try {
      const data = await apiRequest<{ users: User[] }>('/api/users');
      setUsers(data.users);
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Unable to load users.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setBanner(null);
    try {
      await apiRequest('/api/users', {
        method: 'POST',
        body: JSON.stringify({ username, email, full_name: fullName, password, role }),
      });
      setShowCreate(false);
      setUsername('');
      setEmail('');
      setFullName('');
      setPassword('');
      setBanner({ type: 'success', text: `Provisioned user "${username}" (${role}).` });
      await loadUsers();
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to create user.' });
    }
  };

  const handleToggleActive = async (u: User) => {
    try {
      await apiRequest(`/api/users/${u.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ is_active: u.is_active === 1 ? 0 : 1 }),
      });
      await loadUsers();
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to update user.' });
    }
  };

  const handleRoleChange = async (u: User, nextRole: RoleName) => {
    try {
      await apiRequest(`/api/users/${u.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ role: nextRole }),
      });
      setBanner({ type: 'success', text: `Updated ${u.username} role to ${nextRole}.` });
      await loadUsers();
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Role update failed.' });
    }
  };

  const handleUnlock = async (u: User) => {
    try {
      await apiRequest(`/api/users/${u.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ unlock: true }),
      });
      setBanner({ type: 'success', text: `Unlocked account ${u.username}.` });
      await loadUsers();
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Unlock failed.' });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white">User &amp; Role Management (Admin)</h2>
          <p className="text-sm text-slate-400">
            Provision SOC operators, enforce role-based access control, and manage account lockouts.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setShowCreate(true)}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white"
        >
          <Plus className="h-3.5 w-3.5" />
          <span>Add User</span>
        </button>
      </div>

      {banner && (
        <div
          role="status"
          className={`p-3.5 rounded-md border text-sm flex items-center justify-between ${
            banner.type === 'success'
              ? 'bg-emerald-950/50 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-950/50 border-rose-500/40 text-rose-200'
          }`}
        >
          <span>{banner.text}</span>
          <button type="button" onClick={() => setBanner(null)} aria-label="Dismiss notification">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0b1120] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3 font-medium">Username</th>
                <th className="px-4 py-3 font-medium">Full Name &amp; Email</th>
                <th className="px-4 py-3 font-medium">Role</th>
                <th className="px-4 py-3 font-medium">Account Status</th>
                <th className="px-4 py-3 font-medium">Failed Logins</th>
                <th className="px-4 py-3 font-medium">Last Login</th>
                <th className="px-4 py-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-400">
                    Loading users...
                  </td>
                </tr>
              ) : (
                users.map((u) => {
                  const isLocked = u.locked_until && new Date(u.locked_until).getTime() > Date.now();
                  return (
                    <tr key={u.id} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 font-mono text-cyan-300">{u.username}</td>
                      <td className="px-4 py-3">
                        <p className="text-white font-medium">{u.full_name}</p>
                        <p className="text-slate-400">{u.email}</p>
                      </td>
                      <td className="px-4 py-3">
                        <select
                          aria-label={`Role for ${u.username}`}
                          value={u.role}
                          onChange={(e) => handleRoleChange(u, e.target.value as RoleName)}
                          className="px-2.5 py-1 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                        >
                          <option value="ADMIN">ADMIN</option>
                          <option value="SECURITY_ANALYST">SECURITY_ANALYST</option>
                        </select>
                      </td>
                      <td className="px-4 py-3">
                        <StatusTag
                          label={u.is_active ? (isLocked ? 'Locked' : 'Active') : 'Disabled'}
                          variant={u.is_active ? (isLocked ? 'high' : 'low') : 'critical'}
                        />
                      </td>
                      <td className="px-4 py-3 font-mono tabular-nums text-slate-300">
                        {u.failed_login_attempts ?? 0}
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400 whitespace-nowrap">
                        {formatTimestamp(u.last_login_at)}
                      </td>
                      <td className="px-4 py-3 text-right space-x-3 whitespace-nowrap">
                        {(isLocked || (u.failed_login_attempts ?? 0) > 0) && (
                          <button
                            type="button"
                            onClick={() => handleUnlock(u)}
                            className="text-amber-300 hover:underline font-medium"
                          >
                            Unlock
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => handleToggleActive(u)}
                          className="text-cyan-400 hover:underline font-medium"
                        >
                          {u.is_active ? 'Disable' : 'Enable'}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {showCreate && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreate}
            className="bg-[#0f172a] border border-slate-700 rounded-lg max-w-md w-full p-6 space-y-4"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-semibold text-white">Create User Account</h3>
              <button type="button" onClick={() => setShowCreate(false)} aria-label="Close modal">
                <X className="h-5 w-5 text-slate-400" />
              </button>
            </div>
            <div className="space-y-3">
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
                <label className="block text-xs text-slate-300 mb-1">Username</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
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
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-xs text-slate-300 mb-1">Role</label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value as RoleName)}
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                >
                  <option value="SECURITY_ANALYST">SECURITY_ANALYST</option>
                  <option value="ADMIN">ADMIN</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-300 mb-1">Temporary Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Min 8 chars, upper, lower, digit"
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  required
                />
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                className="px-4 py-2 rounded-md border border-slate-700 text-xs text-slate-300"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white"
              >
                Create User
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
