import React, { useState } from 'react';
import { Eye, EyeOff, Shield } from 'lucide-react';
import { sendPasswordResetEmail, signInWithEmailAndPassword, signOut } from 'firebase/auth';
import { apiRequest, setAuthSession } from '../api';
import { firebaseAuth, isFirebaseConfigured } from '../firebase';
import type { User } from '../types';

interface LoginPageProps {
  onSuccess: (user: User) => void;
  onSwitchToRegister: () => void;
}

function firebaseErrorMessage(error: unknown): string {
  const code = typeof error === 'object' && error && 'code' in error ? String((error as { code?: string }).code) : '';
  if (code.includes('user-not-found') || code.includes('wrong-password') || code.includes('invalid-credential')) return 'Invalid email or password.';
  if (code.includes('invalid-email')) return 'Please enter a valid email address.';
  if (code.includes('too-many-requests')) return 'Too many attempts. Please wait and try again.';
  if (code.includes('user-disabled')) return 'This account has been disabled.';
  if (code.includes('user-not-found')) return 'If this email is registered, Firebase has sent a password reset link.';
  return error instanceof Error ? error.message : 'Unable to sign in.';
}

export const LoginPage: React.FC<LoginPageProps> = ({ onSuccess, onSwitchToRegister }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const establishCloudSocSession = async (idToken: string) => {
    const data = await apiRequest<{ user: User; csrfToken: string }>('/api/auth/firebase/session', {
      method: 'POST',
      body: JSON.stringify({ idToken }),
    });
    setAuthSession('', data.csrfToken);
    return data.user;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setNotice('');
    setLoading(true);
    const normalizedEmail = email.trim().toLowerCase();
    try {
      if (isFirebaseConfigured && firebaseAuth) {
        let firebaseCredential;
        try {
          firebaseCredential = await signInWithEmailAndPassword(firebaseAuth, normalizedEmail, password);
        } catch {
          // Keep the existing seeded ADMIN/ANALYST demo accounts working locally.
          const legacy = await apiRequest<{ user: User; csrfToken: string; sessionToken?: string }>('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ identifier: normalizedEmail, password }),
          });
          setAuthSession('', legacy.csrfToken);
          onSuccess(legacy.user);
          return;
        }

        try {
          const user = await establishCloudSocSession(await firebaseCredential.user.getIdToken());
          await signOut(firebaseAuth);
          onSuccess(user);
          return;
        } catch (exchangeError) {
          await signOut(firebaseAuth).catch(() => {});
          throw exchangeError;
        }
      }

      // Local fallback is retained for the project's seeded demo accounts.
      const legacy = await apiRequest<{ user: User; csrfToken: string; sessionToken?: string }>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ identifier: normalizedEmail, password }),
      });
      setAuthSession('', legacy.csrfToken);
      onSuccess(legacy.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : firebaseErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordReset = async () => {
    setError('');
    setNotice('');
    if (!isFirebaseConfigured || !firebaseAuth) {
      setError('Firebase is not configured yet. Complete the Firebase setup before requesting a reset link.');
      return;
    }
    const normalizedEmail = email.trim().toLowerCase();
    if (!normalizedEmail) {
      setError('Enter your email address first, then choose Forgot password.');
      return;
    }
    setLoading(true);
    try {
      await sendPasswordResetEmail(firebaseAuth, normalizedEmail);
      setNotice('If this email is registered, Firebase has sent a password reset link.');
    } catch (err) {
      setError(firebaseErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const fillDemo = (demoEmail: string, demoPassword: string) => {
    setEmail(demoEmail);
    setPassword(demoPassword);
    setError('');
    setNotice('');
  };

  return (
    <div className="min-h-screen bg-[#080d1a] flex flex-col justify-center items-center px-4 py-12">
      <div className="w-full max-w-md bg-[#0f172a] border border-slate-800 rounded-lg p-8">
        <div className="flex items-center gap-2.5 mb-6">
          <Shield className="h-6 w-6 text-cyan-400" />
          <span className="text-xl font-bold tracking-tight text-white">CloudSOC</span>
        </div>
        <h1 className="text-2xl font-semibold text-white mb-1.5">Sign in to Security Console</h1>
        <p className="text-sm text-slate-400 mb-6">Sign in using your email address and password.</p>

        {error && <div role="alert" className="mb-5 p-3 rounded-md bg-rose-950/60 border border-rose-500/40 text-sm text-rose-200">{error}</div>}
        {notice && <div role="status" className="mb-5 p-3 rounded-md bg-emerald-950/50 border border-emerald-500/40 text-sm text-emerald-200">{notice}</div>}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="login-email" className="block text-sm font-medium text-slate-300 mb-1.5">Email Address</label>
            <input id="login-email" type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" className="w-full px-3.5 py-2.5 rounded-md bg-[#080d1a] border border-slate-700 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500" required />
          </div>
          <div>
            <label htmlFor="login-password" className="block text-sm font-medium text-slate-300 mb-1.5">Password</label>
            <div className="relative">
              <input id="login-password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Enter your password" className="w-full px-3.5 py-2.5 pr-10 rounded-md bg-[#080d1a] border border-slate-700 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500" required />
              <button type="button" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? 'Hide password' : 'Show password'} className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-200">
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <div className="text-right mt-2"><button type="button" onClick={handlePasswordReset} disabled={loading} className="text-xs text-cyan-400 hover:text-cyan-300 underline underline-offset-4">Forgot password?</button></div>
          </div>
          <button type="submit" disabled={loading} className="w-full py-2.5 px-4 rounded-md bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-sm font-semibold text-white transition-colors">{loading ? 'Signing in...' : 'Sign In'}</button>
        </form>

        <div className="mt-6 pt-5 border-t border-slate-800">
          <p className="text-xs font-medium text-slate-400 mb-2.5">Existing local evaluation accounts</p>
          <div className="grid grid-cols-2 gap-2">
            <button type="button" onClick={() => fillDemo('admin@cloudsoc.local', 'Admin@CloudSOC2026!')} className="px-3 py-2 rounded-md border border-slate-700 bg-slate-900/70 hover:bg-slate-800 text-xs font-medium text-slate-200 text-left transition-colors">Use Admin Demo</button>
            <button type="button" onClick={() => fillDemo('analyst@cloudsoc.local', 'Analyst@CloudSOC2026!')} className="px-3 py-2 rounded-md border border-slate-700 bg-slate-900/70 hover:bg-slate-800 text-xs font-medium text-slate-200 text-left transition-colors">Use Analyst Demo</button>
          </div>
        </div>
        <p className="mt-6 text-center text-sm text-slate-400">New to CloudSOC?{' '}<button type="button" onClick={onSwitchToRegister} className="text-cyan-400 hover:text-cyan-300 font-medium underline underline-offset-4">Create an account</button></p>
      </div>
    </div>
  );
};
