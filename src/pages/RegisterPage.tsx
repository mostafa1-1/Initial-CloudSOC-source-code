import React, { useState } from 'react';
import { Shield } from 'lucide-react';
import { createUserWithEmailAndPassword, deleteUser, signOut, type User as FirebaseUser } from 'firebase/auth';
import { ApiError, apiRequest, setAuthSession } from '../api';
import { firebaseAuth, isFirebaseConfigured } from '../firebase';
import type { User } from '../types';

interface RegisterPageProps {
  onSuccess: (user: User) => void;
  onSwitchToLogin: () => void;
}

function authErrorMessage(error: unknown): string {
  const code = typeof error === 'object' && error && 'code' in error ? String((error as { code?: string }).code) : '';
  if (code.includes('email-already-in-use')) return 'This email is already registered. Please sign in instead.';
  if (code.includes('invalid-email')) return 'Please enter a valid email address.';
  if (code.includes('weak-password')) return 'Choose a stronger password with at least 8 characters.';
  if (code.includes('operation-not-allowed')) return 'Email/Password sign-in is not enabled in Firebase Authentication.';
  return error instanceof Error ? error.message : 'Registration failed.';
}

export const RegisterPage: React.FC<RegisterPageProps> = ({ onSuccess, onSwitchToLogin }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    const normalizedEmail = email.trim().toLowerCase();
    if (!isFirebaseConfigured || !firebaseAuth) {
      setError('Firebase is not configured. Add the Firebase Web App values to the project .env file first.');
      return;
    }
    if (password.length < 8 || password.length > 128 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
      setError('Password must be 8–128 characters and include uppercase, lowercase, and a number.');
      return;
    }

    setLoading(true);
    let createdFirebaseUser: FirebaseUser | null = null;
    try {
      const credential = await createUserWithEmailAndPassword(firebaseAuth, normalizedEmail, password);
      createdFirebaseUser = credential.user;
      const idToken = await credential.user.getIdToken();
      const data = await apiRequest<{ user: User; csrfToken: string }>('/api/auth/firebase/session', {
        method: 'POST',
        body: JSON.stringify({ idToken }),
      });
      setAuthSession('', data.csrfToken);
      await signOut(firebaseAuth);
      onSuccess(data.user);
    } catch (err) {
      if (createdFirebaseUser && err instanceof ApiError && err.status === 409) {
        await deleteUser(createdFirebaseUser).catch(() => {});
      }
      setError(authErrorMessage(err));
      // Keep a just-created Firebase identity if the server is temporarily unavailable;
      // the user can retry sign-in after the server credentials are configured.
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#080d1a] flex flex-col justify-center items-center px-4 py-12">
      <div className="w-full max-w-md bg-[#0f172a] border border-slate-800 rounded-lg p-8">
        <div className="flex items-center gap-2.5 mb-6"><Shield className="h-6 w-6 text-cyan-400" /><span className="text-xl font-bold tracking-tight text-white">CloudSOC</span></div>
        <h1 className="text-2xl font-semibold text-white mb-1.5">Create your CloudSOC account</h1>
        <p className="text-sm text-slate-400 mb-6">Only an email address and password are required. New accounts receive Security Analyst access.</p>
        {error && <div role="alert" className="mb-5 p-3 rounded-md bg-rose-950/60 border border-rose-500/40 text-sm text-rose-200">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="reg-email" className="block text-sm font-medium text-slate-300 mb-1.5">Email Address</label>
            <input id="reg-email" type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" className="w-full px-3.5 py-2.5 rounded-md bg-[#080d1a] border border-slate-700 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500" required />
          </div>
          <div>
            <label htmlFor="reg-password" className="block text-sm font-medium text-slate-300 mb-1.5">Password</label>
            <div className="relative">
              <input id="reg-password" type={showPassword ? 'text' : 'password'} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="At least 8 characters" minLength={8} maxLength={128} className="w-full px-3.5 py-2.5 pr-10 rounded-md bg-[#080d1a] border border-slate-700 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500" required />
              <button type="button" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? 'Hide password' : 'Show password'} className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-200">{showPassword ? 'Hide' : 'Show'}</button>
            </div>
            <p className="text-xs text-slate-500 mt-1.5">Use uppercase, lowercase, and at least one number.</p>
          </div>
          <button type="submit" disabled={loading} className="w-full py-2.5 px-4 rounded-md bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-sm font-semibold text-white transition-colors">{loading ? 'Creating account...' : 'Create Account'}</button>
        </form>
        <p className="mt-6 text-center text-sm text-slate-400">Already registered?{' '}<button type="button" onClick={onSwitchToLogin} className="text-cyan-400 hover:text-cyan-300 font-medium underline underline-offset-4">Sign In</button></p>
      </div>
    </div>
  );
};
