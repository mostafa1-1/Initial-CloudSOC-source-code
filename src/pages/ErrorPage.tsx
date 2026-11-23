import React from 'react';
import { ShieldAlert } from 'lucide-react';

interface ErrorPageProps {
  code: 403 | 404;
  title: string;
  message: string;
  onReturn: () => void;
}

export const ErrorPage: React.FC<ErrorPageProps> = ({ code, title, message, onReturn }) => {
  return (
    <div className="py-16 flex flex-col items-center justify-center text-center px-4">
      <div className="max-w-md w-full bg-[#0f172a] border border-slate-800 rounded-lg p-8">
        <ShieldAlert className="h-10 w-10 text-amber-400 mx-auto mb-4" />
        <p className="font-mono text-xs text-slate-400 mb-1">HTTP {code}</p>
        <h2 className="text-xl font-semibold text-white mb-2">{title}</h2>
        <p className="text-sm text-slate-400 mb-6">{message}</p>
        <button
          type="button"
          onClick={onReturn}
          className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-sm font-medium text-white transition-colors"
        >
          Return to Dashboard
        </button>
      </div>
    </div>
  );
};
