import React, { useState } from 'react';
import { api } from '../services/api';
import { Shield, Lock, User, AlertCircle, KeyRound } from 'lucide-react';

interface Props {
  onLoginSuccess: (user: { username: string; role: string }) => void;
}

export const LoginPage: React.FC<Props> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('analyst');
  const [password, setPassword] = useState('AnalystPass123!');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await api.login(username, password);
      onLoginSuccess({ username: res.username, role: res.role });
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickRole = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
  };

  return (
    <div className="min-h-screen bg-[#080d1a] flex flex-col justify-center items-center p-4 relative overflow-hidden">
      {/* Background Decorative Glow */}
      <div className="absolute w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-3xl pointer-events-none -top-48 -left-48" />
      <div className="absolute w-[400px] h-[400px] bg-blue-600/10 rounded-full blur-3xl pointer-events-none -bottom-32 -right-32" />

      <div className="max-w-md w-full cyber-card p-8 relative z-10 space-y-6 shadow-2xl border-slate-700/80">
        <div className="text-center space-y-2">
          <div className="w-14 h-14 mx-auto rounded-2xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-[0_0_25px_rgba(6,182,212,0.35)]">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-xl font-extrabold text-white tracking-wide">
            AEGIS FORENSICS
          </h1>
          <p className="text-xs text-slate-400">
            Email Threat Detection, Geolocation & Forensic Intelligence
          </p>
        </div>

        {error && (
          <div className="p-3 bg-red-950/40 border border-red-500/40 rounded-xl text-red-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
              Operator Username
            </label>
            <div className="relative">
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 pl-10 font-mono"
              />
              <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
              Passphrase Key
            </label>
            <div className="relative">
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 pl-10 font-mono"
              />
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-black text-xs uppercase tracking-wider flex items-center justify-center gap-2 shadow-lg transition disabled:opacity-50 mt-2"
          >
            {loading ? 'Authenticating...' : 'Authenticate & Enter SOC'}
          </button>
        </form>

        {/* Demo Fast-Login Selector */}
        <div className="pt-4 border-t border-slate-800 space-y-2">
          <div className="text-[10px] font-mono text-slate-400 uppercase text-center">
            Instant Demo Account Credentials:
          </div>
          <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
            <button
              onClick={() => handleQuickRole('analyst', 'AnalystPass123!')}
              className="p-1.5 rounded bg-slate-800/80 hover:bg-slate-800 text-cyan-400 border border-slate-700 text-center"
            >
              Analyst Role
            </button>
            <button
              onClick={() => handleQuickRole('admin', 'AdminPass123!')}
              className="p-1.5 rounded bg-slate-800/80 hover:bg-slate-800 text-purple-400 border border-slate-700 text-center"
            >
              Admin Role
            </button>
            <button
              onClick={() => handleQuickRole('investigator', 'InvestigatorPass123!')}
              className="p-1.5 rounded bg-slate-800/80 hover:bg-slate-800 text-amber-400 border border-slate-700 text-center"
            >
              Investigator
            </button>
            <button
              onClick={() => handleQuickRole('auditor', 'AuditorPass123!')}
              className="p-1.5 rounded bg-slate-800/80 hover:bg-slate-800 text-emerald-400 border border-slate-700 text-center"
            >
              Auditor
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
