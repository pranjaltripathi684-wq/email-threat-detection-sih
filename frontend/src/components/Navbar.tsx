import React from 'react';
import { Shield, Eye, EyeOff, User, LogOut, Activity, Database } from 'lucide-react';

interface Props {
  maskPII: boolean;
  setMaskPII: (val: boolean) => void;
  currentUser: { username: string; role: string };
  onLogout: () => void;
  onOpenScenarios: () => void;
}

export const Navbar: React.FC<Props> = ({ maskPII, setMaskPII, currentUser, onLogout, onOpenScenarios }) => {
  return (
    <header className="h-16 border-b border-slate-800/80 bg-[#0a0f1d]/95 backdrop-blur-md sticky top-0 z-50 flex items-center justify-between px-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.3)]">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-extrabold text-base tracking-wide text-white">
              AEGIS <span className="text-cyan-400 font-mono text-xs font-normal">EMAIL FORENSICS</span>
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              ACADEMIC PROTOTYPE
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            Threat Detection, Geolocation & Forensic Intelligence
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Quick Scenario Loader Button */}
        <button
          onClick={onOpenScenarios}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500/20 to-blue-500/20 border border-cyan-500/40 text-cyan-300 text-xs font-medium hover:from-cyan-500/30 hover:to-blue-500/30 transition shadow-sm"
        >
          <Database className="w-3.5 h-3.5" />
          <span>Load Test Scenarios (A–E)</span>
        </button>

        {/* PII Masking Switch */}
        <button
          onClick={() => setMaskPII(!maskPII)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition border ${
            maskPII
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              : 'bg-slate-800/60 text-slate-400 border-slate-700 hover:text-slate-200'
          }`}
          title="Privacy Mode: Masks target email addresses & sensitive recipient PII"
        >
          {maskPII ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          <span>Privacy Masking: {maskPII ? 'ON' : 'OFF'}</span>
        </button>

        {/* User Profile & Role */}
        <div className="flex items-center gap-2 pl-3 border-l border-slate-800">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400">
            <User className="w-4 h-4" />
          </div>
          <div className="text-left hidden sm:block">
            <div className="text-xs font-semibold text-slate-200">{currentUser.username}</div>
            <div className="text-[10px] text-cyan-400 font-mono uppercase">{currentUser.role}</div>
          </div>
          <button
            onClick={onLogout}
            className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition ml-1"
            title="Logout"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
