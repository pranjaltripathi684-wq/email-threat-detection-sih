import React from 'react';
import { EmailDetail } from '../types';
import { RiskBadge } from '../components/RiskBadge';
import { ExplainabilityPanel } from '../components/ExplainabilityPanel';
import {
  ShieldAlert, Route, Globe, FileSpreadsheet, Lock, AlertTriangle,
  FolderPlus, FileText, CheckCircle2, User, Activity, Bot
} from 'lucide-react';

interface Props {
  email: EmailDetail | null;
  onNavigateTab: (tab: any) => void;
  maskEmail: (val?: string) => string;
}

export const AnalysisResultPage: React.FC<Props> = ({ email, onNavigateTab, maskEmail }) => {
  if (!email) {
    return (
      <div className="cyber-card p-12 text-center text-slate-400 space-y-3">
        <ShieldAlert className="w-10 h-10 text-slate-600 mx-auto" />
        <div className="text-sm font-semibold text-slate-300">No Email Selected for Analysis</div>
        <p className="text-xs text-slate-500">
          Upload an email file, paste raw headers, or select a scenario to view results.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="cyber-card-glow p-6">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="space-y-2 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <RiskBadge classification={email.risk_classification} score={email.total_risk_score} />
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                Confidence: {((email.confidence_score || 0.85) * 100).toFixed(0)}%
              </span>
              <span className="text-xs text-slate-500 font-mono">ID: #{email.id}</span>
            </div>

            <h2 className="text-lg font-black text-slate-100 leading-snug">
              {email.raw_subject || '(No Subject Line)'}
            </h2>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-400 font-mono pt-1">
              <div>
                <span className="text-slate-500">From: </span>
                <span className="text-slate-200">{maskEmail(email.raw_from)}</span>
              </div>
              <div>
                <span className="text-slate-500">Earliest Public Relay: </span>
                <span className="text-cyan-300 font-bold">
                  {email.earliest_public_ip || 'None identified'}
                </span>
                {email.earliest_public_ip_country && (
                  <span className="text-slate-400"> ({email.earliest_public_ip_country})</span>
                )}
              </div>
              <div>
                <span className="text-slate-500">SHA-256: </span>
                <span className="text-slate-300">{email.sha256_hash.slice(0, 16)}...</span>
              </div>
              <div>
                <span className="text-slate-500">MIME / Size: </span>
                <span className="text-slate-300">RFC 822 ({(email.file_size / 1024).toFixed(1)} KB)</span>
              </div>
            </div>
          </div>

          {/* Master Risk Score Visual */}
          <div className="flex flex-col items-center justify-center p-4 bg-slate-950/60 rounded-2xl border border-slate-800 shrink-0 w-full lg:w-48 text-center">
            <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">
              Total Risk Score
            </div>
            <div
              className={`text-4xl font-black font-mono tracking-tight ${
                email.total_risk_score >= 75
                  ? 'text-red-400 drop-shadow-[0_0_12px_rgba(239,68,68,0.4)]'
                  : email.total_risk_score >= 50
                  ? 'text-orange-400 drop-shadow-[0_0_12px_rgba(249,115,22,0.4)]'
                  : email.total_risk_score >= 25
                  ? 'text-yellow-400'
                  : 'text-emerald-400 drop-shadow-[0_0_12px_rgba(16,185,129,0.4)]'
              }`}
            >
              {email.total_risk_score.toFixed(1)}
              <span className="text-xs text-slate-500 font-normal"> / 100</span>
            </div>
            <div className="text-[10px] text-slate-400 mt-1 uppercase font-semibold">
              {email.risk_classification}
            </div>
          </div>
        </div>

        {/* Quick Navigation Action Chips */}
        <div className="flex flex-wrap items-center gap-2 mt-5 pt-4 border-t border-slate-800/80">
          <button
            onClick={() => onNavigateTab('relay')}
            className="px-3 py-1.5 rounded-lg bg-slate-800/60 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 text-xs font-semibold border border-slate-700/80 flex items-center gap-1.5 transition"
          >
            <Route className="w-3.5 h-3.5 text-cyan-400" />
            <span>Relay Hops ({email.hops.length})</span>
          </button>

          <button
            onClick={() => onNavigateTab('auth')}
            className="px-3 py-1.5 rounded-lg bg-slate-800/60 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 text-xs font-semibold border border-slate-700/80 flex items-center gap-1.5 transition"
          >
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Auth Matrix (SPF/DKIM/DMARC)</span>
          </button>

          <button
            onClick={() => onNavigateTab('urls_attachments')}
            className="px-3 py-1.5 rounded-lg bg-slate-800/60 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 text-xs font-semibold border border-slate-700/80 flex items-center gap-1.5 transition"
          >
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>IoCs ({email.urls.length} URLs / {email.attachments.length} Files)</span>
          </button>

          <button
            onClick={() => onNavigateTab('geomap')}
            className="px-3 py-1.5 rounded-lg bg-slate-800/60 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 text-xs font-semibold border border-slate-700/80 flex items-center gap-1.5 transition"
          >
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            <span>Geolocation Map</span>
          </button>

          <button
            onClick={() => onNavigateTab('report')}
            className="px-3 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 text-xs font-semibold border border-cyan-500/40 flex items-center gap-1.5 transition ml-auto"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-cyan-400" />
            <span>Forensic Report</span>
          </button>
        </div>
      </div>

      {/* Main Explainability Breakdown */}
      <ExplainabilityPanel email={email} />
    </div>
  );
};
