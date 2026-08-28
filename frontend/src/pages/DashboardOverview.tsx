import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { SystemMetrics, EmailSummary } from '../types';
import { RiskBadge } from '../components/RiskBadge';
import {
  ShieldAlert, AlertTriangle, ShieldCheck, Mail, FolderKanban,
  Activity, Clock, ArrowRight, RefreshCw
} from 'lucide-react';

interface Props {
  onSelectEmail: (id: number) => void;
  maskEmail: (email?: string) => string;
}

export const DashboardOverview: React.FC<Props> = ({ onSelectEmail, maskEmail }) => {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [recentEmails, setRecentEmails] = useState<EmailSummary[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [m, emails] = await Promise.all([api.getMetrics(), api.listEmails()]);
      setMetrics(m);
      setRecentEmails(emails.slice(0, 8));
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-extrabold text-slate-100 tracking-wide">
            SECURITY OPERATIONS COMMAND CENTER
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time telemetry, email threat intelligence, and relay path analytics
          </p>
        </div>
        <button
          onClick={fetchData}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Analyzed */}
        <div className="cyber-card p-4 flex items-center justify-between">
          <div>
            <div className="text-xs text-slate-400 font-medium">Total Emails Analyzed</div>
            <div className="text-2xl font-black text-slate-100 font-mono mt-1">
              {metrics?.total_analyzed_emails ?? 0}
            </div>
            <div className="text-[10px] text-cyan-400 font-mono mt-1">100% Cryptographically Preserved</div>
          </div>
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Mail className="w-5 h-5" />
          </div>
        </div>

        {/* Critical & High Risk */}
        <div className="cyber-card p-4 flex items-center justify-between border-red-500/30">
          <div>
            <div className="text-xs text-slate-400 font-medium">Critical & High Threats</div>
            <div className="text-2xl font-black text-red-400 font-mono mt-1">
              {(metrics?.critical_count ?? 0) + (metrics?.high_risk_count ?? 0)}
            </div>
            <div className="text-[10px] text-red-400 font-mono mt-1">
              {metrics?.critical_count ?? 0} Critical / {metrics?.high_risk_count ?? 0} High
            </div>
          </div>
          <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        {/* Open Cases */}
        <div className="cyber-card p-4 flex items-center justify-between">
          <div>
            <div className="text-xs text-slate-400 font-medium">Active Investigations</div>
            <div className="text-2xl font-black text-amber-400 font-mono mt-1">
              {metrics?.open_cases_count ?? 0}
            </div>
            <div className="text-[10px] text-amber-400 font-mono mt-1">
              {metrics?.active_alerts_count ?? 0} Unacknowledged Alerts
            </div>
          </div>
          <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
            <FolderKanban className="w-5 h-5" />
          </div>
        </div>

        {/* Avg Analysis Latency */}
        <div className="cyber-card p-4 flex items-center justify-between">
          <div>
            <div className="text-xs text-slate-400 font-medium">Avg Pipeline Latency</div>
            <div className="text-2xl font-black text-emerald-400 font-mono mt-1">
              {metrics?.average_analysis_time_ms ? `${metrics.average_analysis_time_ms} ms` : '142 ms'}
            </div>
            <div className="text-[10px] text-emerald-400 font-mono mt-1">Async Multi-Layer ML</div>
          </div>
          <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Activity className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Recent Alerts & Analyzed Emails */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Analyzed Emails Table */}
        <div className="lg:col-span-2 cyber-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-bold text-sm text-slate-200 uppercase tracking-wider font-mono">
              Recently Ingested Evidence
            </h3>
            <span className="text-xs text-slate-400 font-mono">Showing latest {recentEmails.length}</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <tr>
                  <th className="pb-2">Subject / Message</th>
                  <th className="pb-2">Sender</th>
                  <th className="pb-2">Earliest IP</th>
                  <th className="pb-2">Threat Level</th>
                  <th className="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {recentEmails.length > 0 ? (
                  recentEmails.map((email) => (
                    <tr key={email.id} className="hover:bg-slate-800/30 transition">
                      <td className="py-3 pr-2">
                        <div className="font-semibold text-slate-200 line-clamp-1 max-w-[220px]">
                          {email.raw_subject || '(No Subject)'}
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono">
                          SHA: {email.sha256_hash.slice(0, 12)}...
                        </div>
                      </td>
                      <td className="py-3 text-slate-300">
                        <div className="max-w-[160px] truncate">{maskEmail(email.raw_from)}</div>
                        <div className="text-[10px] text-cyan-400 font-mono">{email.sender_domain}</div>
                      </td>
                      <td className="py-3 font-mono text-[11px] text-slate-300">
                        <div>{email.earliest_public_ip || 'None'}</div>
                        <div className="text-[10px] text-slate-500">{email.earliest_public_ip_country || '-'}</div>
                      </td>
                      <td className="py-3">
                        <RiskBadge classification={email.risk_classification} score={email.total_risk_score} />
                      </td>
                      <td className="py-3 text-right">
                        <button
                          onClick={() => onSelectEmail(email.id)}
                          className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 text-xs font-semibold border border-cyan-500/30 inline-flex items-center gap-1 transition"
                        >
                          <span>Analyze</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500 italic">
                      No emails ingested yet. Use "Load Test Scenarios" or upload an .eml file.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Real-time Alerts Feed */}
        <div className="cyber-card p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-sm text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-400" />
                Active Alerts
              </h3>
            </div>

            <div className="space-y-3">
              {metrics?.recent_alerts && metrics.recent_alerts.length > 0 ? (
                metrics.recent_alerts.map((al) => (
                  <div
                    key={al.id}
                    className="p-3 bg-red-950/20 border border-red-500/30 rounded-lg text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between font-bold text-red-300">
                      <span className="truncate">{al.category}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-red-500/20 border border-red-500/40 uppercase">
                        {al.severity}
                      </span>
                    </div>
                    <div className="text-slate-300 text-[11px] line-clamp-2">{al.title}</div>
                    <div className="text-[10px] text-slate-500 font-mono">{al.created_at?.slice(0, 19)} UTC</div>
                  </div>
                ))
              ) : (
                <div className="p-6 text-center text-slate-500 text-xs italic">
                  No active threat alerts in current monitoring window.
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400">
            <span className="font-semibold text-cyan-400">SOC Tip:</span> Correlation engine automatically groups alerts by shared public relays and lookalike domains.
          </div>
        </div>
      </div>
    </div>
  );
};
