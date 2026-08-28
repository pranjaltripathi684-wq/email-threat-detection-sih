import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { ShieldAlert, RefreshCw, Filter, Clock, User, Terminal } from 'lucide-react';

export const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<any[]>([]);
  const [actionFilter, setActionFilter] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await api.getAuditLogs(actionFilter || undefined);
      setLogs(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [actionFilter]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            IMMUTABLE SECURITY AUDIT TRAIL
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Chronological, non-repudiable log of all sensitive analyst actions, evidence acquisitions, and configuration changes
          </p>
        </div>

        <button
          onClick={fetchLogs}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Audit Stream</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="cyber-card p-4 flex flex-wrap items-center gap-3">
        <Filter className="w-4 h-4 text-slate-400" />
        <span className="text-xs text-slate-300 font-mono">Filter by Action:</span>
        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
        >
          <option value="">All Actions</option>
          <option value="EMAIL_UPLOAD_AND_ANALYSIS">EMAIL_UPLOAD_AND_ANALYSIS</option>
          <option value="LOAD_DEMO_SCENARIO">LOAD_DEMO_SCENARIO</option>
          <option value="EXPORT_FORENSIC_REPORT">EXPORT_FORENSIC_REPORT</option>
          <option value="EVIDENCE_INTEGRITY_VERIFICATION">EVIDENCE_INTEGRITY_VERIFICATION</option>
          <option value="CREATE_CASE">CREATE_CASE</option>
          <option value="USER_LOGIN_SUCCESS">USER_LOGIN_SUCCESS</option>
        </select>
      </div>

      {/* Logs Table */}
      <div className="cyber-card p-6 space-y-4">
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="p-3">Timestamp (UTC)</th>
                <th className="p-3">Action Event</th>
                <th className="p-3">User</th>
                <th className="p-3">Resource Target</th>
                <th className="p-3">Client IP</th>
                <th className="p-3">Event Telemetry Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {logs.length > 0 ? (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/20">
                    <td className="p-3 text-slate-400 whitespace-nowrap">
                      {log.timestamp_utc?.slice(0, 19)}
                    </td>
                    <td className="p-3 font-bold text-cyan-300">
                      {log.action}
                    </td>
                    <td className="p-3 text-slate-200">
                      {log.username}
                    </td>
                    <td className="p-3 text-slate-400">
                      {log.resource_type ? `${log.resource_type} #${log.resource_id || ''}` : '-'}
                    </td>
                    <td className="p-3 text-slate-500">
                      {log.client_ip || '127.0.0.1'}
                    </td>
                    <td className="p-3 text-slate-300 max-w-[280px] truncate text-[11px]">
                      {log.details || '-'}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 italic font-sans">
                    No audit records match the current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
