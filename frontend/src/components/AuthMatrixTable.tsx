import React from 'react';
import { AuthResult } from '../types';
import { CheckCircle2, XCircle, AlertTriangle, ShieldAlert } from 'lucide-react';

interface Props {
  auth?: AuthResult;
}

export const AuthMatrixTable: React.FC<Props> = ({ auth }) => {
  if (!auth) {
    return (
      <div className="p-6 text-center text-slate-400 bg-slate-900/30 rounded-xl border border-slate-800">
        No authentication header analysis available.
      </div>
    );
  }

  const renderStatusBadge = (status: string) => {
    const s = status?.toLowerCase() || 'none';
    if (s === 'pass') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
          <CheckCircle2 className="w-3.5 h-3.5" /> PASS
        </span>
      );
    }
    if (s === 'fail' || s === 'permerror') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
          <XCircle className="w-3.5 h-3.5" /> {status.toUpperCase()}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-yellow-500/10 text-yellow-400 border border-yellow-500/30">
        <AlertTriangle className="w-3.5 h-3.5" /> {status.toUpperCase()}
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {/* Lookalike Warning Banner */}
      {auth.is_lookalike_domain_auth && (
        <div className="p-4 bg-red-950/40 border border-red-500/40 rounded-xl text-red-200 text-xs flex items-start gap-3 shadow-[0_0_15px_rgba(239,68,68,0.15)]">
          <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-bold text-red-300 text-sm mb-1">AUTHENTIC LOOKALIKE TRAP DETECTED</div>
            This email successfully passed SPF/DKIM authentication because the sender registered their own deceptive domain records. Passing authentication on a lookalike domain does NOT guarantee legitimacy.
          </div>
        </div>
      )}

      {!auth.from_reply_to_aligned && (
        <div className="p-3 bg-yellow-950/40 border border-yellow-500/40 rounded-xl text-yellow-200 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />
          <span>Reply-To domain differs from visible From sender domain (potential redirect/fraud vector).</span>
        </div>
      )}

      {/* Protocol Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 uppercase font-mono text-[11px]">
            <tr>
              <th className="p-3">Protocol</th>
              <th className="p-3">Result</th>
              <th className="p-3">Domain / Selector</th>
              <th className="p-3">Alignment Status</th>
              <th className="p-3">Technical Detail</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            <tr>
              <td className="p-3 font-semibold text-slate-200">SPF</td>
              <td className="p-3">{renderStatusBadge(auth.spf_result)}</td>
              <td className="p-3 text-cyan-300">{auth.spf_domain || 'None declared'}</td>
              <td className="p-3">{auth.spf_result === 'pass' ? 'Aligned with Envelope' : 'Unaligned'}</td>
              <td className="p-3 text-slate-400">Sender Policy Framework validation</td>
            </tr>
            <tr>
              <td className="p-3 font-semibold text-slate-200">DKIM</td>
              <td className="p-3">{renderStatusBadge(auth.dkim_result)}</td>
              <td className="p-3 text-cyan-300">
                {auth.dkim_domain ? `${auth.dkim_domain} (s=${auth.dkim_selector || 'default'})` : 'No signature'}
              </td>
              <td className="p-3">{auth.dkim_result === 'pass' ? 'Cryptographically Valid' : 'No Valid Signature'}</td>
              <td className="p-3 text-slate-400">DomainKeys Identified Mail cryptographic signature</td>
            </tr>
            <tr>
              <td className="p-3 font-semibold text-slate-200">DMARC</td>
              <td className="p-3">{renderStatusBadge(auth.dmarc_result)}</td>
              <td className="p-3 text-cyan-300">Policy: {auth.dmarc_policy || 'none'}</td>
              <td className="p-3 capitalize">{auth.dmarc_alignment}</td>
              <td className="p-3 text-slate-400">Domain-based Message Authentication & Reporting</td>
            </tr>
            <tr>
              <td className="p-3 font-semibold text-slate-200">ARC</td>
              <td className="p-3">{renderStatusBadge(auth.arc_result)}</td>
              <td className="p-3 text-slate-400">Chain: {auth.arc_present ? 'Present' : 'None'}</td>
              <td className="p-3">-</td>
              <td className="p-3 text-slate-400">Authenticated Received Chain intermediaries</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Natural Language Explanation */}
      {auth.natural_language_explanation && (
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-slate-300">
          <div className="font-semibold text-cyan-400 mb-1 font-mono uppercase text-[11px]">
            Forensic Authentication Assessment
          </div>
          {auth.natural_language_explanation}
        </div>
      )}
    </div>
  );
};
