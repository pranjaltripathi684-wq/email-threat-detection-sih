import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { FileCheck2, ShieldCheck, AlertOctagon, RefreshCw, Key, Lock } from 'lucide-react';

interface Props {
  selectedEmailId: number | null;
}

export const EvidenceCustodyPage: React.FC<Props> = ({ selectedEmailId }) => {
  const [evidence, setEvidence] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<any>(null);

  const fetchEvidence = async () => {
    if (!selectedEmailId) return;
    setLoading(true);
    try {
      const data = await api.getEvidenceByEmail(selectedEmailId);
      setEvidence(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    if (!evidence) return;
    setVerifying(true);
    try {
      const res = await api.verifyEvidence(evidence.id);
      setVerifyResult(res);
      fetchEvidence(); // refresh custody timeline
    } catch (e) {
      console.error(e);
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    fetchEvidence();
  }, [selectedEmailId]);

  if (!selectedEmailId) {
    return (
      <div className="cyber-card p-10 text-center text-slate-500 italic">
        Please select an email to view its cryptographic evidence item and chain of custody log.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-cyan-400" />
            FORENSIC EVIDENCE PRESERVATION & CHAIN OF CUSTODY
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Cryptographic SHA-256 integrity validation, legal hold controls, and immutable access logging
          </p>
        </div>

        <button
          onClick={handleVerify}
          disabled={verifying || !evidence}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-md transition disabled:opacity-50"
        >
          <ShieldCheck className="w-4 h-4" />
          <span>{verifying ? 'Auditing Hash...' : 'Verify Cryptographic Integrity'}</span>
        </button>
      </div>

      {verifyResult && (
        <div
          className={`p-4 rounded-xl border flex items-center gap-3 text-xs font-mono ${
            verifyResult.integrity_verified
              ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
              : 'bg-red-950/40 border-red-500/40 text-red-300'
          }`}
        >
          {verifyResult.integrity_verified ? (
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
          ) : (
            <AlertOctagon className="w-5 h-5 text-red-400 shrink-0" />
          )}
          <div>
            <div className="font-bold font-sans text-sm">
              {verifyResult.integrity_verified
                ? 'INTEGRITY AUDIT PASSED: HASHES MATCH IDENTICALLY'
                : 'TAMPER ALERT: CALCULATED HASH DIFFERS FROM EVIDENCE RECORD'}
            </div>
            <div className="text-[11px] mt-0.5 opacity-80">
              Computed SHA-256: {verifyResult.calculated_sha256}
            </div>
          </div>
        </div>
      )}

      {/* Evidence Attributes */}
      {evidence && (
        <div className="cyber-card p-6 space-y-4">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
            <Key className="w-4 h-4 text-cyan-400" />
            Evidence Master Record
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono bg-slate-900/60 p-4 rounded-xl border border-slate-800">
            <div>
              <span className="text-slate-500">Evidence UUID: </span>
              <span className="text-slate-200">{evidence.evidence_uuid}</span>
            </div>
            <div>
              <span className="text-slate-500">Cryptographic Hash (SHA-256): </span>
              <span className="text-cyan-300 font-bold break-all">{evidence.original_sha256}</span>
            </div>
            <div>
              <span className="text-slate-500">Acquisition Timestamp: </span>
              <span className="text-slate-300">{evidence.collected_at?.slice(0, 19)} UTC</span>
            </div>
            <div>
              <span className="text-slate-500">Storage Immutability Status: </span>
              <span className="text-emerald-400 font-bold font-sans">
                {evidence.is_immutable ? 'LOCKED / READ-ONLY' : 'Standard'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Custody Timeline Table */}
      <div className="cyber-card p-6 space-y-4">
        <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
          <Lock className="w-4 h-4 text-cyan-400" />
          Chronological Chain of Custody Audit Log
        </h3>

        {evidence?.custody_events && evidence.custody_events.length > 0 ? (
          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <tr>
                  <th className="p-3">Timestamp (UTC)</th>
                  <th className="p-3">Custody Action</th>
                  <th className="p-3">Actor & Role</th>
                  <th className="p-3">Reason / Scope</th>
                  <th className="p-3 text-right">Hash Verification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 font-mono">
                {evidence.custody_events.map((evt: any) => (
                  <tr key={evt.id} className="hover:bg-slate-800/20">
                    <td className="p-3 text-slate-400">{evt.timestamp_utc?.slice(0, 19)}</td>
                    <td className="p-3 font-semibold text-slate-200 font-sans">{evt.action}</td>
                    <td className="p-3 text-cyan-300">
                      {evt.performed_by_username} <span className="text-slate-500">({evt.performed_by_role})</span>
                    </td>
                    <td className="p-3 text-slate-300 font-sans">{evt.reason || '-'}</td>
                    <td className="p-3 text-right">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        {evt.verification_status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-6 text-center text-slate-500 text-xs italic">
            No chain of custody events recorded yet.
          </div>
        )}
      </div>
    </div>
  );
};
