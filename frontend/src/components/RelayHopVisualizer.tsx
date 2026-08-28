import React from 'react';
import { Hop } from '../types';
import { Server, Shield, AlertTriangle, ArrowDown, Clock, Lock, Globe } from 'lucide-react';

interface Props {
  hops: Hop[];
  earliestPublicIp?: string;
}

export const RelayHopVisualizer: React.FC<Props> = ({ hops, earliestPublicIp }) => {
  if (!hops || hops.length === 0) {
    return (
      <div className="p-8 text-center text-slate-400 bg-slate-900/30 rounded-xl border border-slate-800">
        No transmission relay hops extracted from email headers.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between p-3 bg-slate-900/60 rounded-lg border border-slate-800 text-xs">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          <span>Earliest Reliable Public IP:</span>
          <span className="font-mono text-cyan-300 font-bold bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/60">
            {earliestPublicIp || 'None identified (Internal/Private transmission only)'}
          </span>
        </div>
        <div className="text-slate-400">
          Total Hops: <span className="text-slate-200 font-mono font-bold">{hops.length}</span>
        </div>
      </div>

      <div className="relative pl-6 space-y-6 before:absolute before:left-3 before:top-4 before:bottom-4 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-blue-500 before:to-indigo-500">
        {hops.map((hop, index) => {
          const isEarliest = hop.is_earliest_reliable_public_ip || hop.extracted_ip === earliestPublicIp;
          const hasAnomalies = !!hop.anomaly_flags;

          return (
            <div key={hop.id || index} className="relative">
              {/* Hop Marker Node */}
              <div
                className={`absolute -left-[1.65rem] top-1.5 w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-mono font-bold border ${
                  isEarliest
                    ? 'bg-cyan-500 text-slate-950 border-cyan-300 ring-4 ring-cyan-500/20 animate-pulse'
                    : hasAnomalies
                    ? 'bg-red-500 text-white border-red-300 ring-2 ring-red-500/20'
                    : 'bg-slate-800 text-slate-300 border-slate-600'
                }`}
              >
                {hop.hop_order}
              </div>

              {/* Hop Card */}
              <div
                className={`p-4 rounded-xl border transition ${
                  isEarliest
                    ? 'bg-cyan-950/20 border-cyan-500/40 shadow-[0_0_15px_rgba(6,182,212,0.1)]'
                    : 'bg-slate-900/40 border-slate-800/80 hover:border-slate-700'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-slate-200">
                      HOP #{hop.hop_order}
                    </span>
                    {isEarliest && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500 text-slate-950 uppercase tracking-wider">
                        ★ Earliest Reliable Public IP
                      </span>
                    )}
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                        hop.ip_classification === 'Public'
                          ? 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                          : hop.ip_classification === 'Private'
                          ? 'bg-slate-700/30 text-slate-400 border-slate-600/30'
                          : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                      }`}
                    >
                      {hop.ip_classification} IP
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      Delta: {hop.time_delta_seconds !== undefined ? `${hop.time_delta_seconds.toFixed(1)}s` : '0s'}
                    </span>
                    <span
                      className={`flex items-center gap-1 ${
                        hop.tls_status ? 'text-emerald-400' : 'text-slate-500'
                      }`}
                    >
                      <Lock className="w-3.5 h-3.5" />
                      {hop.tls_status ? 'TLS Encrypted' : 'Plaintext SMTP'}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div>
                    <div className="text-[11px] text-slate-400">Sending Host (from):</div>
                    <div className="font-mono text-slate-300 break-all">{hop.sending_server || 'Not specified'}</div>
                  </div>
                  <div>
                    <div className="text-[11px] text-slate-400">Receiving Host (by):</div>
                    <div className="font-mono text-slate-300 break-all">{hop.receiving_server || 'Not specified'}</div>
                  </div>
                  <div>
                    <div className="text-[11px] text-slate-400">Extracted Relay IP:</div>
                    <div className="font-mono text-cyan-300 font-semibold">{hop.extracted_ip || 'None'}</div>
                  </div>
                  <div>
                    <div className="text-[11px] text-slate-400">Geo Infrastructure:</div>
                    <div className="text-slate-300">
                      {hop.geo_city && hop.geo_country ? `${hop.geo_city}, ${hop.geo_country}` : 'Local / Unresolved'}
                      {hop.asn_org && <span className="text-slate-400 text-[11px]"> ({hop.asn_org})</span>}
                    </div>
                  </div>
                </div>

                {hasAnomalies && (
                  <div className="mt-3 p-2 bg-red-500/10 border border-red-500/30 rounded text-red-300 text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
                    <span>{hop.anomaly_flags}</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
