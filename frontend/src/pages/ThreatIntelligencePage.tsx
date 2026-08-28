import React, { useState } from 'react';
import { api } from '../services/api';
import { Radar, Search, ShieldAlert, Globe, Server, Database, Info } from 'lucide-react';

export const ThreatIntelligencePage: React.FC = () => {
  const [indType, setIndType] = useState('ip');
  const [indValue, setIndValue] = useState('198.51.100.42');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleLookup = async () => {
    if (!indValue) return;
    setLoading(true);
    try {
      const data = await api.lookupIndicator(indType, indValue.trim());
      setResult(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
          <Radar className="w-5 h-5 text-cyan-400" />
          THREAT INTELLIGENCE & REPUTATION CORRELATION
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Query indicator reputation, ASN infrastructure metadata, DNS records, and AbuseIPDB/VirusTotal/URLhaus mock & live feeds
        </p>
      </div>

      {/* Query Bar */}
      <div className="cyber-card p-6 space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <select
            value={indType}
            onChange={(e) => setIndType(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="ip">Public IP Address</option>
            <option value="domain">Sender Domain</option>
            <option value="url">URL Destination</option>
            <option value="hash">File SHA-256 Hash</option>
          </select>

          <input
            type="text"
            value={indValue}
            onChange={(e) => setIndValue(e.target.value)}
            placeholder="Enter IP (e.g. 198.51.100.42), domain (paypa1-update.com), or hash..."
            className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          />

          <button
            onClick={handleLookup}
            disabled={loading}
            className="px-6 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-1.5 transition disabled:opacity-50"
          >
            <Search className="w-4 h-4" />
            <span>{loading ? 'Querying Feeds...' : 'Lookup Indicator'}</span>
          </button>
        </div>

        <div className="flex flex-wrap gap-2 pt-1 text-[11px] text-slate-400 font-mono">
          <span>Sample Test Indicators:</span>
          <button
            onClick={() => { setIndType('ip'); setIndValue('198.51.100.42'); }}
            className="text-cyan-400 hover:underline"
          >
            198.51.100.42 (AbuseIPDB Hit)
          </button>
          <span>•</span>
          <button
            onClick={() => { setIndType('ip'); setIndValue('185.220.101.5'); }}
            className="text-cyan-400 hover:underline"
          >
            185.220.101.5 (Tor Exit Node)
          </button>
          <span>•</span>
          <button
            onClick={() => { setIndType('domain'); setIndValue('paypa1-update.com'); }}
            className="text-cyan-400 hover:underline"
          >
            paypa1-update.com (URLhaus Phishing)
          </button>
        </div>
      </div>

      {/* Result Cards */}
      {result && (
        <div className="space-y-4">
          <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-amber-300 flex items-center gap-2">
            <Info className="w-4 h-4 shrink-0 text-amber-400" />
            <span>{result.disclaimer}</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Enrichment Details */}
            <div className="cyber-card p-5 space-y-3">
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                Infrastructure & Telemetry
              </h3>

              {result.enrichment ? (
                <div className="space-y-2 text-xs font-mono bg-slate-900/40 p-4 rounded-xl border border-slate-800">
                  {Object.entries(result.enrichment).map(([k, v]) => (
                    <div key={k} className="flex justify-between border-b border-slate-800/40 pb-1">
                      <span className="text-slate-500 capitalize">{k.replace('_', ' ')}:</span>
                      <span className="text-slate-200">{Array.isArray(v) ? v.join(', ') : String(v)}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-slate-500 text-xs italic">No enrichment data returned.</div>
              )}
            </div>

            {/* Threat Feed Matches */}
            <div className="cyber-card p-5 space-y-3">
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-400" />
                Threat Feed Matches ({result.threat_matches?.length || 0})
              </h3>

              {result.threat_matches && result.threat_matches.length > 0 ? (
                <div className="space-y-2">
                  {result.threat_matches.map((m: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-3 bg-red-950/20 border border-red-500/30 rounded-lg text-xs space-y-1"
                    >
                      <div className="flex justify-between font-bold text-red-300">
                        <span>Provider: {m.provider}</span>
                        <span className="text-[10px] uppercase">{m.severity} Severity</span>
                      </div>
                      <div className="text-slate-300 text-[11px] font-mono">
                        Confidence: {(m.confidence * 100).toFixed(0)}%
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-6 text-center text-slate-500 text-xs italic bg-slate-900/30 rounded-xl border border-slate-800">
                  No active threat feed alerts matching this indicator.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
