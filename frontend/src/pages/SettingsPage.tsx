import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Settings, Sliders, Shield, Lock, Info, Check } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [config, setConfig] = useState<any>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const data = await api.getSettings();
        setConfig(data);
      } catch (e) {
        console.error(e);
      }
    };
    fetchSettings();
  }, []);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
          <Settings className="w-5 h-5 text-cyan-400" />
          SYSTEM CONFIGURATION & RISK THRESHOLD POLICIES
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Configure explainable risk-scoring weights, classification boundaries, and privacy protection defaults
        </p>
      </div>

      {config && (
        <div className="space-y-6">
          {/* Scoring Weights */}
          <div className="cyber-card p-6 space-y-4">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Explainable Risk-Scoring Weight Allocation (Total: 100 pts)
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800">
                <div className="text-slate-400">Header Anomalies:</div>
                <div className="text-cyan-300 font-bold text-base mt-1">
                  {config.scoring_weights.headers} points
                </div>
              </div>
              <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800">
                <div className="text-slate-400">Authentication & Alignment:</div>
                <div className="text-cyan-300 font-bold text-base mt-1">
                  {config.scoring_weights.authentication} points
                </div>
              </div>
              <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800">
                <div className="text-slate-400">Sender & Domain Impersonation:</div>
                <div className="text-cyan-300 font-bold text-base mt-1">
                  {config.scoring_weights.sender_domain} points
                </div>
              </div>
              <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800">
                <div className="text-slate-400">Content & Social Engineering:</div>
                <div className="text-cyan-300 font-bold text-base mt-1">
                  {config.scoring_weights.content_nlp} points
                </div>
              </div>
              <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800">
                <div className="text-slate-400">URL Threat Signals:</div>
                <div className="text-cyan-300 font-bold text-base mt-1">
                  {config.scoring_weights.urls} points
                </div>
              </div>
              <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800">
                <div className="text-slate-400">Attachment Static Risk:</div>
                <div className="text-cyan-300 font-bold text-base mt-1">
                  {config.scoring_weights.attachments} points
                </div>
              </div>
              <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 sm:col-span-2">
                <div className="text-slate-400">Threat Intelligence & Reputation:</div>
                <div className="text-cyan-300 font-bold text-base mt-1">
                  {config.scoring_weights.threat_intel} points
                </div>
              </div>
            </div>
          </div>

          {/* Classification Thresholds */}
          <div className="cyber-card p-6 space-y-4">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Risk Classification Thresholds
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
              <div className="p-3 bg-yellow-950/20 border border-yellow-500/30 rounded-xl">
                <div className="text-yellow-400 font-bold">Suspicious Threshold</div>
                <div className="text-slate-200 text-sm mt-1">&ge; {config.thresholds.low} points</div>
              </div>
              <div className="p-3 bg-orange-950/20 border border-orange-500/30 rounded-xl">
                <div className="text-orange-400 font-bold">High Risk Threshold</div>
                <div className="text-slate-200 text-sm mt-1">&ge; {config.thresholds.suspicious} points</div>
              </div>
              <div className="p-3 bg-red-950/20 border border-red-500/30 rounded-xl">
                <div className="text-red-400 font-bold">Critical Threat Threshold</div>
                <div className="text-slate-200 text-sm mt-1">&ge; {config.thresholds.high} points</div>
              </div>
            </div>
          </div>

          {/* Legal Attribution Disclaimer */}
          <div className="cyber-card p-6 space-y-3">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-2">
              <Info className="w-4 h-4 text-amber-400" />
              Platform Attribution Policy & Disclaimer
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed font-sans bg-slate-900/60 p-4 rounded-xl border border-slate-800">
              {config.attribution_disclaimer}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
