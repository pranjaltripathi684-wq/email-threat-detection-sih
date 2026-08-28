import React from 'react';
import { EmailDetail } from '../types';
import { ShieldCheck, AlertOctagon, HelpCircle, CheckCircle2, ShieldAlert } from 'lucide-react';

interface Props {
  email: EmailDetail;
}

export const ExplainabilityPanel: React.FC<Props> = ({ email }) => {
  const breakdown = email.score_breakdown || {};
  const categories = [
    { key: 'headers', label: 'Header Anomalies', max: 20 },
    { key: 'authentication', label: 'Authentication & Alignment', max: 20 },
    { key: 'sender_domain', label: 'Sender & Domain Impersonation', max: 15 },
    { key: 'content_nlp', label: 'Content & Social Engineering', max: 15 },
    { key: 'urls', label: 'URL Threat Signals', max: 15 },
    { key: 'attachments', label: 'Attachment Static Risk', max: 10 },
    { key: 'threat_intel', label: 'Threat Intel & Reputation', max: 5 },
  ];

  return (
    <div className="space-y-6">
      {/* 7-Tier Risk Contribution Breakdown */}
      <div className="cyber-card p-5">
        <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono mb-4 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          7-Tier Explainable Risk Breakdown
        </h3>

        <div className="space-y-3">
          {categories.map((cat) => {
            const scoreItem = (breakdown as any)[cat.key] || { score: 0, max: cat.max };
            const pct = Math.min(100, (scoreItem.score / cat.max) * 100);

            return (
              <div key={cat.key} className="space-y-1 text-xs">
                <div className="flex justify-between text-slate-300">
                  <span>{cat.label}</span>
                  <span className="font-mono text-cyan-300">
                    {scoreItem.score.toFixed(1)} / {cat.max} pts
                  </span>
                </div>
                <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      pct > 60 ? 'bg-red-500' : pct > 30 ? 'bg-amber-500' : pct > 0 ? 'bg-cyan-500' : 'bg-slate-700'
                    }`}
                    style={{ width: `${Math.max(2, pct)}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Positive Indicators & Mitigating Evidence */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Positive Evidence (Risk Factors) */}
        <div className="cyber-card p-4 border-red-500/20">
          <div className="flex items-center gap-2 text-red-400 font-semibold text-xs uppercase font-mono mb-3">
            <AlertOctagon className="w-4 h-4" />
            Positive Threat Indicators ({email.positive_evidence?.length || 0})
          </div>
          <ul className="space-y-2 text-xs text-slate-300">
            {email.positive_evidence && email.positive_evidence.length > 0 ? (
              email.positive_evidence.map((ev, i) => (
                <li key={i} className="flex items-start gap-2 bg-red-950/20 p-2 rounded border border-red-900/30">
                  <span className="text-red-400 font-bold">•</span>
                  <span>{ev}</span>
                </li>
              ))
            ) : (
              <li className="text-slate-500 italic">No positive risk indicators detected.</li>
            )}
          </ul>
        </div>

        {/* Mitigating Factors */}
        <div className="cyber-card p-4 border-emerald-500/20">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs uppercase font-mono mb-3">
            <CheckCircle2 className="w-4 h-4" />
            Mitigating Factors ({email.negative_evidence?.length || 0})
          </div>
          <ul className="space-y-2 text-xs text-slate-300">
            {email.negative_evidence && email.negative_evidence.length > 0 ? (
              email.negative_evidence.map((ev, i) => (
                <li key={i} className="flex items-start gap-2 bg-emerald-950/20 p-2 rounded border border-emerald-900/30">
                  <span className="text-emerald-400 font-bold">•</span>
                  <span>{ev}</span>
                </li>
              ))
            ) : (
              <li className="text-slate-500 italic">No mitigating factors identified.</li>
            )}
          </ul>
        </div>
      </div>

      {/* Actionable Recommendation */}
      {email.recommended_action && (
        <div className="cyber-card p-4 border-cyan-500/30 bg-cyan-950/20">
          <div className="text-cyan-400 font-semibold text-xs uppercase font-mono mb-1">
            Recommended SOC / IR Action
          </div>
          <div className="text-xs text-slate-200 leading-relaxed">
            {email.recommended_action}
          </div>
        </div>
      )}
    </div>
  );
};
