import React from 'react';
import { X, Play, ShieldAlert, UserCheck, AlertTriangle, FileCode, CheckCircle2 } from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onSelectScenario: (id: string) => void;
  isLoading: boolean;
}

export const ScenarioPickerModal: React.FC<Props> = ({ isOpen, onClose, onSelectScenario, isLoading }) => {
  if (!isOpen) return null;

  const scenarios = [
    {
      id: 'A',
      title: 'Scenario A: Lookalike-Domain Phishing',
      icon: ShieldAlert,
      badge: 'High Threat',
      badgeColor: 'text-red-400 border-red-500/30 bg-red-500/10',
      description:
        'Sender spoofed as PayPal Security using typosquatted domain "paypa1-update.com" with a deceptive URL destination.',
      highlights: ['Homoglyph Typosquatting', 'Deceptive URL Anchor', 'Authentic Phishing Trap', 'Urgent Credential Request'],
    },
    {
      id: 'B',
      title: 'Scenario B: Executive Impersonation (CEO Fraud)',
      icon: UserCheck,
      badge: 'High Threat',
      badgeColor: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
      description:
        'Display name matches CEO Dr. Arthur Vance, but sent from public freemail (@gmail.com) requesting $2,500 Apple gift cards.',
      highlights: ['Freemail VIP Spoofing', 'Gift Card Purchase Request', 'Confidentiality Pressure', 'No Attachments'],
    },
    {
      id: 'C',
      title: 'Scenario C: Business Email Compromise (BEC)',
      icon: AlertTriangle,
      badge: 'High Threat',
      badgeColor: 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10',
      description:
        'Sent from compromised legitimate vendor partner with valid SPF/DKIM, requesting banking and wire remittance changes.',
      highlights: ['Valid SPF/DKIM Alignment', 'Wire Transfer Redirection', 'Social Engineering Vector', 'Compromised Domain'],
    },
    {
      id: 'D',
      title: 'Scenario D: Malicious Double-Extension Attachment',
      icon: FileCode,
      badge: 'Critical Threat',
      badgeColor: 'text-red-400 border-red-500/30 bg-red-500/10',
      description:
        'Purported court subpoena carrying executable payload with double extension "Subpoena_Notice_Q3.pdf.exe" and PE header.',
      highlights: ['Double Extension (.pdf.exe)', 'MZ PE Header Payload', 'Failed SPF/DMARC', 'Bogon Relay Infrastructure'],
    },
    {
      id: 'E',
      title: 'Scenario E: Legitimate Corporate Communication',
      icon: CheckCircle2,
      badge: 'Benign / Clean',
      badgeColor: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
      description:
        'Internal engineering architecture sprint agenda with full SPF/DKIM/DMARC alignment, matching Reply-To, and clean URLs.',
      highlights: ['Full DMARC Alignment', 'Matching Reply-To', 'Encrypted TLS Hops', 'Zero Threat Indicators'],
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0e1628] border border-slate-700 rounded-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto shadow-2xl p-6 relative">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <span className="text-cyan-400 font-mono">DEMO SCENARIOS:</span> Select Test Case
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Instantly ingest and analyze academic synthetic threat scenarios (A through E).
            </p>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="mt-4 space-y-3">
          {scenarios.map((sc) => {
            const Icon = sc.icon;
            return (
              <div
                key={sc.id}
                className="p-4 rounded-xl border border-slate-800 bg-slate-900/50 hover:border-cyan-500/50 transition-all flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
              >
                <div className="space-y-1.5 flex-1">
                  <div className="flex items-center gap-2">
                    <Icon className="w-4 h-4 text-cyan-400" />
                    <span className="font-semibold text-sm text-slate-200">{sc.title}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${sc.badgeColor}`}>
                      {sc.badge}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{sc.description}</p>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {sc.highlights.map((h, i) => (
                      <span key={i} className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                        {h}
                      </span>
                    ))}
                  </div>
                </div>

                <button
                  onClick={() => onSelectScenario(sc.id)}
                  disabled={isLoading}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs flex items-center gap-1.5 shrink-0 shadow-md transition disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Analyze {sc.id}</span>
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
