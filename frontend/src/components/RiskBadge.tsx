import React from 'react';
import { ShieldAlert, AlertTriangle, ShieldCheck, HelpCircle } from 'lucide-react';

interface Props {
  classification: string;
  score?: number;
  showIcon?: boolean;
}

export const RiskBadge: React.FC<Props> = ({ classification, score, showIcon = true }) => {
  const getBadgeStyle = () => {
    switch (classification?.toLowerCase()) {
      case 'critical':
        return {
          bg: 'bg-red-500/10 text-red-400 border-red-500/30 shadow-[0_0_12px_rgba(239,68,68,0.2)]',
          icon: <ShieldAlert className="w-4 h-4 text-red-400" />
        };
      case 'high risk':
      case 'high':
        return {
          bg: 'bg-orange-500/10 text-orange-400 border-orange-500/30 shadow-[0_0_12px_rgba(249,115,22,0.2)]',
          icon: <AlertTriangle className="w-4 h-4 text-orange-400" />
        };
      case 'suspicious':
        return {
          bg: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30 shadow-[0_0_12px_rgba(234,179,8,0.2)]',
          icon: <AlertTriangle className="w-4 h-4 text-yellow-400" />
        };
      case 'low risk':
      case 'low':
        return {
          bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-[0_0_12px_rgba(16,185,129,0.2)]',
          icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />
        };
      default:
        return {
          bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
          icon: <HelpCircle className="w-4 h-4 text-slate-400" />
        };
    }
  };

  const style = getBadgeStyle();

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${style.bg} uppercase tracking-wider`}>
      {showIcon && style.icon}
      <span>{classification || 'Unknown'}</span>
      {score !== undefined && (
        <span className="ml-1 px-1.5 py-0.2 bg-black/40 rounded text-[11px] font-mono">
          {score}/100
        </span>
      )}
    </span>
  );
};
