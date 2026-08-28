import React, { useState } from 'react';
import { EmailDetail } from '../types';
import { RelayHopVisualizer } from '../components/RelayHopVisualizer';
import { Route, Code2, Search, Copy, Check } from 'lucide-react';

interface Props {
  email: EmailDetail | null;
}

export const HeaderRelayPage: React.FC<Props> = ({ email }) => {
  const [searchFilter, setSearchFilter] = useState('');
  const [copied, setCopied] = useState(false);

  if (!email) {
    return (
      <div className="cyber-card p-10 text-center text-slate-500 italic">
        Please select an email from the dashboard to inspect transmission hops and headers.
      </div>
    );
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(email.hops, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
            <Route className="w-5 h-5 text-cyan-400" />
            TRANSMISSION RELAY PATH & HEADER FORENSICS
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Reverse hop reconstruction, Bogon detection, time delta analysis, and earliest public IP determination
          </p>
        </div>

        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition border border-slate-700"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'Copied Hops JSON' : 'Copy Hops Data'}</span>
        </button>
      </div>

      {/* Visual Timeline */}
      <div className="cyber-card p-6">
        <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono mb-4">
          Step-by-Step SMTP Transmission Chain
        </h3>
        <RelayHopVisualizer hops={email.hops} earliestPublicIp={email.earliest_public_ip} />
      </div>

      {/* Raw Headers / Normalized Details */}
      <div className="cyber-card p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
            <Code2 className="w-4 h-4 text-cyan-400" />
            Standard RFC 5322 Metadata
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono bg-slate-900/60 p-4 rounded-xl border border-slate-800">
          <div>
            <span className="text-slate-500">From: </span>
            <span className="text-slate-200">{email.raw_from}</span>
          </div>
          <div>
            <span className="text-slate-500">Reply-To: </span>
            <span className="text-cyan-300">{email.raw_reply_to || 'None'}</span>
          </div>
          <div>
            <span className="text-slate-500">Return-Path: </span>
            <span className="text-slate-300">{email.raw_return_path || 'None'}</span>
          </div>
          <div>
            <span className="text-slate-500">Date: </span>
            <span className="text-slate-300">{email.raw_date}</span>
          </div>
          <div className="md:col-span-2">
            <span className="text-slate-500">Message-ID: </span>
            <span className="text-slate-300">{email.message_id || 'Missing Header'}</span>
          </div>
          <div className="md:col-span-2">
            <span className="text-slate-500">Sender Domain / Reply Domain: </span>
            <span className="text-cyan-300">{email.sender_domain}</span> / <span className="text-cyan-300">{email.reply_to_domain || 'Same'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
