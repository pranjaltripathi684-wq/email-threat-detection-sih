import React from 'react';
import { EmailDetail } from '../types';
import { AuthMatrixTable } from '../components/AuthMatrixTable';
import { KeyRound, ShieldAlert, CheckCircle2, Info } from 'lucide-react';

interface Props {
  email: EmailDetail | null;
}

export const AuthenticationPage: React.FC<Props> = ({ email }) => {
  if (!email) {
    return (
      <div className="cyber-card p-10 text-center text-slate-500 italic">
        Please select an email to view authentication and alignment results.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
          <KeyRound className="w-5 h-5 text-cyan-400" />
          AUTHENTICATION, ALIGNMENT & DECEPTION MATRIX
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Cryptographic DKIM signature evaluation, SPF policy checks, DMARC alignment modes, and lookalike domain detection
        </p>
      </div>

      <div className="cyber-card p-6">
        <AuthMatrixTable auth={email.auth_results} />
      </div>

      <div className="cyber-card p-6 space-y-3">
        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-2">
          <Info className="w-4 h-4 text-cyan-400" />
          Academic Guidance: Interpretation of Authentication Success
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          In defensive email forensics, passing SPF, DKIM, and DMARC does <strong>not</strong> conclusively verify message benignity. An adversary can register a lookalike domain (e.g. <code>paypa1-security.com</code>) with valid DNS records and DKIM keys. Alternatively, legitimate enterprise accounts may be compromised through credential stuffing. Always correlate authentication with content semantics and reputation.
        </p>
      </div>
    </div>
  );
};
