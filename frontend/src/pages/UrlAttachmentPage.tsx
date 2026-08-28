import React from 'react';
import { EmailDetail } from '../types';
import { FileText, Link2, Paperclip, AlertTriangle, ShieldAlert, ShieldCheck } from 'lucide-react';

interface Props {
  email: EmailDetail | null;
}

export const UrlAttachmentPage: React.FC<Props> = ({ email }) => {
  if (!email) {
    return (
      <div className="cyber-card p-10 text-center text-slate-500 italic">
        Please select an email to inspect extracted URLs and file attachments.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
          <FileText className="w-5 h-5 text-cyan-400" />
          INDICATORS OF COMPROMISE: URLS & ATTACHMENTS
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Safe static payload inspection without execution, deceptive link anchor detection, and entropy scoring
        </p>
      </div>

      {/* URLs Section */}
      <div className="cyber-card p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
            <Link2 className="w-4 h-4 text-cyan-400" />
            Extracted Hyperlink Destinations ({email.urls.length})
          </h3>
        </div>

        {email.urls.length > 0 ? (
          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <tr>
                  <th className="p-3">Destination URL</th>
                  <th className="p-3">Visible Anchor Text</th>
                  <th className="p-3">Domain</th>
                  <th className="p-3">Flags</th>
                  <th className="p-3 text-right">Risk Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 font-mono">
                {email.urls.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-800/20">
                    <td className="p-3 font-semibold text-cyan-300 break-all max-w-[280px]">
                      {u.raw_url}
                    </td>
                    <td className="p-3 text-slate-300 font-sans">{u.display_text || '-'}</td>
                    <td className="p-3 text-slate-400">{u.domain || '-'}</td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1">
                        {u.is_deceptive && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-300 border border-red-500/40">
                            DECEPTIVE LINK
                          </span>
                        )}
                        {u.is_ip_based && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            DIRECT IP
                          </span>
                        )}
                        {u.is_shortened && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-blue-500/20 text-blue-300 border border-blue-500/40">
                            SHORTENER
                          </span>
                        )}
                        {!u.is_deceptive && !u.is_ip_based && !u.is_shortened && (
                          <span className="text-slate-500 font-sans">Clean</span>
                        )}
                      </div>
                    </td>
                    <td className="p-3 text-right font-bold text-slate-200">
                      {u.risk_score.toFixed(1)} / 15
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-6 text-center text-slate-500 text-xs italic bg-slate-900/30 rounded-xl border border-slate-800">
            No external hyperlinks identified in email content.
          </div>
        )}
      </div>

      {/* Attachments Section */}
      <div className="cyber-card p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
            <Paperclip className="w-4 h-4 text-cyan-400" />
            Static Attachment Forensics ({email.attachments.length})
          </h3>
        </div>

        {email.attachments.length > 0 ? (
          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <tr>
                  <th className="p-3">File Name</th>
                  <th className="p-3">Size / Magic Byte</th>
                  <th className="p-3">SHA-256 Hash</th>
                  <th className="p-3">Structural Flags</th>
                  <th className="p-3 text-right">Risk Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 font-mono">
                {email.attachments.map((att) => (
                  <tr key={att.id} className="hover:bg-slate-800/20">
                    <td className="p-3 font-semibold text-slate-200 font-sans">
                      <div className="flex items-center gap-1.5">
                        <Paperclip className="w-3.5 h-3.5 text-cyan-400" />
                        <span>{att.filename}</span>
                      </div>
                    </td>
                    <td className="p-3 text-slate-300">
                      <div>{(att.file_size / 1024).toFixed(1)} KB</div>
                      <div className="text-[10px] text-slate-500">{att.magic_file_type}</div>
                    </td>
                    <td className="p-3 text-cyan-400 break-all max-w-[200px] text-[11px]">
                      {att.sha256_hash}
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1">
                        {att.has_double_extension && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-300 border border-red-500/40">
                            DOUBLE EXTENSION
                          </span>
                        )}
                        {att.is_script_or_executable && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-orange-500/20 text-orange-300 border border-orange-500/40">
                            EXECUTABLE
                          </span>
                        )}
                        {att.has_macros && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            VBA MACROS
                          </span>
                        )}
                        {!att.has_double_extension && !att.is_script_or_executable && !att.has_macros && (
                          <span className="text-slate-500 font-sans">Standard Document</span>
                        )}
                      </div>
                    </td>
                    <td className="p-3 text-right font-bold text-slate-200">
                      {att.risk_score.toFixed(1)} / 10
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-6 text-center text-slate-500 text-xs italic bg-slate-900/30 rounded-xl border border-slate-800">
            No file attachments attached to this message.
          </div>
        )}
      </div>
    </div>
  );
};
