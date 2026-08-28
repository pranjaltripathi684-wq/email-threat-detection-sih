import React from 'react';
import { Users, Shield, Lock, CheckCircle2 } from 'lucide-react';

export const UserManagementPage: React.FC = () => {
  const roles = [
    {
      name: 'Analyst',
      badge: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
      description: 'Upload and analyze emails, inspect indicators, create investigation cases, and export authorized reports.',
      permissions: ['Upload & Ingest Emails', 'Run Threat ML Engine', 'Create & Update Cases', 'Add Analyst Notes', 'Export HTML Reports'],
    },
    {
      name: 'Administrator',
      badge: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
      description: 'Manage users, assign RBAC roles, configure risk thresholds, and manage threat intelligence feeds.',
      permissions: ['Manage Users & Roles', 'Modify Scoring Weights', 'Configure Threat Intel APIs', 'View Audit Logs', 'Set Retention Policies'],
    },
    {
      name: 'Investigator',
      badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      description: 'Access assigned cases, review evidence and chain-of-custody history, correlate campaigns, and generate formal forensic reports.',
      permissions: ['Access Assigned Cases', 'Review Evidence & Custody', 'Perform Graph Correlation', 'Generate Formal Reports', 'Modify Case Severity'],
    },
    {
      name: 'Auditor',
      badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      description: 'View immutable audit logs, verify cryptographic hashes, and inspect evidence access history without altering records.',
      permissions: ['Inspect Audit Logs', 'Verify SHA-256 Hashes', 'Audit Chain of Custody', 'Read-Only Evidence Access', 'Verify Report History'],
    },
  ];

  const defaultUsers = [
    { username: 'admin', role: 'Administrator', email: 'admin@forensics.local', status: 'Active' },
    { username: 'analyst', role: 'Analyst', email: 'analyst@forensics.local', status: 'Active' },
    { username: 'investigator', role: 'Investigator', email: 'investigator@forensics.local', status: 'Active' },
    { username: 'auditor', role: 'Auditor', email: 'auditor@forensics.local', status: 'Active' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
          <Users className="w-5 h-5 text-cyan-400" />
          ROLE-BASED ACCESS CONTROL (RBAC) & USER DIRECTORY
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Enforce separation of duties across Security Analysts, Administrators, Case Investigators, and Compliance Auditors
        </p>
      </div>

      {/* Role Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {roles.map((r) => (
          <div key={r.name} className="cyber-card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase border ${r.badge}`}>
                {r.name}
              </span>
              <Shield className="w-4 h-4 text-slate-500" />
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">{r.description}</p>

            <div className="pt-2 border-t border-slate-800/80 space-y-1.5">
              <div className="text-[10px] font-mono uppercase text-slate-400 font-semibold">Granted Capabilities:</div>
              <div className="grid grid-cols-1 gap-1 text-[11px] text-slate-300">
                {r.permissions.map((p, i) => (
                  <div key={i} className="flex items-center gap-1.5">
                    <CheckCircle2 className="w-3 h-3 text-cyan-400 shrink-0" />
                    <span>{p}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Seeded Users Table */}
      <div className="cyber-card p-6 space-y-4">
        <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
          <Lock className="w-4 h-4 text-cyan-400" />
          Active Platform Accounts
        </h3>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="p-3">Username</th>
                <th className="p-3">Email Address</th>
                <th className="p-3">Assigned Role</th>
                <th className="p-3 text-right">Account Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {defaultUsers.map((u) => (
                <tr key={u.username} className="hover:bg-slate-800/20">
                  <td className="p-3 font-semibold text-slate-200 font-sans">{u.username}</td>
                  <td className="p-3 text-cyan-300">{u.email}</td>
                  <td className="p-3 text-slate-300">{u.role}</td>
                  <td className="p-3 text-right">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                      {u.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
