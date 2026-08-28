import React from 'react';
import {
  LayoutDashboard, UploadCloud, FileSearch, Route, KeyRound,
  Globe2, Network, FolderKanban, FileCheck2, FileSpreadsheet,
  Radar, Users, ShieldAlert, Settings, FileText
} from 'lucide-react';

export type ActiveTab =
  | 'overview'
  | 'upload'
  | 'analysis'
  | 'relay'
  | 'auth'
  | 'urls_attachments'
  | 'geomap'
  | 'graph'
  | 'cases'
  | 'evidence'
  | 'report'
  | 'intel'
  | 'users'
  | 'audit'
  | 'settings';

interface Props {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  selectedEmailId: number | null;
}

export const Sidebar: React.FC<Props> = ({ activeTab, setActiveTab, selectedEmailId }) => {
  const navItems = [
    { id: 'overview', label: 'Overview Dashboard', icon: LayoutDashboard, category: 'Core' },
    { id: 'upload', label: 'Ingest & Upload Email', icon: UploadCloud, category: 'Core' },
    { id: 'analysis', label: 'Threat Assessment', icon: FileSearch, category: 'Investigation', requiresEmail: true },
    { id: 'relay', label: 'Headers & Relay Path', icon: Route, category: 'Investigation', requiresEmail: true },
    { id: 'auth', label: 'Auth & Alignment (SPF/DKIM)', icon: KeyRound, category: 'Investigation', requiresEmail: true },
    { id: 'urls_attachments', label: 'URLs & Attachments', icon: FileText, category: 'Investigation', requiresEmail: true },
    { id: 'geomap', label: 'Geolocation & Infra Map', icon: Globe2, category: 'Investigation', requiresEmail: true },
    { id: 'graph', label: 'Entity Correlation Graph', icon: Network, category: 'Correlation' },
    { id: 'cases', label: 'Case Management', icon: FolderKanban, category: 'Operations' },
    { id: 'evidence', label: 'Evidence & Custody Log', icon: FileCheck2, category: 'Operations', requiresEmail: true },
    { id: 'report', label: 'Forensic Report Export', icon: FileSpreadsheet, category: 'Operations', requiresEmail: true },
    { id: 'intel', label: 'Threat Intel Lookup', icon: Radar, category: 'Intelligence' },
    { id: 'users', label: 'User & Role Access', icon: Users, category: 'Admin' },
    { id: 'audit', label: 'Immutable Audit Trail', icon: ShieldAlert, category: 'Admin' },
    { id: 'settings', label: 'System Settings', icon: Settings, category: 'Admin' },
  ];

  return (
    <aside className="w-64 border-r border-slate-800/80 bg-[#0a0f1d] p-3 flex flex-col justify-between shrink-0 min-h-[calc(100vh-4rem)]">
      <div className="space-y-4">
        {['Core', 'Investigation', 'Correlation', 'Operations', 'Intelligence', 'Admin'].map((category) => {
          const items = navItems.filter((i) => i.category === category);
          return (
            <div key={category} className="space-y-1">
              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 px-3 py-1 font-semibold">
                {category}
              </div>
              {items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                const isDisabled = item.requiresEmail && !selectedEmailId;

                return (
                  <button
                    key={item.id}
                    onClick={() => !isDisabled && setActiveTab(item.id as ActiveTab)}
                    disabled={isDisabled}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                      isActive
                        ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-[0_0_10px_rgba(6,182,212,0.15)] font-semibold'
                        : isDisabled
                        ? 'text-slate-500 cursor-not-allowed opacity-50'
                        : 'text-slate-300 hover:text-slate-100 hover:bg-slate-800/50'
                    }`}
                  >
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span className="truncate">{item.label}</span>
                  </button>
                );
              })}
            </div>
          );
        })}
      </div>

      <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 text-[11px] text-slate-400 mt-4">
        <div className="font-mono text-cyan-400 font-semibold mb-1">LEGAL NOTICE</div>
        Defensive forensics only. Geolocation reflects estimated relay infrastructure.
      </div>
    </aside>
  );
};
