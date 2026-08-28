import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { CaseItem } from '../types';
import { FolderKanban, Plus, Clock, MessageSquare, ShieldAlert, CheckCircle2 } from 'lucide-react';

interface Props {
  selectedEmailId: number | null;
}

export const CaseManagementPage: React.FC<Props> = ({ selectedEmailId }) => {
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [selectedCase, setSelectedCase] = useState<any>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newSeverity, setNewSeverity] = useState('High');
  const [noteText, setNoteText] = useState('');

  const fetchCases = async () => {
    try {
      const data = await api.listCases();
      setCases(data);
      if (data.length > 0 && !selectedCase) {
        loadCaseDetails(data[0].id);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const loadCaseDetails = async (id: number) => {
    try {
      const data = await api.getCaseDetails(id);
      setSelectedCase(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleCreateCase = async () => {
    if (!newTitle) return;
    try {
      await api.createCase({
        title: newTitle,
        description: newDescription,
        severity: newSeverity,
        email_ids: selectedEmailId ? [selectedEmailId] : [],
      });
      setShowCreateModal(false);
      setNewTitle('');
      setNewDescription('');
      fetchCases();
    } catch (e) {
      console.error(e);
    }
  };

  const handleAddNote = async () => {
    if (!noteText || !selectedCase) return;
    try {
      await api.addCaseNote(selectedCase.id, noteText, selectedEmailId || undefined);
      setNoteText('');
      loadCaseDetails(selectedCase.id);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
            <FolderKanban className="w-5 h-5 text-cyan-400" />
            INCIDENT CASE MANAGEMENT
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Track multi-stage investigations, assign threat analysts, maintain chain of custody, and record timeline notes
          </p>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-md transition"
        >
          <Plus className="w-4 h-4" />
          <span>New Investigation Case</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Case List Column */}
        <div className="cyber-card p-4 space-y-3">
          <div className="text-xs font-bold text-slate-400 uppercase font-mono tracking-wider mb-2">
            Active Cases ({cases.length})
          </div>

          <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
            {cases.map((c) => (
              <div
                key={c.id}
                onClick={() => loadCaseDetails(c.id)}
                className={`p-3.5 rounded-xl border cursor-pointer transition ${
                  selectedCase?.id === c.id
                    ? 'bg-cyan-950/30 border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.15)]'
                    : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between font-mono text-[11px] mb-1">
                  <span className="text-cyan-400 font-bold">{c.case_number}</span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-semibold ${
                      c.severity === 'Critical'
                        ? 'bg-red-500/20 text-red-300'
                        : c.severity === 'High'
                        ? 'bg-orange-500/20 text-orange-300'
                        : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    {c.severity}
                  </span>
                </div>
                <div className="font-semibold text-xs text-slate-200 line-clamp-1">{c.title}</div>
                <div className="flex items-center justify-between text-[10px] text-slate-500 mt-2 font-mono">
                  <span>Status: {c.status}</span>
                  <span>{c.email_count} Emails</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Selected Case Workspace */}
        <div className="lg:col-span-2 space-y-4">
          {selectedCase ? (
            <div className="cyber-card p-6 space-y-5">
              <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b border-slate-800">
                <div>
                  <span className="font-mono text-cyan-400 text-xs font-bold">{selectedCase.case_number}</span>
                  <h3 className="text-lg font-bold text-slate-100 mt-0.5">{selectedCase.title}</h3>
                  <p className="text-xs text-slate-400 mt-1">{selectedCase.description || 'No description provided.'}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                    Status: {selectedCase.status}
                  </span>
                </div>
              </div>

              {/* Linked Evidence Emails */}
              <div>
                <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Linked Evidence Items ({selectedCase.emails?.length || 0})
                </h4>
                <div className="space-y-2">
                  {selectedCase.emails?.map((e: any) => (
                    <div key={e.id} className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg text-xs flex justify-between items-center">
                      <div>
                        <div className="font-semibold text-slate-200">{e.subject || '(No Subject)'}</div>
                        <div className="text-[10px] text-slate-500 font-mono">From: {e.from}</div>
                      </div>
                      <span className="font-mono text-xs font-bold text-cyan-400">Score: {e.risk_score}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Timeline Notes */}
              <div>
                <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <MessageSquare className="w-3.5 h-3.5 text-cyan-400" />
                  Analyst Timeline Notes ({selectedCase.notes?.length || 0})
                </h4>
                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {selectedCase.notes?.map((n: any) => (
                    <div key={n.id} className="p-3 bg-slate-900/40 border border-slate-800/80 rounded-lg text-xs space-y-1">
                      <div className="flex justify-between font-mono text-[10px] text-slate-500">
                        <span className="text-cyan-400 font-bold">{n.author_name}</span>
                        <span>{n.created_at?.slice(0, 19)} UTC</span>
                      </div>
                      <p className="text-slate-200">{n.note_text}</p>
                    </div>
                  ))}
                </div>

                {/* Add Note Input */}
                <div className="mt-3 flex gap-2">
                  <input
                    type="text"
                    value={noteText}
                    onChange={(e) => setNoteText(e.target.value)}
                    placeholder="Add timestamped forensic observation note..."
                    className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                  <button
                    onClick={handleAddNote}
                    className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition"
                  >
                    Post Note
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="cyber-card p-12 text-center text-slate-500 italic">
              Select or create an investigation case.
            </div>
          )}
        </div>
      </div>

      {/* Create Case Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#0e1628] border border-slate-700 rounded-2xl max-w-lg w-full p-6 space-y-4">
            <h3 className="text-base font-bold text-slate-100">Create Investigation Case</h3>
            <input
              type="text"
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="Case Title e.g. Executive Spoofing Phishing Incident"
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <textarea
              rows={3}
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              placeholder="Case summary and initial scope..."
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateCase}
                className="px-4 py-2 rounded-lg bg-cyan-500 text-slate-950 text-xs font-bold"
              >
                Create Case
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
