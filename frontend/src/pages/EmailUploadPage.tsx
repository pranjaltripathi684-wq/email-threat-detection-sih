import React, { useState } from 'react';
import { api } from '../services/api';
import { EmailDetail } from '../types';
import { UploadCloud, FileText, Play, CheckCircle2, AlertCircle, Database } from 'lucide-react';

interface Props {
  onAnalysisComplete: (detail: EmailDetail) => void;
  onOpenScenarios: () => void;
}

export const EmailUploadPage: React.FC<Props> = ({ onAnalysisComplete, onOpenScenarios }) => {
  const [activeMode, setActiveMode] = useState<'upload' | 'paste'>('upload');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Raw Paste Form State
  const [subject, setSubject] = useState('');
  const [fromHeader, setFromHeader] = useState('');
  const [toHeader, setToHeader] = useState('');
  const [replyToHeader, setReplyToHeader] = useState('');
  const [rawHeaders, setRawHeaders] = useState('');
  const [bodyText, setBodyText] = useState('');

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleUploadSubmit = async () => {
    if (!selectedFile) return;
    setIsUploading(true);
    setError(null);
    try {
      const res = await api.uploadEmail(selectedFile);
      onAnalysisComplete(res);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to parse and analyze email file.');
    } finally {
      setIsUploading(false);
    }
  };

  const handlePasteSubmit = async () => {
    if (!rawHeaders && !bodyText && !subject) {
      setError('Please provide email headers or body content.');
      return;
    }
    setIsUploading(true);
    setError(null);
    try {
      const res = await api.pasteEmail({
        subject,
        from_header: fromHeader,
        to_header: toHeader,
        reply_to_header: replyToHeader,
        raw_headers: rawHeaders,
        body_text: bodyText,
      });
      onAnalysisComplete(res);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to parse raw email input.');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-extrabold text-slate-100 tracking-wide">
            EMAIL EVIDENCE INGESTION
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Preserve immutable raw evidence, extract RFC 5322 headers, and execute multi-layer threat assessment
          </p>
        </div>
        <button
          onClick={onOpenScenarios}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-xs font-semibold border border-cyan-500/40 transition"
        >
          <Database className="w-4 h-4" />
          <span>Select Test Scenario (A–E)</span>
        </button>
      </div>

      {error && (
        <div className="p-4 bg-red-950/40 border border-red-500/40 rounded-xl text-red-300 text-xs flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Ingestion Mode Toggle */}
      <div className="flex border-b border-slate-800">
        <button
          onClick={() => setActiveMode('upload')}
          className={`px-6 py-3 text-xs font-bold font-mono tracking-wider border-b-2 flex items-center gap-2 transition ${
            activeMode === 'upload'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <UploadCloud className="w-4 h-4" />
          UPLOAD .EML FILE
        </button>
        <button
          onClick={() => setActiveMode('paste')}
          className={`px-6 py-3 text-xs font-bold font-mono tracking-wider border-b-2 flex items-center gap-2 transition ${
            activeMode === 'paste'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileText className="w-4 h-4" />
          PASTE RAW HEADERS & BODY
        </button>
      </div>

      {/* Mode 1: File Upload */}
      {activeMode === 'upload' && (
        <div className="cyber-card p-8 text-center space-y-6">
          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleFileDrop}
            className="border-2 border-dashed border-slate-700 hover:border-cyan-400/60 rounded-2xl p-10 bg-slate-900/30 transition flex flex-col items-center justify-center gap-3"
          >
            <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center shadow-lg">
              <UploadCloud className="w-8 h-8" />
            </div>

            <div className="text-sm font-semibold text-slate-200">
              Drag and drop an RFC 5322 <span className="text-cyan-400 font-mono">.eml</span> or <span className="text-cyan-400 font-mono">.msg</span> file
            </div>
            <p className="text-xs text-slate-400 max-w-md">
              Files are preserved immutably with SHA-256 cryptographic verification and chain-of-custody logging.
            </p>

            <label className="mt-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold cursor-pointer border border-slate-700 transition">
              <span>Browse Local Files</span>
              <input
                type="file"
                accept=".eml,.txt,.msg"
                className="hidden"
                onChange={(e) => e.target.files?.[0] && setSelectedFile(e.target.files[0])}
              />
            </label>

            {selectedFile && (
              <div className="mt-4 p-3 bg-cyan-950/40 border border-cyan-500/30 rounded-xl text-cyan-300 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                <span className="font-mono">{selectedFile.name}</span>
                <span className="text-slate-400 font-mono">({(selectedFile.size / 1024).toFixed(1)} KB)</span>
              </div>
            )}
          </div>

          <button
            onClick={handleUploadSubmit}
            disabled={!selectedFile || isUploading}
            className="w-full sm:w-auto px-8 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-extrabold text-sm flex items-center justify-center gap-2 shadow-lg transition disabled:opacity-50 mx-auto"
          >
            {isUploading ? (
              <span>Executing Forensic Pipeline...</span>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Ingest & Run Forensic Analysis</span>
              </>
            )}
          </button>
        </div>
      )}

      {/* Mode 2: Paste Raw Headers & Body */}
      {activeMode === 'paste' && (
        <div className="cyber-card p-6 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                Subject
              </label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="e.g. Urgent: Account Security Alert"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
                From Header
              </label>
              <input
                type="text"
                value={fromHeader}
                onChange={(e) => setFromHeader(e.target.value)}
                placeholder='e.g. "Security Team" <security@paypa1-update.com>'
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
              Raw Headers (Optional, paste Received/Authentication-Results)
            </label>
            <textarea
              rows={4}
              value={rawHeaders}
              onChange={(e) => setRawHeaders(e.target.value)}
              placeholder="Received: from mail.server.com [198.51.100.42] by mx.gateway.com...&#10;Authentication-Results: spf=pass..."
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1">
              Email Body Text / HTML Content
            </label>
            <textarea
              rows={6}
              value={bodyText}
              onChange={(e) => setBodyText(e.target.value)}
              placeholder="Paste email body message text or HTML code here..."
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <button
            onClick={handlePasteSubmit}
            disabled={isUploading}
            className="w-full sm:w-auto px-8 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-extrabold text-sm flex items-center justify-center gap-2 shadow-lg transition disabled:opacity-50"
          >
            {isUploading ? (
              <span>Analyzing Raw Stream...</span>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Ingest & Analyze Content</span>
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
};
