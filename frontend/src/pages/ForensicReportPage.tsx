import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { FileSpreadsheet, Printer, Download, RefreshCw, ExternalLink } from 'lucide-react';

interface Props {
  selectedEmailId: number | null;
}

export const ForensicReportPage: React.FC<Props> = ({ selectedEmailId }) => {
  const [reportHtml, setReportHtml] = useState<string>('');
  const [loading, setLoading] = useState(false);

  const fetchReport = async () => {
    if (!selectedEmailId) return;
    setLoading(true);
    try {
      const html = await api.getEmailReportHtml(selectedEmailId);
      setReportHtml(html);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, [selectedEmailId]);

  const handlePrint = () => {
    const printWindow = window.open('', '_blank');
    if (printWindow) {
      printWindow.document.write(reportHtml);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 500);
    }
  };

  if (!selectedEmailId) {
    return (
      <div className="cyber-card p-10 text-center text-slate-500 italic">
        Please select an email to generate and export its formal forensic intelligence report.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-extrabold text-slate-100 tracking-wide flex items-center gap-2">
            <FileSpreadsheet className="w-5 h-5 text-cyan-400" />
            FORMAL FORENSIC INTELLIGENCE REPORT
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Structured forensic report complete with executive summary, technical breakdown, chain-of-custody, and legal disclaimers
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchReport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Regenerate</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-md transition"
          >
            <Printer className="w-4 h-4" />
            <span>Print / Export PDF Report</span>
          </button>
        </div>
      </div>

      {/* Live Preview Container */}
      <div className="cyber-card p-6 bg-white rounded-2xl shadow-2xl overflow-hidden min-h-[600px]">
        {loading ? (
          <div className="p-12 text-center text-slate-400 text-xs font-mono">
            Rendering forensic intelligence report template...
          </div>
        ) : reportHtml ? (
          <iframe
            srcDoc={reportHtml}
            title="Forensic Report Preview"
            className="w-full min-h-[750px] border-none rounded"
          />
        ) : (
          <div className="p-12 text-center text-slate-400 text-xs italic">
            Failed to render report template.
          </div>
        )}
      </div>
    </div>
  );
};
