import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { AlertTriangle, Plus, CheckCircle, FileText, XCircle, ArrowRight } from 'lucide-react';

export const FindingsView: React.FC = () => {
  const [findings, setFindings] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState<boolean>(false);
  const [showReport, setShowReport] = useState<string | null>(null);
  const [reportMarkdown, setReportMarkdown] = useState<string>('');

  // Form State
  const [title, setTitle] = useState('');
  const [endpoint, setEndpoint] = useState('');
  const [vuln, setVuln] = useState('IDOR');
  const [severity, setSeverity] = useState('High');

  async function loadFindings() {
    const res = await fetchApi('/api/v1/findings');
    if (res.success && res.data?.findings) {
      setFindings(res.data.findings);
    }
  }

  useEffect(() => {
    loadFindings();
  }, []);

  async function handleCreateFinding(e: React.FormEvent) {
    e.preventDefault();
    const res = await fetchApi('/api/v1/findings', {
      method: 'POST',
      body: JSON.stringify({
        title,
        endpoint,
        vulnerability: vuln,
        severity,
      }),
    });
    if (res.success) {
      setShowCreate(false);
      setTitle('');
      setEndpoint('');
      loadFindings();
    }
  }

  async function handleTransition(findingId: string, newState: string) {
    await fetchApi(`/api/v1/findings/${findingId}/transition`, {
      method: 'POST',
      body: JSON.stringify({
        new_state: newState,
        reason: `Dashboard UI transition to ${newState}`,
      }),
    });
    loadFindings();
  }

  async function handleTriage(findingId: string) {
    await fetchApi(`/api/v1/findings/${findingId}/triage`, { method: 'POST' });
    loadFindings();
  }

  async function handleGenerateReport(findingId: string) {
    const res = await fetchApi(`/api/v1/findings/${findingId}/report?platform=bugcrowd`, { method: 'POST' });
    if (res.success && res.data) {
      setReportMarkdown(res.data.report || JSON.stringify(res.data, null, 2));
      setShowReport(findingId);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel p-6 flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <AlertTriangle className="w-6 h-6 text-amber-400" /> Finding Lifecycle & Triage
          </h2>
          <p className="text-sm text-slate-400">Vulnerability hypotheses, empirical validation, and submission drafts</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-600 hover:to-emerald-600 text-slate-950 font-semibold rounded-lg shadow-lg flex items-center gap-2"
        >
          <Plus className="w-4 h-4" /> New Hypothesis
        </button>
      </div>

      {/* Findings List */}
      <div className="space-y-4">
        {findings.length === 0 ? (
          <div className="glass-panel p-8 text-center text-slate-500">
            No active findings recorded. Click "New Hypothesis" to create one.
          </div>
        ) : (
          findings.map((f: any) => (
            <div key={f.finding_id} className="glass-panel p-5 space-y-3">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
                <div className="flex items-center gap-3">
                  <span className={`px-2.5 py-1 text-xs font-semibold rounded font-mono severity-${f.severity?.toLowerCase() || 'medium'}`}>
                    {f.severity || 'Medium'}
                  </span>
                  <span className="text-md font-bold text-white font-mono">{f.finding_id}</span>
                  <h3 className="text-md font-semibold text-slate-200">{f.title}</h3>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs px-3 py-1 rounded-full bg-slate-800 text-cyan-300 font-mono border border-slate-700">
                    {f.status || 'HYPOTHESIS'}
                  </span>
                </div>
              </div>

              <div className="text-xs font-mono text-slate-400 bg-slate-900/60 p-2.5 rounded border border-slate-800">
                Endpoint: <span className="text-cyan-300">{f.endpoint || 'General Scope'}</span> | Vulnerability: <span className="text-emerald-300">{f.vulnerability || 'IDOR'}</span>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-800/60">
                <button
                  onClick={() => handleTriage(f.finding_id)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-cyan-300 rounded border border-cyan-500/30 flex items-center gap-1.5"
                >
                  <CheckCircle className="w-3.5 h-3.5" /> 7-Question Gate Triage
                </button>
                <button
                  onClick={() => handleTransition(f.finding_id, 'VERIFIED')}
                  className="px-3 py-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 text-xs font-semibold text-emerald-300 rounded border border-emerald-500/30 flex items-center gap-1.5"
                >
                  Mark Verified
                </button>
                <button
                  onClick={() => handleTransition(f.finding_id, 'REJECTED')}
                  className="px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-xs font-semibold text-rose-300 rounded border border-rose-500/30 flex items-center gap-1.5"
                >
                  <XCircle className="w-3.5 h-3.5" /> Mark Rejected
                </button>
                <button
                  onClick={() => handleGenerateReport(f.finding_id)}
                  className="px-3 py-1.5 bg-purple-500/20 hover:bg-purple-500/30 text-xs font-semibold text-purple-300 rounded border border-purple-500/30 flex items-center gap-1.5 ml-auto"
                >
                  <FileText className="w-3.5 h-3.5" /> Generate Report Draft
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Modal Create Finding */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="glass-panel p-6 w-full max-w-lg space-y-4">
            <h3 className="text-lg font-bold text-white">Create Vulnerability Hypothesis</h3>
            <form onSubmit={handleCreateFinding} className="space-y-3">
              <div>
                <label className="text-xs font-mono text-slate-400">Title</label>
                <input
                  type="text"
                  required
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. IDOR in User Profile Endpoint"
                  className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white"
                />
              </div>
              <div>
                <label className="text-xs font-mono text-slate-400">Endpoint URL</label>
                <input
                  type="text"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  placeholder="https://example.com/api/user/123"
                  className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-mono text-slate-400">Vulnerability Class</label>
                  <select
                    value={vuln}
                    onChange={(e) => setVuln(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white"
                  >
                    <option value="IDOR">IDOR</option>
                    <option value="SQLi">SQL Injection</option>
                    <option value="XSS">XSS</option>
                    <option value="SSRF">SSRF</option>
                    <option value="BrokenAuth">Broken Auth</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-mono text-slate-400">Severity</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white"
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3">
                <button
                  type="button"
                  onClick={() => setShowCreate(false)}
                  className="px-4 py-2 bg-slate-800 text-slate-300 text-sm rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-500 text-slate-950 font-semibold text-sm rounded"
                >
                  Save Hypothesis
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal Report Viewer */}
      {showReport && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="glass-panel p-6 w-full max-w-2xl space-y-4 max-h-[80vh] overflow-y-auto">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-bold text-white">Platform Submission Draft ({showReport})</h3>
              <button onClick={() => setShowReport(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>
            <pre className="bg-slate-950 p-4 rounded text-xs text-emerald-300 font-mono overflow-x-auto whitespace-pre-wrap">
              {reportMarkdown}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
