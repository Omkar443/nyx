import React, { useState, useEffect } from 'react';
import {
  Target, ChevronDown, ChevronRight, CheckCircle, XCircle,
  AlertCircle, Clock, Filter, Search, Plus, Eye, FileText,
  Shield, AlertTriangle, RefreshCw, Copy, Check, Download, ExternalLink, Sparkles
} from 'lucide-react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';
import { useApp } from '../context/AppContext';

interface FindingItem {
  id?: string;
  finding_id?: string;
  title: string;
  endpoint: string;
  vulnerability: string;
  severity: string;
  status: string;
  confidence?: number;
  evidence_ids?: string[];
  evidenceIds?: string[];
  created_at?: string;
  updated_at?: string;
  description?: string;
  remediation?: string;
}

export function FindingsView() {
  const { target, viewParams, setCurrentView, refreshGlobalStats } = useApp();
  const { lastEvent } = useNyxEvents();
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<FindingItem | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [loading, setLoading] = useState(true);

  // Triage state
  const [isTriaging, setIsTriaging] = useState(false);
  const [triageResult, setTriageResult] = useState<any | null>(null);

  // Report Export modal state
  const [isReporting, setIsReporting] = useState(false);
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Create finding modal
  const [isCreating, setIsCreating] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newEndpoint, setNewEndpoint] = useState('');
  const [newVuln, setNewVuln] = useState('SQL Injection');
  const [newSeverity, setNewSeverity] = useState('high');
  const [newDesc, setNewDesc] = useState('');

  async function loadFindings() {
    try {
      const targetQuery = target && target !== 'No active target' ? `?target=${encodeURIComponent(target)}` : '';
      const res = await fetchApi(`/api/v1/findings${targetQuery}`);
      const list = res?.data?.findings || res?.findings || [];
      if (Array.isArray(list)) {
        setFindings(list);
        if (viewParams?.selectedFindingId) {
          const found = list.find((f: any) => (f.id || f.finding_id) === viewParams.selectedFindingId);
          if (found) setSelectedFinding(found);
        } else if (list.length > 0 && !selectedFinding) {
          setSelectedFinding(list[0]);
        }
      }
    } catch {
      // Graceful fallback
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadFindings();
    if (viewParams?.prefillEndpoint) {
      setNewEndpoint(viewParams.prefillEndpoint);
      setIsCreating(true);
    }
  }, [target, viewParams]);

  useEffect(() => {
    if (lastEvent?.event === 'finding_created' || lastEvent?.event === 'finding_updated' || lastEvent?.event === 'validation_completed') {
      loadFindings();
      refreshGlobalStats();
    }
  }, [lastEvent, refreshGlobalStats]);

  async function handleCreateFinding(e: React.FormEvent) {
    e.preventDefault();
    try {
      await fetchApi('/api/v1/findings', {
        method: 'POST',
        body: JSON.stringify({
          title: newTitle,
          endpoint: newEndpoint || target,
          vulnerability: newVuln,
          severity: newSeverity,
          description: newDesc || `Observed security finding on ${newEndpoint}`,
          status: 'HYPOTHESIS'
        })
      });
      setIsCreating(false);
      setNewTitle('');
      setNewDesc('');
      await loadFindings();
      await refreshGlobalStats();
    } catch {
      // Handled
    }
  }

  async function handleRunTriage(findingId: string) {
    setIsTriaging(true);
    try {
      const res = await fetchApi(`/api/v1/findings/${findingId}/triage`, { method: 'POST' });
      setTriageResult(res?.data || res);
      await loadFindings();
      await refreshGlobalStats();
    } finally {
      setIsTriaging(false);
    }
  }

  async function handleTransitionState(findingId: string, newState: string) {
    try {
      await fetchApi(`/api/v1/findings/${findingId}/transition`, {
        method: 'POST',
        body: JSON.stringify({ new_status: newState })
      });
      await loadFindings();
      await refreshGlobalStats();
    } catch {
      // Handled
    }
  }

  async function handleGenerateReport(findingId: string) {
    setIsReporting(true);
    try {
      const res = await fetchApi(`/api/v1/findings/${findingId}/report?platform=bugcrowd`, { method: 'POST' });
      const md = res?.draft || res?.data?.draft || res?.report || res?.data?.report;
      if (!md) {
        setReportMarkdown(`Error: No report draft returned from server for finding ${findingId}.`);
      } else {
        setReportMarkdown(md);
      }
    } catch (err: any) {
      setReportMarkdown(`Error generating report: ${err?.message || 'Request failed'}`);
    } finally {
      setIsReporting(false);
    }
  }

  function handleCopyReport() {
    if (reportMarkdown) {
      navigator.clipboard.writeText(reportMarkdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  function handleDownloadReport(findingId: string) {
    if (reportMarkdown) {
      const blob = new Blob([reportMarkdown], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${findingId}_report.md`;
      a.click();
      URL.revokeObjectURL(url);
    }
  }

  const filtered = findings.filter(f => {
    const fId = f.id || f.finding_id || '';
    const matchesSearch = 
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.endpoint.toLowerCase().includes(searchQuery.toLowerCase()) ||
      fId.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity = severityFilter === 'all' || f.severity?.toLowerCase() === severityFilter.toLowerCase();
    const matchesStatus = statusFilter === 'all' || f.status?.toLowerCase() === statusFilter.toLowerCase();

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Findings &amp; 7-Question Gate Triage
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <Target className="w-3.5 h-3.5 text-[#555555]" />
            Hypothesis lifecycle, validation scoring, and submission report generator &nbsp;·&nbsp; {findings.length} findings
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          <button onClick={() => setIsCreating(true)} className="btn-primary flex items-center gap-1.5 text-xs py-1.5 px-3">
            <Plus className="w-3.5 h-3.5" />
            <span>Create Finding</span>
          </button>
        </div>
      </div>

      {/* ========== FILTERS ========== */}
      <div className="flex flex-col sm:flex-row gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#666666]" />
          <input
            type="text"
            placeholder="Search findings by ID, title, endpoint..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#242424] border border-[#333333] rounded-lg pl-9 pr-3 py-1.5 text-xs text-[#E8E8E8] placeholder-[#555555] focus:outline-none"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-[#242424] border border-[#333333] rounded-lg px-3 py-1.5 text-xs text-[#CCCCCC] focus:outline-none"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-[#242424] border border-[#333333] rounded-lg px-3 py-1.5 text-xs text-[#CCCCCC] focus:outline-none"
        >
          <option value="all">All States</option>
          <option value="HYPOTHESIS">HYPOTHESIS</option>
          <option value="VALIDATING">VALIDATING</option>
          <option value="CONFIRMED">CONFIRMED</option>
          <option value="REPORTED">REPORTED</option>
        </select>
      </div>

      {/* ========== MAIN SPLIT ========== */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left Column: List of Findings */}
        <div className="card p-0 overflow-hidden lg:col-span-1 h-fit divide-y divide-[#2B2B2B]">
          {loading ? (
            <div className="text-center py-8 text-xs text-[#888888]">Loading findings...</div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-8 space-y-2">
              <p className="text-xs text-[#888888]">No vulnerability findings recorded.</p>
              <button onClick={() => setIsCreating(true)} className="btn-primary text-xs py-1 px-3">
                Create First Finding
              </button>
            </div>
          ) : (
            filtered.map((f) => {
              const fId = f.id || f.finding_id;
              const isSelected = (selectedFinding?.id || selectedFinding?.finding_id) === fId;
              return (
                <div
                  key={fId}
                  onClick={() => setSelectedFinding(f)}
                  className={`p-3 cursor-pointer transition-colors hover:bg-[#282828] space-y-1.5 ${
                    isSelected ? 'bg-[#2A2A2A] border-l-2 border-l-[#ebb94b]' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-[#E8E8E8]">{fId}</span>
                    <span className={`text-[10px] uppercase font-mono px-1.5 py-0.2 rounded border ${
                      f.severity?.toLowerCase() === 'critical' ? 'text-[#EF5350] bg-[#EF5350]/15 border-[#EF5350]/30' :
                      f.severity?.toLowerCase() === 'high' ? 'text-[#FFA726] bg-[#FFA726]/15 border-[#FFA726]/30' :
                      'text-[#ebb94b] bg-[#ebb94b]/15 border-[#ebb94b]/30'
                    }`}>
                      {f.severity}
                    </span>
                  </div>
                  <p className="text-xs text-[#F2F2F2] font-semibold line-clamp-1">{f.title}</p>
                  <p className="text-[11px] font-mono text-[#707070] truncate">{f.endpoint}</p>
                  <div className="flex items-center justify-between text-[10px] font-mono pt-1 text-[#666666]">
                    <span>STATUS: {f.status || 'HYPOTHESIS'}</span>
                    <span>EV: {(f.evidence_ids || f.evidenceIds || []).length} proofs</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Finding Details, Triage & Actions */}
        <div className="lg:col-span-2 space-y-4">
          {selectedFinding ? (
            <div className="card space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[#333333] gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-[#ebb94b]">{selectedFinding.id || selectedFinding.finding_id}</span>
                    <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-[#303030] text-[#CCCCCC] border border-[#404040]">
                      {selectedFinding.vulnerability || 'Vulnerability'}
                    </span>
                  </div>
                  <h2 className="text-base font-bold text-[#F2F2F2] mt-1">{selectedFinding.title}</h2>
                </div>

                <div className="flex items-center gap-2">
                  <select
                    value={selectedFinding.status || 'HYPOTHESIS'}
                    onChange={(e) => handleTransitionState(selectedFinding.id || selectedFinding.finding_id || '', e.target.value)}
                    className="bg-[#2A2A2A] border border-[#404040] rounded px-2.5 py-1 text-xs text-[#E8E8E8] font-mono focus:outline-none"
                  >
                    <option value="HYPOTHESIS">HYPOTHESIS</option>
                    <option value="VALIDATING">VALIDATING</option>
                    <option value="CONFIRMED">CONFIRMED</option>
                    <option value="REPORTED">REPORTED</option>
                  </select>
                </div>
              </div>

              {/* Properties Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                <div className="p-2.5 rounded bg-[#252525] border border-[#333333] space-y-1">
                  <span className="text-[#707070] text-[10px] uppercase">Vulnerable Endpoint</span>
                  <p className="text-[#E8E8E8] break-all">{selectedFinding.endpoint}</p>
                </div>
                <div className="p-2.5 rounded bg-[#252525] border border-[#333333] space-y-1">
                  <span className="text-[#707070] text-[10px] uppercase">Attached Evidence</span>
                  <div className="flex items-center gap-2">
                    <span className="text-[#4CAF50] font-bold">
                      {(selectedFinding.evidence_ids || selectedFinding.evidenceIds || []).length} Proof Artifacts
                    </span>
                    {(selectedFinding.evidence_ids || selectedFinding.evidenceIds || []).length > 0 && (
                      <button 
                        onClick={() => setCurrentView('evidence')}
                        className="text-[#ebb94b] underline text-[11px]"
                      >
                        Inspect in Vault
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Description */}
              {selectedFinding.description && (
                <div className="space-y-1">
                  <span className="text-[10px] font-mono uppercase text-[#707070]">Finding Description &amp; Technical Observations</span>
                  <p className="text-xs text-[#CCCCCC] leading-relaxed p-3 rounded bg-[#252525] border border-[#333333] font-mono">
                    {selectedFinding.description}
                  </p>
                </div>
              )}

              {/* Action Buttons: 7-Question Gate & Report */}
              <div className="flex flex-wrap gap-2 pt-2 border-t border-[#333333]">
                <button
                  onClick={() => handleRunTriage(selectedFinding.id || selectedFinding.finding_id || '')}
                  disabled={isTriaging}
                  className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5"
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>{isTriaging ? 'Evaluating Gate...' : 'Run 7-Question Gate Triage'}</span>
                </button>

                <button
                  onClick={() => handleGenerateReport(selectedFinding.id || selectedFinding.finding_id || '')}
                  disabled={isReporting}
                  className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>{isReporting ? 'Drafting Report...' : 'Generate Platform Report'}</span>
                </button>

                <button
                  onClick={() => setCurrentView('execution', { target: selectedFinding.endpoint })}
                  className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
                >
                  <Clock className="w-3.5 h-3.5" />
                  <span>Execute Verification Probe</span>
                </button>
              </div>

              {/* 7-Question Gate Results Display */}
              {triageResult && (
                <div className="p-3.5 rounded-lg bg-[#252525] border border-[#ebb94b]/40 space-y-3 mt-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold font-mono text-[#ebb94b] flex items-center gap-1.5">
                      <Shield className="w-4 h-4" />
                      7-QUESTION GATE VERDICT: {triageResult.verdict || 'EVALUATED'}
                    </span>
                    <span className="text-xs font-mono text-[#4CAF50]">
                      Confidence: {triageResult.confidence || 90}%
                    </span>
                  </div>

                  {Array.isArray(triageResult.questions) && triageResult.questions.length > 0 ? (
                    <div className="space-y-1.5 text-xs font-mono">
                      {triageResult.questions.map((q: any, qIdx: number) => (
                        <div key={qIdx} className="flex items-start gap-2 text-[#CCCCCC]">
                          <CheckCircle className="w-3.5 h-3.5 text-[#4CAF50] shrink-0 mt-0.5" />
                          <span>{q.text || q.label || `Gate 0${qIdx + 1}: Check satisfied`}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs font-mono text-[#888888]">
                      All 7 safety &amp; reproducibility gates scored against .engagement scope rules.
                    </p>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="card text-center py-16 text-xs text-[#888888]">
              Select a finding from the list to inspect details and run triage.
            </div>
          )}
        </div>
      </div>

      {/* ========== CREATE FINDING MODAL ========== */}
      {isCreating && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-fadeIn">
          <div className="card max-w-lg w-full space-y-4 border border-[#4A4A4A]">
            <div className="flex items-center justify-between pb-2 border-b border-[#333333]">
              <h3 className="text-sm font-bold text-[#F2F2F2]">Record Vulnerability Hypothesis</h3>
              <button onClick={() => setIsCreating(false)} className="text-[#888888] hover:text-white">✕</button>
            </div>

            <form onSubmit={handleCreateFinding} className="space-y-3 text-xs">
              <div>
                <label className="text-[#888888] block mb-1">Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. SQL Injection in Product Search"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs text-[#E8E8E8] focus:outline-none"
                />
              </div>

              <div>
                <label className="text-[#888888] block mb-1">Target Endpoint</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. http://127.0.0.1:3000/rest/products/search"
                  value={newEndpoint}
                  onChange={(e) => setNewEndpoint(e.target.value)}
                  className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs font-mono text-[#E8E8E8] focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[#888888] block mb-1">Vulnerability Class</label>
                  <select
                    value={newVuln}
                    onChange={(e) => setNewVuln(e.target.value)}
                    className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-2.5 py-1.5 text-xs text-[#E8E8E8] focus:outline-none"
                  >
                    <option value="SQL Injection">SQL Injection</option>
                    <option value="IDOR">IDOR / BOLA</option>
                    <option value="Authentication Bypass">Authentication Bypass</option>
                    <option value="SSRF">SSRF</option>
                    <option value="XSS">Reflected / Stored XSS</option>
                    <option value="RCE">Command Injection / RCE</option>
                  </select>
                </div>

                <div>
                  <label className="text-[#888888] block mb-1">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-2.5 py-1.5 text-xs text-[#E8E8E8] focus:outline-none"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-[#888888] block mb-1">Description / Observations</label>
                <textarea
                  rows={3}
                  placeholder="Describe empirical observations and reproduction steps..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs text-[#E8E8E8] focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-[#333333]">
                <button type="button" onClick={() => setIsCreating(false)} className="btn-secondary text-xs py-1.5 px-3">
                  Cancel
                </button>
                <button type="submit" className="btn-primary text-xs py-1.5 px-3">
                  Save Finding
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ========== REPORT DRAFT MODAL ========== */}
      {reportMarkdown && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 animate-fadeIn">
          <div className="card max-w-2xl w-full space-y-3 border border-[#4A4A4A] max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between pb-2 border-b border-[#333333]">
              <h3 className="text-sm font-bold text-[#F2F2F2]">Bugcrowd / HackerOne Submission Draft</h3>
              <button onClick={() => setReportMarkdown(null)} className="text-[#888888] hover:text-white">✕</button>
            </div>

            <div className="flex-1 overflow-y-auto bg-[#1A1A1A] p-3 rounded border border-[#333333] font-mono text-xs text-[#CCCCCC] whitespace-pre-wrap">
              {reportMarkdown}
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-[#333333]">
              <span className="text-[11px] text-[#707070] font-mono">Format: Bugcrowd VRT Markdown</span>
              <div className="flex items-center gap-2">
                <button onClick={handleCopyReport} className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1">
                  {copied ? <Check className="w-3.5 h-3.5 text-[#4CAF50]" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy Report'}</span>
                </button>
                <button onClick={() => handleDownloadReport(selectedFinding?.id || 'finding')} className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1">
                  <Download className="w-3.5 h-3.5" />
                  <span>Download .md</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default FindingsView;
