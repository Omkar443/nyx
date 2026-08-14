import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { AlertTriangle, Plus, CheckCircle, FileText, XCircle, Shield, Target, Zap, Filter, Search, X, FileCode, Activity } from 'lucide-react';
export const FindingsView: React.FC = () => {
  const [findings, setFindings] = useState<any[]>([]);
  const [showCreate, setShowCreate] = useState<boolean>(false);
  const [showReport, setShowReport] = useState<string | null>(null);
  const [reportMarkdown, setReportMarkdown] = useState<string>('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');

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

  const getSeverityBadgeClass = (sev: string = 'medium') => {
    switch (sev.toLowerCase()) {
      case 'critical': return 'nyx-badge-critical';
      case 'high': return 'nyx-badge-high';
      case 'medium': return 'nyx-badge-medium';
      case 'low': return 'nyx-badge-low';
      default: return 'nyx-badge-info';
    }
  };

  const getStatusBadgeClass = (status: string = 'HYPOTHESIS') => {
    switch (status.toUpperCase()) {
      case 'VERIFIED':
        return 'nyx-badge-success';
      case 'HYPOTHESIS':
        return 'nyx-badge-medium';
      case 'REJECTED':
        return 'nyx-badge-critical';
      case 'TRIAGED':
        return 'nyx-badge-info';
      default:
        return 'nyx-badge-info';
    }
  };

  const filteredFindings = findings.filter((f: any) => {
    const matchesSeverity = filterSeverity === 'all' || (f.severity || 'medium').toLowerCase() === filterSeverity.toLowerCase();
    const matchesSearch = !searchTerm || 
      f.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.finding_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.endpoint?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  return (
    <div className="nyx-findings-view">
      {/* File Update Progress */}

      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div className="flex items-center gap-4">
            <div className="nyx-page-icon nyx-page-icon-amber">
              <AlertTriangle className="w-6 h-6 text-[#FF6B35]" />
            </div>
            <div>
              <h1 className="nyx-page-title">Finding Lifecycle & Triage</h1>
              <p className="nyx-page-subtitle">Vulnerability hypotheses, empirical validation, and submission drafts</p>
            </div>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="nyx-button nyx-button-primary"
          >
            <Plus className="w-4 h-4" />
            <span>New Hypothesis</span>
          </button>
        </div>
      </div>

      {/* Findings Stats */}
      <div className="nyx-stats-overview">
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-amber">
            <AlertTriangle className="w-4 h-4 text-[#FF6B35]" />
          </div>
          <div>
            <div className="nyx-stat-value">{findings.length}</div>
            <div className="nyx-stat-label">Total Findings</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-green">
            <CheckCircle className="w-4 h-4 text-[#00FF88]" />
          </div>
          <div>
            <div className="nyx-stat-value">
              {findings.filter(f => f.status === 'VERIFIED').length}
            </div>
            <div className="nyx-stat-label">Verified</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-critical">
            <Shield className="w-4 h-4 text-[#FF2D55]" />
          </div>
          <div>
            <div className="nyx-stat-value">
              {findings.filter(f => f.severity === 'Critical' || f.severity === 'High').length}
            </div>
            <div className="nyx-stat-label">High Risk</div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="nyx-filters-bar">
        <div className="nyx-search-container">
          <Search className="nyx-search-icon" />
          <input
            type="text"
            placeholder="Search findings..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="nyx-search-input"
          />
          {searchTerm && (
            <button onClick={() => setSearchTerm('')} className="nyx-search-clear">
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
        <div className="nyx-filter-group">
          <Filter className="w-4 h-4 text-[#8B949E]" />
          <button
            onClick={() => setFilterSeverity('all')}
            className={`nyx-filter-button ${filterSeverity === 'all' ? 'nyx-filter-active' : ''}`}
          >
            All
          </button>
          <button
            onClick={() => setFilterSeverity('critical')}
            className={`nyx-filter-button ${filterSeverity === 'critical' ? 'nyx-filter-active' : ''}`}
          >
            Critical
          </button>
          <button
            onClick={() => setFilterSeverity('high')}
            className={`nyx-filter-button ${filterSeverity === 'high' ? 'nyx-filter-active' : ''}`}
          >
            High
          </button>
          <button
            onClick={() => setFilterSeverity('medium')}
            className={`nyx-filter-button ${filterSeverity === 'medium' ? 'nyx-filter-active' : ''}`}
          >
            Medium
          </button>
          <button
            onClick={() => setFilterSeverity('low')}
            className={`nyx-filter-button ${filterSeverity === 'low' ? 'nyx-filter-active' : ''}`}
          >
            Low
          </button>
        </div>
      </div>

      {/* Findings List */}
      <div className="nyx-findings-list">
        {filteredFindings.length === 0 ? (
          <div className="nyx-card nyx-empty-state">
            <div className="nyx-empty-state-icon">
              <AlertTriangle className="w-8 h-8 text-[#484F58]" />
            </div>
            <div className="nyx-empty-state-title">
              {searchTerm || filterSeverity !== 'all' ? 'No findings match filters' : 'No active findings recorded'}
            </div>
            <div className="nyx-empty-state-description">
              {searchTerm || filterSeverity !== 'all' 
                ? 'Adjust your search or filter criteria' 
                : 'Click "New Hypothesis" above to create a finding hypothesis'}
            </div>
          </div>
        ) : (
          filteredFindings.map((f: any) => (
            <div key={f.finding_id} className="nyx-card nyx-finding-card">
              <div className="nyx-finding-card-header">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className={`nyx-badge ${getSeverityBadgeClass(f.severity)}`}>
                    {f.severity || 'Medium'}
                  </span>
                  <span className="nyx-finding-id">{f.finding_id}</span>
                  <h3 className="nyx-finding-title">{f.title}</h3>
                </div>
                <span className={`nyx-badge ${getStatusBadgeClass(f.status)}`}>
                  {f.status || 'HYPOTHESIS'}
                </span>
              </div>

              <div className="nyx-finding-details">
                <div className="nyx-finding-detail-item">
                  <Target className="w-3.5 h-3.5 text-[#00D9FF]" />
                  <span className="nyx-finding-detail-label">Endpoint:</span>
                  <span className="nyx-finding-detail-value">{f.endpoint || 'General Scope'}</span>
                </div>
                <div className="nyx-finding-detail-item">
                  <Zap className="w-3.5 h-3.5 text-[#FF6B35]" />
                  <span className="nyx-finding-detail-label">Vulnerability:</span>
                  <span className="nyx-finding-detail-value">{f.vulnerability || 'IDOR'}</span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="nyx-finding-actions">
                <button
                  onClick={() => handleTriage(f.finding_id)}
                  className="nyx-button nyx-button-triage"
                >
                  <Activity className="w-3.5 h-3.5" />
                  <span>7-Question Gate Triage</span>
                </button>
                <button
                  onClick={() => handleTransition(f.finding_id, 'VERIFIED')}
                  className="nyx-button nyx-button-verify"
                >
                  <CheckCircle className="w-3.5 h-3.5" />
                  <span>Mark Verified</span>
                </button>
                <button
                  onClick={() => handleTransition(f.finding_id, 'REJECTED')}
                  className="nyx-button nyx-button-danger"
                >
                  <XCircle className="w-3.5 h-3.5" />
                  <span>Mark Rejected</span>
                </button>
                <button
                  onClick={() => handleGenerateReport(f.finding_id)}
                  className="nyx-button nyx-button-report ml-auto"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Generate Report Draft</span>
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Modal Create Finding */}
      {showCreate && (
        <div className="nyx-modal-overlay">
          <div className="nyx-modal">
            <div className="nyx-modal-header">
              <div className="flex items-center gap-3">
                <div className="nyx-modal-icon">
                  <AlertTriangle className="w-5 h-5 text-[#FF6B35]" />
                </div>
                <h3 className="nyx-modal-title">Create Vulnerability Hypothesis</h3>
              </div>
              <button onClick={() => setShowCreate(false)} className="nyx-modal-close">
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <form onSubmit={handleCreateFinding} className="nyx-modal-content">
              <div className="nyx-form-field">
                <label className="nyx-form-label">
                  <FileText className="w-3 h-3 text-[#00D9FF]" />
                  Title
                </label>
                <input
                  type="text"
                  required
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. IDOR in User Profile Endpoint"
                  className="nyx-input"
                />
              </div>
              <div className="nyx-form-field">
                <label className="nyx-form-label">
                  <Target className="w-3 h-3 text-[#00FF88]" />
                  Endpoint URL
                </label>
                <input
                  type="text"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  placeholder="https://example.com/api/user/123"
                  className="nyx-input"
                />
              </div>
              <div className="nyx-form-grid">
                <div className="nyx-form-field">
                  <label className="nyx-form-label">
                    <Shield className="w-3 h-3 text-[#FF6B35]" />
                    Vulnerability Class
                  </label>
                  <select
                    value={vuln}
                    onChange={(e) => setVuln(e.target.value)}
                    className="nyx-select"
                  >
                    <option value="IDOR">IDOR</option>
                    <option value="SQLi">SQL Injection</option>
                    <option value="XSS">XSS</option>
                    <option value="SSRF">SSRF</option>
                    <option value="BrokenAuth">Broken Auth</option>
                  </select>
                </div>
                <div className="nyx-form-field">
                  <label className="nyx-form-label">
                    <AlertTriangle className="w-3 h-3 text-[#FF2D55]" />
                    Severity
                  </label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    className="nyx-select"
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>
              </div>

              <div className="nyx-modal-actions">
                <button
                  type="button"
                  onClick={() => setShowCreate(false)}
                  className="nyx-button nyx-button-secondary"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="nyx-button nyx-button-primary"
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
        <div className="nyx-modal-overlay">
          <div className="nyx-modal nyx-modal-lg">
            <div className="nyx-modal-header">
              <div className="flex items-center gap-3">
                <div className="nyx-modal-icon">
                  <FileCode className="w-5 h-5 text-[#7C3AED]" />
                </div>
                <div>
                  <h3 className="nyx-modal-title">Platform Submission Draft</h3>
                  <span className="nyx-badge nyx-badge-info">FINDING: {showReport}</span>
                </div>
              </div>
              <button onClick={() => setShowReport(null)} className="nyx-modal-close">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="nyx-modal-preview">
              <div className="nyx-modal-preview-header">
                <FileText className="w-3 h-3 text-[#00FF88]" />
                <span className="text-[10px] font-mono text-[#00FF88] uppercase tracking-wider">
                  Markdown Preview
                </span>
              </div>
              <div className="nyx-modal-preview-content">
                {reportMarkdown}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};