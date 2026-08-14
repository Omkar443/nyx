import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Terminal, Play, Shield, Activity, Cpu, Zap, FileCode, X, CheckCircle, AlertTriangle, Clock } from 'lucide-react';
export const ExecutionView: React.FC = () => {
  const [history, setHistory] = useState<any[]>([]);
  const [toolName, setToolName] = useState<string>('subfinder');
  const [target, setTarget] = useState<string>('example.com');
  const [dryRun, setDryRun] = useState<boolean>(true);
  const [running, setRunning] = useState<boolean>(false);
  const [selectedExec, setSelectedExec] = useState<any>(null);

  async function loadHistory() {
    const res = await fetchApi('/api/v1/execution/history?limit=50');
    if (res.success && res.data?.history) {
      setHistory(res.data.history);
    }
  }

  useEffect(() => {
    loadHistory();
  }, []);

  async function handleRunTool(e: React.FormEvent) {
    e.preventDefault();
    setRunning(true);
    const res = await fetchApi('/api/v1/execution/run', {
      method: 'POST',
      body: JSON.stringify({
        tool_name: toolName,
        target,
        dry_run: dryRun,
      }),
    });
    setRunning(false);
    loadHistory();
    if (res.success) {
      setSelectedExec(res.data);
    }
  }

  const getToolIcon = (tool: string) => {
    switch (tool.toLowerCase()) {
      case 'subfinder':
        return Activity;
      case 'httpx':
        return Zap;
      case 'katana':
        return Cpu;
      case 'nuclei':
        return Shield;
      case 'nmap':
        return Terminal;
      default:
        return Terminal;
    }
  };

  const getStatusBadge = (status: string = 'COMPLETED') => {
    switch (status.toUpperCase()) {
      case 'COMPLETED':
        return 'nyx-badge-success';
      case 'RUNNING':
        return 'nyx-badge-info';
      case 'FAILED':
        return 'nyx-badge-critical';
      case 'QUEUED':
        return 'nyx-badge-high';
      default:
        return 'nyx-badge-info';
    }
  };

  return (
    <div className="nyx-execution-view">
      {/* File Update Progress */}

      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div className="flex items-center gap-4">
            <div className="nyx-page-icon nyx-page-icon-green">
              <Terminal className="w-6 h-6 text-[#00FF88]" />
            </div>
            <div>
              <h1 className="nyx-page-title">Controlled Execution Engine</h1>
              <p className="nyx-page-subtitle">Policy-gated security tool harness and output artifacts</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#00FF88]" />
            <span className="nyx-badge nyx-badge-success">POLICY ENFORCED</span>
          </div>
        </div>
      </div>

      {/* Execution Stats */}
      <div className="nyx-stats-overview">
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-green">
            <CheckCircle className="w-4 h-4 text-[#00FF88]" />
          </div>
          <div>
            <div className="nyx-stat-value">
              {history.filter(h => h.status === 'COMPLETED').length}
            </div>
            <div className="nyx-stat-label">Completed</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-cyan">
            <Activity className="w-4 h-4 text-[#00D9FF]" />
          </div>
          <div>
            <div className="nyx-stat-value">
              {history.filter(h => h.dry_run).length}
            </div>
            <div className="nyx-stat-label">Dry Runs</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-amber">
            <AlertTriangle className="w-4 h-4 text-[#FF6B35]" />
          </div>
          <div>
            <div className="nyx-stat-value">
              {history.filter(h => h.status === 'FAILED').length}
            </div>
            <div className="nyx-stat-label">Failed</div>
          </div>
        </div>
      </div>

      {/* Tool Runner Form Card */}
      <div className="nyx-card nyx-card-accent-green">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-green">
              <Terminal className="w-4 h-4 text-[#00FF88]" />
            </div>
            <h3 className="nyx-section-title">Execute Controlled Security Tool</h3>
          </div>
          <div className="flex items-center gap-2">
            <Shield className="w-3 h-3 text-[#00FF88]" />
            <span className="text-[10px] font-mono text-[#00FF88] uppercase tracking-wider">
              Policy Gated
            </span>
          </div>
        </div>
        
        <div className="nyx-form-container">
          <form onSubmit={handleRunTool} className="nyx-form-grid">
            <div className="nyx-form-field">
              <label className="nyx-form-label">
                <Terminal className="w-3 h-3 text-[#00FF88]" />
                Security Tool
              </label>
              <select
                value={toolName}
                onChange={(e) => setToolName(e.target.value)}
                className="nyx-select"
              >
                <option value="subfinder">subfinder (Passive)</option>
                <option value="httpx">httpx (Probe)</option>
                <option value="katana">katana (Crawler)</option>
                <option value="nuclei">nuclei (Scanner)</option>
                <option value="nmap">nmap (Port Scanner)</option>
              </select>
            </div>
            <div className="nyx-form-field">
              <label className="nyx-form-label">
                <Cpu className="w-3 h-3 text-[#00D9FF]" />
                Target Host
              </label>
              <input
                type="text"
                required
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="nyx-input"
              />
            </div>
            <div className="nyx-form-field nyx-form-checkbox">
              <label className="nyx-checkbox-label">
                <input
                  type="checkbox"
                  id="dryRun"
                  checked={dryRun}
                  onChange={(e) => setDryRun(e.target.checked)}
                  className="nyx-checkbox"
                />
                <div className="nyx-checkbox-content">
                  <Shield className="w-4 h-4 text-[#00D9FF]" />
                  <div>
                    <span className="nyx-checkbox-title">Dry-Run Mode</span>
                    <span className="nyx-checkbox-subtitle">Safe Execution</span>
                  </div>
                </div>
              </label>
            </div>
            <button
              type="submit"
              disabled={running}
              className="nyx-button nyx-button-primary nyx-button-green nyx-button-full"
            >
              {running ? (
                <>
                  <Activity className="w-4 h-4 animate-spin" />
                  <span>Executing...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Run Tool</span>
                </>
              )}
            </button>
          </form>
        </div>
      </div>

      {/* History Table */}
      <div className="nyx-card nyx-card-accent-cyan">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-cyan">
              <Clock className="w-4 h-4 text-[#00D9FF]" />
            </div>
            <h3 className="nyx-section-title">Execution History Log</h3>
            <span className="nyx-count-pill">{history.length}</span>
          </div>
          <div className="flex items-center gap-2">
            <Activity className="w-3 h-3 text-[#00D9FF]" />
            <span className="text-[10px] font-mono text-[#00D9FF] uppercase tracking-wider">
              Live Log
            </span>
          </div>
        </div>

        {history.length === 0 ? (
          <div className="nyx-empty-state">
            <div className="nyx-empty-state-icon">
              <Terminal className="w-8 h-8 text-[#484F58]" />
            </div>
            <div className="nyx-empty-state-title">No tool executions logged</div>
            <div className="nyx-empty-state-description">
              Run a controlled security tool above to begin
            </div>
          </div>
        ) : (
          <div className="nyx-execution-list">
            <div className="nyx-execution-header">
              <div className="nyx-execution-header-item">Execution ID</div>
              <div className="nyx-execution-header-item">Tool</div>
              <div className="nyx-execution-header-item">Target</div>
              <div className="nyx-execution-header-item">Status</div>
              <div className="nyx-execution-header-item">Mode</div>
              <div className="nyx-execution-header-item">Action</div>
            </div>
            <div className="nyx-execution-body">
              {history.map((h: any, idx: number) => {
                const ToolIcon = getToolIcon(h.tool_name);
                return (
                  <div key={idx} className="nyx-execution-row group">
                    <div className="nyx-execution-cell nyx-execution-id">
                      {h.execution_id || `EXEC-${idx+1}`}
                    </div>
                    <div className="nyx-execution-cell">
                      <span className="nyx-badge nyx-badge-info">
                        <ToolIcon className="w-3 h-3" />
                        {h.tool_name}
                      </span>
                    </div>
                    <div className="nyx-execution-cell nyx-execution-target">
                      {h.target}
                    </div>
                    <div className="nyx-execution-cell">
                      <span className={`nyx-badge ${getStatusBadge(h.status)}`}>
                        {h.status || 'COMPLETED'}
                      </span>
                    </div>
                    <div className="nyx-execution-cell">
                      {h.dry_run ? (
                        <span className="nyx-badge nyx-badge-info">
                          <Shield className="w-3 h-3" />
                          DRY_RUN
                        </span>
                      ) : (
                        <span className="nyx-badge nyx-badge-high">
                          <Zap className="w-3 h-3" />
                          ACTIVE
                        </span>
                      )}
                    </div>
                    <div className="nyx-execution-cell nyx-execution-actions">
                      <button
                        onClick={() => setSelectedExec(h)}
                        className="nyx-button nyx-button-secondary nyx-button-sm"
                      >
                        Details
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Modal Execution Details */}
      {selectedExec && (
        <div className="nyx-modal-overlay">
          <div className="nyx-modal nyx-modal-lg">
            <div className="nyx-modal-header">
              <div className="flex items-center gap-3">
                <div className="nyx-modal-icon">
                  <Terminal className="w-5 h-5 text-[#00FF88]" />
                </div>
                <div>
                  <h3 className="nyx-modal-title">
                    {selectedExec.execution_id || 'Execution Output'}
                  </h3>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="nyx-badge nyx-badge-info">{selectedExec.tool_name}</span>
                    <span className="nyx-badge nyx-badge-success">{selectedExec.target}</span>
                  </div>
                </div>
              </div>
              <button onClick={() => setSelectedExec(null)} className="nyx-modal-close">
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="nyx-modal-content">
              <div className="nyx-modal-details">
                <div className="nyx-modal-detail-row">
                  <div className="nyx-modal-detail-icon">
                    <Activity className="w-4 h-4 text-[#00D9FF]" />
                  </div>
                  <div>
                    <div className="nyx-modal-detail-label">Exit Code</div>
                    <div className="nyx-modal-detail-value">
                      {selectedExec.exit_code ?? 0}
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="nyx-modal-preview">
                <div className="nyx-modal-preview-header">
                  <FileCode className="w-3 h-3 text-[#00FF88]" />
                  <span className="text-[10px] font-mono text-[#00FF88] uppercase tracking-wider">
                    Standard Output (STDOUT)
                  </span>
                </div>
                <div className="nyx-modal-preview-content nyx-modal-stdout">
                  {selectedExec.stdout || '(no stdout output)'}
                </div>
              </div>
              
              {selectedExec.stderr && (
                <div className="nyx-modal-preview">
                  <div className="nyx-modal-preview-header">
                    <AlertTriangle className="w-3 h-3 text-[#FF2D55]" />
                    <span className="text-[10px] font-mono text-[#FF2D55] uppercase tracking-wider">
                      Standard Error (STDERR)
                    </span>
                  </div>
                  <div className="nyx-modal-preview-content nyx-modal-stderr">
                    {selectedExec.stderr}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};