import React, { useState, useEffect } from 'react';
import { Shield, CheckCircle, XCircle, AlertTriangle, Clock, RefreshCw, Plus, AlertOctagon, ShieldAlert, ArrowRight } from 'lucide-react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';
import { useApp } from '../context/AppContext';

export function AgentView() {
  const { target, refreshGlobalStats } = useApp();
  const { lastEvent } = useNyxEvents();
  const [approvals, setApprovals] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [isProposing, setIsProposing] = useState<boolean>(false);
  const [confirmingApproval, setConfirmingApproval] = useState<any | null>(null);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [toolName, setToolName] = useState('nuclei');
  const [targetScope, setTargetScope] = useState(target || '');
  const [reason, setReason] = useState('Active parameter injection validation');

  async function loadApprovals() {
    try {
      const res = await fetchApi('/api/v1/agent/approvals');
      const list = res?.data?.pending || res?.data?.approvals || res?.approvals || (Array.isArray(res?.data) ? res.data : []);
      if (Array.isArray(list)) {
        setApprovals(list);
      }
    } catch {
      // Graceful fallback
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadApprovals();
  }, [target]);

  useEffect(() => {
    if (lastEvent) {
      loadApprovals();
      refreshGlobalStats();
    }
  }, [lastEvent, refreshGlobalStats]);

  async function handleApproveConfirmed(id: string) {
    setIsProcessing(true);
    try {
      await fetchApi(`/api/v1/agent/approve/${encodeURIComponent(id)}`, { method: 'POST' });
      setConfirmingApproval(null);
      await loadApprovals();
      await refreshGlobalStats();
    } catch {
      // Handled
    } finally {
      setIsProcessing(false);
    }
  }

  async function handleDeny(id: string) {
    try {
      await fetchApi(`/api/v1/agent/deny/${encodeURIComponent(id)}`, { method: 'POST' });
      await loadApprovals();
      await refreshGlobalStats();
    } catch {
      // Handled
    }
  }

  async function handleProposeAction(e: React.FormEvent) {
    e.preventDefault();
    try {
      const url = `/api/v1/agent/propose?target=${encodeURIComponent(targetScope || target)}&action=Execute+${encodeURIComponent(toolName)}&reason=${encodeURIComponent(reason)}&tool_name=${encodeURIComponent(toolName)}&risk=High`;
      await fetchApi(url, { method: 'POST' });
      await loadApprovals();
      await refreshGlobalStats();
      setIsProposing(false);
    } catch {
      setIsProposing(false);
    }
  }

  const pendingList = approvals.filter(a => (a.status === 'PENDING' || a.status === 'PENDING_APPROVAL' || !a.status));

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Human Approval Gate &amp; Action Queue
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <Shield className="w-3.5 h-3.5 text-[#555555]" />
            Operator authorization gate for destructive actions, active probes, and safety pauses
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-[#ebb94b] bg-[#ebb94b]/10 border border-[#ebb94b]/25 px-2.5 py-1 rounded">
            {pendingList.length} Pending Review
          </span>
          <button onClick={() => setIsProposing(true)} className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1">
            <Plus className="w-3.5 h-3.5" />
            <span>Propose Action</span>
          </button>
        </div>
      </div>

      {/* ========== APPROVAL CARDS ========== */}
      {approvals.length === 0 ? (
        <div className="card text-center py-16 space-y-2">
          <Shield className="w-8 h-8 text-[#555555] mx-auto opacity-50" />
          <p className="text-xs text-[#888888] font-mono">No pending actions in the approval queue.</p>
          <p className="text-[11px] text-[#555555]">Autonomous agents request operator authorization before executing destructive tests.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {approvals.map((a, idx) => {
            const isPending = a.status === 'PENDING' || a.status === 'PENDING_APPROVAL' || !a.status;
            const actionId = a.action_id || a.id || `ACT-${idx + 1}`;
            const impactClass = a.impact_class || (a.risk === 'High' ? 'DESTRUCTIVE' : 'ACTIVE_TEST');
            const tool = a.tool_name || a.tool || 'Security Tool';
            const just = a.impact_justification || a.reason || a.action || 'Manual operator authorization required.';
            const tgt = a.target || target;

            return (
              <div key={actionId} className="card flex flex-col sm:flex-row sm:items-center justify-between gap-3 border border-[#3A3A3A] bg-[#222222]">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-[#ebb94b]">{actionId}</span>
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded bg-[#303030] text-[#CCCCCC] border border-[#404040]">
                      {tool}
                    </span>
                    <span className={`text-[10px] font-mono uppercase px-1.5 py-0.2 rounded border font-bold ${
                      impactClass === 'DESTRUCTIVE' ? 'text-[#EF5350] bg-[#EF5350]/15 border-[#EF5350]/30' :
                      'text-[#FFA726] bg-[#FFA726]/15 border-[#FFA726]/30'
                    }`}>
                      {impactClass}
                    </span>
                    <span className={`text-[10px] font-mono uppercase px-1.5 py-0.2 rounded border ${
                      a.status === 'APPROVED' ? 'text-[#4CAF50] bg-[#4CAF50]/15 border-[#4CAF50]/30' :
                      a.status === 'DENIED' ? 'text-[#EF5350] bg-[#EF5350]/15 border-[#EF5350]/30' :
                      'text-[#FFA726] bg-[#FFA726]/15 border-[#FFA726]/30'
                    }`}>
                      {a.status || 'PENDING_APPROVAL'}
                    </span>
                  </div>
                  <p className="text-xs text-[#E8E8E8] font-semibold">{a.action || a.name || 'Proposed Gated Action'}</p>
                  <p className="text-[11px] text-[#888888] font-mono">{just}</p>
                  <p className="text-[11px] font-mono text-[#707070]">Target: <span className="text-[#CCCCCC]">{tgt}</span></p>
                </div>

                {isPending && (
                  <div className="flex items-center gap-2 shrink-0">
                    <button 
                      onClick={() => setConfirmingApproval(a)} 
                      className="btn-primary text-xs py-1.5 px-3"
                    >
                      Approve Action
                    </button>
                    <button 
                      onClick={() => handleDeny(actionId)} 
                      className="btn-secondary text-xs py-1.5 px-3 text-[#EF5350]"
                    >
                      Deny
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ========== APPROVE CONFIRMATION MODAL ========== */}
      {confirmingApproval && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 animate-fadeIn">
          <div className="card max-w-lg w-full space-y-4 border border-[#EF5350]/50 bg-[#1E1E1E]">
            <div className="flex items-center justify-between pb-2 border-b border-[#333333]">
              <div className="flex items-center gap-2 text-[#EF5350]">
                <ShieldAlert className="w-5 h-5" />
                <h3 className="text-sm font-bold">Authorize Gated Action</h3>
              </div>
              <button onClick={() => setConfirmingApproval(null)} className="text-[#888888] hover:text-white">✕</button>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <p className="text-[#FFA726] bg-[#FFA726]/10 border border-[#FFA726]/20 p-2.5 rounded">
                WARNING: You are authorizing active execution on a potentially destructive or high-impact test. Review all parameters below before confirming.
              </p>
              <div className="space-y-1.5 p-3 rounded bg-[#242424] border border-[#333333]">
                <div className="flex justify-between">
                  <span className="text-[#888888]">Action ID:</span>
                  <span className="text-[#ebb94b] font-bold">{confirmingApproval.action_id || confirmingApproval.id || 'ACT-ID'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#888888]">Target Endpoint:</span>
                  <span className="text-[#E8E8E8]">{confirmingApproval.target || target}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#888888]">Security Tool:</span>
                  <span className="text-[#E8E8E8]">{confirmingApproval.tool_name || confirmingApproval.tool || 'nuclei'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#888888]">Impact Classification:</span>
                  <span className="text-[#EF5350] font-bold">{confirmingApproval.impact_class || (confirmingApproval.risk === 'High' ? 'DESTRUCTIVE' : 'ACTIVE_TEST')}</span>
                </div>
                <div className="pt-1">
                  <span className="text-[#888888] block mb-0.5">Impact Justification:</span>
                  <p className="text-[#CCCCCC]">{confirmingApproval.impact_justification || confirmingApproval.reason || confirmingApproval.action}</p>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-[#333333]">
              <button 
                type="button" 
                onClick={() => setConfirmingApproval(null)} 
                className="btn-secondary text-xs py-1.5 px-3"
              >
                Cancel
              </button>
              <button 
                type="button" 
                disabled={isProcessing}
                onClick={() => handleApproveConfirmed(confirmingApproval.action_id || confirmingApproval.id)} 
                className="btn-primary text-xs py-1.5 px-3.5 bg-[#EF5350] hover:bg-[#D32F2F] text-white border-none flex items-center gap-1.5"
              >
                {isProcessing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />}
                <span>{isProcessing ? 'Authorizing...' : 'Confirm & Authorize Execution'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========== PROPOSE MODAL ========== */}
      {isProposing && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-fadeIn">
          <div className="card max-w-md w-full space-y-3 border border-[#4A4A4A]">
            <div className="flex items-center justify-between pb-2 border-b border-[#333333]">
              <h3 className="text-sm font-bold text-[#F2F2F2]">Propose Gated Action</h3>
              <button onClick={() => setIsProposing(false)} className="text-[#888888] hover:text-white">✕</button>
            </div>

            <form onSubmit={handleProposeAction} className="space-y-3 text-xs">
              <div>
                <label className="text-[#888888] block mb-1">Target Endpoint</label>
                <input
                  type="text"
                  required
                  value={targetScope || target}
                  onChange={(e) => setTargetScope(e.target.value)}
                  className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs font-mono text-[#E8E8E8] focus:outline-none"
                />
              </div>

              <div>
                <label className="text-[#888888] block mb-1">Security Tool</label>
                <select
                  value={toolName}
                  onChange={(e) => setToolName(e.target.value)}
                  className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-2.5 py-1.5 text-xs text-[#E8E8E8] focus:outline-none"
                >
                  <option value="nuclei">nuclei (CVE Template Runner)</option>
                  <option value="sqlmap">sqlmap (SQL Injection Fuzzer)</option>
                  <option value="ffuf">ffuf (Heavy Directory Fuzzer)</option>
                  <option value="wpscan">wpscan (WordPress Vulnerability Prober)</option>
                </select>
              </div>

              <div>
                <label className="text-[#888888] block mb-1">Operational Justification</label>
                <textarea
                  rows={2}
                  required
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs font-mono text-[#E8E8E8] focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-[#333333]">
                <button type="button" onClick={() => setIsProposing(false)} className="btn-secondary text-xs py-1.5 px-3">
                  Cancel
                </button>
                <button type="submit" className="btn-primary text-xs py-1.5 px-3">
                  Submit for Approval
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default AgentView;
