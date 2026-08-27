import React, { useState, useEffect } from 'react';
import { Shield, CheckCircle, XCircle, AlertTriangle, Clock, RefreshCw, Plus } from 'lucide-react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';
import { useApp } from '../context/AppContext';

export function AgentView() {
  const { target, refreshGlobalStats } = useApp();
  const { lastEvent } = useNyxEvents();
  const [approvals, setApprovals] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [isProposing, setIsProposing] = useState<boolean>(false);
  const [toolName, setToolName] = useState('sqlmap');
  const [targetScope, setTargetScope] = useState(target);
  const [reason, setReason] = useState('Active parameter injection validation');

  async function loadApprovals() {
    try {
      const res = await fetchApi('/api/v1/agent/approvals');
      const list = res?.data?.approvals || res?.approvals || [];
      if (Array.isArray(list)) {
        setApprovals(list);
      }
    } catch {
      // Fallback
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

  async function handleDecision(id: string, decision: 'APPROVED' | 'DENIED') {
    try {
      const endpoint = decision === 'APPROVED' ? `/api/v1/agent/approve/${id}` : `/api/v1/agent/deny/${id}`;
      await fetchApi(endpoint, { method: 'POST' });
      await loadApprovals();
      await refreshGlobalStats();
    } catch {
      // Handled
    }
  }

  async function handleProposeAction(e: React.FormEvent) {
    e.preventDefault();
    try {
      const url = `/api/v1/agent/propose?target=${encodeURIComponent(targetScope)}&action=Execute+${toolName}&reason=${encodeURIComponent(reason)}&tool_name=${toolName}&risk=High`;
      await fetchApi(url, { method: 'POST' });
      await loadApprovals();
      await refreshGlobalStats();
      setIsProposing(false);
    } catch {
      setIsProposing(false);
    }
  }

  const pendingList = approvals.filter(a => a.status === 'PENDING');

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
            Operator authorization gate for potentially high-impact or active fuzzing actions
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
          {approvals.map((a) => {
            const isPending = a.status === 'PENDING';
            return (
              <div key={a.id} className="card flex flex-col sm:flex-row sm:items-center justify-between gap-3 border border-[#3A3A3A]">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-[#ebb94b]">{a.id}</span>
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded bg-[#303030] text-[#CCCCCC] border border-[#404040]">
                      {a.tool || a.tool_name || 'Tool'}
                    </span>
                    <span className={`text-[10px] font-mono uppercase px-1.5 py-0.2 rounded border ${
                      a.status === 'APPROVED' ? 'text-[#4CAF50] bg-[#4CAF50]/15 border-[#4CAF50]/30' :
                      a.status === 'DENIED' ? 'text-[#EF5350] bg-[#EF5350]/15 border-[#EF5350]/30' :
                      'text-[#FFA726] bg-[#FFA726]/15 border-[#FFA726]/30'
                    }`}>
                      {a.status}
                    </span>
                  </div>
                  <p className="text-xs text-[#E8E8E8] font-semibold">{a.reason}</p>
                  <p className="text-[11px] font-mono text-[#707070]">{a.target}</p>
                </div>

                {isPending && (
                  <div className="flex items-center gap-2 shrink-0">
                    <button onClick={() => handleDecision(a.id, 'APPROVED')} className="btn-primary text-xs py-1.5 px-3">
                      Approve Action
                    </button>
                    <button onClick={() => handleDecision(a.id, 'DENIED')} className="btn-secondary text-xs py-1.5 px-3 text-[#EF5350]">
                      Deny
                    </button>
                  </div>
                )}
              </div>
            );
          })}
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
                  value={targetScope}
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
                  <option value="sqlmap">sqlmap (SQL Injection Fuzzer)</option>
                  <option value="nuclei">nuclei (CVE Template Runner)</option>
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
                  className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs text-[#E8E8E8] focus:outline-none"
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
