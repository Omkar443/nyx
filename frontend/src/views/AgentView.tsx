import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Bot, CheckCircle, XCircle, Play, ShieldAlert, Sparkles, Clock, ArrowRight } from 'lucide-react';

export const AgentView: React.FC = () => {
  const [status, setStatus] = useState<any>(null);
  const [plan, setPlan] = useState<any>(null);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [proposeAction, setProposeAction] = useState<string>('');
  const [proposeReason, setProposeReason] = useState<string>('');
  const [proposeTool, setProposeTool] = useState<string>('subfinder');
  const [loading, setLoading] = useState<boolean>(false);

  async function loadAgentData() {
    const sRes = await fetchApi('/api/v1/agent/status');
    if (sRes.success) setStatus(sRes.data);

    const pRes = await fetchApi('/api/v1/agent/plan?target=example.com');
    if (pRes.success) setPlan(pRes.data);

    const aRes = await fetchApi('/api/v1/agent/approvals');
    if (aRes.success && aRes.data?.pending) setApprovals(aRes.data.pending);
  }

  useEffect(() => {
    loadAgentData();
  }, []);

  async function handleStartMission() {
    setLoading(true);
    await fetchApi('/api/v1/agent/start?target=example.com', { method: 'POST' });
    await loadAgentData();
    setLoading(false);
  }

  async function handleProposeAction(e: React.FormEvent) {
    e.preventDefault();
    if (!proposeAction || !proposeReason) return;
    await fetchApi(
      `/api/v1/agent/propose?target=example.com&action=${encodeURIComponent(proposeAction)}&reason=${encodeURIComponent(proposeReason)}&tool_name=${encodeURIComponent(proposeTool)}&risk=Medium`,
      { method: 'POST' }
    );
    setProposeAction('');
    setProposeReason('');
    loadAgentData();
  }

  async function handleApprove(actionId: string) {
    await fetchApi(`/api/v1/agent/approve/${actionId}`, { method: 'POST' });
    loadAgentData();
  }

  async function handleDeny(actionId: string) {
    await fetchApi(`/api/v1/agent/deny/${actionId}?reason=User+Denied+via+Dashboard`, { method: 'POST' });
    loadAgentData();
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Bot className="w-6 h-6 text-cyan-400" /> NYX Autonomous Research Agent
          </h2>
          <p className="text-sm text-slate-400">Policy-checked research planner with mandatory human approval gates</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="px-3 py-1.5 text-xs font-semibold rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-mono">
            State: {status?.agent_state || 'IDLE'}
          </span>
          <button
            onClick={handleStartMission}
            disabled={loading}
            className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 text-slate-950 font-semibold rounded-lg text-sm flex items-center gap-2 disabled:opacity-50"
          >
            <Play className="w-4 h-4 fill-current" /> {loading ? 'Starting...' : 'Start Research Mission'}
          </button>
        </div>
      </div>

      {/* Human Approval Queue */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="text-md font-bold text-white flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-amber-400" /> Human Approval Queue ({approvals.length})
        </h3>
        {approvals.length === 0 ? (
          <div className="text-center py-6 text-slate-500 text-sm glass-card">
            No actions pending human sign-off. All active executions require explicit approval.
          </div>
        ) : (
          <div className="space-y-3">
            {approvals.map((app: any) => (
              <div key={app.action_id} className="glass-card p-4 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-l-4 border-l-amber-400">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-amber-400 font-mono">{app.action_id}</span>
                    <span className="text-sm font-semibold text-white">{app.action}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono">{app.tool_name}</span>
                  </div>
                  <div className="text-xs text-slate-400 font-mono">Reasoning: <span className="text-slate-300">{app.reason}</span></div>
                  <div className="text-xs text-slate-500 font-mono">Risk Level: <span className="text-amber-300 font-semibold">{app.risk || 'Medium'}</span> | Confidence: <span className="text-emerald-300">{app.confidence || 85}%</span></div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleApprove(app.action_id)}
                    className="px-3 py-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 text-xs font-semibold rounded border border-emerald-500/30 flex items-center gap-1"
                  >
                    <CheckCircle className="w-3.5 h-3.5" /> Approve
                  </button>
                  <button
                    onClick={() => handleDeny(app.action_id)}
                    className="px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-xs font-semibold rounded border border-rose-500/30 flex items-center gap-1"
                  >
                    <XCircle className="w-3.5 h-3.5" /> Deny
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Propose Action Form */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="text-md font-bold text-white flex items-center gap-2">
          <Sparkles className="w-5 h-5 text-cyan-400" /> Propose Security Action
        </h3>
        <form onSubmit={handleProposeAction} className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
          <div>
            <label className="text-xs font-mono text-slate-400">Proposed Action</label>
            <input
              type="text"
              required
              placeholder="e.g. Test IDOR vulnerability on user API"
              value={proposeAction}
              onChange={(e) => setProposeAction(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
            />
          </div>
          <div>
            <label className="text-xs font-mono text-slate-400">Reasoning</label>
            <input
              type="text"
              required
              placeholder="e.g. Parameter contains sequential ID"
              value={proposeReason}
              onChange={(e) => setProposeReason(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
            />
          </div>
          <div>
            <label className="text-xs font-mono text-slate-400">Required Tool</label>
            <select
              value={proposeTool}
              onChange={(e) => setProposeTool(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
            >
              <option value="subfinder">subfinder</option>
              <option value="httpx">httpx</option>
              <option value="katana">katana</option>
              <option value="nuclei">nuclei</option>
            </select>
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-slate-950 font-semibold text-sm rounded shadow"
          >
            Submit Proposal
          </button>
        </form>
      </div>

      {/* Active Research Plan */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="text-md font-bold text-white flex items-center gap-2">
          <Clock className="w-5 h-5 text-emerald-400" /> Active Autonomous Research Plan
        </h3>
        {plan ? (
          <div className="space-y-3 font-mono text-xs text-slate-300">
            <div className="bg-slate-950 p-4 rounded text-emerald-300 space-y-2">
              <div>Priority: <span className="text-white font-bold">{plan.priority || 'HIGH'}</span></div>
              <div>Reasoning: <span className="text-slate-200">{plan.reasoning}</span></div>
              <div>Recommended Skills: <span className="text-cyan-300">{plan.recommended_skills?.join(', ')}</span></div>
            </div>
            <div className="space-y-1">
              <div className="text-slate-400 font-bold mb-2">Research Objectives:</div>
              {plan.objectives?.map((obj: string, idx: number) => (
                <div key={idx} className="flex items-center gap-2 p-2 rounded bg-slate-900/60 border border-slate-800">
                  <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span>{obj}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="text-center py-6 text-slate-500 text-sm">
            No research plan generated yet.
          </div>
        )}
      </div>
    </div>
  );
};
