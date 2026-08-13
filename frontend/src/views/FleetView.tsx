import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Users, Bot, ListTodo, ShieldAlert, Plus, Square, RefreshCw, CheckCircle } from 'lucide-react';

export const FleetView: React.FC = () => {
  const [fleetStatus, setFleetStatus] = useState<any>(null);
  const [createType, setCreateType] = useState<string>('recon');
  const [createTarget, setCreateTarget] = useState<string>('example.com');
  const [loading, setLoading] = useState<boolean>(false);

  async function loadFleetData() {
    const res = await fetchApi('/api/v1/fleet/status');
    if (res.success) setFleetStatus(res.data);
  }

  useEffect(() => {
    loadFleetData();
  }, []);

  async function handleCreateAgent(e: React.FormEvent) {
    e.preventDefault();
    if (!createTarget) return;
    setLoading(true);
    await fetchApi(`/api/v1/fleet/agents?type=${encodeURIComponent(createType)}&target=${encodeURIComponent(createTarget)}`, { method: 'POST' });
    await loadFleetData();
    setLoading(false);
  }

  async function handleStopAgent(agentId: string) {
    await fetchApi(`/api/v1/fleet/agents/${agentId}/stop`, { method: 'POST' });
    loadFleetData();
  }

  return (
    <div className="space-y-6">
      {/* Header Metrics */}
      <div className="glass-panel p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Users className="w-6 h-6 text-cyan-400" /> NYX Multi-Agent Distributed Fleet
          </h2>
          <p className="text-sm text-slate-400">Distributed specialized research agents with isolated sandboxes & task queue</p>
        </div>
        <div className="flex items-center gap-4 font-mono text-xs">
          <div className="px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
            Active Agents: <span className="font-bold text-white">{fleetStatus?.total_agents || 0}</span>
          </div>
          <div className="px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-emerald-300">
            Queue Tasks: <span className="font-bold text-white">{fleetStatus?.total_tasks || 0}</span>
          </div>
          <div className="px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-amber-300">
            Pending Approvals: <span className="font-bold text-white">{fleetStatus?.pending_approvals_count || 0}</span>
          </div>
          <button onClick={loadFleetData} className="p-2 rounded bg-slate-800 text-slate-300 hover:text-white">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Create Specialized Agent */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="text-md font-bold text-white flex items-center gap-2">
          <Plus className="w-5 h-5 text-emerald-400" /> Launch Specialized Agent Instance
        </h3>
        <form onSubmit={handleCreateAgent} className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div>
            <label className="text-xs font-mono text-slate-400">Specialized Agent Type</label>
            <select
              value={createType}
              onChange={(e) => setCreateType(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
            >
              <option value="recon">ReconAgent (Asset Discovery & Endpoints)</option>
              <option value="web">WebAgent (Web Attack Surface & Auth)</option>
              <option value="api">APIAgent (API & IDOR Vectors)</option>
              <option value="technology">TechnologyAgent (Stack Mapping)</option>
              <option value="validation">ValidationAgent (Triage & 7-Question Gate)</option>
              <option value="reporting">ReportingAgent (Submission Drafts)</option>
            </select>
          </div>
          <div>
            <label className="text-xs font-mono text-slate-400">Target Domain Scope</label>
            <input
              type="text"
              required
              placeholder="e.g. target.com"
              value={createTarget}
              onChange={(e) => setCreateTarget(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 text-slate-950 font-semibold text-sm rounded shadow disabled:opacity-50"
          >
            {loading ? 'Launching...' : 'Launch Agent'}
          </button>
        </form>
      </div>

      {/* Active Agent Fleet Grid */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="text-md font-bold text-white flex items-center gap-2">
          <Bot className="w-5 h-5 text-cyan-400" /> Active Fleet Instances ({fleetStatus?.agents?.length || 0})
        </h3>
        {(!fleetStatus?.agents || fleetStatus.agents.length === 0) ? (
          <div className="text-center py-6 text-slate-500 text-sm glass-card">
            No specialized agents running in fleet. Launch an instance above.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {fleetStatus.agents.map((ag: any) => (
              <div key={ag.agent_id} className="glass-card p-4 space-y-3 border-l-4 border-l-cyan-400">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-xs font-bold font-mono text-cyan-400">{ag.agent_id}</span>
                    <h4 className="text-sm font-extrabold text-white capitalize">{ag.agent_type} Agent</h4>
                    <span className="text-xs text-slate-400 font-mono">Target: <span className="text-slate-200">{ag.target}</span></span>
                  </div>
                  <button
                    onClick={() => handleStopAgent(ag.agent_id)}
                    className="px-2.5 py-1 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-xs font-semibold rounded border border-rose-500/30 flex items-center gap-1"
                  >
                    <Square className="w-3 h-3 fill-current" /> Stop
                  </button>
                </div>
                <div className="text-xs text-slate-400 font-mono space-y-1 bg-slate-950 p-2.5 rounded border border-slate-800">
                  <div>State: <span className="text-emerald-300 font-bold">{ag.agent_state}</span></div>
                  <div>Skills: <span className="text-cyan-300">{ag.allowed_skills?.join(', ')}</span></div>
                  <div>Tools: <span className="text-amber-300">{ag.allowed_tools?.join(', ')}</span></div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Task Queue View */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="text-md font-bold text-white flex items-center gap-2">
          <ListTodo className="w-5 h-5 text-emerald-400" /> Distributed Task Queue ({fleetStatus?.tasks?.length || 0})
        </h3>
        {(!fleetStatus?.tasks || fleetStatus.tasks.length === 0) ? (
          <div className="text-center py-6 text-slate-500 text-sm glass-card">
            No tasks queued. Tasks are scheduled dynamically by the DistributedScheduler.
          </div>
        ) : (
          <div className="space-y-2">
            {fleetStatus.tasks.map((tsk: any) => (
              <div key={tsk.task_id} className="glass-card p-3 flex justify-between items-center text-xs font-mono">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-emerald-400 font-bold">{tsk.task_id}</span>
                    <span className="text-white font-semibold">{tsk.task_type}</span>
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300">Priority: {tsk.priority}</span>
                  </div>
                  <div className="text-slate-400">Target: <span className="text-slate-200">{tsk.target}</span> | Agent Type: <span className="text-amber-300">{tsk.agent_type}</span></div>
                </div>
                <span className="px-2 py-1 rounded bg-slate-900 text-cyan-300 border border-slate-800 font-bold">
                  {tsk.status}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
