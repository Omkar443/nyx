import React, { useState, useEffect } from 'react';
import { 
  Server, Bot, Plus, RefreshCw, Rocket, 
  Activity, Shield, Lock, Search, Filter, ChevronRight, XCircle, Play
} from 'lucide-react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';
import { useApp } from '../context/AppContext';

export function FleetView() {
  const { target, refreshGlobalStats } = useApp();
  const { lastEvent } = useNyxEvents();
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDeploying, setIsDeploying] = useState(false);
  const [agentRole, setAgentRole] = useState('Recon Specialist');
  const [agentType, setAgentType] = useState('recon');

  async function loadFleet() {
    try {
      const res = await fetchApi('/api/v1/fleet/agents');
      const list = res?.data?.agents || res?.agents || [];
      if (Array.isArray(list)) {
        setAgents(list);
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadFleet();
  }, []);

  useEffect(() => {
    if (lastEvent) {
      loadFleet();
      refreshGlobalStats();
    }
  }, [lastEvent, refreshGlobalStats]);

  async function handleDeployAgent(e: React.FormEvent) {
    e.preventDefault();
    try {
      await fetchApi('/api/v1/fleet/agents', {
        method: 'POST',
        body: JSON.stringify({
          name: agentRole,
          type: agentType,
          target: target,
          capabilities: [agentType, 'reporting']
        })
      });
      setIsDeploying(false);
      await loadFleet();
      await refreshGlobalStats();
    } catch {
      setIsDeploying(false);
    }
  }

  async function handleStopAgent(agentId: string) {
    try {
      await fetchApi(`/api/v1/fleet/agents/${agentId}/stop`, { method: 'POST' });
      await loadFleet();
      await refreshGlobalStats();
    } catch {
      // Handled
    }
  }

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Specialized Agent Fleet
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <Server className="w-3.5 h-3.5 text-[#555555]" />
            Multi-agent research swarm with isolated memory and task dispatch &nbsp;·&nbsp; {agents.length} active operatives
          </p>
        </div>
        <button onClick={() => setIsDeploying(true)} className="btn-primary flex items-center gap-1 text-xs py-1.5 px-3">
          <Rocket className="w-3.5 h-3.5" />
          <span>Deploy Swarm Agent</span>
        </button>
      </div>

      {/* ========== FLEET CARDS ========== */}
      {agents.length === 0 ? (
        <div className="card text-center py-16 space-y-3">
          <Bot className="w-8 h-8 text-[#555555] mx-auto opacity-50" />
          <p className="text-xs text-[#888888] font-mono">No specialized agents currently deployed.</p>
          <button onClick={() => setIsDeploying(true)} className="btn-primary text-xs py-1.5 px-3">
            Deploy First Operative
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {agents.map((ag) => (
            <div key={ag.id} className="card space-y-3 border border-[#3A3A3A]">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Bot className="w-4 h-4 text-[#ebb94b]" />
                  <span className="font-mono text-xs font-bold text-[#E8E8E8]">{ag.id}</span>
                </div>
                <span className={`text-[10px] font-mono uppercase px-1.5 py-0.2 rounded border ${
                  ag.status === 'running' ? 'text-[#4CAF50] bg-[#4CAF50]/15 border-[#4CAF50]/30' : 'text-[#888888] bg-[#333333]'
                }`}>
                  {ag.status || 'idle'}
                </span>
              </div>

              <div>
                <h3 className="text-xs font-bold text-[#F2F2F2]">{ag.name}</h3>
                <p className="text-[11px] font-mono text-[#707070] mt-0.5">Target: {ag.target || target}</p>
              </div>

              <div className="flex items-center justify-between text-[10px] font-mono text-[#666666] pt-2 border-t border-[#2A2A2A]">
                <span>Type: {ag.type}</span>
                <button onClick={() => handleStopAgent(ag.id)} className="text-[#EF5350] hover:underline">
                  Stop Agent
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ========== DEPLOY MODAL ========== */}
      {isDeploying && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50 animate-fadeIn">
          <div className="card max-w-md w-full space-y-3 border border-[#4A4A4A]">
            <div className="flex items-center justify-between pb-2 border-b border-[#333333]">
              <h3 className="text-sm font-bold text-[#F2F2F2]">Deploy Specialized Agent</h3>
              <button onClick={() => setIsDeploying(false)} className="text-[#888888] hover:text-white">✕</button>
            </div>

            <form onSubmit={handleDeployAgent} className="space-y-3 text-xs">
              <div>
                <label className="text-[#888888] block mb-1">Agent Name / Job Title</label>
                <input
                  type="text"
                  required
                  value={agentRole}
                  onChange={(e) => setAgentRole(e.target.value)}
                  className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs text-[#E8E8E8] focus:outline-none"
                />
              </div>

              <div>
                <label className="text-[#888888] block mb-1">Agent Specialization</label>
                <select
                  value={agentType}
                  onChange={(e) => setAgentType(e.target.value)}
                  className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-2.5 py-1.5 text-xs text-[#E8E8E8] focus:outline-none"
                >
                  <option value="recon">Reconnaissance Operative</option>
                  <option value="crawler">HTTP Surface Crawler</option>
                  <option value="api">API Protocol Prober</option>
                  <option value="reporting">Findings Synthesizer</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-[#333333]">
                <button type="button" onClick={() => setIsDeploying(false)} className="btn-secondary text-xs py-1.5 px-3">
                  Cancel
                </button>
                <button type="submit" className="btn-primary text-xs py-1.5 px-3">
                  Deploy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default FleetView;
