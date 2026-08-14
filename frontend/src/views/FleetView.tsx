import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Users, Bot, ListTodo, Plus, Square, RefreshCw, Rocket, Target, Activity, AlertCircle, Server, Cpu, Globe, Zap } from 'lucide-react';
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

  const getAgentTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'recon': return Target;
      case 'web': return Globe;
      case 'api': return Zap;
      case 'technology': return Cpu;
      case 'validation': return AlertCircle;
      case 'reporting': return Server;
      default: return Bot;
    }
  };

  const getAgentStateBadge = (state: string = 'idle') => {
    switch (state.toLowerCase()) {
      case 'running': return 'nyx-badge-success';
      case 'idle': return 'nyx-badge-low';
      case 'error': return 'nyx-badge-critical';
      case 'paused': return 'nyx-badge-high';
      default: return 'nyx-badge-info';
    }
  };

  return (
    <div className="nyx-fleet-view">
      {/* File Update Progress */}

      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div className="flex items-center gap-4">
            <div className="nyx-page-icon nyx-page-icon-purple">
              <Users className="w-6 h-6 text-[#7C3AED]" />
            </div>
            <div>
              <h1 className="nyx-page-title">Multi-Agent Fleet</h1>
              <p className="nyx-page-subtitle">Distributed specialized research agents with isolated sandboxes</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="nyx-metric-pills">
              <div className="nyx-metric-pill">
                <span className="nyx-pill-label">Active Agents</span>
                <span className="nyx-pill-value text-[#00D9FF]">{fleetStatus?.total_agents || 0}</span>
              </div>
              <div className="nyx-metric-pill">
                <span className="nyx-pill-label">Queue Tasks</span>
                <span className="nyx-pill-value text-[#00FF88]">{fleetStatus?.total_tasks || 0}</span>
              </div>
              <div className="nyx-metric-pill">
                <span className="nyx-pill-label">Pending Approvals</span>
                <span className="nyx-pill-value text-[#FF6B35]">{fleetStatus?.pending_approvals_count || 0}</span>
              </div>
            </div>
            <button onClick={loadFleetData} className="nyx-button nyx-button-ghost" title="Refresh">
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Deploy Specialized Agent Card */}
      <div className="nyx-card nyx-card-accent-purple">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-purple">
              <Rocket className="w-4 h-4 text-[#7C3AED]" />
            </div>
            <h2 className="nyx-section-title">Deploy Specialized Agent</h2>
          </div>
          <div className="flex items-center gap-2">
            <Zap className="w-3 h-3 text-[#7C3AED]" />
            <span className="text-[10px] font-mono text-[#7C3AED] uppercase tracking-wider">
              Sandboxed
            </span>
          </div>
        </div>
        
        <div className="nyx-form-container">
          <form onSubmit={handleCreateAgent} className="nyx-form-grid">
            <div className="nyx-form-field">
              <label className="nyx-form-label">
                <Bot className="w-3 h-3 text-[#7C3AED]" />
                Specialized Agent Type
              </label>
              <select
                value={createType}
                onChange={(e) => setCreateType(e.target.value)}
                className="nyx-select"
              >
                <option value="recon">ReconAgent (Asset Discovery & Endpoints)</option>
                <option value="web">WebAgent (Web Attack Surface & Auth)</option>
                <option value="api">APIAgent (API & IDOR Vectors)</option>
                <option value="technology">TechnologyAgent (Stack Mapping)</option>
                <option value="validation">ValidationAgent (Triage & 7-Question Gate)</option>
                <option value="reporting">ReportingAgent (Submission Drafts)</option>
              </select>
            </div>
            <div className="nyx-form-field">
              <label className="nyx-form-label">
                <Target className="w-3 h-3 text-[#00D9FF]" />
                Target Domain Scope
              </label>
              <input
                type="text"
                required
                placeholder="e.g. target.com"
                value={createTarget}
                onChange={(e) => setCreateTarget(e.target.value)}
                className="nyx-input"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="nyx-button nyx-button-primary nyx-button-purple nyx-button-full"
            >
              <Rocket className="w-4 h-4" />
              <span>{loading ? 'Launching...' : 'Launch Agent'}</span>
            </button>
          </form>
        </div>
      </div>

      {/* Active Fleet Instances */}
      <div className="nyx-card nyx-card-accent-cyan">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-cyan">
              <Bot className="w-4 h-4 text-[#00D9FF]" />
            </div>
            <h3 className="nyx-section-title">Active Fleet Instances</h3>
            <span className="nyx-count-pill">{fleetStatus?.agents?.length || 0}</span>
          </div>
          {fleetStatus?.agents?.length > 0 && (
            <span className="nyx-badge nyx-badge-success">
              <span className="w-1.5 h-1.5 rounded-full bg-[#00FF88] inline-block mr-1"></span>
              OPERATIONAL
            </span>
          )}
        </div>

        {(!fleetStatus?.agents || fleetStatus.agents.length === 0) ? (
          <div className="nyx-empty-state">
            <div className="nyx-empty-state-icon">
              <Bot className="w-8 h-8 text-[#484F58]" />
            </div>
            <div className="nyx-empty-state-title">Fleet is idle</div>
            <div className="nyx-empty-state-description">
              Launch a specialized agent above to begin distributed research
            </div>
          </div>
        ) : (
          <div className="nyx-agents-grid">
            {fleetStatus.agents.map((ag: any) => {
              const AgentIcon = getAgentTypeIcon(ag.agent_type);
              return (
                <div key={ag.agent_id} className="nyx-agent-card">
                  <div className="nyx-agent-header">
                    <div className="flex items-center gap-3">
                      <div className="nyx-agent-icon">
                        <AgentIcon className="w-5 h-5 text-[#00D9FF]" />
                      </div>
                      <div>
                        <span className="nyx-agent-id">{ag.agent_id}</span>
                        <h4 className="nyx-agent-type">{ag.agent_type} Agent</h4>
                      </div>
                    </div>
                    <button
                      onClick={() => handleStopAgent(ag.agent_id)}
                      className="nyx-button nyx-button-danger nyx-button-sm"
                    >
                      <Square className="w-3 h-3 fill-current" />
                      <span>Stop</span>
                    </button>
                  </div>
                  
                  <div className="nyx-agent-details">
                    <div className="nyx-agent-detail-row">
                      <span className="nyx-agent-detail-label">Target:</span>
                      <span className="nyx-agent-detail-value">{ag.target}</span>
                    </div>
                    <div className="nyx-agent-detail-row">
                      <span className="nyx-agent-detail-label">State:</span>
                      <span className={`nyx-badge ${getAgentStateBadge(ag.agent_state)}`}>
                        {ag.agent_state}
                      </span>
                    </div>
                    <div className="nyx-agent-detail-row">
                      <span className="nyx-agent-detail-label">Skills:</span>
                      <div className="flex gap-1.5 flex-wrap">
                        {ag.allowed_skills?.map((skill: string, idx: number) => (
                          <span key={idx} className="nyx-badge nyx-badge-low">{skill}</span>
                        ))}
                      </div>
                    </div>
                    <div className="nyx-agent-detail-row">
                      <span className="nyx-agent-detail-label">Tools:</span>
                      <div className="flex gap-1.5 flex-wrap">
                        {ag.allowed_tools?.map((tool: string, idx: number) => (
                          <span key={idx} className="nyx-badge nyx-badge-high">{tool}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Task Queue View */}
      <div className="nyx-card nyx-card-accent-green">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-green">
              <ListTodo className="w-4 h-4 text-[#00FF88]" />
            </div>
            <h3 className="nyx-section-title">Distributed Task Queue</h3>
            <span className="nyx-count-pill">{fleetStatus?.tasks?.length || 0}</span>
          </div>
          <div className="flex items-center gap-2">
            <Activity className="w-3 h-3 text-[#00FF88]" />
            <span className="text-[10px] font-mono text-[#00FF88] uppercase tracking-wider">
              Auto-Scheduled
            </span>
          </div>
        </div>

        {(!fleetStatus?.tasks || fleetStatus.tasks.length === 0) ? (
          <div className="nyx-empty-state">
            <div className="nyx-empty-state-icon">
              <ListTodo className="w-8 h-8 text-[#484F58]" />
            </div>
            <div className="nyx-empty-state-title">No tasks queued</div>
            <div className="nyx-empty-state-description">
              Tasks are scheduled dynamically by the DistributedScheduler
            </div>
          </div>
        ) : (
          <div className="nyx-task-list">
            {fleetStatus.tasks.map((tsk: any) => (
              <div key={tsk.task_id} className="nyx-task-item">
                <div className="flex-1 space-y-2">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="nyx-task-id">{tsk.task_id}</span>
                    <span className="nyx-task-type">{tsk.task_type}</span>
                    <span className="nyx-badge nyx-badge-info">Priority: {tsk.priority}</span>
                  </div>
                  <div className="nyx-task-detail">
                    <span className="nyx-task-label">Target:</span>
                    <span className="text-[#E6EDF3]">{tsk.target}</span>
                    <span className="mx-2 text-[#484F58]">|</span>
                    <span className="nyx-task-label">Agent:</span>
                    <span className="text-[#FF6B35]">{tsk.agent_type}</span>
                  </div>
                </div>
                <span className={`nyx-badge ${getAgentStateBadge(tsk.status)}`}>
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