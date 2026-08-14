import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Bot, CheckCircle, XCircle, Play, ShieldAlert, Sparkles, Clock, ArrowRight, Brain, Zap, Lock } from 'lucide-react';
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

  const getAgentStateBadge = (state: string = 'IDLE') => {
    switch (state.toLowerCase()) {
      case 'running':
        return 'nyx-badge-success';
      case 'planning':
        return 'nyx-badge-info';
      case 'waiting_approval':
        return 'nyx-badge-high';
      case 'idle':
        return 'nyx-badge-low';
      default:
        return 'nyx-badge-info';
    }
  };

  return (
    <div className="nyx-agent-view">
      {/* File Update Progress */}

      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div className="flex items-center gap-4">
            <div className="nyx-page-icon nyx-page-icon-purple">
              <Brain className="w-6 h-6 text-[#7C3AED]" />
            </div>
            <div>
              <h1 className="nyx-page-title">AI Agent Assistant</h1>
              <p className="nyx-page-subtitle">Policy-checked research planner with mandatory human approval gates</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="nyx-status-pill">
              <div className={`nyx-status-dot ${status?.agent_state === 'RUNNING' ? 'nyx-status-dot-live' : 'nyx-status-dot-idle'}`}></div>
              <span className={`nyx-badge ${getAgentStateBadge(status?.agent_state || 'IDLE')}`}>
                {status?.agent_state || 'IDLE'}
              </span>
            </div>
            <button
              onClick={handleStartMission}
              disabled={loading}
              className="nyx-button nyx-button-primary"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>{loading ? 'Starting...' : 'Start Research Mission'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Human Approval Queue */}
      <div className="nyx-card nyx-card-accent-amber">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-amber">
              <ShieldAlert className="w-4 h-4 text-[#FF6B35]" />
            </div>
            <h3 className="nyx-section-title">Human Approval Queue</h3>
            <span className="nyx-count-pill">{approvals.length}</span>
          </div>
          <div className="flex items-center gap-2">
            <Lock className="w-3 h-3 text-[#484F58]" />
            <span className="text-[10px] font-mono text-[#484F58] uppercase tracking-wider">
              Mandatory Sign-off
            </span>
          </div>
        </div>

        {approvals.length === 0 ? (
          <div className="nyx-empty-state">
            <div className="nyx-empty-state-icon">
              <ShieldAlert className="w-8 h-8 text-[#484F58]" />
            </div>
            <div className="nyx-empty-state-title">No actions pending human sign-off</div>
            <div className="nyx-empty-state-description">
              All active executions require explicit approval before execution
            </div>
          </div>
        ) : (
          <div className="nyx-approval-list">
            {approvals.map((app: any) => (
              <div key={app.action_id} className="nyx-approval-item">
                <div className="flex-1 space-y-2">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="nyx-approval-id">{app.action_id}</span>
                    <span className="nyx-approval-action">{app.action}</span>
                    <span className="nyx-badge nyx-badge-low">{app.tool_name}</span>
                  </div>
                  <div className="nyx-approval-detail">
                    <span className="nyx-approval-label">Reasoning:</span>
                    <span className="text-[#E6EDF3]">{app.reason}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="nyx-approval-detail">
                      <span className="nyx-approval-label">Risk:</span>
                      <span className="nyx-badge nyx-badge-high">{app.risk || 'Medium'}</span>
                    </div>
                    <div className="nyx-approval-detail">
                      <span className="nyx-approval-label">Confidence:</span>
                      <span className="nyx-badge nyx-badge-success">{app.confidence || 85}%</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleApprove(app.action_id)}
                    className="nyx-button nyx-button-success"
                  >
                    <CheckCircle className="w-4 h-4" />
                    <span>Approve</span>
                  </button>
                  <button
                    onClick={() => handleDeny(app.action_id)}
                    className="nyx-button nyx-button-danger"
                  >
                    <XCircle className="w-4 h-4" />
                    <span>Deny</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Propose Action Form */}
      <div className="nyx-card nyx-card-accent-cyan">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-cyan">
              <Sparkles className="w-4 h-4 text-[#00D9FF]" />
            </div>
            <h3 className="nyx-section-title">Propose Security Action</h3>
          </div>
          <div className="flex items-center gap-2">
            <Zap className="w-3 h-3 text-[#00D9FF]" />
            <span className="text-[10px] font-mono text-[#00D9FF] uppercase tracking-wider">
              AI Assisted
            </span>
          </div>
        </div>
        
        <div className="nyx-form-container">
          <form onSubmit={handleProposeAction} className="nyx-form-grid">
            <div className="nyx-form-field">
              <label className="nyx-form-label">
                <Bot className="w-3 h-3 text-[#00D9FF]" />
                Proposed Action
              </label>
              <input
                type="text"
                required
                placeholder="e.g. Test IDOR on profile endpoint"
                value={proposeAction}
                onChange={(e) => setProposeAction(e.target.value)}
                className="nyx-input"
              />
            </div>
            <div className="nyx-form-field">
              <label className="nyx-form-label">
                <Brain className="w-3 h-3 text-[#7C3AED]" />
                Reasoning
              </label>
              <input
                type="text"
                required
                placeholder="e.g. Sequential identifier in query"
                value={proposeReason}
                onChange={(e) => setProposeReason(e.target.value)}
                className="nyx-input"
              />
            </div>
            <div className="nyx-form-field">
              <label className="nyx-form-label">
                <Zap className="w-3 h-3 text-[#FF6B35]" />
                Required Tool
              </label>
              <select
                value={proposeTool}
                onChange={(e) => setProposeTool(e.target.value)}
                className="nyx-select"
              >
                <option value="subfinder">subfinder</option>
                <option value="httpx">httpx</option>
                <option value="katana">katana</option>
                <option value="nuclei">nuclei</option>
              </select>
            </div>
            <button
              type="submit"
              className="nyx-button nyx-button-primary nyx-button-full"
            >
              <Sparkles className="w-4 h-4" />
              Submit Proposal
            </button>
          </form>
        </div>
      </div>

      {/* Active Research Plan */}
      <div className="nyx-card nyx-card-accent-green">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-green">
              <Clock className="w-4 h-4 text-[#00FF88]" />
            </div>
            <h3 className="nyx-section-title">Active Autonomous Research Plan</h3>
          </div>
          {plan && (
            <span className="nyx-badge nyx-badge-success">
              ACTIVE
            </span>
          )}
        </div>

        {plan ? (
          <div className="nyx-plan-container">
            <div className="nyx-plan-summary">
              <div className="flex items-center gap-3">
                <span className="nyx-plan-label">Priority:</span>
                <span className="nyx-badge nyx-badge-high">{plan.priority || 'HIGH'}</span>
              </div>
              <div className="nyx-plan-detail">
                <span className="nyx-plan-label">Reasoning:</span>
                <span className="text-[#8B949E]">{plan.reasoning}</span>
              </div>
              <div className="nyx-plan-detail">
                <span className="nyx-plan-label">Recommended Skills:</span>
                <div className="flex gap-2 flex-wrap">
                  {plan.recommended_skills?.map((skill: string, idx: number) => (
                    <span key={idx} className="nyx-badge nyx-badge-info">{skill}</span>
                  ))}
                </div>
              </div>
            </div>
            
            <div className="nyx-plan-objectives">
              <div className="nyx-plan-objectives-header">
                <span className="nyx-plan-label">Research Objectives:</span>
                <span className="nyx-count-pill">{plan.objectives?.length || 0}</span>
              </div>
              <div className="nyx-objectives-list">
                {plan.objectives?.map((obj: string, idx: number) => (
                  <div key={idx} className="nyx-objective-item">
                    <div className="nyx-objective-icon">
                      <ArrowRight className="w-3.5 h-3.5 text-[#00FF88]" />
                    </div>
                    <span className="nyx-objective-text">{obj}</span>
                    <span className="nyx-objective-index">{String(idx + 1).padStart(2, '0')}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="nyx-empty-state">
            <div className="nyx-empty-state-icon">
              <Bot className="w-8 h-8 text-[#484F58]" />
            </div>
            <div className="nyx-empty-state-title">No research plan generated yet</div>
            <div className="nyx-empty-state-description">
              Start a research mission to generate an autonomous security plan
            </div>
          </div>
        )}
      </div>
    </div>
  );
};