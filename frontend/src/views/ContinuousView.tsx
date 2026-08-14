import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Activity, Bell, Shield, Sparkles, RefreshCw, Play, CheckCircle, History, Radar, Database, AlertTriangle, Target, Zap, Lock } from 'lucide-react';
export const ContinuousView: React.FC = () => {
  const [monitoringStatus, setMonitoringStatus] = useState<any>(null);
  const [changes, setChanges] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [opportunities, setOpportunities] = useState<any[]>([]);
  const [knowledgeStatus, setKnowledgeStatus] = useState<any>(null);
  const [target, setTarget] = useState<string>('example.com');
  const [loading, setLoading] = useState<boolean>(false);

  async function loadContinuousData() {
    const mRes = await fetchApi('/api/v1/continuous/monitor/status');
    if (mRes.success) setMonitoringStatus(mRes.data);

    const cRes = await fetchApi('/api/v1/continuous/changes');
    if (cRes.success) setChanges(cRes.data.changes || []);

    const aRes = await fetchApi('/api/v1/continuous/alerts');
    if (aRes.success) setAlerts(aRes.data.alerts || []);

    const oRes = await fetchApi('/api/v1/continuous/research/opportunities');
    if (oRes.success) setOpportunities(oRes.data.opportunities || []);

    const kRes = await fetchApi('/api/v1/continuous/knowledge/verify');
    if (kRes.success) setKnowledgeStatus(kRes.data);
  }

  useEffect(() => {
    loadContinuousData();
  }, []);

  async function handleStartMonitoring(e: React.FormEvent) {
    e.preventDefault();
    if (!target) return;
    setLoading(true);
    await fetchApi(`/api/v1/continuous/monitor/start?target=${encodeURIComponent(target)}`, { method: 'POST' });
    await loadContinuousData();
    setLoading(false);
  }

  async function handleBackupKnowledge() {
    await fetchApi('/api/v1/continuous/knowledge/backup', { method: 'POST' });
    loadContinuousData();
  }

  const getMonitoringStatusBadge = () => {
    if (!monitoringStatus) return 'nyx-badge-info';
    if (monitoringStatus.active) return 'nyx-badge-success';
    return 'nyx-badge-low';
  };

  return (
    <div className="nyx-continuous-view">
      {/* File Update Progress */}

      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div className="flex items-center gap-4">
            <div className="nyx-page-icon nyx-page-icon-cyan">
              <Activity className="w-6 h-6 text-[#00D9FF]" />
            </div>
            <div>
              <h1 className="nyx-page-title">Continuous Intelligence</h1>
              <p className="nyx-page-subtitle">Attack surface monitoring with automated change detection</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleBackupKnowledge}
              className="nyx-button nyx-button-secondary"
            >
              <Database className="w-4 h-4 text-[#00D9FF]" />
              <span>Backup Knowledge</span>
            </button>
            <button onClick={loadContinuousData} className="nyx-button nyx-button-ghost" title="Refresh">
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Launch Surface Monitoring Watcher */}
      <div className="nyx-card nyx-card-accent-cyan">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-green">
              <Radar className="w-4 h-4 text-[#00FF88]" />
            </div>
            <h2 className="nyx-section-title">Launch Surface Monitoring Watcher</h2>
          </div>
          <div className="flex items-center gap-2">
            <span className={`nyx-badge ${getMonitoringStatusBadge()}`}>
              {monitoringStatus?.active ? 'ACTIVE' : 'STANDBY'}
            </span>
          </div>
        </div>
        
        <div className="nyx-form-container">
          <form onSubmit={handleStartMonitoring} className="nyx-form-inline">
            <div className="nyx-form-field nyx-form-field-grow">
              <label className="nyx-form-label">
                <Target className="w-3 h-3 text-[#00D9FF]" />
                Target Domain
              </label>
              <input
                type="text"
                required
                placeholder="e.g. target.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="nyx-input"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="nyx-button nyx-button-primary"
            >
              {loading ? (
                <>
                  <Activity className="w-4 h-4 animate-spin" />
                  <span>Starting...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Start Monitoring Job</span>
                </>
              )}
            </button>
          </form>
        </div>
      </div>

      {/* Knowledge Integrity & Active Alerts Grid */}
      <div className="nyx-status-grid">
        {/* Knowledge Status */}
        <div className="nyx-status-card nyx-status-card-green">
          <div className="nyx-status-card-content">
            <div className="nyx-status-card-header">
              <div className="nyx-status-card-icon">
                <Shield className="w-5 h-5 text-[#00FF88]" />
              </div>
              <span className="nyx-status-card-label">Knowledge Asset Status</span>
            </div>
            <div className="nyx-status-card-value">
              <CheckCircle className="w-4 h-4 text-[#00FF88]" />
              <span className="nyx-data-value">{knowledgeStatus?.total_skills_count || 0}</span>
              <span className="nyx-status-card-text">Skills Verified Intact</span>
            </div>
          </div>
          <span className="nyx-badge nyx-badge-success">PROTECTED</span>
        </div>

        {/* Live Alerts */}
        <div className="nyx-status-card nyx-status-card-cyan">
          <div className="nyx-status-card-content">
            <div className="nyx-status-card-header">
              <div className="nyx-status-card-icon">
                <Bell className="w-5 h-5 text-[#00D9FF]" />
              </div>
              <span className="nyx-status-card-label">Active Security Alerts</span>
            </div>
            <div className="nyx-status-card-value">
              <AlertTriangle className="w-4 h-4 text-[#00D9FF]" />
              <span className="nyx-data-value">{alerts.length}</span>
              <span className="nyx-status-card-text">Total Alerts Logged</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-[#00D9FF] animate-pulse"></div>
            <span className="nyx-badge nyx-badge-low">LIVE ALERTS</span>
          </div>
        </div>
      </div>

      {/* Research Opportunities & Changes Grid */}
      <div className="nyx-content-grid">
        {/* Research Opportunities */}
        <div className="nyx-card nyx-card-accent-amber">
          <div className="nyx-section-header">
            <div className="flex items-center gap-3">
              <div className="nyx-section-icon nyx-section-icon-amber">
                <Sparkles className="w-4 h-4 text-[#FF6B35]" />
              </div>
              <h3 className="nyx-section-title">Prioritized Opportunities</h3>
              <span className="nyx-count-pill">{opportunities.length}</span>
            </div>
          </div>

          {opportunities.length === 0 ? (
            <div className="nyx-empty-state">
              <div className="nyx-empty-state-icon">
                <Sparkles className="w-8 h-8 text-[#484F58]" />
              </div>
              <div className="nyx-empty-state-title">No open research opportunities</div>
              <div className="nyx-empty-state-description">
                Continuous monitoring will suggest opportunities as changes occur
              </div>
            </div>
          ) : (
            <div className="nyx-opportunities-list">
              {opportunities.map((opp) => (
                <div key={opp.opportunity_id} className="nyx-opportunity-card">
                  <div className="nyx-opportunity-header">
                    <h4 className="nyx-opportunity-title">{opp.title}</h4>
                    <span className="nyx-badge nyx-badge-high">
                      <Zap className="w-3 h-3" />
                      SCORE: {opp.priority_score || 5}
                    </span>
                  </div>
                  <p className="nyx-opportunity-description">{opp.description}</p>
                  <div className="nyx-opportunity-skills">
                    <span className="nyx-opportunity-label">Recommended Skills:</span>
                    <div className="flex gap-1.5 flex-wrap">
                      {opp.recommended_skills?.map((skill: string, idx: number) => (
                        <span key={idx} className="nyx-badge nyx-badge-info">{skill}</span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Security Changes Detected */}
        <div className="nyx-card nyx-card-accent-cyan">
          <div className="nyx-section-header">
            <div className="flex items-center gap-3">
              <div className="nyx-section-icon nyx-section-icon-cyan">
                <History className="w-4 h-4 text-[#00D9FF]" />
              </div>
              <h3 className="nyx-section-title">Surface Changes Detected</h3>
              <span className="nyx-count-pill">{changes.length}</span>
            </div>
          </div>

          {changes.length === 0 ? (
            <div className="nyx-empty-state">
              <div className="nyx-empty-state-icon">
                <History className="w-8 h-8 text-[#484F58]" />
              </div>
              <div className="nyx-empty-state-title">No surface changes recorded</div>
              <div className="nyx-empty-state-description">
                All monitored targets are currently within baseline
              </div>
            </div>
          ) : (
            <div className="nyx-changes-list">
              {changes.map((ch, idx) => (
                <div key={idx} className="nyx-change-item">
                  <div className="nyx-change-header">
                    <span className="nyx-change-type">{ch.event_type}</span>
                    <span className="nyx-badge nyx-badge-info">{ch.severity}</span>
                  </div>
                  <div className="nyx-change-description">{ch.description}</div>
                  <div className="nyx-change-target">
                    <Target className="w-3 h-3 text-[#484F58]" />
                    <span>{ch.target}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};