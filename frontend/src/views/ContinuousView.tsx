import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Activity, Bell, Shield, Sparkles, RefreshCw, Play, Clock, CheckCircle, AlertCircle, History } from 'lucide-react';

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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Activity className="w-6 h-6 text-cyan-400" /> NYX Continuous Security Intelligence
          </h2>
          <p className="text-sm text-slate-400">Continuous attack surface monitoring, automated change detection & research opportunity prioritization</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleBackupKnowledge}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 font-semibold text-xs rounded flex items-center gap-1.5"
          >
            <Shield className="w-3.5 h-3.5" /> Backup Knowledge
          </button>
          <button onClick={loadContinuousData} className="p-2 rounded bg-slate-800 text-slate-300 hover:text-white">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Monitoring Job Trigger */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="text-md font-bold text-white flex items-center gap-2">
          <Play className="w-5 h-5 text-emerald-400" /> Launch Surface Monitoring Watcher
        </h3>
        <form onSubmit={handleStartMonitoring} className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div className="md:col-span-2">
            <label className="text-xs font-mono text-slate-400">Target Domain</label>
            <input
              type="text"
              required
              placeholder="e.g. target.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 text-slate-950 font-semibold text-sm rounded shadow disabled:opacity-50"
          >
            {loading ? 'Starting...' : 'Start Monitoring Job'}
          </button>
        </form>
      </div>

      {/* Knowledge Integrity & Active Alerts Banner */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="glass-panel p-4 flex items-center justify-between border-l-4 border-l-emerald-400">
          <div>
            <div className="text-xs text-slate-400 font-mono uppercase">Knowledge Asset Status</div>
            <div className="text-md font-bold text-white flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              {knowledgeStatus?.total_skills_count || 0} Skills Verified Intact
            </div>
          </div>
          <span className="px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-300 font-mono text-xs border border-emerald-500/30">
            PROTECTED
          </span>
        </div>

        <div className="glass-panel p-4 flex items-center justify-between border-l-4 border-l-cyan-400">
          <div>
            <div className="text-xs text-slate-400 font-mono uppercase">Active Security Alerts</div>
            <div className="text-md font-bold text-white flex items-center gap-2">
              <Bell className="w-4 h-4 text-cyan-400" />
              {alerts.length} Total Alerts Logged
            </div>
          </div>
          <span className="px-2.5 py-1 rounded bg-cyan-500/20 text-cyan-300 font-mono text-xs border border-cyan-500/30">
            LIVE ALERTS
          </span>
        </div>
      </div>

      {/* Research Opportunities & Changes Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Research Opportunities */}
        <div className="glass-panel p-6 space-y-4">
          <h3 className="text-md font-bold text-white flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-amber-400" /> Prioritized Research Opportunities ({opportunities.length})
          </h3>
          {opportunities.length === 0 ? (
            <div className="text-center py-6 text-slate-500 text-sm glass-card">No open research opportunities.</div>
          ) : (
            <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
              {opportunities.map((opp) => (
                <div key={opp.opportunity_id} className="glass-card p-4 space-y-2 border-l-4 border-l-amber-400">
                  <div className="flex justify-between items-start">
                    <h4 className="text-sm font-extrabold text-white">{opp.title}</h4>
                    <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 text-xs font-mono font-bold">
                      SCORE: {opp.priority_score || 5}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{opp.description}</p>
                  <div className="text-[11px] font-mono text-slate-400">
                    Recommended Skills: <span className="text-cyan-300">{opp.recommended_skills?.join(', ')}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Security Changes Detected */}
        <div className="glass-panel p-6 space-y-4">
          <h3 className="text-md font-bold text-white flex items-center gap-2">
            <History className="w-5 h-5 text-cyan-400" /> Surface Changes Detected ({changes.length})
          </h3>
          {changes.length === 0 ? (
            <div className="text-center py-6 text-slate-500 text-sm glass-card">No surface changes recorded.</div>
          ) : (
            <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
              {changes.map((ch, idx) => (
                <div key={idx} className="glass-card p-3 font-mono text-xs space-y-1 border-l-2 border-l-cyan-400">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-cyan-300">{ch.event_type}</span>
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">{ch.severity}</span>
                  </div>
                  <div className="text-slate-200">{ch.description}</div>
                  <div className="text-[10px] text-slate-500">Target: {ch.target}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
