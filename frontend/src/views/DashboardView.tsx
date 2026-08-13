import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Shield, Target, Activity, Cpu, AlertTriangle, FileText, CheckCircle } from 'lucide-react';

export const DashboardView: React.FC<{ onNavigate: (tab: string) => void }> = ({ onNavigate }) => {
  const [mission, setMission] = useState<any>(null);
  const [surface, setSurface] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      const mRes = await fetchApi('/api/v1/mission');
      if (mRes.success) setMission(mRes.data);

      const sRes = await fetchApi('/api/v1/assets');
      if (sRes.success) setSurface(sRes.data);

      const fRes = await fetchApi('/api/v1/findings');
      if (fRes.success && fRes.data?.findings) setFindings(fRes.data.findings);
      setLoading(false);
    }
    loadData();
  }, []);

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="glass-panel p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white">NYX Security Operations Console</h1>
              <p className="text-sm text-slate-400">Autonomous Security Intelligence Engine</p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3 bg-slate-900/60 px-4 py-2 rounded-lg border border-slate-800">
          <Target className="w-5 h-5 text-emerald-400" />
          <div>
            <div className="text-xs text-slate-400 font-mono uppercase">Active Target</div>
            <div className="text-sm font-semibold text-emerald-300 font-mono">{mission?.target || 'example.com'}</div>
          </div>
          <span className="ml-4 px-2.5 py-1 text-xs font-semibold rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-mono">
            {mission?.phase || 'DISCOVERY'}
          </span>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass-card p-5 cursor-pointer hover:border-cyan-500/40" onClick={() => onNavigate('surface')}>
          <div className="flex justify-between items-center text-slate-400 mb-2">
            <span className="text-xs uppercase font-semibold tracking-wider font-mono">Harvested Endpoints</span>
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold text-white font-mono">{surface?.endpoints_count ?? 0}</div>
          <div className="text-xs text-slate-400 mt-2">Discovered attack endpoints</div>
        </div>

        <div className="glass-card p-5 cursor-pointer hover:border-emerald-500/40" onClick={() => onNavigate('surface')}>
          <div className="flex justify-between items-center text-slate-400 mb-2">
            <span className="text-xs uppercase font-semibold tracking-wider font-mono">Detected Stack</span>
            <Cpu className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="text-3xl font-bold text-white font-mono">{surface?.technologies_count ?? 0}</div>
          <div className="text-xs text-slate-400 mt-2">Fingerprinted technologies</div>
        </div>

        <div className="glass-card p-5 cursor-pointer hover:border-amber-500/40" onClick={() => onNavigate('findings')}>
          <div className="flex justify-between items-center text-slate-400 mb-2">
            <span className="text-xs uppercase font-semibold tracking-wider font-mono">Recorded Findings</span>
            <AlertTriangle className="w-5 h-5 text-amber-400" />
          </div>
          <div className="text-3xl font-bold text-white font-mono">{findings.length}</div>
          <div className="text-xs text-slate-400 mt-2">Vulnerability hypotheses</div>
        </div>

        <div className="glass-card p-5 cursor-pointer hover:border-purple-500/40" onClick={() => onNavigate('evidence')}>
          <div className="flex justify-between items-center text-slate-400 mb-2">
            <span className="text-xs uppercase font-semibold tracking-wider font-mono">Evidence Vault</span>
            <FileText className="w-5 h-5 text-purple-400" />
          </div>
          <div className="text-3xl font-bold text-white font-mono">{findings.reduce((acc, f) => acc + (f.evidence_ids?.length || 0), 0)}</div>
          <div className="text-xs text-slate-400 mt-2">Verified PoC artifacts</div>
        </div>
      </div>

      {/* Recent Findings Preview */}
      <div className="glass-panel p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" /> Active Security Hypotheses
          </h2>
          <button
            onClick={() => onNavigate('findings')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-mono font-medium hover:underline"
          >
            View All Findings →
          </button>
        </div>

        {findings.length === 0 ? (
          <div className="text-center py-8 text-slate-500 text-sm glass-card">
            No active findings recorded in current mission workspace.
          </div>
        ) : (
          <div className="space-y-3">
            {findings.slice(0, 5).map((f: any) => (
              <div key={f.finding_id} className="glass-card p-4 flex justify-between items-center">
                <div>
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-0.5 text-xs font-semibold rounded font-mono severity-${f.severity?.toLowerCase() || 'medium'}`}>
                      {f.severity || 'Medium'}
                    </span>
                    <span className="text-sm font-semibold text-white font-mono">{f.finding_id}</span>
                    <span className="text-sm text-slate-200">{f.title}</span>
                  </div>
                  <div className="text-xs text-slate-400 mt-1 font-mono">{f.endpoint || 'General Scope'}</div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs px-2 py-1 rounded bg-slate-800 text-slate-300 font-mono">{f.status || 'HYPOTHESIS'}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
