import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Play, Globe, Activity, Shield, Key, Camera, RefreshCw, Terminal, CheckCircle } from 'lucide-react';

export const RuntimeView: React.FC = () => {
  const [sessions, setSessions] = useState<any[]>([]);
  const [runtimeGraph, setRuntimeGraph] = useState<any>(null);
  const [authData, setAuthData] = useState<any>(null);
  const [target, setTarget] = useState<string>('example.com');
  const [loading, setLoading] = useState<boolean>(false);

  async function loadData() {
    const sRes = await fetchApi('/api/v1/browser/sessions');
    if (sRes.success) setSessions(sRes.data.sessions || []);

    const rRes = await fetchApi('/api/v1/browser/runtime');
    if (rRes.success) setRuntimeGraph(rRes.data);

    const aRes = await fetchApi('/api/v1/browser/auth/flows');
    if (aRes.success) setAuthData(aRes.data);
  }

  useEffect(() => {
    loadData();
  }, []);

  async function handleStartSession(e: React.FormEvent) {
    e.preventDefault();
    if (!target) return;
    setLoading(true);
    await fetchApi(`/api/v1/browser/start?target=${encodeURIComponent(target)}`, { method: 'POST' });
    await loadData();
    setLoading(false);
  }

  async function handleRunDynamicAgent() {
    setLoading(true);
    await fetchApi(`/api/v1/browser/agent/dynamic?target=${encodeURIComponent(target)}`, { method: 'POST' });
    await loadData();
    setLoading(false);
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Globe className="w-6 h-6 text-cyan-400" /> NYX Browser & Runtime Intelligence
          </h2>
          <p className="text-sm text-slate-400">Playwright browser automation, authenticated session tracking, and Runtime Intelligence Graph</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleRunDynamicAgent}
            disabled={loading}
            className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 text-slate-950 font-semibold text-xs rounded shadow flex items-center gap-1.5"
          >
            <Play className="w-3.5 h-3.5" /> Run Dynamic Agent
          </button>
          <button onClick={loadData} className="p-2 rounded bg-slate-800 text-slate-300 hover:text-white">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Start Session Form */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="text-md font-bold text-white flex items-center gap-2">
          <Globe className="w-5 h-5 text-emerald-400" /> Launch Managed Browser Session
        </h3>
        <form onSubmit={handleStartSession} className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div className="md:col-span-2">
            <label className="text-xs font-mono text-slate-400">Target Domain</label>
            <input
              type="text"
              required
              placeholder="e.g. app.target.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-cyan-500/30 font-semibold text-sm rounded"
          >
            {loading ? 'Starting...' : 'Start Session'}
          </button>
        </form>
      </div>

      {/* Grid: Sessions & Runtime Graph */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Active Browser Sessions */}
        <div className="glass-panel p-6 space-y-4">
          <h3 className="text-md font-bold text-white flex items-center gap-2">
            <Camera className="w-5 h-5 text-cyan-400" /> Active Browser Sessions ({sessions.length})
          </h3>
          {sessions.length === 0 ? (
            <div className="text-center py-6 text-slate-500 text-sm glass-card">No active browser sessions.</div>
          ) : (
            <div className="space-y-3 max-h-80 overflow-y-auto pr-1">
              {sessions.map((s) => (
                <div key={s.session_id} className="glass-card p-3 font-mono text-xs space-y-1.5 border-l-2 border-l-cyan-400">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-cyan-300">{s.session_id}</span>
                    <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px]">ACTIVE</span>
                  </div>
                  <div>Target: <span className="text-white">{s.target}</span></div>
                  <div>Created: <span className="text-slate-400">{s.created_at}</span></div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Runtime Intelligence Graph Summary */}
        <div className="glass-panel p-6 space-y-4">
          <h3 className="text-md font-bold text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-emerald-400" /> Runtime Intelligence Graph
          </h3>
          <div className="space-y-3 font-mono text-xs">
            <div className="glass-card p-3 flex justify-between items-center">
              <span className="text-slate-400">Observed Requests:</span>
              <span className="font-bold text-cyan-300">{runtimeGraph?.requests?.length || 0}</span>
            </div>
            <div className="glass-card p-3 flex justify-between items-center">
              <span className="text-slate-400">API & GraphQL Operations:</span>
              <span className="font-bold text-emerald-300">{runtimeGraph?.apis?.length || 0}</span>
            </div>
            <div className="glass-card p-3 flex justify-between items-center">
              <span className="text-slate-400">Discovered Parameters:</span>
              <span className="font-bold text-amber-300">{runtimeGraph?.parameters?.length || 0}</span>
            </div>
            <div className="glass-card p-3 flex justify-between items-center">
              <span className="text-slate-400">Detected Stack / Technologies:</span>
              <span className="font-bold text-purple-300">{runtimeGraph?.technologies?.length || 0}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
