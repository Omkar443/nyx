import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Server, Activity, ShieldCheck, Plus, Trash2, RefreshCw, Cpu, CheckCircle, AlertTriangle } from 'lucide-react';

export const WorkerFleetView: React.FC = () => {
  const [workerStatus, setWorkerStatus] = useState<any>(null);
  const [hostname, setHostname] = useState<string>('worker-node-1');
  const [loading, setLoading] = useState<boolean>(false);

  async function loadWorkerData() {
    const res = await fetchApi('/api/v1/workers/status');
    if (res.success) setWorkerStatus(res.data);
  }

  useEffect(() => {
    loadWorkerData();
  }, []);

  async function handleRegisterWorker(e: React.FormEvent) {
    e.preventDefault();
    if (!hostname) return;
    setLoading(true);
    await fetchApi(`/api/v1/workers/register?hostname=${encodeURIComponent(hostname)}`, { method: 'POST' });
    await loadWorkerData();
    setLoading(false);
  }

  async function handleRemoveWorker(workerId: string) {
    await fetchApi(`/api/v1/workers/${workerId}/remove`, { method: 'POST' });
    loadWorkerData();
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Server className="w-6 h-6 text-cyan-400" /> NYX Distributed Worker Fleet
          </h2>
          <p className="text-sm text-slate-400">Remote worker nodes running specialized agents with HMAC mutual authentication & SHA-256 evidence sync</p>
        </div>
        <div className="flex items-center gap-4 font-mono text-xs">
          <div className="px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
            Total Workers: <span className="font-bold text-white">{workerStatus?.total_workers || 0}</span>
          </div>
          <div className="px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-emerald-300">
            Online Workers: <span className="font-bold text-white">{workerStatus?.online_workers || 0}</span>
          </div>
          <button onClick={loadWorkerData} className="p-2 rounded bg-slate-800 text-slate-300 hover:text-white">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Register Worker Form */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="text-md font-bold text-white flex items-center gap-2">
          <Plus className="w-5 h-5 text-emerald-400" /> Register Remote Worker Node
        </h3>
        <form onSubmit={handleRegisterWorker} className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
          <div className="md:col-span-2">
            <label className="text-xs font-mono text-slate-400">Worker Hostname / Identifier</label>
            <input
              type="text"
              required
              placeholder="e.g. worker-node-us-east-1"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 text-slate-950 font-semibold text-sm rounded shadow disabled:opacity-50"
          >
            {loading ? 'Registering...' : 'Register Worker'}
          </button>
        </form>
      </div>

      {/* Worker Grid */}
      <div className="glass-panel p-6 space-y-4">
        <h3 className="text-md font-bold text-white flex items-center gap-2">
          <Cpu className="w-5 h-5 text-cyan-400" /> Connected Worker Nodes ({workerStatus?.workers?.length || 0})
        </h3>
        {(!workerStatus?.workers || workerStatus.workers.length === 0) ? (
          <div className="text-center py-6 text-slate-500 text-sm glass-card">
            No remote worker nodes registered. Register a node above.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {workerStatus.workers.map((w: any) => (
              <div key={w.worker_id} className="glass-card p-4 space-y-3 border-l-4 border-l-cyan-400">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-xs font-bold font-mono text-cyan-400">{w.worker_id}</span>
                    <h4 className="text-sm font-extrabold text-white">{w.hostname}</h4>
                    <span className="text-xs text-slate-400 font-mono">Platform: <span className="text-slate-200">{w.platform}</span></span>
                  </div>
                  <button
                    onClick={() => handleRemoveWorker(w.worker_id)}
                    className="px-2.5 py-1 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 text-xs font-semibold rounded border border-rose-500/30 flex items-center gap-1"
                  >
                    <Trash2 className="w-3 h-3" /> Remove
                  </button>
                </div>
                <div className="text-xs font-mono space-y-1 bg-slate-950 p-2.5 rounded border border-slate-800">
                  <div className="flex items-center gap-2">
                    Status: 
                    <span className={`px-2 py-0.5 rounded font-bold ${w.status === 'ONLINE' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'}`}>
                      {w.status}
                    </span>
                  </div>
                  <div>Supported Agents: <span className="text-cyan-300">{w.agents_supported?.join(', ')}</span></div>
                  <div>Last Heartbeat: <span className="text-slate-400">{w.last_seen}</span></div>
                  <div className="text-[10px] text-slate-500 truncate">Auth Token: {w.auth_token}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
