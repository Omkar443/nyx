import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Globe, Cpu, Play, Search, ShieldCheck } from 'lucide-react';

export const AttackSurfaceView: React.FC = () => {
  const [endpoints, setEndpoints] = useState<any[]>([]);
  const [technologies, setTechnologies] = useState<any[]>([]);
  const [filter, setFilter] = useState<string>('');
  const [running, setRunning] = useState<boolean>(false);
  const [target, setTarget] = useState<string>('example.com');

  async function loadSurface() {
    const epRes = await fetchApi('/api/v1/endpoints');
    if (epRes.success && epRes.data?.endpoints) setEndpoints(epRes.data.endpoints);

    const techRes = await fetchApi('/api/v1/technologies');
    if (techRes.success && techRes.data?.technologies) setTechnologies(techRes.data.technologies);

    const mRes = await fetchApi('/api/v1/mission');
    if (mRes.success && mRes.data?.target) setTarget(mRes.data.target);
  }

  useEffect(() => {
    loadSurface();
  }, []);

  async function handleTriggerRecon() {
    setRunning(true);
    await fetchApi(`/api/v1/surface/recon?target=${encodeURIComponent(target)}`, { method: 'POST' });
    await loadSurface();
    setRunning(false);
  }

  const filteredEndpoints = endpoints.filter((ep: any) =>
    (ep.url || ep).toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel p-6 flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Globe className="w-6 h-6 text-cyan-400" /> Attack Surface Intelligence
          </h2>
          <p className="text-sm text-slate-400">Target assets, harvested endpoints, and technology stack</p>
        </div>
        <button
          onClick={handleTriggerRecon}
          disabled={running}
          className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-600 hover:to-emerald-600 text-slate-950 font-semibold rounded-lg shadow-lg flex items-center gap-2 disabled:opacity-50"
        >
          <Play className="w-4 h-4 fill-current" /> {running ? 'Running Recon...' : 'Run Reconnaissance'}
        </button>
      </div>

      {/* Technology Stack Grid */}
      <div className="glass-panel p-6">
        <h3 className="text-md font-bold text-white mb-4 flex items-center gap-2">
          <Cpu className="w-5 h-5 text-emerald-400" /> Technology Fingerprints ({technologies.length})
        </h3>
        {technologies.length === 0 ? (
          <div className="text-center py-6 text-slate-500 text-sm glass-card">
            No technology fingerprints recorded yet. Run reconnaissance to analyze stack.
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {technologies.map((t: any, idx: number) => (
              <div key={idx} className="glass-card p-3 flex items-center gap-3">
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                <div>
                  <div className="text-sm font-semibold text-white font-mono">{t.name || t}</div>
                  <div className="text-xs text-slate-400 font-mono">{t.category || 'Technology'}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Harvested Endpoints */}
      <div className="glass-panel p-6">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-4">
          <h3 className="text-md font-bold text-white flex items-center gap-2">
            <Globe className="w-5 h-5 text-cyan-400" /> Harvested Endpoints ({endpoints.length})
          </h3>
          <div className="relative w-full md:w-64">
            <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
            <input
              type="text"
              placeholder="Filter endpoints..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>

        {filteredEndpoints.length === 0 ? (
          <div className="text-center py-8 text-slate-500 text-sm glass-card">
            No endpoints matching filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300 font-mono">
              <thead className="bg-slate-900/80 text-xs text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="p-3">#</th>
                  <th className="p-3">Endpoint URL</th>
                  <th className="p-3">Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {filteredEndpoints.slice(0, 100).map((ep: any, idx: number) => {
                  const urlStr = ep.url || ep;
                  return (
                    <tr key={idx} className="hover:bg-slate-800/40">
                      <td className="p-3 text-slate-500 text-xs">{idx + 1}</td>
                      <td className="p-3 font-semibold text-cyan-300">{urlStr}</td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 text-xs rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                          IN_SCOPE
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
