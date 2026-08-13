import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Terminal, Play, CheckCircle, XCircle, FileText, AlertCircle } from 'lucide-react';

export const ExecutionView: React.FC = () => {
  const [history, setHistory] = useState<any[]>([]);
  const [toolName, setToolName] = useState<string>('subfinder');
  const [target, setTarget] = useState<string>('example.com');
  const [dryRun, setDryRun] = useState<boolean>(true);
  const [running, setRunning] = useState<boolean>(false);
  const [selectedExec, setSelectedExec] = useState<any>(null);

  async function loadHistory() {
    const res = await fetchApi('/api/v1/execution/history?limit=50');
    if (res.success && res.data?.history) {
      setHistory(res.data.history);
    }
  }

  useEffect(() => {
    loadHistory();
  }, []);

  async function handleRunTool(e: React.FormEvent) {
    e.preventDefault();
    setRunning(true);
    const res = await fetchApi('/api/v1/execution/run', {
      method: 'POST',
      body: JSON.stringify({
        tool_name: toolName,
        target,
        dry_run: dryRun,
      }),
    });
    setRunning(false);
    loadHistory();
    if (res.success) {
      setSelectedExec(res.data);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel p-6 flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Terminal className="w-6 h-6 text-emerald-400" /> Controlled Execution Engine
          </h2>
          <p className="text-sm text-slate-400">Policy-gated security tool harness and output artifacts</p>
        </div>
      </div>

      {/* Tool Runner Form */}
      <div className="glass-panel p-6">
        <h3 className="text-md font-bold text-white mb-3">Execute Controlled Security Tool</h3>
        <form onSubmit={handleRunTool} className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
          <div>
            <label className="text-xs font-mono text-slate-400">Security Tool</label>
            <select
              value={toolName}
              onChange={(e) => setToolName(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
            >
              <option value="subfinder">subfinder (Passive)</option>
              <option value="httpx">httpx (Probe)</option>
              <option value="katana">katana (Crawler)</option>
              <option value="nuclei">nuclei (Scanner)</option>
              <option value="nmap">nmap (Port Scanner)</option>
            </select>
          </div>
          <div>
            <label className="text-xs font-mono text-slate-400">Target Host</label>
            <input
              type="text"
              required
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
            />
          </div>
          <div className="flex items-center gap-2 mb-2">
            <input
              type="checkbox"
              id="dryRun"
              checked={dryRun}
              onChange={(e) => setDryRun(e.target.checked)}
              className="w-4 h-4 accent-cyan-500"
            />
            <label htmlFor="dryRun" className="text-xs font-mono text-slate-300">Dry-Run Mode (Safe)</label>
          </div>
          <button
            type="submit"
            disabled={running}
            className="px-4 py-2 bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-600 hover:to-cyan-600 text-slate-950 font-semibold rounded shadow flex items-center justify-center gap-2 disabled:opacity-50"
          >
            <Play className="w-4 h-4 fill-current" /> {running ? 'Executing...' : 'Run Tool'}
          </button>
        </form>
      </div>

      {/* History Table */}
      <div className="glass-panel p-6">
        <h3 className="text-md font-bold text-white mb-4">Execution History Log</h3>
        {history.length === 0 ? (
          <div className="text-center py-8 text-slate-500 text-sm">
            No tool executions logged in current session.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300 font-mono">
              <thead className="bg-slate-900/80 text-xs text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="p-3">Execution ID</th>
                  <th className="p-3">Tool</th>
                  <th className="p-3">Target</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Mode</th>
                  <th className="p-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {history.map((h: any, idx: number) => (
                  <tr key={idx} className="hover:bg-slate-800/40">
                    <td className="p-3 font-semibold text-emerald-300">{h.execution_id || `EXEC-${idx+1}`}</td>
                    <td className="p-3 text-cyan-300">{h.tool_name}</td>
                    <td className="p-3 text-slate-300">{h.target}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 text-xs rounded ${h.status === 'COMPLETED' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'}`}>
                        {h.status || 'COMPLETED'}
                      </span>
                    </td>
                    <td className="p-3">
                      {h.dry_run ? (
                        <span className="px-2 py-0.5 text-xs rounded bg-slate-800 text-slate-400">DRY_RUN</span>
                      ) : (
                        <span className="px-2 py-0.5 text-xs rounded bg-purple-500/20 text-purple-300">ACTIVE</span>
                      )}
                    </td>
                    <td className="p-3">
                      <button
                        onClick={() => setSelectedExec(h)}
                        className="px-2.5 py-1 bg-slate-800 text-xs text-cyan-300 rounded hover:bg-slate-700"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal Execution Details */}
      {selectedExec && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="glass-panel p-6 w-full max-w-2xl space-y-4 max-h-[80vh] overflow-y-auto">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-bold text-white font-mono">{selectedExec.execution_id || 'Execution Output'}</h3>
              <button onClick={() => setSelectedExec(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>
            <div className="text-xs font-mono text-slate-400 space-y-1">
              <div>Tool: <span className="text-cyan-300">{selectedExec.tool_name}</span> | Target: <span className="text-emerald-300">{selectedExec.target}</span></div>
              <div>Exit Code: <span className="text-white">{selectedExec.exit_code ?? 0}</span></div>
            </div>
            <div>
              <label className="text-xs font-mono text-slate-400">Standard Output (stdout)</label>
              <pre className="bg-slate-950 p-4 rounded text-xs text-emerald-300 font-mono overflow-x-auto whitespace-pre-wrap max-h-48">
                {selectedExec.stdout || '(no stdout output)'}
              </pre>
            </div>
            {selectedExec.stderr && (
              <div>
                <label className="text-xs font-mono text-slate-400">Standard Error (stderr)</label>
                <pre className="bg-slate-950 p-4 rounded text-xs text-rose-300 font-mono overflow-x-auto whitespace-pre-wrap max-h-32">
                  {selectedExec.stderr}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
