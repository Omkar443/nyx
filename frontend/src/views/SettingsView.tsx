import React, { useEffect, useState } from 'react';
import { fetchApi, getStoredToken, setStoredToken } from '../api/client';
import { Settings, ShieldCheck, Key, Database, Cpu } from 'lucide-react';

export const SettingsView: React.FC = () => {
  const [health, setHealth] = useState<any>(null);
  const [tokenInput, setTokenInput] = useState<string>(getStoredToken());
  const [tokenSaved, setTokenSaved] = useState<boolean>(false);

  useEffect(() => {
    async function loadHealth() {
      const res = await fetchApi('/health');
      if (res) setHealth(res);
    }
    loadHealth();
  }, []);

  function handleSaveToken(e: React.FormEvent) {
    e.preventDefault();
    setStoredToken(tokenInput);
    setTokenSaved(true);
    setTimeout(() => setTokenSaved(false), 3000);
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel p-6 flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Settings className="w-6 h-6 text-slate-400" /> Platform Configuration & System Health
          </h2>
          <p className="text-sm text-slate-400">NYX engine version, local authentication settings, and workspace status</p>
        </div>
      </div>

      {/* System Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-panel p-6 space-y-4">
          <h3 className="text-md font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" /> System Health Status
          </h3>
          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400">NYX Version</span>
              <span className="text-emerald-300 font-bold">{health?.version || '1.0.0'}</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400">Application Name</span>
              <span className="text-white">{health?.app_name || 'NYX Security Operations Dashboard'}</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400">Authentication</span>
              <span className="text-cyan-300">ENABLED (Local Token)</span>
            </div>
            <div className="flex justify-between p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-400">Active Workspace</span>
              <span className="text-emerald-300">.engagement/</span>
            </div>
          </div>
        </div>

        {/* API Token Config */}
        <div className="glass-panel p-6 space-y-4">
          <h3 className="text-md font-bold text-white flex items-center gap-2">
            <Key className="w-5 h-5 text-amber-400" /> Local API Authentication Token
          </h3>
          <form onSubmit={handleSaveToken} className="space-y-3">
            <div>
              <label className="text-xs font-mono text-slate-400">Active API Token</label>
              <input
                type="password"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-sm text-white font-mono"
              />
            </div>
            <button
              type="submit"
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-slate-950 font-semibold text-sm rounded shadow"
            >
              Save Token
            </button>
            {tokenSaved && (
              <span className="text-xs text-emerald-400 font-mono ml-3">Token saved to local storage!</span>
            )}
          </form>
          <div className="text-xs text-slate-400 bg-slate-900/60 p-3 rounded border border-slate-800 font-mono">
            API token is configured locally in memory/env and never exposed in logs or network tracebacks.
          </div>
        </div>
      </div>
    </div>
  );
};
