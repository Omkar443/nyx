import React, { useState, useEffect } from 'react';
import { Settings, Shield, Key, RefreshCw, Copy, Check, Save } from 'lucide-react';
import { fetchApi } from '../api/client';
import { useApp } from '../context/AppContext';

export function SettingsView() {
  const { target, setTarget, refreshGlobalStats } = useApp();
  const [token, setToken] = useState<string>('');
  const [scope, setScope] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);

  async function loadSettings() {
    try {
      const tokRes = await fetchApi('/api/v1/auth/token');
      if (tokRes?.data?.token || tokRes?.token) {
        setToken(tokRes?.data?.token || tokRes?.token);
      }

      const setRes = await fetchApi('/api/v1/settings');
      if (setRes?.data) {
        if (setRes.data.target) setTarget(setRes.data.target);
        if (setRes.data.scope) setScope(Array.isArray(setRes.data.scope) ? setRes.data.scope.join(', ') : setRes.data.scope);
      }
    } catch {
      // Fallback
    }
  }

  useEffect(() => {
    loadSettings();
  }, []);

  async function handleSaveSettings(e: React.FormEvent) {
    e.preventDefault();
    setIsSaving(true);
    try {
      const scopeArr = scope.split(',').map(s => s.trim()).filter(Boolean);
      await fetchApi('/api/v1/settings', {
        method: 'POST',
        body: JSON.stringify({
          target,
          scope: scopeArr
        })
      });
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2000);
      await refreshGlobalStats();
    } finally {
      setIsSaving(false);
    }
  }

  function handleCopyToken() {
    if (token) {
      navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Engagement Configuration &amp; Scope
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <Settings className="w-3.5 h-3.5 text-[#555555]" />
            Target boundaries, policy rules, and API token management
          </p>
        </div>
      </div>

      {/* ========== FORM ========== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card space-y-4 border border-[#3A3A3A]">
          <div className="flex items-center gap-2 pb-2 border-b border-[#333333]">
            <Shield className="w-4 h-4 text-[#4CAF50]" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#E8E8E8]">Scope Whitelist Configuration</h3>
          </div>

          <form onSubmit={handleSaveSettings} className="space-y-3 text-xs">
            <div>
              <label className="text-[#888888] block mb-1">Target Name / Root Asset</label>
              <input
                type="text"
                required
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs font-mono text-[#E8E8E8] focus:outline-none"
              />
            </div>

            <div>
              <label className="text-[#888888] block mb-1">Scope Whitelist Patterns (comma-separated)</label>
              <textarea
                rows={3}
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                placeholder="e.g. *.example.com, 127.0.0.1:3000, http://127.0.0.1:3000"
                className="w-full bg-[#2A2A2A] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs font-mono text-[#E8E8E8] focus:outline-none"
              />
            </div>

            <button type="submit" disabled={isSaving} className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5">
              <Save className="w-3.5 h-3.5" />
              <span>{saveSuccess ? 'Saved Successfully!' : isSaving ? 'Saving...' : 'Save Configuration'}</span>
            </button>
          </form>
        </div>

        <div className="card space-y-4 border border-[#3A3A3A]">
          <div className="flex items-center gap-2 pb-2 border-b border-[#333333]">
            <Key className="w-4 h-4 text-[#ebb94b]" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#E8E8E8]">Operator API Authorization Token</h3>
          </div>

          <div className="space-y-2 text-xs">
            <p className="text-[#888888]">Used by CLI and Web API clients for Bearer authentication:</p>
            <div className="p-2.5 rounded bg-[#1A1A1A] border border-[#333333] font-mono text-xs text-[#ebb94b] break-all">
              {token || 'Loading authorization token...'}
            </div>
            <button onClick={handleCopyToken} className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1">
              {copied ? <Check className="w-3.5 h-3.5 text-[#4CAF50]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied Token' : 'Copy Bearer Token'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default SettingsView;
