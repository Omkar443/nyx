import React, { useState, useEffect } from 'react';
import { Globe, Play, Activity, Shield, Terminal, RefreshCw } from 'lucide-react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';
import { useApp } from '../context/AppContext';

export function RuntimeView() {
  const { target } = useApp();
  const { lastEvent } = useNyxEvents();
  const [sessions, setSessions] = useState<any[]>([]);
  const [url, setUrl] = useState(target.startsWith('http') ? target : `http://${target}`);
  const [isLaunching, setIsLaunching] = useState(false);
  const [loading, setLoading] = useState(true);

  async function loadSessions() {
    try {
      const res = await fetchApi('/api/v1/browser/sessions');
      const list = res?.data?.sessions || res?.sessions || [];
      if (Array.isArray(list)) setSessions(list);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadSessions();
  }, []);

  async function handleLaunch(e: React.FormEvent) {
    e.preventDefault();
    setIsLaunching(true);
    try {
      await fetchApi('/api/v1/browser/start', {
        method: 'POST',
        body: JSON.stringify({ url })
      });
      await loadSessions();
    } finally {
      setIsLaunching(false);
    }
  }

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Browser Runtime &amp; DOM Inspector
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <Globe className="w-3.5 h-3.5 text-[#555555]" />
            Headless execution environment for Single-Page Application dynamic analysis &nbsp;·&nbsp; {sessions.length} sessions
          </p>
        </div>
        <div className="text-xs font-mono text-[#4CAF50]">ENGINE: CHROMIUM PLAYWRIGHT</div>
      </div>

      {/* ========== LAUNCH FORM ========== */}
      <div className="card border border-[#3A3A3A]">
        <form onSubmit={handleLaunch} className="flex gap-2">
          <input
            type="url"
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="flex-1 bg-[#2B2B2B] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs text-[#E8E8E8] font-mono focus:outline-none"
          />
          <button type="submit" disabled={isLaunching} className="btn-primary flex-shrink-0 text-xs py-1.5 px-3 flex items-center gap-1.5">
            <Play className={`w-3.5 h-3.5 ${isLaunching ? 'animate-spin' : ''}`} />
            <span>{isLaunching ? 'Launching...' : 'Launch SPA Session'}</span>
          </button>
        </form>
      </div>

      {/* ========== SESSIONS TABLE ========== */}
      <div className="card p-0 overflow-hidden">
        {sessions.length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <Globe className="w-8 h-8 text-[#555555] mx-auto opacity-50" />
            <p className="text-xs text-[#888888] font-mono">No active browser sessions.</p>
            <p className="text-[11px] text-[#555555]">Enter an SPA URL above and click 'Launch SPA Session' to analyze client-side DOM &amp; routes.</p>
          </div>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="bg-[#1E1E1E] border-b border-[#333333] text-[#707070] uppercase font-mono text-[10px]">
              <tr>
                <th className="px-4 py-2.5">Session ID</th>
                <th className="px-4 py-2.5">Target URL</th>
                <th className="px-4 py-2.5">DOM Elements</th>
                <th className="px-4 py-2.5">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#333333]">
              {sessions.map((s) => (
                <tr key={s.id} className="hover:bg-[#303030] transition-colors">
                  <td className="px-4 py-2.5 font-mono text-xs font-bold text-[#ebb94b]">{s.id}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-[#E8E8E8]">{s.url}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-[#888888]">{s.nodes || 'Analyzed'}</td>
                  <td className="px-4 py-2.5">
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 rounded border text-[#4CAF50] bg-[#4CAF50]/15 border-[#4CAF50]/30">
                      {s.status || 'Active'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export default RuntimeView;
