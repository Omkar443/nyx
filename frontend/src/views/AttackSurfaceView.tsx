import React, { useState, useEffect } from 'react';
import {
  Radar, Search, Filter, ChevronDown, ChevronRight,
  Server, Lock, Code, RefreshCw, AlertTriangle, Play, Plus, Brain, ExternalLink, Globe
} from 'lucide-react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';
import { useApp } from '../context/AppContext';

interface EndpointItem {
  url: string;
  host?: string;
  path?: string;
  status?: number;
  server?: string;
  title?: string;
  content_type?: string;
  length?: number;
  source?: string;
  discovery_method?: string;
  priority?: string;
  added_at?: string;
}

export function AttackSurfaceView() {
  const { target, setCurrentView, refreshGlobalStats } = useApp();
  const { lastEvent } = useNyxEvents();
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [technologies, setTechnologies] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointItem | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanNotice, setScanNotice] = useState<string | null>(null);

  async function loadSurface() {
    try {
      const epsRes = await fetchApi('/api/v1/endpoints');
      const rawEps = epsRes?.endpoints || epsRes?.data?.endpoints || [];
      
      const formatted: EndpointItem[] = rawEps.map((ep: any) => {
        if (typeof ep === 'string') {
          return {
            url: ep,
            host: ep.replace(/https?:\/\//, '').split('/')[0],
            path: ep.replace(/https?:\/\/[^/]+/, '') || '/',
            status: 200,
            source: 'recon_crawler'
          };
        }
        return {
          url: ep.url || ep.endpoint || ep.path || '',
          host: ep.host || (ep.url ? ep.url.replace(/https?:\/\//, '').split('/')[0] : target),
          path: ep.path || (ep.url ? ep.url.replace(/https?:\/\/[^/]+/, '') : '/'),
          status: ep.status_code || ep.status || 200,
          server: ep.server || ep.headers?.server,
          title: ep.title,
          content_type: ep.content_type || ep.headers?.['content-type'],
          length: ep.length || ep.content_length,
          source: ep.source || 'content_discovery',
          discovery_method: ep.discovery_method || 'wordlist_probe',
          priority: ep.priority || (ep.status === 200 ? 'P1' : 'P2'),
          added_at: ep.added_at || ep.timestamp
        };
      });

      setEndpoints(formatted);

      const techRes = await fetchApi('/api/v1/technologies');
      const techList = techRes?.technologies || techRes?.data?.technologies || [];
      if (Array.isArray(techList)) setTechnologies(techList);
    } catch {
      // Graceful fallback
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadSurface();
  }, [target]);

  useEffect(() => {
    if (lastEvent?.event === 'recon_completed') {
      loadSurface();
      refreshGlobalStats();
    }
  }, [lastEvent, refreshGlobalStats]);

  async function handleRunRecon() {
    if (!target || target === 'No active target') {
      setScanNotice('No active target — set a target first (use Settings to configure target scope or initialize an engagement).');
      return;
    }
    setScanNotice(null);
    setIsScanning(true);
    try {
      const res = await fetchApi(`/api/v1/surface/recon?target=${encodeURIComponent(target)}`, { method: 'POST' });
      if (!res?.success && res?.error) {
        setScanNotice(`Recon failed: ${res.error}`);
      }
      await loadSurface();
      await refreshGlobalStats();
    } catch (err: any) {
      setScanNotice(err?.message || 'Recon request failed');
    } finally {
      setIsScanning(false);
    }
  }

  const filtered = endpoints.filter(ep => {
    const matchesSearch = 
      ep.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (ep.title && ep.title.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (ep.server && ep.server.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesStatus = 
      statusFilter === 'all' || 
      (statusFilter === '200' && ep.status === 200) ||
      (statusFilter === '403' && ep.status === 403) ||
      (statusFilter === '404' && ep.status === 404) ||
      (statusFilter === 'other' && ep.status && ![200, 403, 404].includes(ep.status));

    const matchesSource = 
      sourceFilter === 'all' || 
      (ep.source && ep.source.toLowerCase().includes(sourceFilter.toLowerCase()));

    return matchesSearch && matchesStatus && matchesSource;
  });

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Attack Surface &amp; Recon Intelligence
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <Radar className="w-3.5 h-3.5 text-[#555555]" />
            Discovered live URLs, API routes, servers, and technologies &nbsp;·&nbsp; {endpoints.length} assets
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          <button 
            onClick={handleRunRecon} 
            disabled={isScanning}
            className="btn-primary flex items-center gap-1.5 text-xs py-1.5 px-3"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
            <span>{isScanning ? 'Harvesting Target...' : 'Run Reconnaissance'}</span>
          </button>
        </div>
      </div>

      {/* Target Notice / Error Alert */}
      {scanNotice && (
        <div className="p-3 rounded bg-[#FFA726]/10 border border-[#FFA726]/30 text-xs text-[#FFA726] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{scanNotice}</span>
          </div>
          <button 
            onClick={() => setCurrentView('settings')}
            className="btn-secondary text-[11px] py-1 px-2.5 ml-3 shrink-0"
          >
            Go to Settings
          </button>
        </div>
      )}

      {/* ========== TECH STACK PILLS ========== */}
      {technologies.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap bg-[#242424] border border-[#333333] p-2.5 rounded-lg">
          <span className="text-[11px] font-mono text-[#888888] font-semibold flex items-center gap-1">
            <Code className="w-3.5 h-3.5 text-[#ebb94b]" />
            IDENTIFIED TECHNOLOGIES:
          </span>
          {technologies.map((t, idx) => (
            <span key={idx} className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#303030] text-[#E8E8E8] border border-[#404040]">
              {t}
            </span>
          ))}
        </div>
      )}

      {/* ========== CONTROLS ========== */}
      <div className="flex flex-col sm:flex-row gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#666666]" />
          <input
            type="text"
            placeholder="Search endpoints by path, title, or server..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#242424] border border-[#333333] rounded-lg pl-9 pr-3 py-1.5 text-xs text-[#E8E8E8] placeholder-[#555555] focus:outline-none focus:border-[#555555]"
          />
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-[#242424] border border-[#333333] rounded-lg px-3 py-1.5 text-xs text-[#CCCCCC] focus:outline-none"
        >
          <option value="all">All HTTP Statuses</option>
          <option value="200">200 OK</option>
          <option value="403">403 Forbidden</option>
          <option value="404">404 Not Found</option>
          <option value="other">Other Status Codes</option>
        </select>

        <select
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value)}
          className="bg-[#242424] border border-[#333333] rounded-lg px-3 py-1.5 text-xs text-[#CCCCCC] focus:outline-none"
        >
          <option value="all">All Discovery Sources</option>
          <option value="content_discovery">Content Discovery</option>
          <option value="crawler">Web Crawler</option>
          <option value="js_bundle">JS Bundle Extraction</option>
        </select>
      </div>

      {/* ========== ASSET LIST & INSPECTOR ========== */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Table / List */}
        <div className={`card p-0 overflow-hidden ${selectedEndpoint ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          {loading ? (
            <div className="text-center py-12 text-xs text-[#888888]">Loading attack surface assets...</div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-12 space-y-3">
              <Globe className="w-8 h-8 text-[#555555] mx-auto opacity-50" />
              <p className="text-xs text-[#888888]">No attack surface endpoints matching the current filter.</p>
              {endpoints.length === 0 && (
                <button onClick={handleRunRecon} className="btn-primary text-xs py-1.5 px-4">
                  Start Reconnaissance
                </button>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#1E1E1E] border-b border-[#333333] text-[#707070] uppercase font-mono text-[10px]">
                  <tr>
                    <th className="px-3.5 py-2.5">Status</th>
                    <th className="px-3.5 py-2.5">URL / Path</th>
                    <th className="px-3.5 py-2.5">Server / Title</th>
                    <th className="px-3.5 py-2.5">Source</th>
                    <th className="px-3.5 py-2.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#2B2B2B]">
                  {filtered.map((ep, idx) => (
                    <tr 
                      key={idx}
                      onClick={() => setSelectedEndpoint(ep)}
                      className={`cursor-pointer transition-colors hover:bg-[#282828] ${
                        selectedEndpoint?.url === ep.url ? 'bg-[#2A2A2A] border-l-2 border-l-[#ebb94b]' : ''
                      }`}
                    >
                      <td className="px-3.5 py-2.5 font-mono">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                          ep.status === 200 ? 'text-[#4CAF50] bg-[#4CAF50]/15' :
                          ep.status === 403 ? 'text-[#FFA726] bg-[#FFA726]/15' :
                          'text-[#888888] bg-[#333333]'
                        }`}>
                          {ep.status || 200}
                        </span>
                      </td>
                      <td className="px-3.5 py-2.5 font-mono text-[#E8E8E8] max-w-[320px] truncate">
                        {ep.url}
                      </td>
                      <td className="px-3.5 py-2.5 text-[#888888] max-w-[200px] truncate">
                        {ep.title || ep.server || '—'}
                      </td>
                      <td className="px-3.5 py-2.5 text-[#666666] font-mono text-[11px]">
                        {ep.source || 'content_discovery'}
                      </td>
                      <td className="px-3.5 py-2.5 text-right">
                        <ChevronRight className="w-4 h-4 text-[#555555] inline" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Selected Endpoint Inspector */}
        {selectedEndpoint && (
          <div className="card space-y-4 h-fit">
            <div className="flex items-start justify-between pb-2 border-b border-[#333333]">
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-[#707070]">Asset Inspector</span>
                <h3 className="text-sm font-bold text-[#F2F2F2] mt-0.5 font-mono break-all">{selectedEndpoint.url}</h3>
              </div>
              <button onClick={() => setSelectedEndpoint(null)} className="text-[#888888] hover:text-[#FFFFFF] text-xs">✕</button>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-[#2A2A2A]">
                <span className="text-[#707070]">HTTP Status:</span>
                <span className="text-[#4CAF50] font-bold">{selectedEndpoint.status || 200}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#2A2A2A]">
                <span className="text-[#707070]">Server:</span>
                <span className="text-[#E8E8E8]">{selectedEndpoint.server || 'Detected in headers'}</span>
              </div>
              {selectedEndpoint.title && (
                <div className="flex justify-between py-1 border-b border-[#2A2A2A]">
                  <span className="text-[#707070]">HTML Title:</span>
                  <span className="text-[#E8E8E8] truncate max-w-[180px]">{selectedEndpoint.title}</span>
                </div>
              )}
              <div className="flex justify-between py-1 border-b border-[#2A2A2A]">
                <span className="text-[#707070]">Discovery Source:</span>
                <span className="text-[#ebb94b]">{selectedEndpoint.source}</span>
              </div>
            </div>

            <div className="space-y-2 pt-2 border-t border-[#333333]">
              <span className="text-[10px] font-semibold uppercase text-[#707070]">Next Security Actions</span>
              
              <button 
                onClick={() => setCurrentView('execution', { target: selectedEndpoint.url, tool: 'httpx' })}
                className="btn-primary w-full text-xs py-1.5 flex items-center justify-center gap-1.5"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Execute Probe (httpx)</span>
              </button>

              <button 
                onClick={() => setCurrentView('findings', { prefillEndpoint: selectedEndpoint.url })}
                className="btn-secondary w-full text-xs py-1.5 flex items-center justify-center gap-1.5"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Create Vulnerability Hypothesis</span>
              </button>

              <button 
                onClick={() => setCurrentView('intelligence', { target: selectedEndpoint.url })}
                className="btn-secondary w-full text-xs py-1.5 flex items-center justify-center gap-1.5"
              >
                <Brain className="w-3.5 h-3.5" />
                <span>Synthesize AI Attack Playbook</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default AttackSurfaceView;
