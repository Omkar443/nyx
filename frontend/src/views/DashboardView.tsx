import React, { useState, useEffect } from 'react';
import { 
  Server, Cpu, Target, Shield, Terminal, 
  ChevronRight, Activity, Zap, RefreshCw, CheckCircle, AlertTriangle, Play, Sparkles
} from 'lucide-react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';
import { useApp } from '../context/AppContext';

export function DashboardView() {
  const { 
    target, phase, endpointsCount, findingsCount, 
    evidenceCount, setCurrentView, refreshGlobalStats 
  } = useApp();
  const { lastEvent } = useNyxEvents();
  const [technologies, setTechnologies] = useState<string[]>([]);
  const [recentFindings, setRecentFindings] = useState<any[]>([]);
  const [recentExecutions, setRecentExecutions] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [isReconRunning, setIsReconRunning] = useState<boolean>(false);

  async function loadDashboard() {
    try {
      // 1. Technologies
      const techRes = await fetchApi('/api/v1/technologies');
      const tList = techRes?.data?.technologies || techRes?.technologies || [];
      if (Array.isArray(tList)) setTechnologies(tList);

      // 2. Recent Findings
      const findingsRes = await fetchApi('/api/v1/findings');
      const fList = findingsRes?.data?.findings || findingsRes?.findings || [];
      if (Array.isArray(fList)) setRecentFindings(fList.slice(0, 5));

      // 3. Recent Executions scoped to target
      const targetQuery = target && target !== 'No active target' ? `&target=${encodeURIComponent(target)}` : '';
      const execRes = await fetchApi(`/api/v1/execution/history?limit=5${targetQuery}`);
      const eList = execRes?.data?.history || execRes?.history || [];
      if (Array.isArray(eList)) setRecentExecutions(eList.slice(0, 5));
    } catch {
      // Graceful fallback
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadDashboard();
  }, [target]);

  useEffect(() => {
    if (lastEvent) {
      loadDashboard();
      refreshGlobalStats();
    }
  }, [lastEvent, refreshGlobalStats]);

  async function handleQuickRecon() {
    if (!target || target === 'No active target') return;
    setIsReconRunning(true);
    try {
      await fetchApi(`/api/v1/surface/recon?target=${encodeURIComponent(target)}`, { method: 'POST' });
      await loadDashboard();
      await refreshGlobalStats();
    } finally {
      setIsReconRunning(false);
    }
  }

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Command Center
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-[#555555]" />
            Active Target: <span className="font-mono text-[#E8E8E8] font-semibold">{target}</span>
            <span className="text-[#444444]">·</span>
            Phase: <span className="font-mono text-[#ebb94b] uppercase font-semibold">{phase}</span>
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          <button 
            onClick={handleQuickRecon} 
            disabled={isReconRunning || !target || target === 'No active target'}
            className="btn-primary flex items-center gap-1.5 text-xs py-1.5 px-3"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isReconRunning ? 'animate-spin' : ''}`} />
            <span>{isReconRunning ? 'Harvesting Surface...' : 'Run Reconnaissance'}</span>
          </button>
          <button 
            onClick={() => setCurrentView('mission')}
            className="btn-secondary flex items-center gap-1.5 text-xs py-1.5 px-3"
          >
            <span>Mission Plan</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* ========== METRIC CARDS ========== */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
        <div 
          onClick={() => setCurrentView('attack-surface')}
          className="card-metric cursor-pointer hover:border-[#4A4A4A] transition-colors"
        >
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[#707070]">Endpoints Discovered</p>
              <div className="flex items-baseline gap-2">
                <span className={`text-2xl font-bold tracking-tight ${endpointsCount === 0 ? 'text-[#555555]' : 'text-[#F2F2F2]'}`}>
                  {endpointsCount}
                </span>
                {endpointsCount === 0 && <span className="text-[10px] font-mono text-[#444444]">—</span>}
              </div>
              <p className="text-[10px] font-mono text-[#555555]">
                {endpointsCount > 0 ? 'Click to inspect attack surface' : 'Click to run discovery'}
              </p>
            </div>
            <div className="p-1.5 rounded-md bg-[#303030] border border-[#3A3A3A]">
              <Server className="w-4 h-4 text-[#707070]" />
            </div>
          </div>
        </div>

        <div 
          onClick={() => setCurrentView('attack-surface')}
          className="card-metric cursor-pointer hover:border-[#4A4A4A] transition-colors"
        >
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[#707070]">Detected Stack</p>
              <div className="flex items-baseline gap-2">
                <span className={`text-2xl font-bold tracking-tight ${technologies.length === 0 ? 'text-[#555555]' : 'text-[#F2F2F2]'}`}>
                  {technologies.length}
                </span>
                {technologies.length === 0 && <span className="text-[10px] font-mono text-[#444444]">—</span>}
              </div>
              <p className="text-[10px] font-mono text-[#555555]">
                {technologies.length > 0 ? technologies.slice(0, 3).join(', ') : 'Technologies identified'}
              </p>
            </div>
            <div className="p-1.5 rounded-md bg-[#303030] border border-[#3A3A3A]">
              <Cpu className="w-4 h-4 text-[#707070]" />
            </div>
          </div>
        </div>

        <div 
          onClick={() => setCurrentView('findings')}
          className="card-metric cursor-pointer hover:border-[#ebb94b]/60 transition-colors border-[#ebb94b]/30"
        >
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[#ebb94b]">Active Hypotheses</p>
              <div className="flex items-baseline gap-2">
                <span className={`text-2xl font-bold tracking-tight ${findingsCount === 0 ? 'text-[#555555]' : 'text-[#F2F2F2]'}`}>
                  {findingsCount}
                </span>
                {findingsCount === 0 && <span className="text-[10px] font-mono text-[#444444]">—</span>}
              </div>
              <p className="text-[10px] font-mono text-[#ebb94b]/80">Findings under triage</p>
            </div>
            <div className="p-1.5 rounded-md bg-[#303030] border border-[#ebb94b]/40">
              <Target className="w-4 h-4 text-[#ebb94b]" />
            </div>
          </div>
        </div>

        <div 
          onClick={() => setCurrentView('evidence')}
          className="card-metric cursor-pointer hover:border-[#4A4A4A] transition-colors"
        >
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[#707070]">Evidence Proofs</p>
              <div className="flex items-baseline gap-2">
                <span className={`text-2xl font-bold tracking-tight ${evidenceCount === 0 ? 'text-[#555555]' : 'text-[#4CAF50]'}`}>
                  {evidenceCount}
                </span>
                {evidenceCount === 0 && <span className="text-[10px] font-mono text-[#444444]">—</span>}
              </div>
              <p className="text-[10px] font-mono text-[#555555]">SHA-256 anchored artifacts</p>
            </div>
            <div className="p-1.5 rounded-md bg-[#303030] border border-[#3A3A3A]">
              <Shield className="w-4 h-4 text-[#4CAF50]" />
            </div>
          </div>
        </div>
      </div>

      {/* ========== MAIN CONTENT SPLIT ========== */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Left 2/3: Active Findings & Hypotheses */}
        <div className="xl:col-span-2 space-y-4">
          <div className="card">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#2E2E2E]">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-[#E8E8E8]">Active Vulnerability Hypotheses</h3>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#2A2A2A] text-[#888888] font-mono border border-[#3A3A3A]">
                  {recentFindings.length}
                </span>
              </div>
              <button 
                onClick={() => setCurrentView('findings')} 
                className="text-xs text-[#ebb94b] hover:underline flex items-center gap-1 font-mono"
              >
                <span>View All Findings</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            </div>

            {recentFindings.length === 0 ? (
              <div className="text-center py-8 space-y-2">
                <Target className="w-8 h-8 text-[#555555] mx-auto opacity-50" />
                <p className="text-xs text-[#888888]">No vulnerability hypotheses recorded yet for {target}.</p>
                <div className="flex items-center justify-center gap-2 pt-2">
                  <button onClick={handleQuickRecon} className="btn-primary text-xs py-1 px-3">
                    Start Reconnaissance
                  </button>
                  <button onClick={() => setCurrentView('findings')} className="btn-secondary text-xs py-1 px-3">
                    Create Finding
                  </button>
                </div>
              </div>
            ) : (
              <div className="divide-y divide-[#2E2E2E]">
                {recentFindings.map((f: any) => (
                  <div 
                    key={f.id || f.finding_id} 
                    onClick={() => setCurrentView('findings', { selectedFindingId: f.id || f.finding_id })}
                    className="py-2.5 flex items-center justify-between cursor-pointer hover:bg-[#252525] px-2 rounded transition-colors"
                  >
                    <div className="space-y-0.5 min-w-0 pr-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-[#E8E8E8]">{f.id || f.finding_id}</span>
                        <span className={`text-[10px] uppercase font-mono px-1.5 py-0.2 rounded border ${
                          f.severity?.toLowerCase() === 'critical' ? 'text-[#EF5350] bg-[#EF5350]/15 border-[#EF5350]/30' :
                          f.severity?.toLowerCase() === 'high' ? 'text-[#FFA726] bg-[#FFA726]/15 border-[#FFA726]/30' :
                          'text-[#ebb94b] bg-[#ebb94b]/15 border-[#ebb94b]/30'
                        }`}>
                          {f.severity || 'Medium'}
                        </span>
                        <span className="text-[10px] font-mono text-[#888888] bg-[#2A2A2A] px-1.5 py-0.2 rounded border border-[#3A3A3A]">
                          {f.status || 'HYPOTHESIS'}
                        </span>
                      </div>
                      <p className="text-xs text-[#CCCCCC] truncate font-medium">{f.title}</p>
                      <p className="text-[11px] font-mono text-[#777777] truncate">{f.endpoint}</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-[#555555] shrink-0" />
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Recent Executions Scoped to Current Scan */}
          <div className="card">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#2E2E2E]">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-[#E8E8E8]">Recent Tool Executions</h3>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#2A2A2A] text-[#888888] font-mono border border-[#3A3A3A]">
                  {recentExecutions.length}
                </span>
              </div>
              <button 
                onClick={() => setCurrentView('execution', { target })} 
                className="text-xs text-[#ebb94b] hover:underline flex items-center gap-1 font-mono"
              >
                <span>Full Audit Trail</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            </div>

            {recentExecutions.length === 0 ? (
              <div className="text-center py-6 text-xs text-[#777777] italic font-mono">
                No tool executions recorded for target {target}. Run a probe from Execution view.
              </div>
            ) : (
              <div className="divide-y divide-[#2E2E2E]">
                {recentExecutions.map((e: any, idx: number) => (
                  <div key={idx} className="py-2 flex items-center justify-between font-mono text-xs">
                    <div className="flex items-center gap-2.5">
                      <span className={`w-2 h-2 rounded-full ${
                        e.status === 'SKIPPED' ? 'bg-[#ebb94b]' :
                        e.status === 'UNAVAILABLE' ? 'bg-[#FFA726]' :
                        e.status === 'BLOCKED' ? 'bg-[#CE93D8]' :
                        e.exit_code === 0 ? 'bg-[#4CAF50]' : 'bg-[#EF5350]'
                      }`} />
                      <span className="text-[#E8E8E8] font-semibold">{e.tool || e.tool_name}</span>
                      <span className="text-[#777777] text-[11px] truncate max-w-[280px]">{e.target}</span>
                    </div>
                    <span className="text-[10px] text-[#888888]">{e.timestamp?.slice(11, 19) || 'Just now'}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right 1/3: Next Action & Shortcuts */}
        <div className="space-y-4">
          <div className="card space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#707070]">Next Action</h3>
            <div className="p-3 rounded-lg bg-[#252525] border border-[#3A3A3A] space-y-2">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-[#ebb94b]" />
                <span className="text-xs font-semibold text-[#E8E8E8]">
                  {endpointsCount === 0 ? '1. Harvest Attack Surface' : findingsCount === 0 ? '2. Synthesize AI Hypotheses' : '3. 7-Question Gate Triage'}
                </span>
              </div>
              <p className="text-xs text-[#8A8A8A] leading-relaxed">
                {endpointsCount === 0 
                  ? 'No endpoints discovered yet. Trigger reconnaissance to enumerate routes, parameters, and technologies.'
                  : findingsCount === 0 
                    ? 'Attack surface mapped with ' + endpointsCount + ' endpoints. Generate AI hypotheses and route attack skills.'
                    : 'Hypotheses registered. Run empirical triage and attach cryptographic proof-of-concept evidence.'}
              </p>
              <button 
                onClick={() => {
                  if (endpointsCount === 0) handleQuickRecon();
                  else if (findingsCount === 0) setCurrentView('intelligence', { target });
                  else setCurrentView('findings');
                }}
                className="btn-primary w-full text-xs py-1.5 mt-1"
              >
                {endpointsCount === 0 ? 'Run Recon Now' : findingsCount === 0 ? 'Synthesize AI Plan' : 'Open Findings & Triage'}
              </button>
            </div>
          </div>

          <div className="card space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#707070]">Operational Shortcuts</h3>
            <div className="space-y-1.5">
              <button 
                onClick={() => setCurrentView('attack-surface')} 
                className="w-full btn-secondary text-xs py-2 flex items-center justify-between"
              >
                <span>Inspect Attack Surface ({endpointsCount})</span>
                <ChevronRight className="w-3.5 h-3.5 text-[#666666]" />
              </button>
              <button 
                onClick={() => setCurrentView('intelligence', { target })} 
                className="w-full btn-secondary text-xs py-2 flex items-center justify-between"
              >
                <span>AI Playbook Planner</span>
                <ChevronRight className="w-3.5 h-3.5 text-[#666666]" />
              </button>
              <button 
                onClick={() => setCurrentView('execution', { target })} 
                className="w-full btn-secondary text-xs py-2 flex items-center justify-between"
              >
                <span>Execute Security Tool</span>
                <ChevronRight className="w-3.5 h-3.5 text-[#666666]" />
              </button>
              <button 
                onClick={() => setCurrentView('engine')} 
                className="w-full btn-secondary text-xs py-2 flex items-center justify-between"
              >
                <span>Engine Diagnostic Status</span>
                <ChevronRight className="w-3.5 h-3.5 text-[#666666]" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default DashboardView;
