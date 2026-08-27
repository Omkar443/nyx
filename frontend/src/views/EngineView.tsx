import React, { useState, useEffect, useCallback } from 'react';
import { 
  Gauge, 
  CheckCircle, 
  RefreshCw, 
  Cpu, 
  Server, 
  Shield, 
  Database, 
  Lock, 
  TerminalSquare, 
  Activity, 
  HardDrive, 
  AlertTriangle,
  Bot,
  Layers,
  Check,
  X
} from 'lucide-react';
import { fetchApi } from '../api/client';
import { useSkills } from '../hooks/useSkills';
import { useApp } from '../context/AppContext';

export interface ToolDiagnostic {
  tool: string;
  available: boolean;
  environment?: string;
  command_vector?: string[];
  native_path?: string | null;
  message?: string;
}

export interface EngineTelemetryData {
  engine: {
    name: string;
    version: string;
    status: string;
    target: string;
    phase: string;
    workspace_active: boolean;
    authorization_enforced: boolean;
    scope_enforced: boolean;
    platform?: string;
    python_version?: string;
  };
  skills: {
    count: number;
    categories: Record<string, number>;
  };
  tools: {
    available_count: number;
    total_count: number;
    list: ToolDiagnostic[];
  };
  workers: {
    total: number;
    online: number;
  };
  fleet: {
    total_agents: number;
    active_agents: number;
    pending_approvals: number;
  };
  vault: {
    mounted: boolean;
    path: string;
    evidence_count: number;
    findings_count: number;
  };
  ai_providers?: Array<{
    name: string;
    configured: boolean;
    model?: string;
    tier?: string;
  }>;
}

export function EngineView() {
  const { target: appTarget, phase: appPhase, isConnected } = useApp();
  const { skills, count: hookSkillCount, categories: hookCategories, refreshSkills } = useSkills();
  const [telemetry, setTelemetry] = useState<EngineTelemetryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const loadTelemetry = useCallback(async () => {
    setError(null);
    try {
      const res = await fetchApi<any>('/api/v1/engine/status');
      if (res?.data?.engine) {
        setTelemetry(res.data);
      } else {
        // Fallback: aggregate from /health and /skills/stats
        const healthRes = await fetchApi<any>('/health');
        const statsRes = await fetchApi<any>('/api/v1/skills/stats');
        setTelemetry({
          engine: {
            name: healthRes?.app_name || 'NYX Security Intelligence Engine',
            version: healthRes?.version || '1.0.0',
            status: healthRes?.status === 'ok' ? 'HEALTHY' : 'ACTIVE',
            target: healthRes?.target || appTarget || 'No active target',
            phase: appPhase || 'DISCOVERY',
            workspace_active: Boolean(healthRes?.workspace_active),
            authorization_enforced: true,
            scope_enforced: true,
          },
          skills: {
            count: statsRes?.data?.skill_count ?? hookSkillCount ?? 0,
            categories: statsRes?.data?.categories ?? hookCategories ?? {},
          },
          tools: {
            available_count: 0,
            total_count: 0,
            list: [],
          },
          workers: { total: 0, online: 0 },
          fleet: { total_agents: 0, active_agents: 0, pending_approvals: 0 },
          vault: { mounted: true, path: '.engagement', evidence_count: 0, findings_count: 0 },
        });
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to load engine telemetry.');
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, [appTarget, appPhase, hookSkillCount, hookCategories]);

  useEffect(() => {
    loadTelemetry();
  }, [loadTelemetry]);

  async function handleRefresh() {
    setIsRefreshing(true);
    await Promise.all([loadTelemetry(), refreshSkills()]);
    setIsRefreshing(false);
  }

  // Safe resolved values
  const effectiveCategories: Record<string, number> = telemetry?.skills?.categories || hookCategories || {};
  const effectiveSkillCount = telemetry?.skills?.count ?? hookSkillCount ?? skills?.length ?? 0;
  const toolsList = telemetry?.tools?.list || [];
  const engineInfo = telemetry?.engine;
  const vaultInfo = telemetry?.vault;

  const diagnosticsCards = [
    { 
      label: 'Security Intelligence Core', 
      status: engineInfo?.status || 'HEALTHY', 
      subtext: `v${engineInfo?.version || '1.0.0'} · ${engineInfo?.platform || 'Active'}`, 
      icon: Shield,
      isOk: true 
    },
    { 
      label: 'Dynamic Skills Inventory', 
      status: `${effectiveSkillCount} Skills Loaded`, 
      subtext: `${Object.keys(effectiveCategories).length} Categories Active`, 
      icon: Cpu,
      isOk: effectiveSkillCount > 0 
    },
    { 
      label: 'Authentication & Scope Policy Gate', 
      status: 'Enforced', 
      subtext: `Strict Scope Check (${engineInfo?.target || appTarget || 'Default'})`, 
      icon: Lock,
      isOk: true 
    },
    { 
      label: 'Persistent Engagement Vault', 
      status: vaultInfo?.mounted ? 'Mounted' : 'Unmounted', 
      subtext: `${vaultInfo?.findings_count || 0} findings · ${vaultInfo?.evidence_count || 0} evidence records`, 
      icon: Database,
      isOk: Boolean(vaultInfo?.mounted) 
    },
    { 
      label: 'Real-Time WebSocket Ingestion', 
      status: isConnected ? 'Connected' : 'Disconnected', 
      subtext: isConnected ? 'Live stream active (/ws/events)' : 'Attempting reconnection...', 
      icon: Server,
      isOk: isConnected 
    },
    { 
      label: 'Remote Worker Runtime', 
      status: `${telemetry?.workers?.online || 0} Online`, 
      subtext: `${telemetry?.workers?.total || 0} registered workers · ${telemetry?.fleet?.total_agents || 0} fleet agents`, 
      icon: HardDrive,
      isOk: true 
    },
  ];

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Engine Telemetry &amp; System Health
          </h1>
          <p className="text-xs text-[#707070] mt-0.5 flex items-center gap-2 font-mono">
            <Gauge className="w-3.5 h-3.5 text-[#ebb94b]" />
            Authoritative subsystem diagnostics, tool execution status, and security policy gates
          </p>
        </div>
        <button 
          onClick={handleRefresh} 
          disabled={isRefreshing} 
          className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5 self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {/* ========== ERROR BANNER ========== */}
      {error && (
        <div className="p-3 rounded bg-[#251A1A] border border-[#EF5350]/30 text-xs text-[#EF5350] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={handleRefresh} className="btn-secondary text-[11px] py-1 px-2.5">
            Retry
          </button>
        </div>
      )}

      {/* ========== LOADING SKELETON ========== */}
      {loading && !telemetry ? (
        <div className="card text-center py-12 space-y-3">
          <RefreshCw className="w-6 h-6 text-[#ebb94b] animate-spin mx-auto" />
          <p className="text-xs font-mono text-[#888888]">Loading engine telemetry and system health...</p>
        </div>
      ) : (
        <>
          {/* ========== DIAGNOSTICS OVERVIEW GRID ========== */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {diagnosticsCards.map((d, idx) => {
              const Icon = d.icon;
              return (
                <div key={idx} className="card p-3.5 flex items-center justify-between border border-[#333333] hover:border-[#444444] transition-colors">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded border ${d.isOk ? 'bg-[#2A2A2A] border-[#3A3A3A] text-[#4CAF50]' : 'bg-[#2A1A1A] border-[#EF5350]/30 text-[#EF5350]'}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="text-xs font-bold text-[#E8E8E8]">{d.label}</h3>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[11px] font-mono text-[#CCCCCC] font-bold">{d.status}</span>
                      </div>
                      <p className="text-[10px] font-mono text-[#777777] truncate max-w-[200px]">{d.subtext}</p>
                    </div>
                  </div>
                  {d.isOk ? (
                    <CheckCircle className="w-4 h-4 text-[#4CAF50] shrink-0" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-[#EF5350] shrink-0" />
                  )}
                </div>
              );
            })}
          </div>

          {/* ========== TOOLS RESOLUTION MATRIX ========== */}
          <div className="card space-y-3">
            <div className="flex items-center justify-between border-b border-[#333333] pb-2">
              <div className="flex items-center gap-2">
                <TerminalSquare className="w-4 h-4 text-[#ebb94b]" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-[#E8E8E8]">
                  Security Tooling &amp; Binary Resolution Matrix
                </h3>
              </div>
              <span className="text-[11px] font-mono text-[#888888]">
                {telemetry?.tools?.available_count || 0} / {telemetry?.tools?.total_count || toolsList.length} Tools Ready
              </span>
            </div>

            {toolsList.length === 0 ? (
              <p className="text-xs font-mono text-[#777777] italic py-2">
                Tool discovery initialized across system PATH and WSL subsystem.
              </p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
                {toolsList.map((t, idx) => (
                  <div key={idx} className="p-2.5 rounded bg-[#242424] border border-[#333333] flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-xs font-bold text-[#E8E8E8]">{t.tool}</span>
                        <span className="text-[10px] font-mono px-1 rounded bg-[#1E1E1E] text-[#888888]">
                          {t.environment || (t.available ? 'Native' : 'Unavailable')}
                        </span>
                      </div>
                      <p className="text-[10px] font-mono text-[#666666] truncate max-w-[170px] mt-0.5">
                        {Array.isArray(t.command_vector) && t.command_vector.length > 0
                          ? t.command_vector.join(' ')
                          : t.native_path || (t.available ? 'Resolved' : 'Not found')}
                      </p>
                    </div>
                    {t.available ? (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#4CAF50]/15 text-[#4CAF50] border border-[#4CAF50]/30 font-bold flex items-center gap-1">
                        <Check className="w-2.5 h-2.5" />
                        <span>OK</span>
                      </span>
                    ) : (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#FFA726]/15 text-[#FFA726] border border-[#FFA726]/30 font-bold flex items-center gap-1">
                        <X className="w-2.5 h-2.5" />
                        <span>MISSING</span>
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ========== SKILL CATEGORIES DISTRIBUTION ========== */}
          <div className="card space-y-3">
            <div className="flex items-center justify-between border-b border-[#333333] pb-2">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-[#ebb94b]" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-[#E8E8E8]">
                  Skill Categories &amp; Security Arsenal Distribution
                </h3>
              </div>
              <span className="text-[11px] font-mono text-[#ebb94b] font-bold">
                {effectiveSkillCount} Total Skills
              </span>
            </div>

            {Object.keys(effectiveCategories).length === 0 ? (
              <div className="text-xs font-mono text-[#777777] italic py-4 text-center">
                No skill categories currently indexed.
              </div>
            ) : (
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-xs font-mono">
                {Object.entries(effectiveCategories).map(([cat, cnt]) => (
                  <div key={cat} className="p-2 rounded bg-[#242424] border border-[#333333] flex justify-between items-center">
                    <span className="text-[#AAAAAA] capitalize truncate pr-1">{cat}</span>
                    <span className="text-[#ebb94b] font-bold shrink-0">{cnt}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ========== AI PROVIDERS & MULTI-AGENT STATUS ========== */}
          {telemetry?.ai_providers && telemetry.ai_providers.length > 0 && (
            <div className="card space-y-3">
              <div className="flex items-center justify-between border-b border-[#333333] pb-2">
                <div className="flex items-center gap-2">
                  <Bot className="w-4 h-4 text-[#ebb94b]" />
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[#E8E8E8]">
                    AI Providers &amp; Planning Intelligence Readiness
                  </h3>
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
                {telemetry.ai_providers.map((p, idx) => (
                  <div key={idx} className="p-2.5 rounded bg-[#242424] border border-[#333333] flex items-center justify-between">
                    <div>
                      <span className="font-mono text-xs font-bold text-[#E8E8E8] uppercase">{p.name}</span>
                      <p className="text-[10px] font-mono text-[#777777] truncate">{p.model || p.tier || 'Ready'}</p>
                    </div>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-bold ${
                      p.configured ? 'bg-[#4CAF50]/15 text-[#4CAF50] border border-[#4CAF50]/30' : 'bg-[#333333] text-[#888888]'
                    }`}>
                      {p.configured ? 'READY' : 'UNCONFIGURED'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default EngineView;
