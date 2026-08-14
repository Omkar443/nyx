import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Play, Globe, Activity, Camera, RefreshCw, Monitor, Cpu, Zap, Radio, Eye, Code, Database } from 'lucide-react';
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
    <div className="nyx-runtime-view">
      {/* File Update Progress */}

      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div className="flex items-center gap-4">
            <div className="nyx-page-icon nyx-page-icon-green">
              <Monitor className="w-6 h-6 text-[#00FF88]" />
            </div>
            <div>
              <h1 className="nyx-page-title">Browser Runtime</h1>
              <p className="nyx-page-subtitle">Playwright browser automation, authenticated session tracking, and Runtime Intelligence Graph</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleRunDynamicAgent}
              disabled={loading}
              className="nyx-button nyx-button-primary"
            >
              {loading ? (
                <>
                  <Activity className="w-4 h-4 animate-spin" />
                  <span>Running...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Run Dynamic Agent</span>
                </>
              )}
            </button>
            <button onClick={loadData} className="nyx-button nyx-button-ghost" title="Refresh">
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Runtime Stats */}
      <div className="nyx-stats-overview">
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-green">
            <Camera className="w-4 h-4 text-[#00FF88]" />
          </div>
          <div>
            <div className="nyx-stat-value">{sessions.length}</div>
            <div className="nyx-stat-label">Active Sessions</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-cyan">
            <Radio className="w-4 h-4 text-[#00D9FF]" />
          </div>
          <div>
            <div className="nyx-stat-value">{runtimeGraph?.requests?.length || 0}</div>
            <div className="nyx-stat-label">Observed Requests</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-purple">
            <Code className="w-4 h-4 text-[#7C3AED]" />
          </div>
          <div>
            <div className="nyx-stat-value">{runtimeGraph?.apis?.length || 0}</div>
            <div className="nyx-stat-label">API Operations</div>
          </div>
        </div>
      </div>

      {/* Start Session Form */}
      <div className="nyx-card nyx-card-accent-green">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-green">
              <Globe className="w-4 h-4 text-[#00FF88]" />
            </div>
            <h2 className="nyx-section-title">Launch Managed Browser Session</h2>
          </div>
          <div className="flex items-center gap-2">
            <Eye className="w-3 h-3 text-[#00FF88]" />
            <span className="text-[10px] font-mono text-[#00FF88] uppercase tracking-wider">
              Managed
            </span>
          </div>
        </div>
        
        <div className="nyx-form-container">
          <form onSubmit={handleStartSession} className="nyx-form-inline">
            <div className="nyx-form-field nyx-form-field-grow">
              <label className="nyx-form-label">
                <Globe className="w-3 h-3 text-[#00D9FF]" />
                Target Domain
              </label>
              <input
                type="text"
                required
                placeholder="e.g. app.target.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="nyx-input"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="nyx-button nyx-button-secondary"
            >
              {loading ? 'Starting...' : 'Start Session'}
            </button>
          </form>
        </div>
      </div>

      {/* Grid: Sessions & Runtime Graph */}
      <div className="nyx-content-grid">
        {/* Active Browser Sessions */}
        <div className="nyx-card nyx-card-accent-cyan">
          <div className="nyx-section-header">
            <div className="flex items-center gap-3">
              <div className="nyx-section-icon nyx-section-icon-cyan">
                <Camera className="w-4 h-4 text-[#00D9FF]" />
              </div>
              <h3 className="nyx-section-title">Active Browser Sessions</h3>
              <span className="nyx-count-pill">{sessions.length}</span>
            </div>
            {sessions.length > 0 && (
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-[#00FF88] animate-pulse"></div>
                <span className="text-[10px] font-mono text-[#00FF88] uppercase tracking-wider">
                  Live
                </span>
              </div>
            )}
          </div>

          {sessions.length === 0 ? (
            <div className="nyx-empty-state">
              <div className="nyx-empty-state-icon">
                <Camera className="w-8 h-8 text-[#484F58]" />
              </div>
              <div className="nyx-empty-state-title">No active browser sessions</div>
              <div className="nyx-empty-state-description">
                Launch a managed browser session above to begin
              </div>
            </div>
          ) : (
            <div className="nyx-sessions-list">
              {sessions.map((s) => (
                <div key={s.session_id} className="nyx-session-card">
                  <div className="nyx-session-header">
                    <div className="flex items-center gap-2">
                      <Monitor className="w-4 h-4 text-[#00D9FF]" />
                      <span className="nyx-session-id">{s.session_id}</span>
                    </div>
                    <span className="nyx-badge nyx-badge-success">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#00FF88] inline-block mr-1"></span>
                      ACTIVE
                    </span>
                  </div>
                  <div className="nyx-session-details">
                    <div className="nyx-session-detail-row">
                      <span className="nyx-session-detail-label">Target:</span>
                      <span className="nyx-session-detail-value">{s.target}</span>
                    </div>
                    <div className="nyx-session-detail-row">
                      <span className="nyx-session-detail-label">Created:</span>
                      <span className="nyx-session-detail-value text-[#8B949E]">{s.created_at}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Runtime Intelligence Graph Summary */}
        <div className="nyx-card nyx-card-accent-green">
          <div className="nyx-section-header">
            <div className="flex items-center gap-3">
              <div className="nyx-section-icon nyx-section-icon-green">
                <Activity className="w-4 h-4 text-[#00FF88]" />
              </div>
              <h3 className="nyx-section-title">Runtime Intelligence Graph</h3>
            </div>
            <div className="flex items-center gap-2">
              <Zap className="w-3 h-3 text-[#00FF88]" />
              <span className="text-[10px] font-mono text-[#00FF88] uppercase tracking-wider">
                Analyzing
              </span>
            </div>
          </div>

          <div className="nyx-runtime-stats">
            <div className="nyx-runtime-stat">
              <div className="nyx-runtime-stat-icon">
                <Radio className="w-4 h-4 text-[#00D9FF]" />
              </div>
              <div className="flex-1">
                <div className="nyx-runtime-stat-label">Observed Requests</div>
                <div className="nyx-runtime-stat-value">{runtimeGraph?.requests?.length || 0}</div>
              </div>
              <div className="nyx-runtime-stat-bar">
                <div className="nyx-runtime-stat-bar-fill" style={{ width: `${Math.min((runtimeGraph?.requests?.length || 0) * 10, 100)}%` }}></div>
              </div>
            </div>
            
            <div className="nyx-runtime-stat">
              <div className="nyx-runtime-stat-icon">
                <Code className="w-4 h-4 text-[#00FF88]" />
              </div>
              <div className="flex-1">
                <div className="nyx-runtime-stat-label">API & GraphQL Operations</div>
                <div className="nyx-runtime-stat-value">{runtimeGraph?.apis?.length || 0}</div>
              </div>
              <div className="nyx-runtime-stat-bar">
                <div className="nyx-runtime-stat-bar-fill" style={{ width: `${Math.min((runtimeGraph?.apis?.length || 0) * 10, 100)}%`, backgroundColor: '#00FF88' }}></div>
              </div>
            </div>
            
            <div className="nyx-runtime-stat">
              <div className="nyx-runtime-stat-icon">
                <Database className="w-4 h-4 text-[#FF6B35]" />
              </div>
              <div className="flex-1">
                <div className="nyx-runtime-stat-label">Discovered Parameters</div>
                <div className="nyx-runtime-stat-value">{runtimeGraph?.parameters?.length || 0}</div>
              </div>
              <div className="nyx-runtime-stat-bar">
                <div className="nyx-runtime-stat-bar-fill" style={{ width: `${Math.min((runtimeGraph?.parameters?.length || 0) * 10, 100)}%`, backgroundColor: '#FF6B35' }}></div>
              </div>
            </div>
            
            <div className="nyx-runtime-stat">
              <div className="nyx-runtime-stat-icon">
                <Cpu className="w-4 h-4 text-[#7C3AED]" />
              </div>
              <div className="flex-1">
                <div className="nyx-runtime-stat-label">Detected Stack / Technologies</div>
                <div className="nyx-runtime-stat-value">{runtimeGraph?.technologies?.length || 0}</div>
              </div>
              <div className="nyx-runtime-stat-bar">
                <div className="nyx-runtime-stat-bar-fill" style={{ width: `${Math.min((runtimeGraph?.technologies?.length || 0) * 10, 100)}%`, backgroundColor: '#7C3AED' }}></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};