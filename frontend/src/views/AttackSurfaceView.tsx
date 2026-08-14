import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Globe, Cpu, Play, Search, ShieldCheck, Target, Radar, Layers, Activity, ChevronRight, Filter } from 'lucide-react';
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

  const getTechIcon = (category: string = 'Technology') => {
    switch (category.toLowerCase()) {
      case 'framework':
        return Layers;
      case 'server':
        return Cpu;
      case 'database':
        return Activity;
      case 'security':
        return ShieldCheck;
      default:
        return Cpu;
    }
  };

  return (
    <div className="nyx-attack-surface-view">
      {/* File Update Progress */}

      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div className="flex items-center gap-4">
            <div className="nyx-page-icon nyx-page-icon-cyan">
              <Globe className="w-6 h-6 text-[#00D9FF]" />
            </div>
            <div>
              <h1 className="nyx-page-title">Attack Surface Intelligence</h1>
              <p className="nyx-page-subtitle">Target assets, harvested endpoints, and technology stack</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="nyx-target-display">
              <Target className="w-4 h-4 text-[#00D9FF]" />
              <span className="nyx-label">Target:</span>
              <span className="nyx-data-value">{target}</span>
            </div>
            <button
              onClick={handleTriggerRecon}
              disabled={running}
              className="nyx-button nyx-button-primary"
            >
              {running ? (
                <>
                  <Activity className="w-4 h-4 animate-spin" />
                  <span>Running Recon...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Run Reconnaissance</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="nyx-stats-overview">
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-cyan">
            <Globe className="w-4 h-4 text-[#00D9FF]" />
          </div>
          <div>
            <div className="nyx-stat-value">{endpoints.length}</div>
            <div className="nyx-stat-label">Endpoints</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-purple">
            <Cpu className="w-4 h-4 text-[#7C3AED]" />
          </div>
          <div>
            <div className="nyx-stat-value">{technologies.length}</div>
            <div className="nyx-stat-label">Technologies</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-green">
            <ShieldCheck className="w-4 h-4 text-[#00FF88]" />
          </div>
          <div>
            <div className="nyx-stat-value">{filteredEndpoints.length}</div>
            <div className="nyx-stat-label">In Scope</div>
          </div>
        </div>
      </div>

      {/* Technology Stack Grid */}
      <div className="nyx-card nyx-card-accent-purple">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-purple">
              <Cpu className="w-4 h-4 text-[#7C3AED]" />
            </div>
            <h3 className="nyx-section-title">Technology Fingerprints</h3>
            <span className="nyx-count-pill">{technologies.length}</span>
          </div>
          <div className="flex items-center gap-2">
            <Radar className="w-3 h-3 text-[#7C3AED]" />
            <span className="text-[10px] font-mono text-[#7C3AED] uppercase tracking-wider">
              Fingerprinted
            </span>
          </div>
        </div>

        {technologies.length === 0 ? (
          <div className="nyx-empty-state">
            <div className="nyx-empty-state-icon">
              <Cpu className="w-8 h-8 text-[#484F58]" />
            </div>
            <div className="nyx-empty-state-title">No technology fingerprints recorded</div>
            <div className="nyx-empty-state-description">
              Run reconnaissance to analyze target technology stack
            </div>
          </div>
        ) : (
          <div className="nyx-tech-grid">
            {technologies.map((t: any, idx: number) => {
              const TechIcon = getTechIcon(t.category);
              return (
                <div key={idx} className="nyx-tech-item group">
                  <div className="nyx-tech-icon">
                    <TechIcon className="w-5 h-5 text-[#00FF88]" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="nyx-tech-name">{t.name || t}</div>
                    <div className="nyx-tech-category">{t.category || 'Technology'}</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-[#484F58] group-hover:text-[#00D9FF] transition-colors" />
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Harvested Endpoints */}
      <div className="nyx-card nyx-card-accent-cyan">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-cyan">
              <Globe className="w-4 h-4 text-[#00D9FF]" />
            </div>
            <h3 className="nyx-section-title">Harvested Endpoints</h3>
            <span className="nyx-count-pill">{endpoints.length}</span>
          </div>
          <div className="nyx-search-container">
            <Search className="nyx-search-icon" />
            <input
              type="text"
              placeholder="Filter endpoints..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="nyx-search-input"
            />
            {filter && (
              <button 
                onClick={() => setFilter('')}
                className="nyx-search-clear"
              >
                ×
              </button>
            )}
          </div>
        </div>

        {filteredEndpoints.length === 0 ? (
          <div className="nyx-empty-state">
            <div className="nyx-empty-state-icon">
              <Globe className="w-8 h-8 text-[#484F58]" />
            </div>
            <div className="nyx-empty-state-title">No endpoints matching filter</div>
            <div className="nyx-empty-state-description">
              {filter ? `No results for "${filter}"` : 'Run reconnaissance to discover endpoints'}
            </div>
          </div>
        ) : (
          <div className="nyx-endpoints-list">
            <div className="nyx-endpoints-header">
              <div className="nyx-endpoints-header-item">#</div>
              <div className="nyx-endpoints-header-item">Endpoint URL</div>
              <div className="nyx-endpoints-header-item">Scope</div>
              <div className="nyx-endpoints-header-item">Status</div>
            </div>
            <div className="nyx-endpoints-body">
              {filteredEndpoints.slice(0, 100).map((ep: any, idx: number) => {
                const urlStr = ep.url || ep;
                return (
                  <div key={idx} className="nyx-endpoint-row group">
                    <div className="nyx-endpoint-index">{String(idx + 1).padStart(3, '0')}</div>
                    <div className="nyx-endpoint-url">{urlStr}</div>
                    <div className="nyx-endpoint-scope">
                      <span className="nyx-badge nyx-badge-success">IN_SCOPE</span>
                    </div>
                    <div className="nyx-endpoint-status">
                      <div className="w-1.5 h-1.5 rounded-full bg-[#00FF88]"></div>
                      <span className="text-[10px] font-mono text-[#00FF88] uppercase">Active</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};