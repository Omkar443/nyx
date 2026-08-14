import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Bot, BookOpen, Search, Sparkles, Code2, Brain, Database, Cpu, Globe, Layers, Shield, Zap, Target, Activity } from 'lucide-react';
export const IntelligenceView: React.FC = () => {
  const [providers, setProviders] = useState<any[]>([]);
  const [activeProvider, setActiveProvider] = useState<string>('gemini');
  const [context, setContext] = useState<any>(null);
  const [skills, setSkills] = useState<any[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [searchResults, setSearchResults] = useState<any[]>([]);

  useEffect(() => {
    async function loadData() {
      const pRes = await fetchApi('/api/v1/ai/providers');
      if (pRes.success && pRes.data?.providers) setProviders(pRes.data.providers);

      const cRes = await fetchApi('/api/v1/intelligence/context?target=example.com');
      if (cRes.success) setContext(cRes.data);

      const sRes = await fetchApi('/api/v1/skills');
      if (sRes.success && sRes.data?.skills) setSkills(sRes.data.skills);
    }
    loadData();
  }, []);

  async function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    const res = await fetchApi(`/api/v1/knowledge/search?query=${encodeURIComponent(searchQuery)}`);
    if (res.success && res.data?.results) setSearchResults(res.data.results);
  }

  const getProviderIcon = (provider: string) => {
    switch (provider.toLowerCase()) {
      case 'gemini':
        return Sparkles;
      case 'claude':
        return Brain;
      case 'openai':
        return Cpu;
      case 'local':
        return Database;
      default:
        return Bot;
    }
  };

  const getSkillIcon = (category: string = 'security') => {
    switch (category.toLowerCase()) {
      case 'recon':
        return Globe;
      case 'web':
        return Layers;
      case 'api':
        return Zap;
      case 'cloud':
        return Database;
      case 'network':
        return Activity;
      default:
        return Shield;
    }
  };

  return (
    <div className="nyx-intelligence-view">
      {/* File Update Progress */}

      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div className="flex items-center gap-4">
            <div className="nyx-page-icon nyx-page-icon-purple">
              <Brain className="w-6 h-6 text-[#7C3AED]" />
            </div>
            <div>
              <h1 className="nyx-page-title">Intelligence & AI Orchestration</h1>
              <p className="nyx-page-subtitle">Provider-agnostic security intelligence engine & research skills catalog</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-[#7C3AED]" />
            <span className="nyx-badge nyx-badge-info">AI ENHANCED</span>
          </div>
        </div>
      </div>

      {/* Intelligence Stats */}
      <div className="nyx-stats-overview">
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-purple">
            <Bot className="w-4 h-4 text-[#7C3AED]" />
          </div>
          <div>
            <div className="nyx-stat-value">{providers.length}</div>
            <div className="nyx-stat-label">AI Providers</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-cyan">
            <BookOpen className="w-4 h-4 text-[#00D9FF]" />
          </div>
          <div>
            <div className="nyx-stat-value">{skills.length}</div>
            <div className="nyx-stat-label">Skills Catalog</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-green">
            <Target className="w-4 h-4 text-[#00FF88]" />
          </div>
          <div>
            <div className="nyx-stat-value">{context?.endpoints_count ?? 0}</div>
            <div className="nyx-stat-label">Indexed Endpoints</div>
          </div>
        </div>
      </div>

      {/* AI Provider & Context Grid */}
      <div className="nyx-content-grid">
        {/* Active AI Provider Card */}
        <div className="nyx-card nyx-card-accent-purple">
          <div className="nyx-section-header">
            <div className="flex items-center gap-3">
              <div className="nyx-section-icon nyx-section-icon-purple">
                <Sparkles className="w-4 h-4 text-[#7C3AED]" />
              </div>
              <h3 className="nyx-section-title">Active AI Provider</h3>
            </div>
            <span className="nyx-badge nyx-badge-info">
              {activeProvider.toUpperCase()}
            </span>
          </div>
          
          <div className="nyx-provider-grid">
            {['gemini', 'claude', 'openai', 'local'].map((p) => {
              const ProviderIcon = getProviderIcon(p);
              return (
                <button
                  key={p}
                  onClick={() => setActiveProvider(p)}
                  className={`nyx-provider-card ${activeProvider === p ? 'nyx-provider-active' : ''}`}
                >
                  <div className="nyx-provider-icon">
                    <ProviderIcon className="w-5 h-5" />
                  </div>
                  <div className="flex-1">
                    <div className="nyx-provider-name">{p}</div>
                    <div className="nyx-provider-status">
                      {activeProvider === p ? 'Active' : 'Available'}
                    </div>
                  </div>
                  {activeProvider === p && (
                    <div className="nyx-status-dot nyx-status-dot-live"></div>
                  )}
                </button>
              );
            })}
          </div>
          
          <div className="nyx-provider-note">
            <Shield className="w-3.5 h-3.5 text-[#7C3AED]" />
            <span>Provider abstraction layer communicates through NYX security policy enforcement boundaries.</span>
          </div>
        </div>

        {/* Target Reasoning Context */}
        <div className="nyx-card nyx-card-accent-green">
          <div className="nyx-section-header">
            <div className="flex items-center gap-3">
              <div className="nyx-section-icon nyx-section-icon-green">
                <Code2 className="w-4 h-4 text-[#00FF88]" />
              </div>
              <h3 className="nyx-section-title">Target Reasoning Context</h3>
            </div>
          </div>
          
          <div className="nyx-context-display">
            <div className="nyx-context-item">
              <div className="nyx-context-icon">
                <Target className="w-4 h-4 text-[#00D9FF]" />
              </div>
              <div>
                <div className="nyx-context-label">Target</div>
                <div className="nyx-context-value">{context?.target || 'example.com'}</div>
              </div>
            </div>
            <div className="nyx-context-item">
              <div className="nyx-context-icon">
                <Activity className="w-4 h-4 text-[#00FF88]" />
              </div>
              <div>
                <div className="nyx-context-label">Phase</div>
                <div className="nyx-context-value">{context?.phase || 'DISCOVERY'}</div>
              </div>
            </div>
            <div className="nyx-context-item">
              <div className="nyx-context-icon">
                <Globe className="w-4 h-4 text-[#FF6B35]" />
              </div>
              <div>
                <div className="nyx-context-label">Endpoints Indexed</div>
                <div className="nyx-context-value">{context?.endpoints_count ?? 0}</div>
              </div>
            </div>
            <div className="nyx-context-item">
              <div className="nyx-context-icon">
                <BookOpen className="w-4 h-4 text-[#7C3AED]" />
              </div>
              <div>
                <div className="nyx-context-label">Matched Skills</div>
                <div className="nyx-context-value">{context?.skills_matched?.length ?? 0}</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Knowledge Search */}
      <div className="nyx-card nyx-card-accent-purple">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-purple">
              <BookOpen className="w-4 h-4 text-[#7C3AED]" />
            </div>
            <h3 className="nyx-section-title">Knowledge Base & Vulnerability Patterns</h3>
          </div>
        </div>
        
        <div className="nyx-form-container">
          <form onSubmit={handleSearch} className="nyx-form-inline">
            <div className="nyx-form-field nyx-form-field-grow">
              <div className="nyx-search-container">
                <Search className="nyx-search-icon" />
                <input
                  type="text"
                  placeholder="Search attack patterns, CVEs, or vulnerability classes..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="nyx-search-input"
                />
                {searchQuery && (
                  <button 
                    type="button"
                    onClick={() => setSearchQuery('')}
                    className="nyx-search-clear"
                  >
                    ×
                  </button>
                )}
              </div>
            </div>
            <button type="submit" className="nyx-button nyx-button-primary">
              <Search className="w-4 h-4" />
              <span>Search</span>
            </button>
          </form>
        </div>

        {searchResults.length > 0 && (
          <div className="nyx-search-results">
            <div className="nyx-search-results-header">
              <Database className="w-3 h-3 text-[#7C3AED]" />
              <span className="text-[10px] font-mono text-[#7C3AED] uppercase tracking-wider">
                Search Results: {searchResults.length}
              </span>
            </div>
            <div className="nyx-search-results-list">
              {searchResults.map((res: any, idx: number) => (
                <div key={idx} className="nyx-search-result-item">
                  <div className="nyx-search-result-index">{String(idx + 1).padStart(2, '0')}</div>
                  <div className="nyx-search-result-content">
                    {typeof res === 'string' ? res : JSON.stringify(res)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Security Skills Catalog Grid */}
      <div className="nyx-card nyx-card-accent-cyan">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-cyan">
              <BookOpen className="w-4 h-4 text-[#00D9FF]" />
            </div>
            <h3 className="nyx-section-title">Security Skills Catalog</h3>
            <span className="nyx-count-pill">{skills.length}</span>
          </div>
          <div className="flex items-center gap-2">
            <Layers className="w-3 h-3 text-[#00D9FF]" />
            <span className="text-[10px] font-mono text-[#00D9FF] uppercase tracking-wider">
              Curated
            </span>
          </div>
        </div>

        <div className="nyx-skills-grid">
          {skills.slice(0, 30).map((sk: any, idx: number) => {
            const SkillIcon = getSkillIcon(sk.category);
            return (
              <div key={idx} className="nyx-skill-card group">
                <div className="nyx-skill-icon">
                  <SkillIcon className="w-4 h-4 text-[#00D9FF]" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="nyx-skill-name">{sk.name || sk}</div>
                  <div className="nyx-skill-category">{sk.category || 'Security Skill'}</div>
                </div>
                <div className="nyx-skill-badge">
                  <Shield className="w-3 h-3 text-[#00FF88]" />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};