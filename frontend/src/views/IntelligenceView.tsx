import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Bot, BookOpen, Search, Sparkles, Code2 } from 'lucide-react';

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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel p-6 flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Bot className="w-6 h-6 text-cyan-400" /> NYX Intelligence & AI Orchestration
          </h2>
          <p className="text-sm text-slate-400">Provider-agnostic security intelligence engine & research skills catalog</p>
        </div>
      </div>

      {/* AI Provider & Context */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-panel p-6 space-y-4">
          <h3 className="text-md font-bold text-white flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-amber-400" /> Active AI Provider
          </h3>
          <div className="grid grid-cols-2 gap-3">
            {['gemini', 'claude', 'openai', 'local'].map((p) => (
              <button
                key={p}
                onClick={() => setActiveProvider(p)}
                className={`p-3 rounded-lg border font-mono text-sm capitalize text-left flex justify-between items-center ${
                  activeProvider === p
                    ? 'bg-cyan-500/20 border-cyan-500 text-cyan-300'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <span>{p}</span>
                {activeProvider === p && <span className="w-2 h-2 rounded-full bg-cyan-400"></span>}
              </button>
            ))}
          </div>
          <div className="text-xs text-slate-400 bg-slate-900/60 p-3 rounded border border-slate-800 font-mono">
            Provider abstraction layer communicates through NYX security policy enforcement boundaries.
          </div>
        </div>

        <div className="glass-panel p-6 space-y-3">
          <h3 className="text-md font-bold text-white flex items-center gap-2">
            <Code2 className="w-5 h-5 text-emerald-400" /> Target Reasoning Context
          </h3>
          <div className="text-xs font-mono space-y-2 bg-slate-950 p-4 rounded text-emerald-300 overflow-x-auto">
            <div>Target: <span className="text-white">{context?.target || 'example.com'}</span></div>
            <div>Phase: <span className="text-white">{context?.phase || 'DISCOVERY'}</span></div>
            <div>Endpoints Indexed: <span className="text-white">{context?.endpoints_count ?? 0}</span></div>
            <div>Matched Skills: <span className="text-white">{context?.skills_matched?.length ?? 0}</span></div>
          </div>
        </div>
      </div>

      {/* Knowledge Search */}
      <div className="glass-panel p-6">
        <h3 className="text-md font-bold text-white mb-3 flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-purple-400" /> Knowledge Base & Vulnerability Patterns
        </h3>
        <form onSubmit={handleSearch} className="flex gap-3 mb-4">
          <input
            type="text"
            placeholder="Search attack patterns, CVEs, or vulnerability classes..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-4 py-2 text-sm text-white font-mono placeholder-slate-500"
          />
          <button type="submit" className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-semibold text-sm rounded-lg flex items-center gap-2">
            <Search className="w-4 h-4" /> Search
          </button>
        </form>

        {searchResults.length > 0 && (
          <div className="space-y-2">
            {searchResults.map((res: any, idx: number) => (
              <div key={idx} className="glass-card p-3 text-xs font-mono text-slate-300">
                {typeof res === 'string' ? res : JSON.stringify(res)}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Security Skills Catalog Grid */}
      <div className="glass-panel p-6">
        <h3 className="text-md font-bold text-white mb-4 flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-cyan-400" /> Security Skills Catalog ({skills.length})
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {skills.slice(0, 30).map((sk: any, idx: number) => (
            <div key={idx} className="glass-card p-3 space-y-1">
              <div className="text-xs font-bold text-cyan-300 font-mono">{sk.name || sk}</div>
              <div className="text-xs text-slate-400">{sk.category || 'Security Skill'}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
