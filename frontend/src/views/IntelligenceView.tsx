import React, { useState, useEffect } from 'react';
import { Brain, Sparkles, Target, Shield, BookOpen, Search, Play, CheckCircle, RefreshCw } from 'lucide-react';
import { fetchApi } from '../api/client';
import { useSkills } from '../hooks/useSkills';
import { useApp } from '../context/AppContext';

export function IntelligenceView() {
  const { target, viewParams, setCurrentView } = useApp();
  const { skills, count: skillsCount } = useSkills();
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState<'skills' | 'planner'>('planner');

  // AI Playbook Planner
  const [planTarget, setPlanTarget] = useState(viewParams?.target || target);
  const [vulnClass, setVulnClass] = useState('SQL Injection');
  const [isPlanning, setIsPlanning] = useState(false);
  const [planResult, setPlanResult] = useState<any | null>(null);

  useEffect(() => {
    if (viewParams?.target) setPlanTarget(viewParams.target);
  }, [viewParams]);

  async function handleSynthesizePlan(e: React.FormEvent) {
    e.preventDefault();
    setIsPlanning(true);
    try {
      const res = await fetchApi('/api/v1/ai/plan', {
        method: 'POST',
        body: JSON.stringify({
          target: planTarget,
          vulnerability_type: vulnClass,
          context: { target: planTarget }
        })
      });
      setPlanResult(res?.data || res);
    } finally {
      setIsPlanning(false);
    }
  }

  const filteredSkills = skills.filter(s => 
    s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    s.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
    s.category.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Intelligence &amp; AI Playbook Planner
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <Brain className="w-3.5 h-3.5 text-[#555555]" />
            Automated hypothesis reasoning, 7-Question constraints, and {skillsCount} security attack skills
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button 
            onClick={() => setActiveTab('planner')} 
            className={`text-xs py-1.5 px-3 rounded font-mono ${activeTab === 'planner' ? 'bg-[#ebb94b] text-black font-bold' : 'bg-[#2A2A2A] text-[#CCCCCC]'}`}
          >
            AI Playbook Planner
          </button>
          <button 
            onClick={() => setActiveTab('skills')} 
            className={`text-xs py-1.5 px-3 rounded font-mono ${activeTab === 'skills' ? 'bg-[#ebb94b] text-black font-bold' : 'bg-[#2A2A2A] text-[#CCCCCC]'}`}
          >
            Skills Catalog ({skillsCount})
          </button>
        </div>
      </div>

      {/* ========== TAB: AI PLAYBOOK PLANNER ========== */}
      {activeTab === 'planner' && (
        <div className="space-y-4">
          <div className="card space-y-3 border border-[#3A3A3A]">
            <div className="flex items-center gap-2 pb-2 border-b border-[#333333]">
              <Sparkles className="w-4 h-4 text-[#ebb94b]" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#E8E8E8]">Synthesize Attack Hypothesis &amp; Validation Sequences</h3>
            </div>

            <form onSubmit={handleSynthesizePlan} className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
              <div>
                <label className="text-[#707070] block mb-1 font-mono">Target Asset</label>
                <input
                  type="text"
                  required
                  value={planTarget}
                  onChange={(e) => setPlanTarget(e.target.value)}
                  className="w-full bg-[#252525] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs font-mono text-[#E8E8E8] focus:outline-none"
                />
              </div>

              <div>
                <label className="text-[#707070] block mb-1 font-mono">Vulnerability Class</label>
                <select
                  value={vulnClass}
                  onChange={(e) => setVulnClass(e.target.value)}
                  className="w-full bg-[#252525] border border-[#3A3A3A] rounded px-2.5 py-1.5 text-xs text-[#E8E8E8] focus:outline-none"
                >
                  <option value="SQL Injection">SQL Injection</option>
                  <option value="IDOR">IDOR / BOLA</option>
                  <option value="Authentication Bypass">Authentication Bypass</option>
                  <option value="SSRF">SSRF</option>
                  <option value="Reflected XSS">Reflected XSS</option>
                  <option value="Command Injection">Command Injection / RCE</option>
                </select>
              </div>

              <div className="flex items-end">
                <button
                  type="submit"
                  disabled={isPlanning}
                  className="btn-primary w-full py-1.5 flex items-center justify-center gap-1.5"
                >
                  <Sparkles className={`w-3.5 h-3.5 ${isPlanning ? 'animate-spin' : ''}`} />
                  <span>{isPlanning ? 'Synthesizing...' : 'Generate Playbook'}</span>
                </button>
              </div>
            </form>
          </div>

          {planResult && (
            <div className="card space-y-3 border border-[#ebb94b]/40">
              <div className="flex items-center justify-between pb-2 border-b border-[#333333]">
                <h3 className="text-xs font-bold text-[#ebb94b] font-mono">
                  Synthesized Attack Playbook: {vulnClass} on {planTarget}
                </h3>
                <span className="text-[11px] font-mono text-[#888888]">Engine: NYX AI Reasoning</span>
              </div>

              <div className="p-3 rounded bg-[#1E1E1E] border border-[#333333] space-y-2 text-xs font-mono text-[#CCCCCC]">
                <div className="text-[#ebb94b] font-bold">1. Attack Hypothesis</div>
                <p className="text-[#AAAAAA]">{planResult.plan?.hypothesis || `Target accepts unvalidated inputs over parameter boundaries.`}</p>

                <div className="text-[#ebb94b] font-bold pt-2">2. Required Sequence</div>
                <div className="space-y-1 text-[#888888]">
                  <div>• Step 1: Establish clean dual-session baseline (Attacker A / Victim B)</div>
                  <div>• Step 2: Inject non-destructive probe and observe delta</div>
                  <div>• Step 3: Run 7-Question Gate and attach raw HTTP trace</div>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#333333]">
                <button 
                  onClick={() => setCurrentView('findings', { prefillEndpoint: planTarget })} 
                  className="btn-primary text-xs py-1.5 px-3"
                >
                  Promote to Finding
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========== TAB: SKILLS CATALOG ========== */}
      {activeTab === 'skills' && (
        <div className="space-y-3">
          <input
            type="text"
            placeholder="Search skills by name, class, description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#242424] border border-[#333333] rounded px-3 py-1.5 text-xs text-[#E8E8E8] focus:outline-none"
          />

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {filteredSkills.map(s => (
              <div key={s.name} className="card space-y-1.5 border border-[#3A3A3A]">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-[#ebb94b]">{s.name}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#303030] text-[#888888]">
                    {s.category}
                  </span>
                </div>
                <p className="text-xs text-[#CCCCCC] line-clamp-2 leading-relaxed">{s.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default IntelligenceView;
