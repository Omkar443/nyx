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
  const [planError, setPlanError] = useState<string | null>(null);

  useEffect(() => {
    if (viewParams?.target) setPlanTarget(viewParams.target);
  }, [viewParams]);

  async function handleSynthesizePlan(e: React.FormEvent) {
    e.preventDefault();
    setIsPlanning(true);
    setPlanError(null);
    try {
      const res = await fetchApi('/api/v1/ai/plan', {
        method: 'POST',
        body: JSON.stringify({
          target: planTarget,
          vulnerability_type: vulnClass,
          context: { target: planTarget }
        })
      });
      if (res?.success === false || res?.status === 'error' || res?.error) {
        setPlanError(res.error || res.message || 'Failed to synthesize plan');
        setPlanResult(null);
      } else {
        const payload = res?.data || res;
        setPlanResult(payload);
        if (payload?.status === 'error') {
          setPlanError(payload.error || 'Mission planning error');
        }
      }
    } catch (err: any) {
      setPlanError(err?.message || 'Network error executing AI synthesis');
      setPlanResult(null);
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

          {planError && (
            <div className="card space-y-2 border border-[#EF5350]/40 bg-[#2A1515]">
              <div className="flex items-center gap-2 text-[#EF5350] font-mono text-xs font-bold">
                <Shield className="w-4 h-4" />
                <span>AI Reasoning Notice: {planError}</span>
              </div>
              <p className="text-xs text-[#CCCCCC] font-mono leading-relaxed">
                The AI provider could not complete real-time synthesis. Verify provider configuration or check scope authorization.
              </p>
            </div>
          )}

          {planResult && !planError && (
            <div className="card space-y-4 border border-[#ebb94b]/40 bg-[#191919]">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-2.5 border-b border-[#333333]">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-[#ebb94b]" />
                  <h3 className="text-xs font-bold text-[#E8E8E8] font-mono">
                    Synthesized Attack Playbook: <span className="text-[#ebb94b]">{vulnClass}</span> on <span className="text-[#E8E8E8]">{planResult.target || planTarget}</span>
                  </h3>
                </div>
                <div className="flex items-center gap-2 font-mono text-[11px] text-[#888888]">
                  <span className="px-2 py-0.5 rounded bg-[#252525] border border-[#3A3A3A] text-[#CCCCCC]">
                    Provider: {planResult.provider || 'NYX AI Engine'}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[#252525] border border-[#3A3A3A] text-[#ebb94b]">
                    Phase: {planResult.phase || 'DISCOVERY'}
                  </span>
                </div>
              </div>

              {/* 1. Attack Hypothesis & Strategic Reasoning */}
              <div className="p-3.5 rounded-lg bg-[#202020] border border-[#333333] space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#ebb94b] uppercase tracking-wider font-mono">
                    1. Attack Hypothesis &amp; Strategic Reasoning
                  </span>
                  {planResult.recommended_focus && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#ebb94b]/20 text-[#ebb94b] border border-[#ebb94b]/30">
                      Focus: {planResult.recommended_focus}
                    </span>
                  )}
                </div>
                <p className="text-xs text-[#CCCCCC] font-mono leading-relaxed whitespace-pre-wrap">
                  {planResult.analysis || "No strategic analysis returned by AI reasoning engine."}
                </p>
              </div>

              {/* 2. Structured Action Plan & Validation Sequences */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#ebb94b] uppercase tracking-wider font-mono">
                    2. Validation Sequence ({planResult.steps?.length || 0} Steps)
                  </span>
                  <span className="text-[10px] font-mono text-[#888888]">
                    Policy: 7-Question Gate Enforced
                  </span>
                </div>

                {(!planResult.steps || planResult.steps.length === 0) ? (
                  <div className="p-3 rounded bg-[#202020] border border-[#333333] text-xs text-[#777777] italic font-mono">
                    No validation steps generated for this target and vulnerability class.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {planResult.steps.map((step: any, idx: number) => {
                      const isDestructive = step.impact_class === 'DESTRUCTIVE';
                      return (
                        <div key={idx} className="p-3 rounded-lg bg-[#202020] border border-[#333333] space-y-2 text-xs font-mono">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span className="text-[#E8E8E8] font-bold">
                                Step {step.step || idx + 1}: {step.name}
                              </span>
                              {step.tool && (
                                <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#2A2A2A] text-[#888888] border border-[#3A3A3A]">
                                  {step.tool}
                                </span>
                              )}
                            </div>

                            <div className="flex items-center gap-1.5">
                              {/* Destructive / Non-Destructive Impact Tag */}
                              <span
                                title={step.impact_justification || (isDestructive ? 'State-changing mutation' : 'Read-only / idempotent operation')}
                                className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                                  isDestructive
                                    ? 'bg-[#EF5350]/20 text-[#EF5350] border-[#EF5350]/40'
                                    : 'bg-[#4CAF50]/20 text-[#81C784] border-[#4CAF50]/40'
                                }`}
                              >
                                {isDestructive ? 'DESTRUCTIVE' : 'NON-DESTRUCTIVE'}
                              </span>

                              {/* Policy Status Badge */}
                              <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                                step.permitted !== false ? 'bg-[#0288D1]/20 text-[#4FC3F7] border-[#0288D1]/30' : 'bg-[#EF5350]/20 text-[#EF5350] border-[#EF5350]/30'
                              }`}>
                                {step.policy_status || (step.permitted !== false ? 'PERMITTED' : 'BLOCKED')}
                              </span>
                            </div>
                          </div>

                          <p className="text-[#AAAAAA] leading-relaxed">
                            {step.description}
                          </p>

                          {step.impact_justification && (
                            <div className="text-[11px] text-[#777777] flex items-center gap-1.5 pt-1 border-t border-[#2A2A2A]">
                              <span className="text-[#888888] font-semibold">Impact Rationale:</span>
                              <span>{step.impact_justification}</span>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#333333]">
                <button 
                  onClick={() => setCurrentView('findings', { prefillEndpoint: planResult.target || planTarget })} 
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
