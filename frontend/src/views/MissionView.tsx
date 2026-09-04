import React, { useState, useEffect } from 'react';
import { 
  Map, CheckCircle, Clock, Shield, Target, Play, 
  ArrowRight, AlertTriangle, RefreshCw, FileText, AlertOctagon,
  Zap, Check, X, ShieldAlert, Cpu, ChevronDown, ChevronUp
} from 'lucide-react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';
import { useApp } from '../context/AppContext';

export function MissionView() {
  const { target, phase, setCurrentView, refreshGlobalStats, selectedProvider, detectedDefaultProvider } = useApp();
  const { lastEvent } = useNyxEvents();
  const [missionState, setMissionState] = useState<string>(phase || 'DISCOVERY');
  const [timeline, setTimeline] = useState<any[]>([]);
  const [scopeList, setScopeList] = useState<string[]>([]);
  const [isTransitioning, setIsTransitioning] = useState<boolean>(false);

  // Mission Runner State
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [activePermitted, setActivePermitted] = useState<boolean>(false);
  const [maxIterations, setMaxIterations] = useState<number>(15);
  const [missionResult, setMissionResult] = useState<any | null>(null);
  const [missionError, setMissionError] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);
  const [progressData, setProgressData] = useState<any | null>(null);
  const [isPipelineOpen, setIsPipelineOpen] = useState<boolean>(false);

  const formatElapsed = (sec: number) => {
    const mins = Math.floor(sec / 60);
    const remSec = sec % 60;
    return `${mins.toString().padStart(2, '0')}:${remSec.toString().padStart(2, '0')}`;
  };

  useEffect(() => {
    let timer: any = null;
    if (isRunning) {
      timer = setInterval(() => {
        setElapsedSeconds((prev) => prev + 1);
      }, 1000);
    } else {
      setElapsedSeconds(0);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isRunning]);

  const phases = [
    { name: 'DISCOVERY', desc: 'Passive OSINT, HTTP probing, endpoint & asset harvesting' },
    { name: 'ANALYSIS', desc: 'Attack surface reasoning, technology mapping, hypothesis formulating' },
    { name: 'VALIDATION', desc: 'Controlled PoC execution, 7-Question Gate triage, evidence anchoring' },
    { name: 'REPORTING', desc: 'VRT severity mapping, remediation guidance, report export' }
  ];

  async function loadMission() {
    try {
      const res = await fetchApi('/api/v1/mission');
      if (res?.data) {
        setMissionState(res.data.state || res.data.curr_state || 'DISCOVERY');
      }

      const histRes = await fetchApi('/api/v1/mission/history');
      if (histRes?.data?.timeline) {
        setTimeline(histRes.data.timeline);
      } else if (Array.isArray(histRes?.data?.history)) {
        setTimeline(histRes.data.history);
      }

      const setRes = await fetchApi('/api/v1/settings');
      if (setRes?.data?.scope) {
        setScopeList(setRes.data.scope);
      }
    } catch {
      // Fallback
    }
  }

  useEffect(() => {
    loadMission();
  }, [target]);

  useEffect(() => {
    if (phase) {
      setMissionState(phase);
    }
  }, [phase]);

  useEffect(() => {
    if (!lastEvent) return;
    if (lastEvent.event === 'mission_progress' && lastEvent.data) {
      setProgressData(lastEvent.data);
      if (lastEvent.data.state === 'completed') {
        setIsRunning(false);
      } else if (lastEvent.data.state === 'paused') {
        setIsRunning(false);
        setMissionResult((prev: any) => ({
          ...prev,
          status: 'paused_for_approval',
          pending_step: lastEvent.data.pending_step || prev?.pending_step,
          action_id: lastEvent.data.action_id || prev?.action_id,
          current_step_index: lastEvent.data.current_step_index || prev?.current_step_index,
          total_planned_steps: lastEvent.data.total_planned_steps || prev?.total_planned_steps,
          remaining_destructive_count: lastEvent.data.remaining_destructive_count ?? prev?.remaining_destructive_count,
          upcoming_pipeline: lastEvent.data.upcoming_pipeline || prev?.upcoming_pipeline,
        }));
      }
    } else if (
      lastEvent.event === 'mission_started' ||
      lastEvent.event === 'mission_completed' ||
      lastEvent.event === 'phase_changed' ||
      lastEvent.event === 'mission_step'
    ) {
      if (lastEvent.event === 'phase_changed' && lastEvent.data?.phase) {
        setMissionState(lastEvent.data.phase);
      }
      if (lastEvent.event === 'mission_completed') {
        setIsRunning(false);
        setProgressData(null);
      }
      loadMission();
      refreshGlobalStats();
    }
  }, [lastEvent, refreshGlobalStats]);

  async function handleStateTransition(newState: string) {
    setIsTransitioning(true);
    try {
      await fetchApi('/api/v1/mission/state', {
        method: 'POST',
        body: JSON.stringify({ new_state: newState, mode: 'research', force: false })
      });
      setMissionState(newState);
      await loadMission();
      await refreshGlobalStats();
    } finally {
      setIsTransitioning(false);
    }
  }

  async function handleRunAutonomousMission() {
    if (!target || target === 'No active target') {
      setMissionError('No active target — set a target first (use Settings to configure target scope or initialize an engagement).');
      return;
    }
    setIsRunning(true);
    setMissionError(null);
    setMissionResult(null);

    try {
      const activeP = selectedProvider || detectedDefaultProvider || 'local';
      const payload = {
        target: target,
        provider_name: activeP,
        active_permitted: activePermitted,
        max_iterations: maxIterations
      };
      const res = await fetchApi('/api/v1/ai/autonomous-run', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      if (res) {
        setMissionResult((res?.data && res.data.status) ? res.data : res);
      }
      await loadMission();
      await refreshGlobalStats();
    } catch (err: any) {
      setMissionError(err?.message || 'Failed to start autonomous mission');
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Mission Plan &amp; Autonomous Runner
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <Map className="w-3.5 h-3.5 text-[#555555]" />
            Sequential execution workflow with policy safety gates &nbsp;·&nbsp; Target: <span className="font-mono text-[#E8E8E8]">{target}</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-[#ebb94b] bg-[#ebb94b]/10 border border-[#ebb94b]/20 px-2.5 py-1 rounded">
            CURRENT PHASE: {missionState}
          </span>
        </div>
      </div>

      {/* ========== PHASE PROGRESSION CARDS ========== */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {phases.map((p, idx) => {
          const isCurrent = missionState === p.name;
          const isPast = phases.findIndex(x => x.name === missionState) > idx;

          return (
            <div 
              key={p.name}
              onClick={() => handleStateTransition(p.name)}
              className={`card cursor-pointer transition-all ${
                isCurrent 
                  ? 'border-[#ebb94b] bg-[#2A2A2A] shadow-md shadow-[#ebb94b]/5' 
                  : isPast 
                    ? 'border-[#4CAF50]/40 hover:border-[#4CAF50]' 
                    : 'opacity-70 hover:opacity-100'
              }`}
            >
              <div className="flex items-center justify-between pb-1">
                <span className="text-[10px] font-mono text-[#707070]">PHASE 0{idx + 1}</span>
                {isPast && <CheckCircle className="w-3.5 h-3.5 text-[#4CAF50]" />}
                {isCurrent && <span className="w-2 h-2 rounded-full bg-[#ebb94b] animate-pulse" />}
              </div>
              <h3 className="text-sm font-bold text-[#F2F2F2] mt-0.5">{p.name}</h3>
              <p className="text-[11px] text-[#888888] mt-1 leading-normal">{p.desc}</p>
            </div>
          );
        })}
      </div>

      {/* ========== AUTONOMOUS MISSION RUNNER PANEL ========== */}
      <div className="card space-y-4 border border-[#3A3A3A] bg-[#222222]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[#333333] gap-3">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-[#ebb94b]" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#E8E8E8]">
              Autonomous Mission Runner
            </h3>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <span className="font-mono text-[#ebb94b] bg-[#ebb94b]/10 border border-[#ebb94b]/20 px-2 py-0.5 rounded text-[11px]">
              Active Provider: <span className="font-bold">{selectedProvider || detectedDefaultProvider}</span>
            </span>
            <label className="flex items-center gap-1.5 text-[#888888] font-mono cursor-pointer">
              <input
                type="checkbox"
                checked={activePermitted}
                onChange={(e) => setActivePermitted(e.target.checked)}
                className="rounded border-[#444444] bg-[#2A2A2A] text-[#ebb94b] focus:ring-0"
              />
              <span>Allow Active Scans</span>
            </label>
            <div className="flex items-center gap-1 text-[#888888] font-mono">
              <span>Max Iter:</span>
              <select
                value={maxIterations}
                onChange={(e) => setMaxIterations(Number(e.target.value))}
                className="bg-[#2A2A2A] border border-[#3A3A3A] rounded px-2 py-0.5 text-xs text-[#E8E8E8] focus:outline-none"
              >
                <option value={5}>5</option>
                <option value={10}>10</option>
                <option value={15}>15</option>
                <option value={25}>25</option>
              </select>
            </div>
            <button
              onClick={handleRunAutonomousMission}
              disabled={isRunning}
              className="btn-primary text-xs py-1.5 px-3.5 flex items-center gap-1.5"
            >
              {isRunning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
              <span>
                {isRunning ? (
                  progressData?.state === 'reasoning'
                    ? `Reasoning (${progressData.provider || selectedProvider || 'AI'})...`
                    : progressData?.state === 'executing'
                    ? `Executing ${progressData.tool || 'step'}...`
                    : 'Running Mission...'
                ) : 'Start Autonomous Mission'}
              </span>
            </button>
          </div>
        </div>

        {/* Error Alert */}
        {missionError && (
          <div className="p-3 rounded bg-[#EF5350]/10 border border-[#EF5350]/30 text-xs text-[#EF5350] flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 shrink-0" />
            <span>{missionError}</span>
          </div>
        )}

        {/* Running Status */}
        {isRunning && (
          <div className="p-4 rounded bg-[#2A2A2A] border border-[#ebb94b]/40 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono">
            <div className="flex items-center gap-3 text-[#E8E8E8]">
              <RefreshCw className="w-4 h-4 animate-spin text-[#ebb94b] shrink-0" />
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="text-[#ebb94b] font-bold">
                    Iteration {progressData?.iteration || 1}/{progressData?.max_iterations || maxIterations}
                  </span>
                  <span className="text-[#555555]">|</span>
                  <span className="text-[#E8E8E8] font-semibold">
                    {progressData?.state === 'reasoning' ? (
                      <span className="flex items-center gap-1.5 text-[#64B5F6]">
                        <Cpu className="w-3.5 h-3.5 text-[#64B5F6]" />
                        <span>Reasoning with {progressData.provider || selectedProvider || 'local'} AI...</span>
                      </span>
                    ) : progressData?.state === 'executing' ? (
                      <span className="flex items-center gap-1.5 text-[#81C784]">
                        <Zap className="w-3.5 h-3.5 text-[#81C784]" />
                        <span>Executing: {progressData.step_name || 'Candidate Step'} ({progressData.tool || 'tool'})</span>
                      </span>
                    ) : (
                      <span>Autonomous loop active across candidates for {target}...</span>
                    )}
                  </span>
                </div>
                {progressData?.message && (
                  <div className="text-[11px] text-[#888888]">
                    {progressData.message}
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-center gap-3 text-xs shrink-0 self-end md:self-auto">
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#1E1E1E] border border-[#3A3A3A] text-[#ebb94b]">
                <Clock className="w-3.5 h-3.5" />
                <span className="font-mono">{formatElapsed(elapsedSeconds)}</span>
              </div>
              <span className="text-[#888888] hidden lg:inline">Non-blocking background reasoning</span>
            </div>
          </div>
        )}

        {/* Mission Status Banners */}
        {missionResult && (
          <div className="space-y-3">
            {/* PAUSED FOR APPROVAL */}
            {missionResult.status === 'paused_for_approval' && (() => {
              const stepIdx = missionResult.current_step_index ?? progressData?.current_step_index ?? 1;
              const totalSteps = missionResult.total_planned_steps ?? progressData?.total_planned_steps ?? ((missionResult.upcoming_pipeline?.length || 0) + 1);
              const remainingCount = missionResult.remaining_destructive_count ?? progressData?.remaining_destructive_count ?? (missionResult.upcoming_pipeline?.length || 0);
              const upcomingPipeline = missionResult.upcoming_pipeline || progressData?.upcoming_pipeline || [];

              return (
                <div className="p-4 rounded bg-[#FFA726]/10 border border-[#FFA726]/30 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2 text-[#FFA726] font-bold text-xs">
                        <AlertTriangle className="w-4 h-4 shrink-0" />
                        <span>MISSION PAUSED — Destructive Action Pending Operator Sign-Off</span>
                      </div>
                      <div className="text-xs text-[#FFA726]/80 font-mono mt-0.5">
                        Step {stepIdx} of {totalSteps} &middot; {remainingCount} more queued
                      </div>
                    </div>
                    <button
                      onClick={() => setCurrentView('agent')}
                      className="btn-primary text-xs py-1 px-2.5 flex items-center gap-1 self-start sm:self-auto shrink-0"
                    >
                      <span>View in Approval Queue</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                  {missionResult.pending_step && (
                    <div className="bg-[#1E1E1E] p-2.5 rounded border border-[#333333] text-xs font-mono space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-[#E8E8E8] font-bold">{missionResult.pending_step.name}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/40 uppercase font-bold">
                          {missionResult.pending_step.impact_class || 'DESTRUCTIVE'}
                        </span>
                        <span className="text-[#888888]">Tool: {missionResult.pending_step.tool}</span>
                      </div>
                      <p className="text-[#CCCCCC]">{missionResult.pending_step.impact_justification || missionResult.pending_step.description}</p>
                    </div>
                  )}

                  {/* Upcoming Pipeline Preview Accordion */}
                  {upcomingPipeline.length > 0 && (
                    <div className="border border-[#3A3A3A] rounded bg-[#161616] overflow-hidden">
                      <button
                        type="button"
                        onClick={() => setIsPipelineOpen(!isPipelineOpen)}
                        className="w-full flex items-center justify-between p-2.5 text-xs text-[#AAAAAA] hover:text-[#E8E8E8] hover:bg-[#1E1E1E] transition-colors"
                      >
                        <span className="flex items-center gap-2 font-mono">
                          <Clock className="w-3.5 h-3.5 text-[#FFA726]" />
                          <span>Upcoming Pipeline Preview ({upcomingPipeline.length} subsequent candidate{upcomingPipeline.length > 1 ? 's' : ''})</span>
                        </span>
                        {isPipelineOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      </button>
                      {isPipelineOpen && (
                        <div className="p-2.5 border-t border-[#333333] space-y-2 bg-[#121212]">
                          <div className="text-[11px] text-[#777777] italic">
                            Candidates scheduled for sequential evaluation. Each step will be evaluated and prompted individually following execution.
                          </div>
                          <div className="space-y-1.5">
                            {upcomingPipeline.map((step: any, sIdx: number) => (
                              <div key={sIdx} className="bg-[#1E1E1E] p-2 rounded border border-[#2B2B2B] text-xs font-mono flex items-center justify-between gap-2">
                                <div className="flex items-center gap-2 min-w-0 truncate">
                                  <span className="text-[#888888] shrink-0">#{stepIdx + sIdx + 1}</span>
                                  <span className="text-[#CCCCCC] truncate font-medium">{step.name || step.action}</span>
                                  <span className="text-[10px] px-1 py-0.2 rounded bg-[#333333] text-[#AAAAAA] shrink-0">
                                    {step.tool || step.tool_name || 'tool'}
                                  </span>
                                </div>
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#EF5350]/15 text-[#EF5350] border border-[#EF5350]/30 shrink-0 uppercase font-bold">
                                  {step.impact_class || 'DESTRUCTIVE'}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })()}

            {/* ESCALATED */}
            {missionResult.status === 'escalated' && (
              <div className="p-4 rounded bg-[#AB47BC]/10 border border-[#AB47BC]/30 space-y-2">
                <div className="flex items-center gap-2 text-[#AB47BC] font-bold text-xs">
                  <Zap className="w-4 h-4" />
                  <span>STRATEGIC ESCALATION — AI Decision Engine Triggered Escalation</span>
                </div>
                {missionResult.escalated_step && (
                  <div className="bg-[#1E1E1E] p-2.5 rounded border border-[#333333] text-xs font-mono space-y-1">
                    <p className="text-[#E8E8E8] font-bold">{missionResult.escalated_step.name} ({missionResult.escalated_step.tool})</p>
                    <p className="text-[#888888]">{missionResult.reasoning?.reasoning || 'Hypothesis confirmed — escalating to high-priority verification'}</p>
                  </div>
                )}
              </div>
            )}

            {/* BLOCKED BY POLICY */}
            {missionResult.status === 'blocked' && (
              <div className="p-4 rounded bg-[#EF5350]/10 border border-[#EF5350]/30 space-y-2">
                <div className="flex items-center gap-2 text-[#EF5350] font-bold text-xs">
                  <ShieldAlert className="w-4 h-4" />
                  <span>BLOCKED BY POLICY — Step Restricted by Engagement Scope</span>
                </div>
                {missionResult.blocked_step && (
                  <div className="bg-[#1E1E1E] p-2.5 rounded border border-[#333333] text-xs font-mono">
                    <span className="text-[#E8E8E8]">{missionResult.blocked_step.name} ({missionResult.blocked_step.tool})</span>
                  </div>
                )}
              </div>
            )}

            {/* COMPLETE */}
            {missionResult.status === 'complete' && (
              <div className="p-3 rounded bg-[#4CAF50]/10 border border-[#4CAF50]/30 flex items-center gap-2 text-xs text-[#4CAF50] font-mono">
                <CheckCircle className="w-4 h-4 shrink-0" />
                <span>
                  {missionResult.message || 
                   (missionResult.is_dedup
                     ? `All candidate vectors already evaluated in a prior run — ${missionResult.tested_vectors_count || 'multiple'} vectors previously tested.`
                     : 'Autonomous Mission Loop Complete: No candidate vectors found for this target.')}
                </span>
              </div>
            )}

            {/* MAX ITERATIONS REACHED */}
            {missionResult.status === 'max_iterations_reached' && (
              <div className="p-3 rounded bg-[#FFA726]/10 border border-[#FFA726]/30 flex items-center gap-2 text-xs text-[#FFA726] font-mono">
                <Clock className="w-4 h-4" />
                <span>Max Iterations Reached ({maxIterations}) — Autonomous loop cycle concluded.</span>
              </div>
            )}

            {/* Iterations Execution Timeline */}
            {Array.isArray(missionResult.iterations) && missionResult.iterations.length > 0 && (
              <div className="space-y-2 pt-2">
                <h4 className="text-[11px] font-bold uppercase tracking-wider text-[#707070]">
                  Execution Iteration Timeline ({missionResult.iterations.length} iterations)
                </h4>
                <div className="space-y-2">
                  {missionResult.iterations.map((it: any, idx: number) => {
                    const step = it.step || {};
                    const res = it.result || {};
                    const isSkipped = res.status === 'skipped';
                    const isManual = res.status === 'manual_action_required';
                    return (
                      <div key={idx} className="p-2.5 rounded bg-[#1C1C1C] border border-[#333333] text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="text-[#ebb94b] font-bold">#{it.iteration || idx + 1}</span>
                            <span className="text-[#E8E8E8] font-semibold">{step.name || 'Step'}</span>
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#2A2A2A] text-[#888888] border border-[#3A3A3A]">
                              {step.tool}
                            </span>
                            <span className={`text-[10px] px-1.5 py-0.2 rounded border ${
                              step.impact_class === 'DESTRUCTIVE' ? 'text-[#EF5350] bg-[#EF5350]/15 border-[#EF5350]/30' : 'text-[#4CAF50] bg-[#4CAF50]/15 border-[#4CAF50]/30'
                            }`}>
                              {step.impact_class || 'NON_DESTRUCTIVE'}
                            </span>
                          </div>
                          {it.ai_reasoning?.reasoning && (
                            <p className="text-[11px] text-[#707070] italic">AI: {it.ai_reasoning.reasoning}</p>
                          )}
                        </div>
                        <div className="text-right shrink-0">
                          <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                            isSkipped ? 'bg-[#FFA726]/10 text-[#FFA726] border border-[#FFA726]/20' :
                            isManual ? 'bg-[#29B6F6]/10 text-[#29B6F6] border border-[#29B6F6]/20' :
                            'bg-[#4CAF50]/10 text-[#4CAF50] border border-[#4CAF50]/20'
                          }`}>
                            {res.status || 'COMPLETED'}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ========== SCOPE BOUNDARIES & POLICY RULES ========== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-[#333333]">
            <Shield className="w-4 h-4 text-[#4CAF50]" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#E8E8E8]">Authorized Scope Boundaries</h3>
          </div>
          <div className="space-y-1.5 font-mono text-xs">
            <p className="text-[#888888]">Only testing assets matching these whitelist patterns is permitted:</p>
            <div className="p-2.5 rounded bg-[#242424] border border-[#333333] space-y-1">
              {scopeList.length > 0 ? (
                scopeList.map((sc, sIdx) => (
                  <div key={sIdx} className="text-[#4CAF50] flex items-center gap-1.5">
                    <span>✓</span>
                    <span>{sc}</span>
                  </div>
                ))
              ) : (
                <div className="text-[#4CAF50] flex items-center gap-1.5">
                  <span>✓</span>
                  <span>{target}</span>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="card space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-[#333333]">
            <Clock className="w-4 h-4 text-[#ebb94b]" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#E8E8E8]">Engagement State History</h3>
          </div>
          <div className="space-y-2">
            {timeline.length === 0 ? (
              <p className="text-xs font-mono text-[#707070] italic">Engagement initialized in {missionState} phase.</p>
            ) : (
              timeline.map((t, idx) => (
                <div key={idx} className="flex flex-col gap-0.5 text-xs font-mono p-2 rounded bg-[#242424] border border-[#333333]">
                  <div className="flex items-center justify-between">
                    <span className="text-[#E8E8E8] font-bold">
                      {t.previous_phase && t.previous_phase !== (t.phase || t.state)
                        ? `${t.previous_phase} → ${t.phase || t.state}`
                        : (t.phase || t.state || 'DISCOVERY')}
                    </span>
                    <span className="text-[#707070] text-[11px]">{t.timestamp?.slice(11, 19) || 'Recorded'}</span>
                  </div>
                  {t.reason && (
                    <span className="text-[10px] text-[#888888] truncate" title={t.reason}>
                      {t.reason}
                    </span>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default MissionView;
