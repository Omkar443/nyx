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
  const { target, phase, setCurrentView, refreshGlobalStats, selectedProvider, detectedDefaultProvider, endpointsCount } = useApp();
  const { lastEvent } = useNyxEvents();
  const [missionState, setMissionState] = useState<string>(phase || 'DISCOVERY');
  const [timeline, setTimeline] = useState<any[]>([]);
  const [scopeList, setScopeList] = useState<string[]>([]);
  const [isTransitioning, setIsTransitioning] = useState<boolean>(false);

  // Mission Runner State
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [activePermitted, setActivePermitted] = useState<boolean>(false);
  const [autoApprove, setAutoApprove] = useState<boolean>(false);
  const [showAutoApproveModal, setShowAutoApproveModal] = useState<boolean>(false);
  const [maxIterations, setMaxIterations] = useState<number>(15);
  const [missionResult, setMissionResult] = useState<any | null>(null);
  const [completedSummary, setCompletedSummary] = useState<any | null>(null);
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

  async function syncAutonomousStatus() {
    try {
      const autoStatusRes = await fetchApi('/api/v1/ai/autonomous-status');
      if (autoStatusRes?.data) {
        const autoData = autoStatusRes.data;
        if (autoData.is_running) {
          setIsRunning(true);
          if (autoData.last_progress) {
            setProgressData(autoData.last_progress);
          } else {
            setProgressData({
              state: 'initializing',
              step_name: 'Initializing autonomous mission loop...',
              message: 'Initializing autonomous mission loop...',
              iteration: autoData.current_iteration || 1,
              max_iterations: autoData.max_iterations || maxIterations,
              provider: autoData.provider_name || selectedProvider,
            });
          }
          if (typeof autoData.elapsed_seconds === 'number') {
            setElapsedSeconds(autoData.elapsed_seconds);
          }
          if (autoData.auto_approve !== undefined) {
            setAutoApprove(Boolean(autoData.auto_approve));
          }
          if (autoData.active_permitted !== undefined) {
            setActivePermitted(Boolean(autoData.active_permitted));
          }
          if (autoData.max_iterations) {
            setMaxIterations(autoData.max_iterations);
          }
        } else if (autoData.status === 'paused_for_approval' && autoData.pending_approval) {
          setIsRunning(false);
          if (typeof autoData.elapsed_seconds === 'number') {
            setElapsedSeconds(autoData.elapsed_seconds);
          }
          if (autoData.auto_approve !== undefined) {
            setAutoApprove(Boolean(autoData.auto_approve));
          }
          if (autoData.active_permitted !== undefined) {
            setActivePermitted(Boolean(autoData.active_permitted));
          }
          const pa = autoData.pending_approval;
          setMissionResult((prev: any) => ({
            ...prev,
            status: 'paused_for_approval',
            pending_step: pa.pending_step || pa.step,
            action_id: pa.action_id,
            current_step_index: pa.current_step_index,
            total_planned_steps: pa.total_planned_steps,
            remaining_destructive_count: pa.remaining_destructive_count,
            upcoming_pipeline: pa.upcoming_pipeline,
          }));
        } else if (autoData.status === 'completed' && autoData.result) {
          setIsRunning(false);
          setCompletedSummary({
            target: autoData.target || autoData.result.target || target,
            iterations_count: Array.isArray(autoData.result.iterations) ? autoData.result.iterations.length : (autoData.current_iteration || 0),
            reason: autoData.result.reason || autoData.result.status || 'Mission completed naturally',
            message: autoData.result.message || 'Autonomous mission loop completed naturally.',
            endpoints_count: autoData.result.endpoints_count,
            elapsed_seconds: autoData.elapsed_seconds,
            ended_at: autoData.ended_at,
          });
        }
      }
    } catch {
      // Fallback
    }
  }

  async function loadMission() {
    try {
      const [missionRes, histRes, setRes] = await Promise.allSettled([
        fetchApi('/api/v1/mission'),
        fetchApi('/api/v1/mission/history'),
        fetchApi('/api/v1/settings')
      ]);

      if (missionRes.status === 'fulfilled' && missionRes.value?.data) {
        const res = missionRes.value;
        setMissionState(res.data.state || res.data.curr_state || 'DISCOVERY');
      }

      if (histRes.status === 'fulfilled' && histRes.value?.data) {
        const hData = histRes.value.data;
        if (hData.timeline) {
          setTimeline(hData.timeline);
        } else if (Array.isArray(hData.history)) {
          setTimeline(hData.history);
        }
      }

      if (setRes.status === 'fulfilled' && setRes.value?.data?.scope) {
        setScopeList(setRes.value.data.scope);
      }
    } catch {
      // Fallback
    }
  }

  // Guard against uninitialized target mount races
  useEffect(() => {
    if (!target || target === 'No active target') return;
    loadMission();
  }, [target]);

  // Authoritative independent status check and self-limiting polling
  useEffect(() => {
    syncAutonomousStatus();
    if (target && target !== 'No active target') {
      loadMission();
    }

    let pollCount = 0;
    const MAX_POLLS = 8; // 8 * 2.5s = 20s
    const pollTimer = setInterval(() => {
      pollCount++;
      syncAutonomousStatus();
      if (!isRunning && pollCount >= MAX_POLLS) {
        clearInterval(pollTimer);
      }
    }, 2500);

    return () => {
      clearInterval(pollTimer);
    };
  }, [isRunning, target]);

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
        setCompletedSummary({
          target: lastEvent.data.target || target,
          iterations_count: lastEvent.data.iterations_count || (lastEvent.data.result?.iterations?.length) || 0,
          reason: lastEvent.data.reason || lastEvent.data.status || 'Mission completed naturally',
          message: lastEvent.data.message || 'Autonomous mission completed naturally.',
          endpoints_count: lastEvent.data.result?.endpoints_count,
        });
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
      } else if (lastEvent.data.state === 'executing' || lastEvent.data.state === 'reasoning') {
        setIsRunning(true);
        setCompletedSummary(null);
        if (lastEvent.data.auto_approved) {
          setAutoApprove(true);
        }
      }
    } else if (lastEvent.event === 'mission_completed' && lastEvent.data) {
      setIsRunning(false);
      setCompletedSummary({
        target: lastEvent.data.target || target,
        iterations_count: lastEvent.data.iterations_count || (lastEvent.data.result?.iterations?.length) || 0,
        reason: lastEvent.data.reason || lastEvent.data.status || 'Mission completed naturally',
        message: lastEvent.data.message || 'Autonomous mission completed naturally.',
        endpoints_count: lastEvent.data.result?.endpoints_count,
      });
      loadMission();
      refreshGlobalStats();
    } else if (
      lastEvent.event === 'mission_started' ||
      lastEvent.event === 'phase_changed' ||
      lastEvent.event === 'mission_step'
    ) {
      if (lastEvent.event === 'mission_started') {
        setIsRunning(true);
        setCompletedSummary(null);
      }
      if (lastEvent.event === 'phase_changed' && lastEvent.data?.phase) {
        setMissionState(lastEvent.data.phase);
      }
      loadMission();
      refreshGlobalStats();
    }
  }, [lastEvent, refreshGlobalStats, target]);

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
    setCompletedSummary(null);
    setElapsedSeconds(0);

    try {
      const activeP = selectedProvider || detectedDefaultProvider || 'local';
      const payload = {
        target: target,
        provider_name: activeP,
        active_permitted: activePermitted,
        max_iterations: maxIterations,
        auto_approve: autoApprove
      };
      const res = await fetchApi('/api/v1/ai/autonomous-run', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      if (res) {
        const d = (res?.data && res.data.status) ? res.data : res;
        setMissionResult(d);
        if (d.status === 'max_iterations_reached' || d.status === 'complete') {
          setCompletedSummary({
            target: d.target || target,
            iterations_count: Array.isArray(d.iterations) ? d.iterations.length : 0,
            reason: d.reason || d.status || 'Mission completed naturally',
            message: d.message || 'Autonomous mission loop completed naturally.',
            endpoints_count: d.endpoints_count,
            elapsed_seconds: elapsedSeconds,
          });
        }
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
      <div className="card space-y-3.5 border border-[#3A3A3A] bg-[#222222]">
        {/* Top Header Row: Title, Provider Badge, Primary Action */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[#333333] gap-3">
          <div className="flex items-center gap-2.5">
            <Cpu className="w-4 h-4 text-[#ebb94b]" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#E8E8E8]">
              Autonomous Mission Runner
            </h3>
            <span className="font-mono text-[#ebb94b] bg-[#ebb94b]/10 border border-[#ebb94b]/20 px-2 py-0.5 rounded text-[11px] ml-1">
              AI: <span className="font-semibold">{selectedProvider || detectedDefaultProvider}</span>
            </span>
          </div>

          <button
            onClick={handleRunAutonomousMission}
            disabled={isRunning}
            className="btn-primary text-xs py-1.5 px-3.5 flex items-center gap-1.5 shrink-0 self-start sm:self-auto"
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

        {/* Sub-toolbar: Execution & Safety Parameters */}
        <div className="flex flex-wrap items-center justify-between gap-3 p-2.5 rounded bg-[#1A1A1A] border border-[#2F2F2F] text-xs font-mono">
          <div className="flex flex-wrap items-center gap-4">
            <span className="text-[11px] uppercase tracking-wider text-[#666666] font-semibold flex items-center gap-1">
              <Shield className="w-3.5 h-3.5 text-[#888888]" />
              <span>Permissions:</span>
            </span>
            <label className="flex items-center gap-1.5 text-[#AAAAAA] hover:text-[#E8E8E8] cursor-pointer transition-colors">
              <input
                type="checkbox"
                checked={activePermitted}
                onChange={(e) => {
                  const val = e.target.checked;
                  setActivePermitted(val);
                  if (!val && autoApprove) {
                    setAutoApprove(false);
                  }
                }}
                className="rounded border-[#444444] bg-[#2A2A2A] text-[#ebb94b] focus:ring-0"
              />
              <span>Allow Active Scans</span>
            </label>
            <label className="flex items-center gap-1.5 cursor-pointer transition-colors">
              <input
                type="checkbox"
                checked={autoApprove}
                onChange={(e) => {
                  if (e.target.checked) {
                    setShowAutoApproveModal(true);
                  } else {
                    setAutoApprove(false);
                  }
                }}
                className="rounded border-[#444444] bg-[#2A2A2A] text-[#EF5350] focus:ring-0"
              />
              <span className={autoApprove ? 'text-[#EF5350] font-semibold flex items-center gap-1' : 'text-[#888888] hover:text-[#CCCCCC]'}>
                {autoApprove && <AlertTriangle className="w-3 h-3 text-[#EF5350]" />}
                Auto-approve destructive actions
              </span>
            </label>
          </div>

          <div className="flex items-center gap-2 text-[#888888]">
            <span className="text-[11px] uppercase tracking-wider text-[#666666]">Depth:</span>
            <select
              value={maxIterations}
              onChange={(e) => setMaxIterations(Number(e.target.value))}
              className="bg-[#242424] border border-[#3A3A3A] rounded px-2 py-0.5 text-xs text-[#E8E8E8] focus:outline-none focus:border-[#ebb94b]"
            >
              <option value={5}>5 iterations</option>
              <option value={10}>10 iterations</option>
              <option value={15}>15 iterations</option>
              <option value={25}>25 iterations</option>
            </select>
          </div>
        </div>

        {/* Confirmation Modal for Auto-Approve Mode */}
        {showAutoApproveModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-fadeIn">
            <div className="bg-[#1E1E1E] border border-[#EF5350]/60 rounded-lg max-w-md w-full p-5 space-y-4 shadow-2xl animate-scaleIn">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 rounded-full bg-[#EF5350]/20 border border-[#EF5350]/40 flex items-center justify-center shrink-0 text-[#EF5350]">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-sm font-bold text-[#F2F2F2]">
                    Enable Auto-Approve Mode?
                  </h3>
                  <p className="text-xs text-[#AAAAAA] leading-relaxed">
                    This will automatically approve all destructive actions including <span className="font-mono text-[#E8E8E8] font-semibold">nuclei</span>, <span className="font-mono text-[#E8E8E8] font-semibold">sqlmap</span>, and <span className="font-mono text-[#E8E8E8] font-semibold">ffuf</span> without operator sign-off for this mission run.
                  </p>
                </div>
              </div>
              <div className="p-3 rounded bg-[#252525] border border-[#333333] text-[11px] text-[#888888] font-mono space-y-1.5">
                <div className="text-[#4CAF50] flex items-center gap-2">
                  <span>✓</span>
                  <span>Engagement scope boundaries strictly enforced</span>
                </div>
                <div className="text-[#4CAF50] flex items-center gap-2">
                  <span>✓</span>
                  <span>Actions still policy-checked before execution</span>
                </div>
                <div className="text-[#4CAF50] flex items-center gap-2">
                  <span>✓</span>
                  <span>Every action audited in approvals.json (approved_by: &quot;auto&quot;)</span>
                </div>
              </div>
              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#333333]">
                <button
                  type="button"
                  onClick={() => {
                    setShowAutoApproveModal(false);
                    setAutoApprove(false);
                  }}
                  className="px-3.5 py-1.5 rounded bg-[#2A2A2A] hover:bg-[#333333] text-xs font-medium text-[#CCCCCC] transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setAutoApprove(true);
                    setActivePermitted(true);
                    setShowAutoApproveModal(false);
                  }}
                  className="px-4 py-1.5 rounded bg-[#EF5350] hover:bg-[#D32F2F] text-xs font-bold text-white transition-colors flex items-center gap-1.5 shadow-md shadow-[#EF5350]/20"
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Enable Auto-Approve</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Error Alert */}
        {missionError && (
          <div className="p-3 rounded bg-[#EF5350]/10 border border-[#EF5350]/30 text-xs text-[#EF5350] flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 shrink-0" />
            <span>{missionError}</span>
          </div>
        )}

        {/* Completed Mission Summary Banner */}
        {!isRunning && completedSummary && (
          <div className="rounded-lg border border-[#4CAF50]/40 bg-[#162218] p-4 text-xs font-mono shadow-lg animate-fadeIn flex flex-col gap-3">
            <div className="flex items-center justify-between gap-3 border-b border-[#4CAF50]/20 pb-2.5">
              <div className="flex items-center gap-2 min-w-0">
                <CheckCircle className="w-4 h-4 text-[#4CAF50] shrink-0" />
                <span className="font-bold uppercase tracking-wider text-[#4CAF50] text-[12px]">
                  Mission Completed
                </span>
                <span className="text-[#666666]">·</span>
                <span className="text-[#CCCCCC] truncate font-semibold">
                  {completedSummary.target}
                </span>
              </div>
              <button
                onClick={() => setCompletedSummary(null)}
                className="text-[#888888] hover:text-[#FFFFFF] text-[11px] px-2 py-0.5 rounded hover:bg-[#2A3A2C] transition-colors shrink-0"
                title="Dismiss completed banner"
              >
                ✕ Dismiss
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-[11px]">
              <div className="p-2.5 rounded bg-[#101912] border border-[#4CAF50]/20">
                <span className="text-[#888888] block text-[10px] uppercase font-semibold">Iterations Completed</span>
                <span className="text-[#E0E0E0] font-bold text-sm">
                  {completedSummary.iterations_count ?? 0}
                </span>
              </div>

              <div className="p-2.5 rounded bg-[#101912] border border-[#4CAF50]/20">
                <span className="text-[#888888] block text-[10px] uppercase font-semibold">Completion Reason</span>
                <span className="text-[#4CAF50] font-semibold truncate block">
                  {completedSummary.reason}
                </span>
              </div>

              <div className="p-2.5 rounded bg-[#101912] border border-[#4CAF50]/20">
                <span className="text-[#888888] block text-[10px] uppercase font-semibold">Endpoints in Scope</span>
                <span className="text-[#E0E0E0] font-bold text-sm">
                  {completedSummary.endpoints_count ?? (typeof endpointsCount === 'number' ? endpointsCount : '—')}
                </span>
              </div>
            </div>

            {completedSummary.message && (
              <p className="text-[#AAAAAA] text-[11px] leading-relaxed bg-[#101912] p-2.5 rounded border border-[#4CAF50]/15">
                {completedSummary.message}
              </p>
            )}
          </div>
        )}

        {/* Unified Mission Execution Console */}
        {isRunning && (
          <div className="rounded-lg border border-[#ebb94b]/40 bg-[#1A1A1A] overflow-hidden shadow-lg animate-fadeIn">
            {/* Top Header Strip: Auto-Approve Warning or Standard Mode Header + Timer */}
            <div className={`px-3.5 py-2 flex items-center justify-between gap-3 text-xs font-mono border-b ${
              autoApprove 
                ? 'bg-[#EF5350]/15 border-[#EF5350]/30 text-[#EF5350]' 
                : 'bg-[#222222] border-[#2E2E2E] text-[#AAAAAA]'
            }`}>
              <div className="flex items-center gap-2 min-w-0">
                {autoApprove ? (
                  <>
                    <AlertTriangle className="w-4 h-4 shrink-0 text-[#EF5350] animate-pulse" />
                    <span className="font-bold uppercase tracking-wider text-[11px] text-[#EF5350]">
                      AUTOPILOT ACTIVE
                    </span>
                    <span className="text-[#D0D0D0] text-[11px] hidden sm:inline truncate">
                      — Destructive validation actions executing automatically
                    </span>
                  </>
                ) : (
                  <>
                    <span className="w-2 h-2 rounded-full bg-[#4CAF50] shrink-0 animate-pulse" />
                    <span className="font-semibold text-[#CCCCCC] text-[11px]">
                      Standard Execution Mode
                    </span>
                    <span className="text-[#777777] text-[11px] hidden sm:inline">
                      — Destructive actions will pause for operator sign-off
                    </span>
                  </>
                )}
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-[#121212] border border-[#333333] text-[#ebb94b] font-mono text-[11px]">
                  <Clock className="w-3 h-3 text-[#ebb94b]" />
                  <span>{formatElapsed(elapsedSeconds)}</span>
                </div>
              </div>
            </div>

            {/* Console Body: Live Status, Primary Step Name, Target, and Reason */}
            <div className="p-4 space-y-2.5">
              {/* Metadata Micro-Pills */}
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                <span className="text-[#ebb94b] font-bold bg-[#ebb94b]/10 border border-[#ebb94b]/20 px-2 py-0.5 rounded text-[11px]">
                  Iteration {progressData?.iteration || 1}/{progressData?.max_iterations || maxIterations}
                </span>

                {progressData?.phase && (
                  <span className="text-[#A0A0A0] bg-[#262626] border border-[#363636] px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider">
                    {progressData.phase}
                  </span>
                )}

                {progressData?.tool && (
                  <span className="text-[#64B5F6] bg-[#64B5F6]/10 border border-[#64B5F6]/20 px-2 py-0.5 rounded text-[10px] uppercase font-semibold">
                    {progressData.tool}
                  </span>
                )}

                {progressData?.auto_approved && (
                  <span className="text-[#EF5350] bg-[#EF5350]/15 border border-[#EF5350]/30 px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider">
                    AUTO-APPROVED
                  </span>
                )}
              </div>

              {/* Main Action Headline (Elevated visual weight) */}
              <div className="flex items-start gap-2 pt-0.5">
                <div className="mt-1 shrink-0">
                  {progressData?.state === 'reasoning' ? (
                    <Cpu className="w-4 h-4 text-[#64B5F6] animate-pulse" />
                  ) : progressData?.state === 'executing' ? (
                    <Zap className="w-4 h-4 text-[#81C784]" />
                  ) : (
                    <RefreshCw className="w-4 h-4 animate-spin text-[#ebb94b]" />
                  )}
                </div>
                <div className="space-y-0.5 min-w-0">
                  <h4 className="text-sm font-semibold text-[#F2F2F2] tracking-tight">
                    {progressData?.state === 'reasoning'
                      ? `Reasoning with ${progressData.provider || selectedProvider || 'local'} AI...`
                      : progressData?.step_name || 'Autonomous Loop Planning'}
                  </h4>
                  {target && (
                    <p className="text-xs text-[#888888] font-mono truncate">
                      Target: <span className="text-[#CCCCCC]">{target}</span>
                    </p>
                  )}
                </div>
              </div>

              {/* Live Status Message / Log */}
              {progressData?.message && (
                <div className="text-xs text-[#999999] font-mono bg-[#141414] p-2.5 rounded border border-[#2B2B2B]">
                  <span className="text-[#ebb94b] mr-1.5 font-bold">↳</span>
                  <span>{progressData.message}</span>
                </div>
              )}
            </div>

            {/* Integrated Pipeline Queue Preview Footer */}
            {progressData?.upcoming_pipeline && progressData.upcoming_pipeline.length > 0 && (
              <div className="border-t border-[#2A2A2A] bg-[#141414] font-mono text-xs">
                <button
                  type="button"
                  onClick={() => setIsPipelineOpen(!isPipelineOpen)}
                  className="w-full flex items-center justify-between p-2.5 text-[#AAAAAA] hover:text-[#E8E8E8] hover:bg-[#1C1C1C] transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <Clock className="w-3.5 h-3.5 text-[#FFA726]" />
                    <span>
                      Step {progressData.current_step_index || 1} of {progressData.total_planned_steps || (progressData.upcoming_pipeline.length + 1)} · {progressData.remaining_destructive_count ?? progressData.upcoming_pipeline.length} more queued
                    </span>
                  </span>
                  <div className="flex items-center gap-1.5 text-[11px] text-[#777777]">
                    <span>{isPipelineOpen ? 'Hide Queue' : 'Preview Queue'}</span>
                    {isPipelineOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </div>
                </button>

                {isPipelineOpen && (
                  <div className="p-3 border-t border-[#222222] space-y-1.5 bg-[#101010]">
                    {progressData.upcoming_pipeline.map((step: any, sIdx: number) => (
                      <div key={sIdx} className="bg-[#181818] p-2 rounded border border-[#272727] text-xs flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 min-w-0 truncate">
                          <span className="text-[#666666] shrink-0">#{(progressData.current_step_index || 1) + sIdx + 1}</span>
                          <span className="text-[#CCCCCC] truncate font-medium">{step.name || step.action}</span>
                          <span className="text-[10px] px-1 py-0.2 rounded bg-[#2A2A2A] text-[#999999] shrink-0">
                            {step.tool || step.tool_name || 'tool'}
                          </span>
                        </div>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#EF5350]/15 text-[#EF5350] border border-[#EF5350]/30 shrink-0 uppercase font-bold">
                          {step.impact_class || 'DESTRUCTIVE'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
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
                            {it.approved_by === 'auto' && (
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/40 font-bold uppercase">
                                AUTO-APPROVED
                              </span>
                            )}
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
