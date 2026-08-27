import React, { useState, useEffect } from 'react';
import { 
  Map, CheckCircle, Clock, Shield, Target, Play, 
  ArrowRight, AlertTriangle, RefreshCw, FileText
} from 'lucide-react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';
import { useApp } from '../context/AppContext';

export function MissionView() {
  const { target, phase, setCurrentView, refreshGlobalStats } = useApp();
  const { lastEvent } = useNyxEvents();
  const [missionState, setMissionState] = useState<string>(phase || 'DISCOVERY');
  const [timeline, setTimeline] = useState<any[]>([]);
  const [scopeList, setScopeList] = useState<string[]>([]);
  const [isTransitioning, setIsTransitioning] = useState<boolean>(false);

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
    if (lastEvent?.event === 'mission_started' || lastEvent?.event === 'mission_completed') {
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

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Mission Plan &amp; State Machine
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
                <div key={idx} className="flex items-center justify-between text-xs font-mono p-2 rounded bg-[#242424] border border-[#333333]">
                  <span className="text-[#E8E8E8]">{t.phase || t.state}</span>
                  <span className="text-[#707070] text-[11px]">{t.timestamp?.slice(11, 19) || 'Recorded'}</span>
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
