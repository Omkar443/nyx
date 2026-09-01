import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';

export interface AppState {
  currentView: string;
  target: string;
  phase: string;
  endpointsCount: number;
  findingsCount: number;
  approvalsCount: number;
  agentsCount: number;
  evidenceCount: number;
  isConnected: boolean;
  viewParams: Record<string, any>;
  selectedProvider: string;
  detectedDefaultProvider: string;
}

interface AppContextType extends AppState {
  setCurrentView: (view: string, params?: Record<string, any>) => void;
  refreshGlobalStats: () => Promise<void>;
  setTarget: (target: string) => void;
  setSelectedProvider: (provider: string) => void;
}

const defaultState: AppState = {
  currentView: 'dashboard',
  target: '',
  phase: 'DISCOVERY',
  endpointsCount: 0,
  findingsCount: 0,
  approvalsCount: 0,
  agentsCount: 0,
  evidenceCount: 0,
  isConnected: true,
  viewParams: {},
  selectedProvider: '',
  detectedDefaultProvider: 'local',
};

const AppContext = createContext<AppContextType>({
  ...defaultState,
  setCurrentView: () => {},
  refreshGlobalStats: async () => {},
  setTarget: () => {},
  setSelectedProvider: () => {},
});

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [currentView, setCurrentViewState] = useState<string>('dashboard');
  const [viewParams, setViewParams] = useState<Record<string, any>>({});
  const [target, setTargetState] = useState<string>('');
  const [phase, setPhase] = useState<string>('DISCOVERY');
  const [endpointsCount, setEndpointsCount] = useState<number>(0);
  const [findingsCount, setFindingsCount] = useState<number>(0);
  const [approvalsCount, setApprovalsCount] = useState<number>(0);
  const [agentsCount, setAgentsCount] = useState<number>(0);
  const [evidenceCount, setEvidenceCount] = useState<number>(0);
  const [selectedProvider, setSelectedProviderState] = useState<string>(() => {
    return localStorage.getItem('nyx_selected_provider') || '';
  });
  const [detectedDefaultProvider, setDetectedDefaultProvider] = useState<string>('local');
  const { connected, lastEvent } = useNyxEvents();

  const setSelectedProvider = useCallback((provider: string) => {
    setSelectedProviderState(provider);
    localStorage.setItem('nyx_selected_provider', provider);
  }, []);

  const refreshGlobalStats = useCallback(async () => {
    try {
      // 1. Mission / Target
      const missionRes = await fetchApi('/api/v1/mission');
      if (missionRes?.data?.target) {
        setTargetState(missionRes.data.target);
      } else {
        const healthRes = await fetchApi('/health');
        if (healthRes?.target && healthRes.target !== 'No active target') {
          setTargetState(healthRes.target);
        }
      }

      if (missionRes?.data?.state || missionRes?.data?.curr_state) {
        setPhase(missionRes.data.state || missionRes.data.curr_state);
      }

      // 2. Assets / Endpoints
      const assetsRes = await fetchApi('/api/v1/assets');
      if (assetsRes?.data?.endpoints_count !== undefined) {
        setEndpointsCount(assetsRes.data.endpoints_count);
      }

      // 3. Findings
      const findingsRes = await fetchApi('/api/v1/findings');
      const fList = findingsRes?.data?.findings || findingsRes?.findings || [];
      if (Array.isArray(fList)) {
        setFindingsCount(fList.length);
        const evTotal = fList.reduce((acc: number, f: any) => acc + (f.evidence_ids?.length || f.evidenceIds?.length || 0), 0);
        setEvidenceCount(evTotal);
      }

      // 4. Approvals
      const approvalsRes = await fetchApi('/api/v1/agent/approvals');
      const aList = approvalsRes?.data?.approvals || approvalsRes?.approvals || [];
      if (Array.isArray(aList)) {
        setApprovalsCount(aList.filter((a: any) => a.status === 'PENDING').length);
      }

      // 5. Fleet Agents
      const fleetRes = await fetchApi('/api/v1/fleet/agents');
      const agList = fleetRes?.data?.agents || fleetRes?.agents || [];
      if (Array.isArray(agList)) {
        setAgentsCount(agList.length);
      }

      // 6. Active Provider
      const provRes = await fetchApi('/api/v1/ai/active-provider');
      if (provRes?.data) {
        const active = provRes.data.active_provider || provRes.data.detected_default || 'local';
        setDetectedDefaultProvider(active);
        if (!localStorage.getItem('nyx_selected_provider')) {
          setSelectedProviderState(active);
        }
      }
    } catch {
      // Graceful fallback
    }
  }, []);

  useEffect(() => {
    refreshGlobalStats();
  }, [refreshGlobalStats]);

  useEffect(() => {
    if (lastEvent) {
      refreshGlobalStats();
    }
  }, [lastEvent, refreshGlobalStats]);

  const setCurrentView = useCallback((view: string, params: Record<string, any> = {}) => {
    setCurrentViewState(view);
    setViewParams(params);
  }, []);

  const setTarget = useCallback((newTarget: string) => {
    setTargetState(newTarget);
  }, []);

  return (
    <AppContext.Provider
      value={{
        currentView,
        target: target || 'No active target',
        phase,
        endpointsCount,
        findingsCount,
        approvalsCount,
        agentsCount,
        evidenceCount,
        isConnected: connected,
        viewParams,
        selectedProvider,
        detectedDefaultProvider,
        setCurrentView,
        refreshGlobalStats,
        setTarget,
        setSelectedProvider,
      }}
    >
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  return useContext(AppContext);
}
