import React, { useState } from 'react';
import { 
  LayoutDashboard, 
  Map, 
  Radar, 
  Target, 
  Terminal, 
  Shield, 
  Server, 
  Gauge, 
  Brain, 
  Globe, 
  Eye, 
  Activity, 
  HardDrive, 
  Settings,
  ChevronLeft,
  ChevronRight,
  Wifi,
  WifiOff,
  Cpu
} from 'lucide-react';

// Import logo
import nyxLogo from './assets/logo.png';

import { AppProvider, useApp } from './context/AppContext';

// Views
import DashboardView from './views/DashboardView';
import FleetView from './views/FleetView';
import FindingsView from './views/FindingsView';
import AgentView from './views/AgentView';
import AttackSurfaceView from './views/AttackSurfaceView';
import ContinuousView from './views/ContinuousView';
import EvidenceView from './views/EvidenceView';
import ExecutionView from './views/ExecutionView';
import IntelligenceView from './views/IntelligenceView';
import RuntimeView from './views/RuntimeView';
import SettingsView from './views/SettingsView';
import WorkerFleetView from './views/WorkerFleetView';
import MissionView from './views/MissionView';
import EngineView from './views/EngineView';
import ErrorBoundary from './components/ErrorBoundary';

function AppContent() {
  const { 
    currentView, setCurrentView, target, phase, 
    endpointsCount, findingsCount, approvalsCount, agentsCount, isConnected,
    selectedProvider, detectedDefaultProvider, setSelectedProvider
  } = useApp();
  const [isCollapsed, setIsCollapsed] = useState(false);

  const navItems = [
    // Main Section
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, view: <DashboardView />, section: 'main' },
    { id: 'findings', label: 'Findings & Triage', icon: Target, view: <FindingsView />, badge: findingsCount > 0 ? String(findingsCount) : undefined, section: 'main' },
    { id: 'mission', label: 'Mission Plan', icon: Map, view: <MissionView />, section: 'main' },
    { id: 'attack-surface', label: 'Attack Surface', icon: Radar, view: <AttackSurfaceView />, badge: endpointsCount > 0 ? String(endpointsCount) : undefined, section: 'main' },

    // Operations Section
    { id: 'execution', label: 'Execution History', icon: Terminal, view: <ExecutionView />, section: 'operations' },
    { id: 'agent', label: 'Approval Queue', icon: Shield, view: <AgentView />, badge: approvalsCount > 0 ? String(approvalsCount) : undefined, section: 'operations' },
    { id: 'fleet', label: 'Fleet', icon: Server, view: <FleetView />, badge: agentsCount > 0 ? String(agentsCount) : undefined, section: 'operations' },

    // System Section
    { id: 'engine', label: 'Engine Status', icon: Gauge, view: <EngineView />, section: 'system' },
    { id: 'intelligence', label: 'Intelligence & AI', icon: Brain, view: <IntelligenceView />, section: 'system' },
    { id: 'runtime', label: 'Browser Runtime', icon: Globe, view: <RuntimeView />, section: 'system' },
    { id: 'evidence', label: 'Evidence Vault', icon: Eye, view: <EvidenceView />, section: 'system' },
    { id: 'continuous', label: 'Continuous Intel', icon: Activity, view: <ContinuousView />, section: 'system' },
    { id: 'worker-fleet', label: 'Remote Workers', icon: HardDrive, view: <WorkerFleetView />, section: 'system' },
    { id: 'settings', label: 'Settings', icon: Settings, view: <SettingsView />, section: 'system' },
  ];

  const currentNavItem = navItems.find(item => item.id === currentView) || navItems[0];

  return (
    <div className="flex h-screen bg-[#1F1F1F] overflow-hidden">
      {/* ========== SIDEBAR ========== */}
      <aside 
        className={`sidebar flex flex-col justify-between transition-all duration-300 border-r border-[#333333] ${
          isCollapsed ? 'w-16' : 'w-60'
        }`}
      >
        <div className="flex flex-col h-full overflow-y-auto">
          {/* Logo & Brand Header */}
          <div className="p-3 border-b border-[#333333] flex items-center justify-between">
            {!isCollapsed ? (
              <div className="flex items-center gap-2.5">
                <img 
                  src={nyxLogo} 
                  alt="NYX Logo" 
                  className="w-8 h-8 object-contain flex-shrink-0"
                />
                <div>
                  <h1 className="text-sm font-bold text-[#F2F2F2] tracking-wider font-mono">NYX</h1>
                  <p className="text-[10px] text-[#707070] font-mono">v1.0.0 · Core Engine</p>
                </div>
              </div>
            ) : (
              <img 
                src={nyxLogo} 
                alt="NYX Logo" 
                className="w-8 h-8 object-contain flex-shrink-0 mx-auto"
              />
            )}
            <button
              onClick={() => setIsCollapsed(!isCollapsed)}
              className="p-1 rounded hover:bg-[#303030] text-[#707070] hover:text-[#CCCCCC]"
            >
              {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
            </button>
          </div>

          {/* Nav Items */}
          <nav className="p-2 space-y-4 flex-1">
            {['main', 'operations', 'system'].map((sec) => {
              const secItems = navItems.filter(i => i.section === sec);
              return (
                <div key={sec} className="space-y-1">
                  {!isCollapsed && (
                    <span className="text-[9px] uppercase font-mono tracking-wider text-[#666666] px-2 block mb-1">
                      {sec}
                    </span>
                  )}
                  {secItems.map((item) => {
                    const Icon = item.icon;
                    const isActive = currentView === item.id;
                    return (
                      <button
                        key={item.id}
                        onClick={() => setCurrentView(item.id)}
                        className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs transition-colors font-mono ${
                          isActive 
                            ? 'bg-[#2A2A2A] text-[#ebb94b] font-bold border-l-2 border-l-[#ebb94b]' 
                            : 'text-[#AAAAAA] hover:bg-[#282828] hover:text-[#FFFFFF]'
                        }`}
                      >
                        <div className="flex items-center gap-2.5">
                          <Icon className="w-4 h-4 shrink-0" />
                          {!isCollapsed && <span>{item.label}</span>}
                        </div>
                        {!isCollapsed && item.badge && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#333333] text-[#CCCCCC]">
                            {item.badge}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              );
            })}
          </nav>
        </div>
      </aside>

      {/* ========== MAIN CONTENT VIEW ========== */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header */}
        <header className="h-12 border-b border-[#333333] bg-[#242424] flex items-center justify-between px-4">
          <div className="flex items-center gap-3 font-mono text-xs">
            <span className="text-[#888888]">TARGET:</span>
            <span className="text-[#E8E8E8] font-bold">{target}</span>
            <span className="text-[#444444]">|</span>
            <span className="text-[#888888]">PHASE:</span>
            <span className="text-[#ebb94b] font-bold">{phase}</span>
          </div>

          <div className="flex items-center gap-3 font-mono text-[11px]">
            {/* Global Provider Switcher */}
            <div className="flex items-center gap-1.5 bg-[#1F1F1F] border border-[#333333] px-2 py-0.5 rounded text-[11px]">
              <Cpu className="w-3 h-3 text-[#ebb94b]" />
              <span className="text-[#888888]">AI:</span>
              <select
                value={selectedProvider || detectedDefaultProvider}
                onChange={(e) => setSelectedProvider(e.target.value)}
                className="bg-transparent text-[#E8E8E8] font-bold focus:outline-none cursor-pointer"
              >
                <option value="local" className="bg-[#242424] text-[#E8E8E8]">local (Ollama)</option>
                <option value="groq" className="bg-[#242424] text-[#E8E8E8]">groq</option>
                <option value="openai" className="bg-[#242424] text-[#E8E8E8]">openai</option>
                <option value="claude" className="bg-[#242424] text-[#E8E8E8]">claude</option>
                <option value="grok" className="bg-[#242424] text-[#E8E8E8]">grok</option>
                <option value="gemini" className="bg-[#242424] text-[#E8E8E8]">gemini</option>
              </select>
            </div>

            {isConnected ? (
              <span className="text-[#4CAF50] bg-[#4CAF50]/10 border border-[#4CAF50]/30 px-2 py-0.5 rounded flex items-center gap-1">
                <Wifi className="w-3 h-3" />
                <span>LIVE</span>
              </span>
            ) : (
              <span className="text-[#EF5350] bg-[#EF5350]/10 border border-[#EF5350]/30 px-2 py-0.5 rounded flex items-center gap-1">
                <WifiOff className="w-3 h-3" />
                <span>DISCONNECTED</span>
              </span>
            )}
          </div>
        </header>

        {/* View Viewport */}
        <main className="flex-1 overflow-y-auto p-4 bg-[#1E1E1E]">
          <ErrorBoundary key={currentView} fallbackTitle={`Error rendering ${currentNavItem.label}`}>
            {currentNavItem.view}
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

export function App() {
  return (
    <AppProvider>
      <AppContent />
    </AppProvider>
  );
}

export default App;