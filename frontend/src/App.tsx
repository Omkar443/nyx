import React, { useState } from 'react';
import { useNyxEvents } from './hooks/useNyxEvents';
import { DashboardView } from './views/DashboardView';
import { AttackSurfaceView } from './views/AttackSurfaceView';
import { FindingsView } from './views/FindingsView';
import { EvidenceView } from './views/EvidenceView';
import { IntelligenceView } from './views/IntelligenceView';
import { ExecutionView } from './views/ExecutionView';
import { AgentView } from './views/AgentView';
import { FleetView } from './views/FleetView';
import { WorkerFleetView } from './views/WorkerFleetView';
import { RuntimeView } from './views/RuntimeView';
import { ContinuousView } from './views/ContinuousView';
import { SettingsView } from './views/SettingsView';

import {
  LayoutDashboard,
  Globe,
  AlertTriangle,
  FileText,
  Bot,
  Terminal,
  Settings,
  Shield,
  Wifi,
  WifiOff,
  Sparkles,
  Users,
  Server,
  Activity,
  Radio,
} from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const { connected, lastEvent } = useNyxEvents();

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'continuous', label: 'Continuous Intelligence', icon: Radio },
    { id: 'fleet', label: 'Multi-Agent Fleet', icon: Users },
    { id: 'workers', label: 'Remote Worker Nodes', icon: Server },
    { id: 'runtime', label: 'Browser Runtime', icon: Activity },
    { id: 'agent', label: 'AI Agent Assistant', icon: Sparkles },
    { id: 'surface', label: 'Attack Surface', icon: Globe },
    { id: 'findings', label: 'Findings & Triage', icon: AlertTriangle },
    { id: 'evidence', label: 'Evidence Vault', icon: FileText },
    { id: 'intelligence', label: 'Intelligence & AI', icon: Bot },
    { id: 'execution', label: 'Tool Execution', icon: Terminal },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <div className="min-h-screen bg-[#0b0f19] flex">
      {/* Sidebar */}
      <aside className="w-64 bg-[#0d1322] border-r border-slate-800/80 p-4 flex flex-col justify-between shrink-0">
        <div className="space-y-6">
          {/* Logo Header */}
          <div className="flex items-center gap-3 px-2 py-3 border-b border-slate-800/80">
            <Shield className="w-7 h-7 text-cyan-400" />
            <div>
              <div className="text-lg font-extrabold tracking-wider text-white font-mono">NYX ENGINE</div>
              <div className="text-[10px] uppercase font-mono text-cyan-400 tracking-widest">v1.0 Continuous</div>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-lg shadow-cyan-500/5'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Footer WebSocket Indicator */}
        <div className="pt-4 border-t border-slate-800/80 px-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400 flex items-center gap-2">
              {connected ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                  <Wifi className="w-3.5 h-3.5 text-emerald-400" /> Live Stream
                </>
              ) : (
                <>
                  <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                  <WifiOff className="w-3.5 h-3.5 text-amber-400" /> Reconnecting
                </>
              )}
            </span>
            <span className="text-slate-500 text-[10px]">WS 8000</span>
          </div>
          {lastEvent && (
            <div className="mt-2 text-[10px] font-mono text-slate-500 truncate bg-slate-900/60 p-1.5 rounded border border-slate-800">
              Event: <span className="text-cyan-300">{lastEvent.event}</span>
            </div>
          )}
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 p-8 overflow-y-auto">
        <div className="max-w-7xl mx-auto">
          {activeTab === 'dashboard' && <DashboardView onNavigate={(tab) => setActiveTab(tab)} />}
          {activeTab === 'continuous' && <ContinuousView />}
          {activeTab === 'fleet' && <FleetView />}
          {activeTab === 'workers' && <WorkerFleetView />}
          {activeTab === 'runtime' && <RuntimeView />}
          {activeTab === 'agent' && <AgentView />}
          {activeTab === 'surface' && <AttackSurfaceView />}
          {activeTab === 'findings' && <FindingsView />}
          {activeTab === 'evidence' && <EvidenceView />}
          {activeTab === 'intelligence' && <Bot />}
          {activeTab === 'execution' && <ExecutionView />}
          {activeTab === 'settings' && <SettingsView />}
        </div>
      </main>
    </div>
  );
};

export default App;
