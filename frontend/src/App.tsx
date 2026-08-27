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
  Sparkles,
  Users,
  Server,
  Activity,
  Radio,
  Brain,
  Crosshair,
  Database,
  Lock,
} from 'lucide-react';

interface NavGroup {
  section: string;
  items: {
    id: string;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
  }[];
}

import nyxLogo from './assets/logo.png';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const { connected, lastEvent } = useNyxEvents();

  const navGroups: NavGroup[] = [
    {
      section: 'OPERATIONS',
      items: [
        { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { id: 'continuous', label: 'Continuous Intel', icon: Radio },
        { id: 'surface', label: 'Attack Surface', icon: Globe },
      ],
    },
    {
      section: 'EXECUTION & FLEET',
      items: [
        { id: 'fleet', label: 'Multi-Agent Fleet', icon: Users },
        { id: 'workers', label: 'Remote Workers', icon: Server },
        { id: 'runtime', label: 'Browser Runtime', icon: Activity },
        { id: 'agent', label: 'AI Agent Assistant', icon: Sparkles },
      ],
    },
    {
      section: 'RESEARCH & EVIDENCE',
      items: [
        { id: 'findings', label: 'Findings & Triage', icon: AlertTriangle },
        { id: 'evidence', label: 'Evidence Vault', icon: FileText },
        { id: 'intelligence', label: 'Intelligence & AI', icon: Brain },
        { id: 'execution', label: 'Tool Execution', icon: Terminal },
      ],
    },
    {
      section: 'SYSTEM',
      items: [
        { id: 'settings', label: 'Settings', icon: Settings },
      ],
    },
  ];

  return (
    <div className="nyx-app">
      {/* Fixed Top Bar (48px height) */}
      <header className="nyx-top-bar">
        {/* Left Logo Header */}
        <div className="nyx-logo-section">
          <div className="nyx-logo-icon">
            <img
              src={nyxLogo}
              alt="NYX Logo"
              className="nyx-logo-img"
              style={{ width: '28px', height: '28px', maxWidth: '28px', maxHeight: '28px', objectFit: 'contain', display: 'block' }}
            />
          </div>
          <div className="flex items-center gap-2">
            <span className="nyx-logo-text">NYX ENGINE</span>
            <span className="nyx-version-badge">
              v1.0.0
            </span>
          </div>
        </div>

        {/* Center WebSocket Status Pill */}
        <div className="nyx-status-section">
          {connected ? (
            <div className="nyx-websocket-pill nyx-websocket-connected">
              <span className="nyx-websocket-dot"></span>
              LIVE
            </div>
          ) : (
            <div className="nyx-websocket-pill nyx-websocket-reconnecting">
              <span className="nyx-websocket-dot"></span>
              RECONNECTING
            </div>
          )}
          {lastEvent && (
            <div className="nyx-event-display">
              <span className="nyx-event-label">Event:</span>
              <span className="nyx-event-value">{lastEvent.event}</span>
            </div>
          )}
        </div>

        {/* Right Settings Quick Action */}
        <div className="nyx-actions-section">
          <button
            onClick={() => setActiveTab('settings')}
            className={`nyx-icon-button ${activeTab === 'settings' ? 'nyx-icon-button-active' : ''}`}
            title="Settings"
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* Main Body Area: Fixed 220px Sidebar + Scrollable Main Content */}
      <div className="nyx-main-layout">
        {/* Fixed Left Sidebar (220px) */}
        <aside className="nyx-sidebar">
          <div className="nyx-nav-groups">
            {navGroups.map((group, groupIdx) => (
              <div key={groupIdx} className="nyx-nav-group">
                <div className="nyx-nav-section-label">
                  {group.section}
                </div>
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => setActiveTab(item.id)}
                      className={`nyx-nav-item ${isActive ? 'nyx-nav-item-active' : ''}`}
                    >
                      <Icon className={`nyx-nav-icon ${isActive ? 'nyx-nav-icon-active' : ''}`} />
                      <span className="nyx-nav-label">{item.label}</span>
                      {isActive && <div className="nyx-nav-indicator"></div>}
                    </button>
                  );
                })}
              </div>
            ))}
          </div>

          {/* Bottom Sidebar Footer Info */}
          <div className="nyx-sidebar-footer">
            <div className="nyx-sidebar-footer-content">
              <span className="nyx-sidebar-footer-label">NYX Engine</span>
              <span className="nyx-sidebar-footer-version">v1.0</span>
            </div>
            <div className="nyx-sidebar-footer-status">
              <Lock className="w-3 h-3 text-[#00FF88]" />
              <span className="text-[10px] font-mono text-[#00FF88] uppercase tracking-wider">
                Secured
              </span>
            </div>
          </div>
        </aside>

        {/* Scrollable Main Content Area */}
        <main className="nyx-main-content">
          <div className="nyx-content-wrapper">
            {activeTab === 'dashboard' && <DashboardView onNavigate={(tab) => setActiveTab(tab)} />}
            {activeTab === 'continuous' && <ContinuousView />}
            {activeTab === 'fleet' && <FleetView />}
            {activeTab === 'workers' && <WorkerFleetView />}
            {activeTab === 'runtime' && <RuntimeView />}
            {activeTab === 'agent' && <AgentView />}
            {activeTab === 'surface' && <AttackSurfaceView />}
            {activeTab === 'findings' && <FindingsView />}
            {activeTab === 'evidence' && <EvidenceView />}
            {activeTab === 'intelligence' && <IntelligenceView />}
            {activeTab === 'execution' && <ExecutionView />}
            {activeTab === 'settings' && <SettingsView />}
          </div>
        </main>
      </div>
    </div>
  );
};

export default App;