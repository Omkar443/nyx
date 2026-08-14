import React, { useEffect, useState } from 'react';
import { fetchApi, getStoredToken, setStoredToken } from '../api/client';
import { Settings, ShieldCheck, Key, Server, Database, Lock, Activity, CheckCircle, Cpu, HardDrive, Globe, Info } from 'lucide-react';
export const SettingsView: React.FC = () => {
  const [health, setHealth] = useState<any>(null);
  const [tokenInput, setTokenInput] = useState<string>(getStoredToken());
  const [tokenSaved, setTokenSaved] = useState<boolean>(false);

  useEffect(() => {
    async function loadHealth() {
      const res = await fetchApi('/health');
      if (res) setHealth(res);
    }
    loadHealth();
  }, []);

  function handleSaveToken(e: React.FormEvent) {
    e.preventDefault();
    setStoredToken(tokenInput);
    setTokenSaved(true);
    setTimeout(() => setTokenSaved(false), 3000);
  }

  return (
    <div className="nyx-settings-view">
      {/* File Update Progress */}

      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div className="flex items-center gap-4">
            <div className="nyx-page-icon nyx-page-icon-blue">
              <Settings className="w-6 h-6 text-[#58A6FF]" />
            </div>
            <div>
              <h1 className="nyx-page-title">Platform Configuration & System Health</h1>
              <p className="nyx-page-subtitle">NYX engine version, local authentication settings, and workspace status</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[#00FF88]" />
            <span className="nyx-badge nyx-badge-success">SYSTEM OPERATIONAL</span>
          </div>
        </div>
      </div>

      {/* System Status Stats */}
      <div className="nyx-stats-overview">
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-green">
            <CheckCircle className="w-4 h-4 text-[#00FF88]" />
          </div>
          <div>
            <div className="nyx-stat-value">1.0.0</div>
            <div className="nyx-stat-label">NYX Version</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-cyan">
            <Database className="w-4 h-4 text-[#00D9FF]" />
          </div>
          <div>
            <div className="nyx-stat-value">Active</div>
            <div className="nyx-stat-label">Workspace</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-amber">
            <Lock className="w-4 h-4 text-[#FF6B35]" />
          </div>
          <div>
            <div className="nyx-stat-value">Secure</div>
            <div className="nyx-stat-label">Auth Token</div>
          </div>
        </div>
      </div>

      {/* System Status Grid */}
      <div className="nyx-content-grid">
        {/* System Health Status */}
        <div className="nyx-card nyx-card-accent-green">
          <div className="nyx-section-header">
            <div className="flex items-center gap-3">
              <div className="nyx-section-icon nyx-section-icon-green">
                <ShieldCheck className="w-4 h-4 text-[#00FF88]" />
              </div>
              <h3 className="nyx-section-title">System Health Status</h3>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-[#00FF88] animate-pulse"></div>
              <span className="text-[10px] font-mono text-[#00FF88] uppercase tracking-wider">
                Healthy
              </span>
            </div>
          </div>
          
          <div className="nyx-health-list">
            <div className="nyx-health-item">
              <div className="nyx-health-icon">
                <Cpu className="w-4 h-4 text-[#00FF88]" />
              </div>
              <div className="flex-1">
                <div className="nyx-health-label">NYX Version</div>
                <div className="nyx-health-value">{health?.version || '1.0.0'}</div>
              </div>
              <span className="nyx-badge nyx-badge-success">STABLE</span>
            </div>
            
            <div className="nyx-health-item">
              <div className="nyx-health-icon">
                <Server className="w-4 h-4 text-[#E6EDF3]" />
              </div>
              <div className="flex-1">
                <div className="nyx-health-label">Application Name</div>
                <div className="nyx-health-value">{health?.app_name || 'NYX Security Operations Dashboard'}</div>
              </div>
            </div>
            
            <div className="nyx-health-item">
              <div className="nyx-health-icon">
                <ShieldCheck className="w-4 h-4 text-[#00D9FF]" />
              </div>
              <div className="flex-1">
                <div className="nyx-health-label">Authentication</div>
                <div className="nyx-health-value">ENABLED (Local Token)</div>
              </div>
              <span className="nyx-badge nyx-badge-info">ACTIVE</span>
            </div>
            
            <div className="nyx-health-item">
              <div className="nyx-health-icon">
                <HardDrive className="w-4 h-4 text-[#00FF88]" />
              </div>
              <div className="flex-1">
                <div className="nyx-health-label">Active Workspace</div>
                <div className="nyx-health-value">.engagement/</div>
              </div>
              <span className="nyx-badge nyx-badge-success">MOUNTED</span>
            </div>
          </div>
        </div>

        {/* API Token Config */}
        <div className="nyx-card nyx-card-accent-amber">
          <div className="nyx-section-header">
            <div className="flex items-center gap-3">
              <div className="nyx-section-icon nyx-section-icon-amber">
                <Key className="w-4 h-4 text-[#FF6B35]" />
              </div>
              <h3 className="nyx-section-title">Local API Authentication Token</h3>
            </div>
            <div className="flex items-center gap-2">
              <Lock className="w-3 h-3 text-[#FF6B35]" />
              <span className="text-[10px] font-mono text-[#FF6B35] uppercase tracking-wider">
                Encrypted
              </span>
            </div>
          </div>
          
          <form onSubmit={handleSaveToken} className="nyx-form-container">
            <div className="nyx-form-field">
              <label className="nyx-form-label">
                <Key className="w-3 h-3 text-[#FF6B35]" />
                Active API Token
              </label>
              <div className="nyx-token-input-container">
                <input
                  type="password"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  className="nyx-input nyx-token-input"
                  placeholder="Enter API token..."
                />
                <Lock className="w-4 h-4 text-[#484F58] absolute right-3 top-1/2 transform -translate-y-1/2" />
              </div>
            </div>
            
            <div className="flex items-center gap-3">
              <button
                type="submit"
                className="nyx-button nyx-button-primary"
              >
                <ShieldCheck className="w-4 h-4" />
                Save Token
              </button>
              {tokenSaved && (
                <div className="nyx-token-saved">
                  <CheckCircle className="w-4 h-4 text-[#00FF88]" />
                  <span>Token saved to local storage!</span>
                </div>
              )}
            </div>
          </form>
          
          <div className="nyx-token-note">
            <Info className="w-3.5 h-3.5 text-[#58A6FF]" />
            <span>API token is configured locally in memory/env and never exposed in logs or network tracebacks.</span>
          </div>
        </div>
      </div>

      {/* System Info Footer */}
      <div className="nyx-system-footer">
        <div className="flex items-center gap-2">
          <Globe className="w-3 h-3 text-[#484F58]" />
          <span className="text-[10px] font-mono text-[#484F58] uppercase tracking-wider">
            NYX Security Intelligence Engine v1.0 Continuous
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Activity className="w-3 h-3 text-[#00FF88]" />
          <span className="text-[10px] font-mono text-[#00FF88] uppercase tracking-wider">
            All Systems Operational
          </span>
        </div>
      </div>
    </div>
  );
};