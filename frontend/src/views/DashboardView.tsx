import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Shield, Target, Activity, Cpu, AlertTriangle, FileText, ArrowRight, Layers, Crosshair } from 'lucide-react';

export const DashboardView: React.FC<{ onNavigate: (tab: string) => void }> = ({ onNavigate }) => {
  const [mission, setMission] = useState<any>(null);
  const [surface, setSurface] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [metricsAnimated, setMetricsAnimated] = useState<boolean>(false);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      const mRes = await fetchApi('/api/v1/mission');
      if (mRes.success) setMission(mRes.data);

      const sRes = await fetchApi('/api/v1/assets');
      if (sRes.success) setSurface(sRes.data);

      const fRes = await fetchApi('/api/v1/findings');
      if (fRes.success && fRes.data?.findings) setFindings(fRes.data.findings);
      setLoading(false);
      
      setTimeout(() => setMetricsAnimated(true), 100);
    }
    loadData();
  }, []);

  const getSeverityBadgeClass = (sev: string = 'medium') => {
    switch (sev.toLowerCase()) {
      case 'critical': return 'nyx-badge-critical';
      case 'high': return 'nyx-badge-high';
      case 'medium': return 'nyx-badge-medium';
      case 'low': return 'nyx-badge-low';
      default: return 'nyx-badge-info';
    }
  };

  return (
    <div className="nyx-dashboard">
      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div>
            <h1 className="nyx-page-title">Security Operations Console</h1>
            <p className="nyx-page-subtitle">NYX Autonomous Intelligence Engine</p>
            
            {/* Target pills below title */}
            <div className="nyx-target-pill-container">
              <div className="nyx-target-pill">
                <span className="nyx-target-pill-dot"></span>
                <span>{mission?.target || 'example.com'}</span>
              </div>
              <div className="nyx-target-pill">
                <span className="text-[#00D9FF]">{mission?.phase || 'DISCOVERY'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Status Metrics Grid (4-Column Grid) */}
      <div className="nyx-metrics-grid">
        {/* Card 1 - Harvested Endpoints */}
        <div
          onClick={() => onNavigate('surface')}
          className="nyx-metric-card nyx-metric-card-cyan cursor-pointer group"
        >
          <div className="nyx-metric-card-content">
            <div className="flex justify-between items-start">
              <span className="nyx-metric-label">
                ENDPOINTS DISCOVERED
              </span>
              <div className="nyx-metric-icon nyx-metric-icon-cyan">
                <Activity className="w-4 h-4" />
              </div>
            </div>
            <div className={`nyx-metric-value ${metricsAnimated ? 'nyx-metric-value-animated' : ''}`}>
              {surface?.endpoints_count ?? 0}
            </div>
            <div className="nyx-metric-description">
              Discovered attack endpoints
            </div>
          </div>
        </div>

        {/* Card 2 - Detected Stack */}
        <div
          onClick={() => onNavigate('surface')}
          className="nyx-metric-card nyx-metric-card-purple cursor-pointer group"
        >
          <div className="nyx-metric-card-content">
            <div className="flex justify-between items-start">
              <span className="nyx-metric-label">
                TECHNOLOGIES FINGERPRINTED
              </span>
              <div className="nyx-metric-icon nyx-metric-icon-purple">
                <Layers className="w-4 h-4" />
              </div>
            </div>
            <div className={`nyx-metric-value ${metricsAnimated ? 'nyx-metric-value-animated' : ''}`}>
              {surface?.technologies_count ?? 0}
            </div>
            <div className="nyx-metric-description">
              Fingerprinted technologies
            </div>
          </div>
        </div>

        {/* Card 3 - Recorded Findings */}
        <div
          onClick={() => onNavigate('findings')}
          className="nyx-metric-card nyx-metric-card-amber cursor-pointer group"
        >
          <div className="nyx-metric-card-content">
            <div className="flex justify-between items-start">
              <span className="nyx-metric-label">
                VULNERABILITY HYPOTHESES
              </span>
              <div className="nyx-metric-icon nyx-metric-icon-amber">
                <AlertTriangle className="w-4 h-4" />
              </div>
            </div>
            <div className={`nyx-metric-value ${metricsAnimated ? 'nyx-metric-value-animated' : ''}`}>
              {findings.length}
            </div>
            <div className="nyx-metric-description">
              Vulnerability hypotheses
            </div>
          </div>
        </div>

        {/* Card 4 - Evidence Vault */}
        <div
          onClick={() => onNavigate('evidence')}
          className="nyx-metric-card nyx-metric-card-green cursor-pointer group"
        >
          <div className="nyx-metric-card-content">
            <div className="flex justify-between items-start">
              <span className="nyx-metric-label">
                VERIFIED POC ARTIFACTS
              </span>
              <div className="nyx-metric-icon nyx-metric-icon-green">
                <FileText className="w-4 h-4" />
              </div>
            </div>
            <div className={`nyx-metric-value ${metricsAnimated ? 'nyx-metric-value-animated' : ''}`}>
              {findings.reduce((acc, f) => acc + (f.evidence_ids?.length || 0), 0)}
            </div>
            <div className="nyx-metric-description">
              Verified PoC artifacts
            </div>
          </div>
        </div>
      </div>

      {/* Active Security Hypotheses Section */}
      <div className="nyx-card nyx-card-section">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-amber">
              <AlertTriangle className="w-4 h-4 text-[#FF6B35]" />
            </div>
            <h2 className="nyx-section-title">Active Security Hypotheses</h2>
            <span className="nyx-count-pill">
              {findings.length}
            </span>
          </div>
          <button
            onClick={() => onNavigate('findings')}
            className="nyx-link-button"
          >
            <span>View All Findings</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {findings.length === 0 ? (
          <div className="nyx-empty-state">
            <div className="nyx-empty-state-icon">
              <Shield className="w-6 h-6 text-[#484F58]" />
            </div>
            <div className="nyx-empty-state-title">No active hypotheses</div>
            <div className="nyx-empty-state-description">
              Run reconnaissance to discover vulnerabilities
            </div>
          </div>
        ) : (
          <div className="nyx-findings-list">
            {findings.slice(0, 5).map((f: any) => (
              <div
                key={f.finding_id}
                onClick={() => onNavigate('findings')}
                className="nyx-finding-item group"
              >
                <div className="flex items-center gap-3">
                  <span className={`nyx-badge ${getSeverityBadgeClass(f.severity)}`}>
                    {f.severity || 'Medium'}
                  </span>
                  <span className="nyx-finding-id">{f.finding_id}</span>
                  <span className="nyx-finding-title">{f.title}</span>
                </div>
                <div className="flex items-center gap-3 w-full sm:w-auto justify-between sm:justify-end">
                  <span className="nyx-finding-endpoint">{f.endpoint || 'General Scope'}</span>
                  <span className="nyx-status-badge">
                    {f.status || 'HYPOTHESIS'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};