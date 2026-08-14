import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { Server, Plus, Trash2, RefreshCw, Cpu, Activity, Shield, Database, Network, Lock, MonitorSmartphone } from 'lucide-react';
export const WorkerFleetView: React.FC = () => {
  const [workerStatus, setWorkerStatus] = useState<any>(null);
  const [hostname, setHostname] = useState<string>('worker-node-1');
  const [loading, setLoading] = useState<boolean>(false);

  async function loadWorkerData() {
    const res = await fetchApi('/api/v1/workers/status');
    if (res.success) setWorkerStatus(res.data);
  }

  useEffect(() => {
    loadWorkerData();
  }, []);

  async function handleRegisterWorker(e: React.FormEvent) {
    e.preventDefault();
    if (!hostname) return;
    setLoading(true);
    await fetchApi(`/api/v1/workers/register?hostname=${encodeURIComponent(hostname)}`, { method: 'POST' });
    await loadWorkerData();
    setLoading(false);
  }

  async function handleRemoveWorker(workerId: string) {
    await fetchApi(`/api/v1/workers/${workerId}/remove`, { method: 'POST' });
    loadWorkerData();
  }

  const getWorkerStatusBadge = (status: string = 'OFFLINE') => {
    switch (status.toUpperCase()) {
      case 'ONLINE':
        return 'nyx-badge-success';
      case 'OFFLINE':
        return 'nyx-badge-high';
      case 'SYNCING':
        return 'nyx-badge-info';
      case 'ERROR':
        return 'nyx-badge-critical';
      default:
        return 'nyx-badge-info';
    }
  };

  const getPlatformIcon = (platform: string = 'linux') => {
    switch (platform.toLowerCase()) {
      case 'linux':
        return MonitorSmartphone;
      case 'windows':
        return MonitorSmartphone;
      case 'darwin':
        return MonitorSmartphone;
      default:
        return Server;
    }
  };

  return (
    <div className="nyx-worker-fleet-view">
      {/* File Update Progress */}

      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div className="flex items-center gap-4">
            <div className="nyx-page-icon nyx-page-icon-cyan">
              <Server className="w-6 h-6 text-[#00D9FF]" />
            </div>
            <div>
              <h1 className="nyx-page-title">Remote Worker Nodes</h1>
              <p className="nyx-page-subtitle">HMAC mutual authentication & SHA-256 evidence sync</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="nyx-metric-pills">
              <div className="nyx-metric-pill">
                <span className="nyx-pill-label">Total Workers</span>
                <span className="nyx-pill-value text-[#00D9FF]">{workerStatus?.total_workers || 0}</span>
              </div>
              <div className="nyx-metric-pill">
                <span className="nyx-pill-label">Online Workers</span>
                <span className="nyx-pill-value text-[#00FF88]">{workerStatus?.online_workers || 0}</span>
              </div>
            </div>
            <button onClick={loadWorkerData} className="nyx-button nyx-button-ghost" title="Refresh">
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Register Worker Form Card */}
      <div className="nyx-card nyx-card-accent-cyan">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-green">
              <Plus className="w-4 h-4 text-[#00FF88]" />
            </div>
            <h2 className="nyx-section-title">Register Remote Worker Node</h2>
          </div>
          <div className="flex items-center gap-2">
            <Lock className="w-3 h-3 text-[#00D9FF]" />
            <span className="text-[10px] font-mono text-[#00D9FF] uppercase tracking-wider">
              HMAC Protected
            </span>
          </div>
        </div>
        
        <div className="nyx-form-container">
          <form onSubmit={handleRegisterWorker} className="nyx-form-inline">
            <div className="nyx-form-field nyx-form-field-grow">
              <label className="nyx-form-label">
                <Server className="w-3 h-3 text-[#00D9FF]" />
                Worker Hostname / Identifier
              </label>
              <input
                type="text"
                required
                placeholder="e.g. worker-node-us-east-1"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                className="nyx-input"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="nyx-button nyx-button-primary"
            >
              <Plus className="w-4 h-4" />
              <span>{loading ? 'Registering...' : 'Register Worker'}</span>
            </button>
          </form>
        </div>
      </div>

      {/* Connected Worker Nodes Grid */}
      <div className="nyx-card nyx-card-accent-cyan">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-cyan">
              <Cpu className="w-4 h-4 text-[#00D9FF]" />
            </div>
            <h3 className="nyx-section-title">Connected Worker Nodes</h3>
            <span className="nyx-count-pill">{workerStatus?.workers?.length || 0}</span>
          </div>
          {workerStatus?.online_workers > 0 && (
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-[#00FF88] animate-pulse"></div>
              <span className="text-[10px] font-mono text-[#00FF88] uppercase tracking-wider">
                {workerStatus.online_workers} Online
              </span>
            </div>
          )}
        </div>

        {(!workerStatus?.workers || workerStatus.workers.length === 0) ? (
          <div className="nyx-empty-state">
            <div className="nyx-empty-state-icon">
              <Server className="w-8 h-8 text-[#484F58]" />
            </div>
            <div className="nyx-empty-state-title">No remote worker nodes registered</div>
            <div className="nyx-empty-state-description">
              Register a worker node above to scale task execution
            </div>
          </div>
        ) : (
          <div className="nyx-workers-grid">
            {workerStatus.workers.map((w: any) => {
              const PlatformIcon = getPlatformIcon(w.platform);
              return (
                <div key={w.worker_id} className="nyx-worker-card">
                  <div className="nyx-worker-header">
                    <div className="flex items-center gap-3">
                      <div className="nyx-worker-icon">
                        <PlatformIcon className="w-5 h-5 text-[#00D9FF]" />
                      </div>
                      <div>
                        <span className="nyx-worker-id">{w.worker_id}</span>
                        <h4 className="nyx-worker-hostname">{w.hostname}</h4>
                      </div>
                    </div>
                    <button
                      onClick={() => handleRemoveWorker(w.worker_id)}
                      className="nyx-button nyx-button-danger nyx-button-sm"
                    >
                      <Trash2 className="w-3 h-3" />
                      <span>Remove</span>
                    </button>
                  </div>
                  
                  <div className="nyx-worker-details">
                    <div className="nyx-worker-detail-row">
                      <span className="nyx-worker-detail-label">
                        <MonitorSmartphone className="w-3 h-3 text-[#8B949E]" />
                        Platform:
                      </span>
                      <span className="nyx-worker-detail-value">{w.platform}</span>
                    </div>
                    <div className="nyx-worker-detail-row">
                      <span className="nyx-worker-detail-label">
                        <Activity className="w-3 h-3 text-[#8B949E]" />
                        Status:
                      </span>
                      <span className={`nyx-badge ${getWorkerStatusBadge(w.status)}`}>
                        {w.status}
                      </span>
                    </div>
                    <div className="nyx-worker-detail-row">
                      <span className="nyx-worker-detail-label">
                        <Database className="w-3 h-3 text-[#8B949E]" />
                        Supported Agents:
                      </span>
                      <div className="flex gap-1.5 flex-wrap">
                        {w.agents_supported?.map((agent: string, idx: number) => (
                          <span key={idx} className="nyx-badge nyx-badge-low">{agent}</span>
                        ))}
                      </div>
                    </div>
                    <div className="nyx-worker-detail-row">
                      <span className="nyx-worker-detail-label">
                        <Network className="w-3 h-3 text-[#8B949E]" />
                        Last Heartbeat:
                      </span>
                      <span className="nyx-worker-detail-value text-[#8B949E]">{w.last_seen}</span>
                    </div>
                  </div>
                  
                  <div className="nyx-worker-auth">
                    <Shield className="w-3 h-3 text-[#484F58]" />
                    <span className="nyx-worker-auth-token">{w.auth_token}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};