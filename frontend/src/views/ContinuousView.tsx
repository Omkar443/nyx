import React, { useState, useEffect } from 'react';
import { Activity, Shield, Clock, Radio, Bell, RefreshCw } from 'lucide-react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';
import { useApp } from '../context/AppContext';

export function ContinuousView() {
  const { target } = useApp();
  const { lastEvent } = useNyxEvents();
  const [alerts, setAlerts] = useState<any[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [loading, setLoading] = useState(true);

  async function loadAlerts() {
    try {
      const res = await fetchApi('/api/v1/continuous/alerts');
      const list = res?.data?.alerts || res?.alerts || [];
      if (Array.isArray(list)) setAlerts(list);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAlerts();
  }, []);

  async function handleDriftScan() {
    setIsScanning(true);
    try {
      await fetchApi('/api/v1/continuous/monitor/start', { method: 'POST' });
      await loadAlerts();
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Continuous Intel &amp; Perimeter Drift
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <Activity className="w-3.5 h-3.5 text-[#555555]" />
            24/7 autonomous monitoring for certificate transparency logs, DNS changes, and open port drift
          </p>
        </div>
        <button onClick={handleDriftScan} disabled={isScanning} className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5">
          <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
          <span>{isScanning ? 'Checking Drift...' : 'Trigger Perimeter Drift Check'}</span>
        </button>
      </div>

      {/* ========== FEED ========== */}
      <div className="card space-y-2.5">
        <div className="text-xs font-semibold uppercase tracking-[0.08em] text-[#A8A8A8] pb-2 border-b border-[#333333]">
          Perimeter Drift Log
        </div>

        {alerts.length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <Activity className="w-8 h-8 text-[#555555] mx-auto opacity-50" />
            <p className="text-xs text-[#888888] font-mono">No perimeter drift detected.</p>
            <p className="text-[11px] text-[#555555]">Target perimeter matches verified baseline. Click above to execute a drift scan.</p>
          </div>
        ) : (
          <div className="space-y-1.5">
            {alerts.map((a, idx) => (
              <div key={idx} className="bg-[#2B2B2B] border border-[#3A3A3A] rounded p-2.5 flex items-center justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2 text-[11px] font-mono">
                    <span className="text-[#ebb94b] font-medium">{a.type || 'Drift Event'}</span>
                    <span className="text-[#707070]">· {a.timestamp || 'Recorded'}</span>
                  </div>
                  <p className="text-xs text-[#E8E8E8] mt-0.5 font-mono">{a.message || a.desc}</p>
                </div>
                <span className="text-[10px] font-mono font-medium uppercase px-1.5 py-0.5 rounded border text-[#FFA726] bg-[#FFA726]/15 border-[#FFA726]/30">
                  {a.severity || 'Medium'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default ContinuousView;
