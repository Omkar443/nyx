import React, { useState, useEffect } from 'react';
import { HardDrive, Server, Activity, Shield, Zap, Plus } from 'lucide-react';
import { fetchApi } from '../api/client';

export function WorkerFleetView() {
  const [workers, setWorkers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  async function loadWorkers() {
    try {
      const res = await fetchApi('/api/v1/workers');
      const list = res?.data?.workers || res?.workers || [];
      if (Array.isArray(list)) setWorkers(list);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadWorkers();
  }, []);

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Remote Execution Compute Nodes
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <HardDrive className="w-3.5 h-3.5 text-[#555555]" />
            Distributed worker cluster handling queue dispatch and scanner workloads &nbsp;·&nbsp; {workers.length} nodes
          </p>
        </div>
        <div className="text-xs font-mono text-[#4CAF50]">ENGINE: LOCAL ASYNC WORKER</div>
      </div>

      {/* ========== TABLE ========== */}
      <div className="card p-0 overflow-hidden">
        {workers.length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <HardDrive className="w-8 h-8 text-[#555555] mx-auto opacity-50" />
            <p className="text-xs text-[#888888] font-mono">Local execution engine is handling all tasks.</p>
            <p className="text-[11px] text-[#555555]">No external remote compute nodes registered.</p>
          </div>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="bg-[#1E1E1E] border-b border-[#333333] text-[#707070] uppercase font-mono text-[10px]">
              <tr>
                <th className="px-4 py-2.5">Worker ID</th>
                <th className="px-4 py-2.5">Host</th>
                <th className="px-4 py-2.5">Role</th>
                <th className="px-4 py-2.5">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#333333]">
              {workers.map((w) => (
                <tr key={w.id} className="hover:bg-[#303030] transition-colors">
                  <td className="px-4 py-2.5 font-mono text-xs font-medium text-[#ebb94b]">{w.id}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-[#E8E8E8]">{w.host}</td>
                  <td className="px-4 py-2.5 text-xs text-[#A0A0A0]">{w.role}</td>
                  <td className="px-4 py-2.5">
                    <span className="text-[10px] font-mono font-medium uppercase px-1.5 py-0.5 rounded border text-[#4CAF50] bg-[#4CAF50]/15 border-[#4CAF50]/30">
                      {w.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export default WorkerFleetView;
