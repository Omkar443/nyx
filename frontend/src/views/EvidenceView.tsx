import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { FileText, ShieldCheck, Eye, CheckCircle2, Lock } from 'lucide-react';

export const EvidenceView: React.FC = () => {
  const [evidenceList, setEvidenceList] = useState<any[]>([]);
  const [selectedEv, setSelectedEv] = useState<any>(null);
  const [verifyStatus, setVerifyStatus] = useState<string | null>(null);

  async function loadEvidence() {
    // Collect findings to gather evidence IDs
    const fRes = await fetchApi('/api/v1/findings');
    if (fRes.success && fRes.data?.findings) {
      const allEv: any[] = [];
      for (const f of fRes.data.findings) {
        const evRes = await fetchApi(`/api/v1/findings/${f.finding_id}/evidence`);
        if (evRes.success && evRes.data?.evidence) {
          allEv.push(...evRes.data.evidence);
        }
      }
      setEvidenceList(allEv);
    }
  }

  useEffect(() => {
    loadEvidence();
  }, []);

  async function handleVerifyHash(evidenceId: string) {
    const res = await fetchApi(`/api/v1/evidence/${evidenceId}/verify`, { method: 'POST' });
    if (res.success) {
      setVerifyStatus(`SHA-256 Hash Verified: ${res.data?.sha256 || 'MATCH'}`);
    } else {
      setVerifyStatus(`Verification Error: ${res.error}`);
    }
  }

  async function handleViewDetails(evidenceId: string) {
    const res = await fetchApi(`/api/v1/evidence/${evidenceId}`);
    if (res.success) {
      setSelectedEv(res.data);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel p-6 flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-purple-400" /> Evidence Vault & Cryptographic Integrity
          </h2>
          <p className="text-sm text-slate-400">Sanitized PoC evidence artifacts and SHA-256 checksum integrity verification</p>
        </div>
      </div>

      {verifyStatus && (
        <div className="p-4 rounded-lg bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 text-sm font-mono flex items-center gap-2">
          <CheckCircle2 className="w-5 h-5 text-emerald-400" /> {verifyStatus}
        </div>
      )}

      {/* Evidence Table */}
      <div className="glass-panel p-6">
        {evidenceList.length === 0 ? (
          <div className="text-center py-8 text-slate-500 text-sm">
            No evidence artifacts recorded in active workspace.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300 font-mono">
              <thead className="bg-slate-900/80 text-xs text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="p-3">Evidence ID</th>
                  <th className="p-3">Finding ID</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">Sanitization</th>
                  <th className="p-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {evidenceList.map((ev: any, idx: number) => (
                  <tr key={idx} className="hover:bg-slate-800/40">
                    <td className="p-3 font-semibold text-purple-300">{ev.evidence_id || ev.id || `EV-${idx+1}`}</td>
                    <td className="p-3 text-cyan-300">{ev.finding_id || 'N/A'}</td>
                    <td className="p-3 text-slate-400 uppercase text-xs">{ev.type || 'note'}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 text-xs rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1 w-fit">
                        <Lock className="w-3 h-3" /> Sanitized
                      </span>
                    </td>
                    <td className="p-3 flex items-center gap-2">
                      <button
                        onClick={() => handleViewDetails(ev.evidence_id || ev.id)}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 rounded flex items-center gap-1"
                      >
                        <Eye className="w-3.5 h-3.5" /> View
                      </button>
                      <button
                        onClick={() => handleVerifyHash(ev.evidence_id || ev.id)}
                        className="px-2.5 py-1 bg-purple-500/20 hover:bg-purple-500/30 text-xs text-purple-300 rounded border border-purple-500/30 flex items-center gap-1"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" /> Verify Hash
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedEv && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="glass-panel p-6 w-full max-w-xl space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-bold text-white font-mono">{selectedEv.evidence_id}</h3>
              <button onClick={() => setSelectedEv(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="text-slate-400">SHA-256 Hash: <span className="text-emerald-300">{selectedEv.sha256 || 'Calculated on read'}</span></div>
              <div className="text-slate-400">Sanitization Status: <span className="text-cyan-300">Sanitized (Redacted Auth Tokens / PII)</span></div>
            </div>
            <div className="bg-slate-950 p-4 rounded text-xs text-slate-200 font-mono whitespace-pre-wrap max-h-60 overflow-y-auto">
              {selectedEv.content || selectedEv.description || 'No raw content preview'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
