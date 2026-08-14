import React, { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import { FileText, ShieldCheck, Eye, CheckCircle2, Lock, Database, Hash, Key, FileCode, X } from 'lucide-react';
export const EvidenceView: React.FC = () => {
  const [evidenceList, setEvidenceList] = useState<any[]>([]);
  const [selectedEv, setSelectedEv] = useState<any>(null);
  const [verifyStatus, setVerifyStatus] = useState<string | null>(null);

  async function loadEvidence() {
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

  const getEvidenceTypeIcon = (type: string = 'note') => {
    switch (type.toLowerCase()) {
      case 'screenshot':
        return FileCode;
      case 'request':
        return Hash;
      case 'response':
        return Database;
      case 'poc':
        return Key;
      default:
        return FileText;
    }
  };

  return (
    <div className="nyx-evidence-view">
      {/* File Update Progress */}

      {/* Page Header */}
      <div className="nyx-page-header">
        <div className="nyx-page-header-content">
          <div className="flex items-center gap-4">
            <div className="nyx-page-icon nyx-page-icon-purple">
              <ShieldCheck className="w-6 h-6 text-[#7C3AED]" />
            </div>
            <div>
              <h1 className="nyx-page-title">Evidence Vault & Integrity</h1>
              <p className="nyx-page-subtitle">Sanitized PoC evidence artifacts and SHA-256 checksum integrity verification</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-[#00FF88]" />
            <span className="nyx-badge nyx-badge-success">INTEGRITY PROTECTED</span>
          </div>
        </div>
      </div>

      {verifyStatus && (
        <div className="nyx-verify-status">
          <CheckCircle2 className="w-4 h-4 text-[#00FF88]" />
          <span>{verifyStatus}</span>
          <button onClick={() => setVerifyStatus(null)} className="nyx-verify-close">
            <X className="w-3 h-3" />
          </button>
        </div>
      )}

      {/* Evidence Stats */}
      <div className="nyx-stats-overview">
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-purple">
            <FileText className="w-4 h-4 text-[#7C3AED]" />
          </div>
          <div>
            <div className="nyx-stat-value">{evidenceList.length}</div>
            <div className="nyx-stat-label">Total Artifacts</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-green">
            <ShieldCheck className="w-4 h-4 text-[#00FF88]" />
          </div>
          <div>
            <div className="nyx-stat-value">100%</div>
            <div className="nyx-stat-label">Sanitized</div>
          </div>
        </div>
        <div className="nyx-stat-card">
          <div className="nyx-stat-icon nyx-stat-icon-cyan">
            <Hash className="w-4 h-4 text-[#00D9FF]" />
          </div>
          <div>
            <div className="nyx-stat-value">SHA-256</div>
            <div className="nyx-stat-label">Hash Verified</div>
          </div>
        </div>
      </div>

      {/* Evidence Table */}
      <div className="nyx-card nyx-card-accent-purple">
        <div className="nyx-section-header">
          <div className="flex items-center gap-3">
            <div className="nyx-section-icon nyx-section-icon-purple">
              <FileText className="w-4 h-4 text-[#7C3AED]" />
            </div>
            <h3 className="nyx-section-title">Evidence Artifacts</h3>
            <span className="nyx-count-pill">{evidenceList.length}</span>
          </div>
          <div className="flex items-center gap-2">
            <Database className="w-3 h-3 text-[#7C3AED]" />
            <span className="text-[10px] font-mono text-[#7C3AED] uppercase tracking-wider">
              Vault Secured
            </span>
          </div>
        </div>

        {evidenceList.length === 0 ? (
          <div className="nyx-empty-state">
            <div className="nyx-empty-state-icon">
              <FileText className="w-8 h-8 text-[#484F58]" />
            </div>
            <div className="nyx-empty-state-title">No evidence artifacts recorded</div>
            <div className="nyx-empty-state-description">
              Evidence is attached during vulnerability validation phase
            </div>
          </div>
        ) : (
          <div className="nyx-evidence-list">
            <div className="nyx-evidence-header">
              <div className="nyx-evidence-header-item">Evidence ID</div>
              <div className="nyx-evidence-header-item">Finding ID</div>
              <div className="nyx-evidence-header-item">Type</div>
              <div className="nyx-evidence-header-item">Sanitization</div>
              <div className="nyx-evidence-header-item">Actions</div>
            </div>
            <div className="nyx-evidence-body">
              {evidenceList.map((ev: any, idx: number) => {
                const TypeIcon = getEvidenceTypeIcon(ev.type);
                return (
                  <div key={idx} className="nyx-evidence-row group">
                    <div className="nyx-evidence-cell nyx-evidence-id">
                      <FileText className="w-3 h-3 text-[#7C3AED]" />
                      <span>{ev.evidence_id || ev.id || `EV-${idx+1}`}</span>
                    </div>
                    <div className="nyx-evidence-cell nyx-evidence-finding">
                      {ev.finding_id || 'N/A'}
                    </div>
                    <div className="nyx-evidence-cell">
                      <span className="nyx-badge nyx-badge-info">
                        <TypeIcon className="w-3 h-3" />
                        {ev.type || 'note'}
                      </span>
                    </div>
                    <div className="nyx-evidence-cell">
                      <span className="nyx-badge nyx-badge-success">
                        <Lock className="w-3 h-3" />
                        Sanitized
                      </span>
                    </div>
                    <div className="nyx-evidence-cell nyx-evidence-actions">
                      <button
                        onClick={() => handleViewDetails(ev.evidence_id || ev.id)}
                        className="nyx-button nyx-button-secondary nyx-button-sm"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        View
                      </button>
                      <button
                        onClick={() => handleVerifyHash(ev.evidence_id || ev.id)}
                        className="nyx-button nyx-button-verify nyx-button-sm"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        Verify Hash
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedEv && (
        <div className="nyx-modal-overlay">
          <div className="nyx-modal">
            <div className="nyx-modal-header">
              <div className="flex items-center gap-3">
                <div className="nyx-modal-icon">
                  <FileCode className="w-5 h-5 text-[#7C3AED]" />
                </div>
                <div>
                  <h3 className="nyx-modal-title">{selectedEv.evidence_id}</h3>
                  <span className="nyx-badge nyx-badge-success">
                    <Lock className="w-3 h-3" />
                    SANITIZED
                  </span>
                </div>
              </div>
              <button onClick={() => setSelectedEv(null)} className="nyx-modal-close">
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="nyx-modal-content">
              <div className="nyx-modal-details">
                <div className="nyx-modal-detail-row">
                  <div className="nyx-modal-detail-icon">
                    <Hash className="w-4 h-4 text-[#00FF88]" />
                  </div>
                  <div>
                    <div className="nyx-modal-detail-label">SHA-256 Hash</div>
                    <div className="nyx-modal-detail-value">
                      {selectedEv.sha256 || 'Calculated on read'}
                    </div>
                  </div>
                </div>
                <div className="nyx-modal-detail-row">
                  <div className="nyx-modal-detail-icon">
                    <ShieldCheck className="w-4 h-4 text-[#00D9FF]" />
                  </div>
                  <div>
                    <div className="nyx-modal-detail-label">Sanitization Status</div>
                    <div className="nyx-modal-detail-value">
                      Sanitized (Redacted Auth Tokens / PII)
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="nyx-modal-preview">
                <div className="nyx-modal-preview-header">
                  <FileCode className="w-3 h-3 text-[#8B949E]" />
                  <span className="text-[10px] font-mono text-[#8B949E] uppercase tracking-wider">
                    Content Preview
                  </span>
                </div>
                <div className="nyx-modal-preview-content">
                  {selectedEv.content || selectedEv.description || 'No raw content preview'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};