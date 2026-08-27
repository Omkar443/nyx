import React, { useState, useEffect } from 'react';
import { 
  Terminal, Play, CheckCircle, XCircle, 
  Clock, Shield, Search, RefreshCw, Copy, Check, TerminalSquare
} from 'lucide-react';
import { fetchApi } from '../api/client';
import { useNyxEvents } from '../hooks/useNyxEvents';
import { useApp } from '../context/AppContext';

interface ExecItem {
  execution_id?: string;
  id?: string;
  tool?: string;
  tool_name?: string;
  target?: string;
  command?: string | string[];
  exit_code?: number;
  duration?: number | string;
  timestamp?: string;
  started_at?: string;
  stdout?: string;
  stderr?: string;
  sha256?: string;
}

export function ExecutionView() {
  const { target: appTarget, viewParams, refreshGlobalStats } = useApp();
  const { lastEvent } = useNyxEvents();
  const [logs, setLogs] = useState<ExecItem[]>([]);
  const [selectedLog, setSelectedLog] = useState<ExecItem | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);

  // Execution Launcher
  const [toolName, setToolName] = useState(viewParams?.tool || 'httpx');
  const [execTarget, setExecTarget] = useState(viewParams?.target || appTarget || '');
  const [cliArgs, setCliArgs] = useState('-status-code -title');
  const [isExecuting, setIsExecuting] = useState(false);
  const [copied, setCopied] = useState(false);

  const availableTools = [
    { name: 'httpx', desc: 'Fast multi-purpose HTTP prober & title extraction' },
    { name: 'subfinder', desc: 'Passive DNS subdomain discovery' },
    { name: 'katana', desc: 'Web crawler & endpoint pipeline spider' },
    { name: 'nuclei', desc: 'Vulnerability template scanner' },
    { name: 'nmap', desc: 'Port scanner & service fingerprinting' },
    { name: 'ffuf', desc: 'Fast web fuzzer & content discovery' },
    { name: 'wpscan', desc: 'WordPress security scanner' },
    { name: 'sqlmap', desc: 'Automatic SQL injection & database takeover' },
  ];

  async function loadHistory() {
    try {
      const targetQuery = appTarget && appTarget !== 'No active target' ? `?target=${encodeURIComponent(appTarget)}` : '';
      const res = await fetchApi(`/api/v1/execution/history${targetQuery}`);
      const list = res?.data?.history || res?.history || [];
      if (Array.isArray(list)) {
        setLogs(list);
        if (list.length > 0 && !selectedLog) {
          setSelectedLog(list[0]);
        }
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadHistory();
    if (viewParams?.target) setExecTarget(viewParams.target);
    else if (appTarget && appTarget !== 'No active target') setExecTarget(appTarget);
    if (viewParams?.tool) setToolName(viewParams.tool);
  }, [viewParams, appTarget]);

  useEffect(() => {
    if (lastEvent?.event === 'execution_finished' || lastEvent?.event === 'recon_completed') {
      loadHistory();
      refreshGlobalStats();
    }
  }, [lastEvent, refreshGlobalStats]);

  async function handleExecuteTool(e: React.FormEvent) {
    e.preventDefault();
    setIsExecuting(true);
    try {
      const argsList = cliArgs.trim() ? cliArgs.split(' ') : [];
      const res = await fetchApi('/api/v1/execution/run', {
        method: 'POST',
        body: JSON.stringify({
          tool_name: toolName,
          target: execTarget,
          arguments: ['-u', execTarget, ...argsList],
          dry_run: false,
          active_permitted: true
        })
      });
      await loadHistory();
      await refreshGlobalStats();
      if (res?.data) setSelectedLog(res.data);
    } finally {
      setIsExecuting(false);
    }
  }

  function handleCopyOutput() {
    if (selectedLog?.stdout || selectedLog?.stderr) {
      navigator.clipboard.writeText(selectedLog.stdout || selectedLog.stderr || '');
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  const filtered = logs.filter(l => {
    const tName = l.tool || l.tool_name || '';
    const tgt = l.target || '';
    return tName.toLowerCase().includes(searchQuery.toLowerCase()) || tgt.toLowerCase().includes(searchQuery.toLowerCase());
  });

  return (
    <div className="space-y-5 animate-fadeInUp">
      {/* ========== HEADER ========== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-[#F2F2F2] tracking-tight">
            Execution Audit Trail &amp; Tool Runner
          </h1>
          <p className="text-sm text-[#707070] mt-0.5 flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-[#555555]" />
            Audited execution engine with scope policy enforcement &nbsp;·&nbsp; Target: <span className="font-mono text-[#E8E8E8]">{appTarget}</span> &nbsp;·&nbsp; {logs.length} operations
          </p>
        </div>
      </div>

      {/* ========== TOOL LAUNCHER FORM ========== */}
      <div className="card space-y-3 border border-[#3A3A3A]">
        <div className="flex items-center gap-2 pb-2 border-b border-[#333333]">
          <Play className="w-4 h-4 text-[#ebb94b]" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#E8E8E8]">Launch Security Probe</h3>
        </div>

        <form onSubmit={handleExecuteTool} className="grid grid-cols-1 sm:grid-cols-4 gap-2.5 text-xs">
          <div>
            <label className="text-[#707070] block mb-1 font-mono">Tool</label>
            <select
              value={toolName}
              onChange={(e) => setToolName(e.target.value)}
              className="w-full bg-[#252525] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs text-[#E8E8E8] font-mono focus:outline-none"
            >
              {availableTools.map(t => (
                <option key={t.name} value={t.name}>{t.name} — {t.desc}</option>
              ))}
            </select>
          </div>

          <div className="sm:col-span-2">
            <label className="text-[#707070] block mb-1 font-mono">Target URL / Asset</label>
            <input
              type="text"
              required
              value={execTarget}
              onChange={(e) => setExecTarget(e.target.value)}
              className="w-full bg-[#252525] border border-[#3A3A3A] rounded px-3 py-1.5 text-xs font-mono text-[#E8E8E8] focus:outline-none"
            />
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={isExecuting || !execTarget}
              className="btn-primary w-full py-1.5 flex items-center justify-center gap-1.5"
            >
              <Play className={`w-3.5 h-3.5 ${isExecuting ? 'animate-spin' : ''}`} />
              <span>{isExecuting ? 'Executing...' : 'Run Tool'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* ========== LOGS & OUTPUT SPLIT ========== */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left Column: History Table */}
        <div className="card p-0 overflow-hidden lg:col-span-1 h-fit divide-y divide-[#2B2B2B]">
          <div className="p-2.5 bg-[#1E1E1E] border-b border-[#333333]">
            <input
              type="text"
              placeholder="Search executions..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#252525] border border-[#333333] rounded px-2.5 py-1 text-xs text-[#E8E8E8] focus:outline-none"
            />
          </div>

          {loading ? (
            <div className="text-center py-8 text-xs text-[#888888]">Loading history...</div>
          ) : filtered.length === 0 ? (
            <div className="text-center py-8 text-xs text-[#888888] italic">No execution records for target {appTarget}.</div>
          ) : (
            filtered.map((item, idx) => {
              const isSelected = selectedLog === item;
              const isSuccess = item.exit_code === 0;
              return (
                <div
                  key={idx}
                  onClick={() => setSelectedLog(item)}
                  className={`p-3 cursor-pointer transition-colors hover:bg-[#282828] space-y-1 ${
                    isSelected ? 'bg-[#2A2A2A] border-l-2 border-l-[#ebb94b]' : ''
                  }`}
                >
                  <div className="flex items-center justify-between font-mono text-xs">
                    <span className="font-bold text-[#E8E8E8]">{item.tool || item.tool_name}</span>
                    {item.status === 'SKIPPED' ? (
                      <span className="text-[10px] px-1.5 py-0.2 rounded font-bold text-[#ebb94b] bg-[#ebb94b]/15 border border-[#ebb94b]/30">
                        SKIPPED
                      </span>
                    ) : item.status === 'UNAVAILABLE' ? (
                      <span className="text-[10px] px-1.5 py-0.2 rounded font-bold text-[#FFA726] bg-[#FFA726]/15 border border-[#FFA726]/30">
                        UNAVAILABLE
                      </span>
                    ) : item.status === 'BLOCKED' ? (
                      <span className="text-[10px] px-1.5 py-0.2 rounded font-bold text-[#CE93D8] bg-[#CE93D8]/15 border border-[#CE93D8]/30">
                        BLOCKED
                      </span>
                    ) : (
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${
                        isSuccess ? 'text-[#4CAF50] bg-[#4CAF50]/15' : 'text-[#EF5350] bg-[#EF5350]/15'
                      }`}>
                        {isSuccess ? 'EXIT 0' : `EXIT ${item.exit_code}`}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] font-mono text-[#777777] truncate">{item.target}</p>
                  <span className="text-[10px] font-mono text-[#555555] block">
                    {item.timestamp?.slice(11, 19) || item.started_at?.slice(11, 19) || 'Recorded'}
                  </span>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Execution Output Inspector */}
        <div className="lg:col-span-2 space-y-3">
          {selectedLog ? (
            <div className="card space-y-3 flex flex-col h-full">
              <div className="flex items-center justify-between pb-2 border-b border-[#333333]">
                <div className="flex items-center gap-2">
                  <TerminalSquare className="w-4 h-4 text-[#ebb94b]" />
                  <span className="font-mono text-xs font-bold text-[#E8E8E8]">
                    {selectedLog.tool || selectedLog.tool_name} &nbsp;·&nbsp; {selectedLog.target}
                  </span>
                </div>
                <button onClick={handleCopyOutput} className="btn-secondary text-xs py-1 px-2.5 flex items-center gap-1">
                  {copied ? <Check className="w-3.5 h-3.5 text-[#4CAF50]" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy Output'}</span>
                </button>
              </div>

              <div className="flex-1 min-h-[300px] bg-[#1A1A1A] border border-[#333333] rounded-lg p-3 font-mono text-xs text-[#CCCCCC] overflow-auto whitespace-pre-wrap">
                {selectedLog.stdout || selectedLog.stderr || '[Empty Output] Tool executed with zero output.'}
              </div>
            </div>
          ) : (
            <div className="card text-center py-16 text-xs text-[#888888]">
              Select an execution log to inspect raw stdout / stderr output.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default ExecutionView;
