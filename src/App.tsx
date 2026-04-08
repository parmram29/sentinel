import React, { useState, useRef, useEffect } from 'react';
import { Shield, ShieldAlert, ShieldCheck, Terminal, Code, Server, Lock, AlertTriangle, CheckCircle, Loader2, Upload, Download, FileText, ChevronRight, Play, History, Clock, LogOut, X } from 'lucide-react';
import { AuditResult, CliExecutionResult, HistoryEntry } from './types';
import { performAudit, executeCliCommand } from './services/auditService';
import { exportReport } from './utils/exportUtils';

export default function App() {
  const [inputCode, setInputCode] = useState('');
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditResult, setAuditResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const HISTORY_KEY = 'sentinel_audit_history';
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [rightView, setRightView] = useState<'report' | 'history'>('report');

  useEffect(() => {
    try {
      const stored = localStorage.getItem(HISTORY_KEY);
      if (stored) setHistory(JSON.parse(stored));
    } catch {
      localStorage.removeItem(HISTORY_KEY);
    }
  }, []);

  const saveToHistory = (result: AuditResult, input: string) => {
    const entry: HistoryEntry = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      trailId: result.managementSummary.auditTrailId,
      complianceStatus: result.managementSummary.complianceStatus,
      isSecure: result.isSecure,
      findingCount: result.findings.length,
      inputSummary: input.slice(0, 120).replace(/\s+/g, ' '),
      result,
    };
    setHistory((prev) => {
      const updated = [entry, ...prev].slice(0, 50);
      try { localStorage.setItem(HISTORY_KEY, JSON.stringify(updated)); } catch {}
      return updated;
    });
  };

  const loadFromHistory = (entry: HistoryEntry) => {
    setAuditResult(entry.result);
    setError(null);
    setRightView('report');
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem(HISTORY_KEY);
  };

  const [activeTab, setActiveTab] = useState<'payload' | 'cli'>('payload');
  const [cliCommand, setCliCommand] = useState('');
  const [isExecutingCli, setIsExecutingCli] = useState(false);
  const [cliOutput, setCliOutput] = useState<CliExecutionResult | null>(null);

  const PRESET_COMMANDS = [
    { label: 'npm audit', cmd: 'npm audit' },
    { label: 'npm outdated', cmd: 'npm outdated' },
    { label: 'pip-audit', cmd: 'pip-audit' },
    { label: 'bandit', cmd: 'bandit -r .' },
    { label: 'semgrep', cmd: 'semgrep --config auto .' },
    { label: 'trivy fs', cmd: 'trivy fs .' },
    { label: 'git log', cmd: 'git log --oneline -20' },
    { label: 'package.json', cmd: 'cat package.json' },
    { label: 'requirements.txt', cmd: 'cat requirements.txt' },
  ] as const;

  const [isDevMode, setIsDevMode] = useState(false);

  const handleShieldClick = () => {
    const passphrase = window.prompt("Authorization required:");
    if (!passphrase) return;
    const expected = import.meta.env.VITE_DEV_PASSPHRASE;
    if (expected && passphrase === expected) setIsDevMode(true);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    let newContent = '';
    for (let i = 0; i < files.length; i++) {
      try {
        const text = await files[i].text();
        newContent += `\n\n--- File: ${files[i].name} ---\n${text}\n`;
      } catch {}
    }
    setInputCode((prev) => (prev ? prev + newContent : newContent.trim()));
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const runAudit = async () => {
    if (!inputCode.trim()) return;
    setIsAuditing(true);
    setError(null);
    setAuditResult(null);
    try {
      const result = await performAudit(inputCode);
      setAuditResult(result);
      saveToHistory(result, inputCode);
    } catch (err: any) {
      setError(err.message || "An error occurred during the audit.");
    } finally {
      setIsAuditing(false);
    }
  };

  const runCliCommand = async () => {
    if (!cliCommand.trim()) return;
    setIsExecutingCli(true);
    setCliOutput(null);
    try {
      const result = await executeCliCommand(cliCommand);
      setCliOutput(result);
    } catch (err: any) {
      setCliOutput({ stdout: '', stderr: '', error: err.message || "Execution failed." });
    } finally {
      setIsExecutingCli(false);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-300 font-sans selection:bg-emerald-500/30 flex flex-col">
      <header className="border-b border-zinc-800 bg-zinc-900/50 backdrop-blur-sm sticky top-0 z-10 shrink-0">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
          <Shield
  className={`w-6 h-6 transition-colors cursor-pointer ${isDevMode ? 'text-purple-500' : 'text-emerald-500'}`}
  onClick={handleShieldClick}
/>
            <h1 className="font-mono text-lg font-medium text-zinc-100 tracking-tight">CompTIA Sentinel</h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider bg-zinc-800 text-zinc-400 border border-zinc-700 hidden sm:inline-block">
              v2.1.0-RT
            </span>
          </div>
          <div className="flex items-center gap-3 text-xs font-mono text-zinc-500">
            <div className="hidden md:flex items-center gap-1.5"><Server className="w-3.5 h-3.5" /><span>SY0-701</span></div>
            <div className="hidden md:flex items-center gap-1.5"><Lock className="w-3.5 h-3.5" /><span>CV0-003</span></div>
            <div className="hidden md:flex items-center gap-1.5 text-emerald-500/80 border-l border-zinc-700 pl-3">
              <ShieldAlert className="w-3.5 h-3.5" /><span>Anomaly Detection Active</span>
            </div>
            <button
              onClick={() => setRightView(v => v === 'history' ? 'report' : 'history')}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded border font-mono text-[10px] uppercase tracking-wider transition-colors ${rightView === 'history' ? 'bg-zinc-700 border-zinc-600 text-zinc-200' : 'bg-zinc-900 border-zinc-700 text-zinc-500 hover:text-zinc-300'}`}
            >
              <History className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">History</span>
              {history.length > 0 && <span className="bg-emerald-500/20 text-emerald-400 px-1 rounded text-[9px]">{history.length}</span>}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1 h-full min-h-0">
        <div className="flex flex-col gap-4 h-full min-h-[400px]">
          {isDevMode && (
            <div className="bg-purple-900/20 border border-purple-500/30 rounded-lg p-4 mb-2">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-purple-400 font-mono text-xs uppercase tracking-widest font-bold flex items-center gap-2">
                  <Terminal className="w-4 h-4" />Corporate Dev Mode Unlocked
                </h3>
                <button onClick={() => setIsDevMode(false)} className="text-zinc-500 hover:text-zinc-300 text-xs font-mono">[CLOSE]</button>
              </div>
              <p className="text-zinc-400 text-xs mb-3">AI logic is secured on the backend — prompt exposure prevented.</p>
              <div className="flex gap-2">
                <button onClick={() => setInputCode(p => p + '\n// [DEV-INJECT]: Bypass standard validation check\n')}
                  className="px-3 py-1.5 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded font-mono text-xs transition-colors">
                  Inject Test Payload
                </button>
                <button onClick={() => console.log("Audit State:", auditResult)}
                  className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 rounded font-mono text-xs transition-colors">
                  Dump State to Console
                </button>
              </div>
            </div>
          )}

          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-1 bg-zinc-900/50 p-1 rounded-lg border border-zinc-800">
              <button onClick={() => setActiveTab('payload')}
                className={`flex items-center gap-2 px-3 py-1.5 text-xs font-mono uppercase tracking-widest rounded transition-colors ${activeTab === 'payload' ? 'bg-zinc-800 text-zinc-200 shadow-sm' : 'text-zinc-500 hover:text-zinc-300'}`}>
                <Code className="w-4 h-4" />Target Payload
              </button>
              <button onClick={() => setActiveTab('cli')}
                className={`flex items-center gap-2 px-3 py-1.5 text-xs font-mono uppercase tracking-widest rounded transition-colors ${activeTab === 'cli' ? 'bg-zinc-800 text-zinc-200 shadow-sm' : 'text-zinc-500 hover:text-zinc-300'}`}>
                <Terminal className="w-4 h-4" />CLI / Scripts
              </button>
            </div>
            {activeTab === 'payload' && (
              <div className="flex items-center gap-2">
                <input type="file" multiple className="hidden" ref={fileInputRef} onChange={handleFileUpload} />
                <button onClick={() => fileInputRef.current?.click()}
                  className="flex items-center gap-2 px-3 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-mono text-xs uppercase tracking-wider font-semibold rounded transition-colors border border-zinc-700">
                  <Upload className="w-4 h-4" /><span className="hidden sm:inline-block">Upload Files</span>
                </button>
                <button onClick={runAudit} disabled={isAuditing || !inputCode.trim()}
                  className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-400 disabled:bg-zinc-800 disabled:text-zinc-500 text-zinc-950 font-mono text-xs uppercase tracking-wider font-semibold rounded transition-colors">
                  {isAuditing ? <><Loader2 className="w-4 h-4 animate-spin" />Scanning...</> : <><ShieldAlert className="w-4 h-4" />Run Audit</>}
                </button>
              </div>
            )}
          </div>

          {activeTab === 'payload' ? (
            <div className="flex-1 relative rounded-lg border border-zinc-800 bg-zinc-900/50 overflow-hidden focus-within:border-emerald-500/50 transition-colors">
              <textarea value={inputCode} onChange={(e) => setInputCode(e.target.value)}
                placeholder="Paste source code, IaC (Terraform/Bicep), configuration files, or logs here..."
                className="w-full h-full p-4 bg-transparent text-zinc-300 font-mono text-sm resize-none focus:outline-none" spellCheck={false} />
            </div>
          ) : (
            <div className="flex-1 flex flex-col gap-3">
              <div className="flex flex-wrap gap-1.5">
                {PRESET_COMMANDS.map(({ label, cmd }) => (
                  <button key={cmd} onClick={() => setCliCommand(cmd)}
                    className="px-2.5 py-1 text-[10px] font-mono uppercase tracking-wider bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 border border-zinc-700 rounded transition-colors">
                    {label}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-2">
                <div className="flex-1 relative rounded-lg border border-zinc-800 bg-zinc-900/50 overflow-hidden focus-within:border-emerald-500/50 transition-colors flex items-center px-3">
                  <ChevronRight className="w-4 h-4 text-emerald-500 shrink-0" />
                  <input type="text" value={cliCommand} onChange={(e) => setCliCommand(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && runCliCommand()}
                    placeholder="Select a preset or type an allowed command..."
                    className="w-full py-3 px-2 bg-transparent text-zinc-300 font-mono text-sm focus:outline-none" spellCheck={false} />
                </div>
                <button onClick={runCliCommand} disabled={isExecutingCli || !cliCommand.trim()}
                  className="flex items-center gap-2 px-4 py-3 bg-emerald-500 hover:bg-emerald-400 disabled:bg-zinc-800 disabled:text-zinc-500 text-zinc-950 font-mono text-xs uppercase tracking-wider font-semibold rounded transition-colors shrink-0">
                  {isExecutingCli ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}Execute
                </button>
              </div>
              <div className="flex-1 rounded-lg border border-zinc-800 bg-black overflow-hidden flex flex-col">
                <div className="px-4 py-2 border-b border-zinc-800 bg-zinc-900/50 flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">Terminal Output</span>
                  {cliOutput && (
                    <button onClick={() => { setInputCode(p => p ? p + '\n\n' + `STDOUT:\n${cliOutput.stdout}` : `STDOUT:\n${cliOutput.stdout}`); setActiveTab('payload'); }}
                      className="text-[10px] font-mono uppercase tracking-widest text-emerald-500 hover:text-emerald-400 transition-colors">
                      Send to Payload
                    </button>
                  )}
                </div>
                <div className="flex-1 p-4 overflow-y-auto font-mono text-xs whitespace-pre-wrap">
                  {!cliOutput && !isExecutingCli && <span className="text-zinc-600">Ready for command execution...</span>}
                  {isExecutingCli && <span className="text-emerald-500/70 animate-pulse">Executing command...</span>}
                  {cliOutput && (
                    <div className="flex flex-col gap-4">
                      {cliOutput.stdout && <div><span className="text-zinc-500 select-none">stdout &gt;</span><div className="text-zinc-300 mt-1">{cliOutput.stdout}</div></div>}
                      {cliOutput.stderr && <div><span className="text-amber-500/70 select-none">stderr &gt;</span><div className="text-amber-400 mt-1">{cliOutput.stderr}</div></div>}
                      {cliOutput.error && <div><span className="text-red-500/70 select-none">error &gt;</span><div className="text-red-400 mt-1">{cliOutput.error}</div></div>}
                      {!cliOutput.stdout && !cliOutput.stderr && !cliOutput.error && <span className="text-zinc-500 italic">Command executed with no output.</span>}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="flex flex-col gap-4 h-full min-h-[400px] lg:overflow-hidden">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <h2 className="text-xs font-mono uppercase tracking-widest text-zinc-400 flex items-center gap-2">
              {rightView === 'history' ? <><History className="w-4 h-4" />Audit History</> : <><ShieldAlert className="w-4 h-4" />Audit Report</>}
            </h2>
            <div className="flex items-center gap-2">
              {rightView === 'history' && history.length > 0 && (
                <button onClick={clearHistory} className="flex items-center gap-1.5 px-3 py-2 bg-zinc-800 hover:bg-red-900/30 text-zinc-400 hover:text-red-400 font-mono text-xs rounded border border-zinc-700 hover:border-red-500/30 transition-colors">
                  <X className="w-3.5 h-3.5" />Clear
                </button>
              )}
              {rightView === 'report' && auditResult && (
                <button onClick={() => exportReport(auditResult)} className="flex items-center gap-2 px-3 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-mono text-xs uppercase tracking-wider font-semibold rounded transition-colors border border-zinc-700">
                  <Download className="w-4 h-4" /><span className="hidden sm:inline-block">Export Sheet</span>
                </button>
              )}
            </div>
          </div>

          <div className="flex-1 rounded-lg border border-zinc-800 bg-zinc-900/50 overflow-y-auto p-4 flex flex-col gap-6">
            {rightView === 'history' && (
              history.length === 0 ? (
                <div className="flex-1 flex flex-col items-center justify-center text-zinc-600 gap-3 min-h-[200px]">
                  <History className="w-10 h-10 opacity-20" />
                  <p className="font-mono text-sm">No audits yet. Run your first scan.</p>
                </div>
              ) : (
                <div className="flex flex-col gap-2">
                  {history.map((entry) => (
                    <button key={entry.id} onClick={() => loadFromHistory(entry)}
                      className="text-left p-3 rounded-lg border border-zinc-800 hover:border-zinc-600 bg-zinc-950 hover:bg-zinc-900 transition-colors">
                      <div className="flex items-start justify-between gap-3 mb-1">
                        <span className={`text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${entry.isSecure ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' : 'text-amber-400 bg-amber-500/10 border-amber-500/20'}`}>
                          {entry.isSecure ? 'Secure' : `${entry.findingCount} finding${entry.findingCount !== 1 ? 's' : ''}`}
                        </span>
                        <span className="text-[10px] font-mono text-zinc-600 flex items-center gap-1">
                          <Clock className="w-3 h-3" />{new Date(entry.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <p className="text-xs text-zinc-400 font-mono truncate">{entry.inputSummary}</p>
                      <p className="text-[10px] text-zinc-600 font-mono mt-1">{entry.complianceStatus}</p>
                    </button>
                  ))}
                </div>
              )
            )}

            {rightView === 'report' && (
              <>
                {!auditResult && !isAuditing && !error && (
                  <div className="flex-1 flex flex-col items-center justify-center text-zinc-600 gap-3 min-h-[200px]">
                    <Shield className="w-12 h-12 opacity-20" />
                    <p className="font-mono text-sm text-center px-4">System idle. Awaiting payload for analysis.</p>
                  </div>
                )}
                {isAuditing && (
                  <div className="flex-1 flex flex-col items-center justify-center text-emerald-500/70 gap-4 min-h-[200px]">
                    <Loader2 className="w-10 h-10 animate-spin" />
                    <div className="font-mono text-xs uppercase tracking-widest animate-pulse text-center">Analyzing against CompTIA standards...</div>
                  </div>
                )}
                {error && (
                  <div className="p-4 rounded border border-red-500/20 bg-red-500/10 text-red-400 font-mono text-sm flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
                    <div><div className="font-semibold mb-1">Audit Failure</div>{error}</div>
                  </div>
                )}
                {auditResult && (
                  <>
                    {auditResult.isSecure ? (
                      <div className="p-4 rounded border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 font-mono text-sm flex items-center gap-3">
                        <ShieldCheck className="w-5 h-5 shrink-0" />
                        <span>Scan complete: No violations detected.</span>
                      </div>
                    ) : (
                      <div className="p-4 rounded border border-amber-500/20 bg-amber-500/10 text-amber-400 font-mono text-sm flex items-center gap-3">
                        <AlertTriangle className="w-5 h-5 shrink-0" />
                        <span>Scan complete: Vulnerabilities detected. Immediate remediation required.</span>
                      </div>
                    )}
                    {auditResult.findings.length > 0 && (
                      <div className="flex flex-col gap-4">
                        {auditResult.findings.map((finding, idx) => {
                          const isCritical = finding.severity.toLowerCase().includes('critical');
                          const isHigh = finding.severity.toLowerCase().includes('high');
                          const isMedium = finding.severity.toLowerCase().includes('medium');
                          const severityColor = isCritical ? 'text-red-400 bg-red-500/10 border-red-500/20' :
                            isHigh ? 'text-orange-400 bg-orange-500/10 border-orange-500/20' :
                            isMedium ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' :
                            'text-blue-400 bg-blue-500/10 border-blue-500/20';
                          const highlightColor = isCritical || isHigh ? 'border-red-500/30 bg-red-500/5 text-red-300' : 'border-amber-500/30 bg-amber-500/5 text-amber-300';
                          return (
                            <div key={idx} className="rounded-lg border border-zinc-800 bg-zinc-950 overflow-hidden flex flex-col">
                              <div className="p-4 border-b border-zinc-800/50 bg-zinc-900/30 flex flex-wrap items-start justify-between gap-3">
                                <div className="flex-1 min-w-[200px]">
                                  <h3 className="text-sm font-semibold text-zinc-200 mb-1">{finding.finding}</h3>
                                  <div className="font-mono text-[10px] text-zinc-500 uppercase tracking-wider">{finding.domain}</div>
                                </div>
                                <span className={`inline-flex items-center px-2 py-1 rounded text-[10px] font-mono uppercase tracking-wider border ${severityColor}`}>{finding.severity}</span>
                              </div>
                              <div className="p-4 flex flex-col gap-4">
                                {finding.affectedCode && (
                                  <div className="flex flex-col gap-1.5">
                                    <div className="text-xs font-mono uppercase tracking-wider text-zinc-500 flex items-center gap-1.5">
                                      <Code className="w-3.5 h-3.5" />Highlighted Problem Area
                                    </div>
                                    <pre className={`p-3 rounded border font-mono text-xs overflow-x-auto ${highlightColor}`}><code>{finding.affectedCode}</code></pre>
                                  </div>
                                )}
                                <div className="text-sm text-zinc-300">
                                  <strong className="text-zinc-400 font-mono text-xs uppercase tracking-wider block mb-1">Remediation:</strong>
                                  {finding.remediation}
                                </div>
                                {finding.detailedSteps && finding.detailedSteps.length > 0 && (
                                  <div className="mt-2 p-4 rounded bg-zinc-900 border border-zinc-800">
                                    <h4 className="text-xs font-mono uppercase tracking-wider text-emerald-500 flex items-center gap-2 mb-3">
                                      <FileText className="w-4 h-4" />Step-by-Step Remediation Sheet
                                    </h4>
                                    <ol className="space-y-2">
                                      {finding.detailedSteps.map((step, i) => (
                                        <li key={i} className="text-sm text-zinc-300 flex items-start gap-2">
                                          <span className="text-emerald-500/50 font-mono text-xs mt-0.5">{i + 1}.</span>
                                          <span className="flex-1">{step}</span>
                                        </li>
                                      ))}
                                    </ol>
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                    {auditResult.seniorDeveloperTips && auditResult.seniorDeveloperTips.length > 0 && (
                      <div className="mt-4 border-t border-zinc-800 pt-6">
                        <h3 className="text-xs font-mono uppercase tracking-widest text-purple-400 mb-4 flex items-center gap-2">
                          <Terminal className="w-4 h-4" />Senior Developer Tips & Tricks
                        </h3>
                        <div className="p-4 rounded-lg bg-purple-900/10 border border-purple-500/20">
                          <ul className="space-y-3">
                            {auditResult.seniorDeveloperTips.map((tip, idx) => (
                              <li key={idx} className="text-sm text-zinc-300 flex items-start gap-3">
                                <span className="text-purple-500 mt-0.5">💡</span>
                                <span className="flex-1 leading-relaxed">{tip}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}
                    <div className="mt-4 border-t border-zinc-800 pt-6">
                      <h3 className="text-xs font-mono uppercase tracking-widest text-zinc-400 mb-4 flex items-center gap-2">
                        <CheckCircle className="w-4 h-4" />Management Workflow Output
                      </h3>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div className="p-3 rounded bg-zinc-950 border border-zinc-800/50">
                          <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-1">1. Compliance Status</div>
                          <div className="font-mono text-sm text-zinc-200">{auditResult.managementSummary.complianceStatus}</div>
                        </div>
                        <div className="p-3 rounded bg-zinc-950 border border-zinc-800/50">
                          <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-1">2. Legal Jurisdiction</div>
                          <div className="font-mono text-sm text-zinc-200">{auditResult.managementSummary.legalJurisdiction}</div>
                        </div>
                        <div className="p-3 rounded bg-zinc-950 border border-zinc-800/50">
                          <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-1">3. Executive Action Required</div>
                          <div className="font-mono text-sm text-zinc-200">{auditResult.managementSummary.executiveActionRequired}</div>
                        </div>
                        <div className="p-3 rounded bg-zinc-950 border border-zinc-800/50">
                          <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-1">4. Audit Trail ID</div>
                          <div className="font-mono text-xs text-emerald-500/70">{auditResult.managementSummary.auditTrailId}</div>
                        </div>
                      </div>
                    </div>
                  </>
                )}
              </>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
