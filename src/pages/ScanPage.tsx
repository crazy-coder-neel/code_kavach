import React, { useState, useRef, useEffect } from 'react';
import {
  Play,
  RotateCcw,
  Shield,
  AlertCircle,
  Lock,
} from 'lucide-react';
import { CodeEditor, CodeEditorRef } from '../components/editor/CodeEditor';
import { AnalysisPanel } from '../components/findings/AnalysisPanel';
import { CodeLanguage, GuardResponse } from '../types/guard';
import { SAMPLE_SNIPPETS } from '../lib/constants/taxonomy';
import { scanCode, normalizeGuardResponse } from '../lib/api/guard';
import { apiClient } from '../lib/api/client';
import { saveScanToHistory } from '../lib/storage/history';

export const ScanPage: React.FC = () => {
  const [selectedLanguage, setSelectedLanguage] = useState<CodeLanguage>('python');
  const [code, setCode] = useState<string>(SAMPLE_SNIPPETS[0].code);
  const [selectedSampleId, setSelectedSampleId] = useState<string>(SAMPLE_SNIPPETS[0].id);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [analysisResult, setAnalysisResult] = useState<GuardResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activeHighlightLine, setActiveHighlightLine] = useState<number | null>(null);
  const [interceptSimulationOpen, setInterceptSimulationOpen] = useState(false);
  const [vsCodeSync, setVsCodeSync] = useState(false);
  const lastLiveTimestamp = useRef<string | null>(null);

  const editorRef = useRef<CodeEditorRef>(null);

  const currentInput = useRef({ code, language: selectedLanguage });
  currentInput.current = { code, language: selectedLanguage };
  const scanInFlight = useRef(false);

  useEffect(() => {
    if (!vsCodeSync) return;
    const interval = setInterval(async () => {
      try {
        const res = await apiClient.fetchWithTimeout('/v1/live/latest', { method: 'GET' });
        if (res.ok) {
          const data = await res.json();
          if (data && data.active && data.timestamp !== lastLiveTimestamp.current) {
            lastLiveTimestamp.current = data.timestamp;
            setCode(data.code);
            if (data.result) {
              const normalized = normalizeGuardResponse(data.result);
              setAnalysisResult(normalized);
            }
          }
        }
      } catch {
        // quiet live poll
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [vsCodeSync]);

  useEffect(() => {
    if (vsCodeSync) return;
    setAnalysisResult(null);
    setActiveHighlightLine(null);
  }, [code, selectedLanguage, vsCodeSync]);

  // Handle sample selection
  const handleSelectSample = (sampleId: string) => {
    setSelectedSampleId(sampleId);
    const sample = SAMPLE_SNIPPETS.find((s) => s.id === sampleId);
    if (sample) {
      setCode(sample.code);
      setSelectedLanguage(sample.language);
      setAnalysisResult(null);
      setErrorMsg(null);
      setActiveHighlightLine(null);
    }
  };

  // Run security scan
  const handleRunScan = async () => {
    if (scanInFlight.current) return;
    if (!code.trim()) {
      setErrorMsg('Code input is empty. Please enter or select code to analyze.');
      return;
    }

    scanInFlight.current = true;
    setIsLoading(true);
    setAnalysisResult(null);
    setErrorMsg(null);

    try {
      const response = await scanCode({
        code,
        code_language: selectedLanguage,
      });
      if (currentInput.current.code === code && currentInput.current.language === selectedLanguage) {
        setAnalysisResult(response);
      }
      saveScanToHistory(code, response);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Scan execution failed';
      setErrorMsg(msg);
      setAnalysisResult(null);
    } finally {
      scanInFlight.current = false;
      setIsLoading(false);
    }
  };

  // Keyboard shortcut Cmd/Ctrl + Enter to run scan
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        e.preventDefault();
        handleRunScan();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [code, selectedLanguage]);

  // Handle jumping to specific line in Monaco
  const handleJumpToLine = (lineNumber: number) => {
    setActiveHighlightLine(lineNumber);
    if (editorRef.current) {
      editorRef.current.scrollToLine(lineNumber);
    }
  };

  // Reset editor
  const handleClearCode = () => {
    setCode('');
    setAnalysisResult(null);
    setErrorMsg(null);
    setActiveHighlightLine(null);
  };

  const handleRestoreCurrentSample = () => {
    const sample = SAMPLE_SNIPPETS.find((s) => s.id === selectedSampleId);
    if (sample) {
      setCode(sample.code);
      setSelectedLanguage(sample.language);
      setAnalysisResult(null);
      setErrorMsg(null);
      setActiveHighlightLine(null);
    }
  };

  const lineCount = code ? code.split('\n').length : 0;
  const charCount = code.length;

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-[var(--surface)]">
      {/* Workbench Toolbar - Clean white surface */}
      <div className="px-4 py-2.5 bg-[var(--surface)] border-b border-[var(--border)] flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2 mr-2">
            <h1 className="text-sm font-semibold text-[var(--text-primary)] tracking-tight">
              Code security scanner
            </h1>
            <span className="text-xs text-[var(--text-muted)] font-mono hidden md:inline">
              · {lineCount} {lineCount === 1 ? 'line' : 'lines'} · {charCount} chars
            </span>
          </div>

          {/* Sample Snippet Selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-mono text-[var(--text-secondary)]">Scenario:</span>
            <select
              value={selectedSampleId}
              onChange={(e) => handleSelectSample(e.target.value)}
              className="text-xs font-medium py-1 px-2.5 rounded-md bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)]"
            >
              {SAMPLE_SNIPPETS.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.language})
                </option>
              ))}
            </select>
          </div>

          {/* Language Selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-mono text-[var(--text-secondary)]">Lang:</span>
            <select
              value={selectedLanguage}
              onChange={(e) => setSelectedLanguage(e.target.value as CodeLanguage)}
              className="text-xs font-medium py-1 px-2 rounded-md bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)]"
            >
              <option value="python">Python</option>
              <option value="bash">Bash</option>
              <option value="javascript">JavaScript</option>
              <option value="sql">SQL</option>
              <option value="yaml">YAML</option>
            </select>
          </div>
        </div>

        <label className="text-xs cursor-pointer underline">
          Upload source
          <input type="file" className="sr-only" accept=".py,.js,.ts,.sh,.sql,.yaml,.yml,.md,.txt" onChange={async (event) => {
            const file = event.target.files?.[0];
            event.target.value = '';
            if (!file) return;
            if (file.size > 65536) { setErrorMsg('Source exceeds the 64 KiB limit.'); return; }
            try {
              setCode(await file.text());
              setErrorMsg(null);
            } catch { setErrorMsg('Unable to read the selected file.'); }
          }} />
        </label>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleRestoreCurrentSample}
            className="px-2.5 py-1 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] rounded-md hover:bg-[var(--surface-secondary)] transition-colors flex items-center gap-1 border border-transparent hover:border-[var(--border)]"
            title="Reset to scenario default"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Reset</span>
          </button>

          <button
            onClick={() => setVsCodeSync(!vsCodeSync)}
            className={`px-2.5 py-1 text-xs rounded-md transition-colors flex items-center gap-1.5 border font-medium ${
              vsCodeSync
                ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-secondary)] border-transparent hover:border-[var(--border)]'
            }`}
            title="Mirror code and live scans from VS Code in real-time"
          >
            <span className={`w-2 h-2 rounded-full ${vsCodeSync ? 'bg-emerald-500 animate-pulse' : 'bg-gray-400'}`} />
            <span>VS Code Sync</span>
          </button>

          <button
            onClick={handleClearCode}
            className="px-2.5 py-1 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] rounded-md hover:bg-[var(--surface-secondary)] transition-colors border border-transparent hover:border-[var(--border)]"
          >
            Clear
          </button>

          <button
            onClick={handleRunScan}
            disabled={isLoading || !code.trim()}
            className="px-4 py-1.5 rounded-lg bg-[var(--primary)] hover:bg-[var(--primary-hover)] text-[var(--primary-foreground)] text-xs font-medium transition-colors flex items-center gap-1.5 shadow-xs disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Analyze code</span>
                <kbd className="hidden md:inline ml-1 text-[10px] bg-[var(--surface)]/20 px-1 py-0.2 rounded text-[var(--primary-foreground)]/90">
                  ⌘↵
                </kbd>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error alert banner */}
      {errorMsg && (
        <div className="mx-4 mt-3 p-3 bg-[var(--block-background)] border border-[var(--block-background)] rounded-lg flex items-start gap-2.5 text-xs text-[var(--block)]">
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="flex-1">
            <strong>Scan Error: </strong>
            <span>{errorMsg}</span>
          </div>
          <button
            onClick={() => setErrorMsg(null)}
            className="hover:underline font-mono text-[11px]"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Main Split Grid: Editor (Left/Top) + Analysis Panel (Right/Bottom) */}
      <div className="flex-1 p-4 grid grid-cols-1 lg:grid-cols-12 gap-4 min-h-0 overflow-y-auto bg-[var(--surface)]">
        {/* Editor Area: 7 cols on desktop */}
        <div className="lg:col-span-7 flex flex-col h-[520px] lg:h-full min-h-[400px]">
          <CodeEditor
            ref={editorRef}
            value={code}
            onChange={setCode}
            language={selectedLanguage}
            vulnerableLines={analysisResult?.vulnerable_lines || []}
            activeLine={activeHighlightLine}
            isLoading={isLoading}
          />

          {/* Interception Simulation Trigger */}
          <div className="mt-2.5 p-2.5 rounded-lg bg-[var(--surface)] border border-[var(--border)] flex items-center justify-between text-xs shadow-xs">
            <div className="flex items-center gap-2 text-[var(--text-secondary)]">
              <Lock className="w-3.5 h-3.5 text-[var(--text-primary)]" />
              <span>Interceptor Gate:</span>
              <strong className="text-[var(--text-primary)]">
                {analysisResult
                  ? analysisResult.verdict === 'BLOCK'
                    ? 'Quarantined (Blocked)'
                    : 'Clear to Execute'
                  : 'Pending Analysis'}
              </strong>
            </div>

            <button
              onClick={() => setInterceptSimulationOpen(true)}
              disabled={!analysisResult}
              className="text-xs font-mono text-[var(--text-primary)] hover:underline disabled:opacity-40 disabled:cursor-not-allowed font-medium"
            >
              Inspect Intercept Trail →
            </button>
          </div>
        </div>

        {/* Analysis Results Panel: 5 cols on desktop */}
        <div className="lg:col-span-5 flex flex-col h-[520px] lg:h-full min-h-[400px]">
          <AnalysisPanel
            response={analysisResult}
            isLoading={isLoading}
            onSelectLine={handleJumpToLine}
            onRescan={handleRunScan}
            onClear={() => setAnalysisResult(null)}
          />
        </div>
      </div>

      {/* Execution Interception Modal */}
      {interceptSimulationOpen && (
        <div className="fixed inset-0 bg-black/45 z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[var(--surface-card)] border border-[var(--border)] rounded-xl shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-[var(--text-primary)]" />
                <h3 className="font-semibold text-sm text-[var(--text-primary)]">
                  Pre-Execution Interception Trail
                </h3>
              </div>
              <button
                onClick={() => setInterceptSimulationOpen(false)}
                className="text-xs font-mono text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Close ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2">
                <div className="flex items-center justify-between font-mono">
                  <span className="text-[var(--text-secondary)]">Step 1: Submission</span>
                  <span className="text-[var(--allow)] font-semibold">OK</span>
                </div>
                <div className="flex items-center justify-between font-mono">
                  <span className="text-[var(--text-secondary)]">Step 2: AST Static Analysis</span>
                  <span className="text-[var(--allow)] font-semibold">PASSED ({analysisResult?.metadata?.duration_ms}ms)</span>
                </div>
                <div className="flex items-center justify-between font-mono">
                  <span className="text-[var(--text-secondary)]">Step 3: Kavach Verdict</span>
                  <span
                    className={
                      analysisResult?.verdict === 'BLOCK'
                        ? 'font-bold text-[var(--block)]'
                        : 'font-bold text-[var(--allow)]'
                    }
                  >
                    {analysisResult?.verdict}
                  </span>
                </div>
                <div className="flex items-center justify-between font-mono border-t border-[var(--border)] pt-2">
                  <span className="text-[var(--text-secondary)]">Step 4: Interceptor Action</span>
                  <span className="font-bold text-[var(--text-primary)]">
                    {analysisResult?.verdict === 'BLOCK'
                      ? 'EXECUTION_DENIED_KILL_PROCESS'
                      : 'EXECUTION_PERMITTED'}
                  </span>
                </div>
              </div>

              <div className="text-[var(--text-secondary)] leading-relaxed">
                {analysisResult?.verdict === 'BLOCK' ? (
                  <p>
                    <strong className="text-[var(--block)]">Verdict Enforcement: </strong>
                    The payload contains high-risk patterns ({analysisResult.categories.join(', ')}).
                    Kavach pre-execution hooks prevented this snippet from spawning child processes or touching
                    the operating system environment.
                  </p>
                ) : (
                  <p>
                    <strong className="text-[var(--allow)]">Verified Allow: </strong>
                    No dangerous indicators detected. In a production pipeline, this code would be dispatched
                    to the sandbox runner. The frontend does not execute arbitrary code unsafely in the browser.
                  </p>
                )}
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setInterceptSimulationOpen(false)}
                className="px-4 py-1.5 rounded-lg bg-[var(--primary)] text-[var(--primary-foreground)] text-xs font-medium hover:bg-[var(--primary-hover)] transition-colors"
              >
                Understood
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
