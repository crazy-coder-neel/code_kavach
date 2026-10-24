import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldX,
  Copy,
  Check,
  ChevronRight,
  Terminal,
  Activity,
  RefreshCw,
  Trash2,
  Lock,
} from 'lucide-react';
import { GuardResponse, ThreatCategory } from '../../types/guard';
import { THREAT_TAXONOMY } from '../../lib/constants/taxonomy';
import { ScoreExplanation } from './ScoreExplanation';

interface AnalysisPanelProps {
  response: GuardResponse | null;
  isLoading: boolean;
  onSelectLine: (lineNumber: number) => void;
  onRescan: () => void;
  onClear: () => void;
}

export const AnalysisPanel: React.FC<AnalysisPanelProps> = ({
  response,
  isLoading,
  onSelectLine,
  onRescan,
  onClear,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'flow' | 'technical' | 'scoring' | 'pipeline'>('overview');
  const [copiedSummary, setCopiedSummary] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);

  if (isLoading) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-8 bg-[var(--surface)] border border-[var(--border)] rounded-xl text-center">
        <div className="w-7 h-7 border-2 border-[var(--primary)] border-t-transparent rounded-full animate-spin mb-3" />
        <h4 className="text-sm font-semibold text-[var(--text-primary)]">Evaluating Code Semantics</h4>
        <p className="text-xs text-[var(--text-secondary)] mt-1 text-center max-w-xs font-mono">
          Scanning AST signatures, credential accesses, and outbound network sinks...
        </p>
      </div>
    );
  }

  if (!response) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-8 bg-[var(--surface)] border border-[var(--border)] rounded-xl text-center">
        <div className="w-10 h-10 rounded-full bg-[var(--surface-secondary)] flex items-center justify-center mb-3 text-[var(--text-muted)]">
          <Activity className="w-5 h-5" />
        </div>
        <h4 className="text-sm font-semibold text-[var(--text-primary)]">Security Analysis Awaiting Input</h4>
        <p className="text-xs text-[var(--text-secondary)] mt-1 max-w-sm leading-relaxed">
          Select a sample snippet or paste code into the editor, then click <strong className="text-[var(--text-primary)]">Analyze code</strong> to inspect pre-execution safety.
        </p>
      </div>
    );
  }

  const isBlocked = response.verdict === 'BLOCK';
  const findings = response.findings || [];
  const flows = response.source_sink_flows || [];

  const handleCopySummary = () => {
    const text = `code_kavach Verdict: ${response.verdict}\nRisk Score: ${response.risk_score} (0-1 scale)\nCategories: ${response.categories.join(', ') || 'None'}\nReason: ${response.reason}\nVulnerable Lines: ${response.vulnerable_lines.join(', ') || 'None'}\nScan ID: ${response.scan_id}`;
    navigator.clipboard.writeText(text);
    setCopiedSummary(true);
    setTimeout(() => setCopiedSummary(false), 2000);
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(response, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  return (
    <div className="h-full flex flex-col bg-[var(--surface)] border border-[var(--border)] rounded-xl overflow-hidden shadow-xs">
      {/* Verdict Header - White dominant with restrained semantic pill indicator */}
      <div className="p-4 bg-[var(--surface)] border-b border-[var(--border)]">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className="pt-0.5">
              {isBlocked ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-[var(--block-background)] text-[var(--block)] border border-[var(--block-background)]">
                  <ShieldX className="w-3.5 h-3.5" />
                  <span>BLOCK</span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-[var(--allow-background)] text-[var(--allow)] border border-[var(--allow-background)]">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>ALLOW</span>
                </span>
              )}
            </div>

            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-semibold text-[var(--text-primary)] uppercase">
                  {response.code_language}
                </span>
                <span className="text-[10px] text-[var(--text-muted)] font-mono">·</span>
                {response.metadata?.is_mock && (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--surface-secondary)] text-[var(--text-secondary)] border border-[var(--border)]">
                    Deterministic Engine
                  </span>
                )}
              </div>
              <p className="text-xs text-[var(--text-primary)] font-medium mt-1 leading-snug">
                {response.reason}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1 shrink-0">
            <button
              onClick={handleCopySummary}
              className="p-1.5 rounded-md hover:bg-[var(--surface-secondary)] text-[var(--text-secondary)] transition-colors"
              title="Copy verdict summary"
              aria-label="Copy verdict summary"
            >
              {copiedSummary ? <Check className="w-4 h-4 text-[var(--allow)]" /> : <Copy className="w-4 h-4" />}
            </button>
            <button
              onClick={onRescan}
              className="p-1.5 rounded-md hover:bg-[var(--surface-secondary)] text-[var(--text-secondary)] transition-colors"
              title="Rescan current snippet"
              aria-label="Rescan current snippet"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={onClear}
              className="p-1.5 rounded-md hover:bg-[var(--surface-secondary)] text-[var(--text-secondary)] transition-colors"
              title="Clear analysis result"
              aria-label="Clear analysis result"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Risk Score Gauge */}
        <div className="mt-3 pt-3 border-t border-[var(--border)] flex items-center justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center justify-between text-xs font-mono mb-1">
              <span className="text-[var(--text-secondary)]">Calculated Risk Score</span>
              <span className="font-bold text-[var(--text-primary)] tabular-nums">
                {response.risk_score.toFixed(2)} / 1.00
              </span>
            </div>
            {/* Minimal meter bar */}
            <div className="w-full h-1.5 bg-[var(--border-strong)] rounded-full overflow-hidden flex">
              <div
                className={`h-full transition-all duration-300 rounded-full ${
                  response.risk_score >= 0.7
                    ? 'bg-[var(--block)]'
                    : response.risk_score >= 0.4
                    ? 'bg-[var(--critical)]'
                    : 'bg-[var(--allow)]'
                }`}
                style={{ width: `${Math.max(4, Math.round(response.risk_score * 100))}%` }}
              />
            </div>
          </div>

          <div className="text-right text-xs font-mono text-[var(--text-secondary)] shrink-0">
            <div>{response.metadata?.duration_ms} ms</div>
            <div className="text-[10px] text-[var(--text-muted)]">{response.scan_id.slice(0, 14)}</div>
          </div>
        </div>
      </div>

      {/* Tabs Bar - Clean White Surface */}
      <div className="flex flex-wrap items-center px-3 border-b border-[var(--border)] bg-[var(--surface)] text-xs font-medium">
        <button onClick={() => setActiveTab('scoring')} aria-pressed={activeTab === 'scoring'}
          className={`py-2 px-3 border-b-2 ${activeTab === 'scoring' ? 'border-[var(--primary)] font-semibold' : 'border-transparent'}`}>
          Score &amp; reasoning
        </button>
        <button
          onClick={() => setActiveTab('overview')}
          className={`py-2 px-3 border-b-2 transition-colors ${
            activeTab === 'overview'
              ? 'border-[var(--primary)] text-[var(--text-primary)] font-semibold'
              : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
          }`}
        >
          Overview
        </button>
        <button
          onClick={() => setActiveTab('findings')}
          className={`py-2 px-3 border-b-2 flex items-center gap-1.5 transition-colors ${
            activeTab === 'findings'
              ? 'border-[var(--primary)] text-[var(--text-primary)] font-semibold'
              : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
          }`}
        >
          <span>Findings</span>
          {findings.length > 0 && (
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[var(--block)] text-[var(--primary-foreground)]">
              {findings.length}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab('flow')}
          className={`py-2 px-3 border-b-2 flex items-center gap-1.5 transition-colors ${
            activeTab === 'flow'
              ? 'border-[var(--primary)] text-[var(--text-primary)] font-semibold'
              : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
          }`}
        >
          <span>Code Flow</span>
          {flows.length > 0 && (
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[var(--primary)] text-[var(--primary-foreground)]">
              {flows.length}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab('pipeline')}
          className={`py-2 px-3 border-b-2 flex items-center gap-1.5 transition-colors ${
            activeTab === 'pipeline'
              ? 'border-[var(--primary)] text-[var(--text-primary)] font-semibold'
              : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
          }`}
        >
          <span>Pipeline Trace</span>
          {response.runtime_trace && (
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[var(--surface-secondary)] text-[var(--text-secondary)] border border-[var(--border)]">
              {response.runtime_trace.length}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab('technical')}
          className={`py-2 px-3 border-b-2 transition-colors ${
            activeTab === 'technical'
              ? 'border-[var(--primary)] text-[var(--text-primary)] font-semibold'
              : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
          }`}
        >
          Technical Details
        </button>
      </div>

      {/* Tab Panels Body - White dominant */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-[var(--surface)]">
        {activeTab === 'scoring' && <ScoreExplanation response={response} onSelectLine={onSelectLine} />}
        {activeTab === 'overview' && (
          <div className="space-y-4">
            {/* Threat Categories Detected */}
            <div>
              <h5 className="text-xs font-mono uppercase text-[var(--text-muted)] mb-2">
                Identified Threat Taxonomy ({response.categories.length})
              </h5>
              {response.categories.length > 0 ? (
                <div className="space-y-2">
                  {response.categories.map((catId) => {
                    const meta = THREAT_TAXONOMY[catId as ThreatCategory];
                    return (
                      <div
                        key={catId}
                        className="p-3 rounded-lg bg-[var(--surface-card)] border border-[var(--border)] text-xs hover:border-[var(--border-strong)] transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-[var(--text-primary)]">
                            {meta ? meta.name : catId}
                          </span>
                          <span className="font-mono text-[11px] font-semibold text-[var(--block)]">
                            {meta?.severity || 'HIGH'}
                          </span>
                        </div>
                        <p className="text-[11px] text-[var(--text-secondary)] mt-1 leading-relaxed">
                          {meta?.description || 'Threat indicator triggered by static analysis.'}
                        </p>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-xs text-[var(--text-secondary)]">
                  No threat categories flagged. The snippet complies with baseline pre-execution safety rules.
                </div>
              )}
            </div>

            {/* Affected Line Markers */}
            {response.vulnerable_lines.length > 0 && (
              <div>
                <h5 className="text-xs font-mono uppercase text-[var(--text-muted)] mb-1.5">
                  Vulnerable Source Locations
                </h5>
                <div className="flex flex-wrap gap-1.5">
                  {response.vulnerable_lines.map((line) => (
                    <button
                      key={line}
                      onClick={() => onSelectLine(line)}
                      className="px-2.5 py-1 rounded-md bg-[var(--block-background)] hover:opacity-90 text-[var(--block)] border border-[var(--block-background)] text-xs font-mono flex items-center gap-1 transition-colors font-medium"
                      title={`Jump to line ${line} in editor`}
                    >
                      <Terminal className="w-3 h-3" />
                      <span>Line {line}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Pre-Execution Interception UX Notice */}
            <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-xs space-y-1">
              <div className="font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-[var(--text-primary)]" />
                <span>Pre-Execution Interception Status</span>
              </div>
              <p className="text-[var(--text-secondary)] leading-relaxed">
                {isBlocked
                  ? 'Kavach Interceptor has quarantined this snippet. Execution in host environment is strictly prevented.'
                  : 'Pre-execution safety checks passed. Note: Code was inspected statically; runtime sandbox execution is not automatically triggered in preview.'}
              </p>
            </div>
          </div>
        )}

        {activeTab === 'findings' && (
          <div className="space-y-3">
            {findings.length > 0 ? (
              findings.map((f) => (
                <div
                  key={f.id}
                  className="p-3.5 rounded-lg bg-[var(--surface-card)] border border-[var(--border)] space-y-2 text-xs"
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="font-semibold text-[var(--text-primary)]">
                      {f.title}
                    </span>
                    <button
                      onClick={() => onSelectLine(f.line_number)}
                      className="font-mono text-[11px] text-[var(--text-primary)] hover:underline flex items-center gap-0.5 shrink-0 font-medium"
                    >
                      Line {f.line_number}
                      <ChevronRight className="w-3 h-3" />
                    </button>
                  </div>

                  <div className="font-mono text-[11px] p-2 rounded-md bg-[#171B19] dark:bg-[var(--surface)] text-[#D8DFD7] dark:text-[var(--text-primary)] overflow-x-auto">
                    {f.snippet || 'Pattern matched by rule'}
                  </div>

                  <div className="space-y-1 text-[var(--text-secondary)]">
                    <div>
                      <strong className="text-[var(--text-primary)]">Evidence: </strong>
                      {f.evidence}
                    </div>
                    <div>
                      <strong className="text-[var(--text-primary)]">Remediation: </strong>
                      {f.remediation}
                      {f.fix && <details className="mt-2">
                        <summary className="cursor-pointer font-semibold">{f.fix.title}</summary>
                        <ol className="list-decimal pl-5 mt-2">{f.fix.steps.map(step => <li key={step}>{step}</li>)}</ol>
                        {f.fix.example && <pre className="overflow-auto p-2 mt-2 bg-[var(--surface-secondary)]">{f.fix.example}</pre>}
                        <p className="mt-2">{f.fix.caveat}</p>
                      </details>}
                    </div>
                  </div>

                  <div className="pt-2 border-t border-[var(--border)] flex items-center justify-between text-[10px] font-mono text-[var(--text-muted)]">
                    <span>Rule: {f.rule_id}</span>
                    <span className="uppercase font-semibold text-[var(--block)]">{f.severity}</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="p-6 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-xs text-[var(--text-secondary)] text-center">
                No specific vulnerability findings registered for this scan.
              </div>
            )}
          </div>
        )}

        {activeTab === 'flow' && (
          <div className="space-y-3">
            <h5 className="text-xs font-mono uppercase text-[var(--text-muted)]">
              Source-to-Sink Data Flow Trace
            </h5>
            {flows.length > 0 ? (
              flows.map((flow) => (
                <div
                  key={flow.id}
                  className="p-3.5 rounded-lg bg-[var(--surface-card)] border border-[var(--border)] space-y-3 text-xs"
                >
                  {/* Source */}
                  <div className="flex items-start gap-2.5">
                    <span className="px-1.5 py-0.5 rounded bg-[var(--block)] text-[var(--primary-foreground)] font-mono text-[10px] font-bold shrink-0">
                      SOURCE
                    </span>
                    <div className="flex-1">
                      <div className="font-medium text-[var(--text-primary)]">
                        {flow.source.description}
                      </div>
                      <div className="font-mono text-[11px] text-[var(--text-secondary)] mt-0.5">
                        Line {flow.source.line}: <code>{flow.source.code}</code>
                      </div>
                    </div>
                  </div>

                  {/* Transform (if present) */}
                  {flow.transform && (
                    <div className="flex items-start gap-2.5 pl-4 border-l border-dashed border-[var(--border)]">
                      <span className="px-1.5 py-0.5 rounded bg-[var(--critical)] text-[var(--primary-foreground)] font-mono text-[10px] font-bold shrink-0">
                        TRANSFORM
                      </span>
                      <div className="flex-1">
                        <div className="font-medium text-[var(--text-primary)]">
                          {flow.transform.description}
                        </div>
                        <div className="font-mono text-[11px] text-[var(--text-secondary)] mt-0.5">
                          Line {flow.transform.line}: <code>{flow.transform.code}</code>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Sink */}
                  <div className="flex items-start gap-2.5">
                    <span className="px-1.5 py-0.5 rounded bg-[var(--allow)] text-[var(--primary-foreground)] font-mono text-[10px] font-bold shrink-0">
                      SINK
                    </span>
                    <div className="flex-1">
                      <div className="font-medium text-[var(--text-primary)]">
                        {flow.sink.description}
                      </div>
                      <div className="font-mono text-[11px] text-[var(--text-secondary)] mt-0.5">
                        Line {flow.sink.line}: <code>{flow.sink.code}</code>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="p-6 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-xs text-[var(--text-secondary)] text-center">
                No active source-to-sink data leaks identified in the current AST scope.
              </div>
            )}
          </div>
        )}

        {activeTab === 'pipeline' && (
          <div className="space-y-3">
            <div className="p-3 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-xs">
              <div className="font-semibold text-[var(--text-primary)] mb-1 flex items-center justify-between">
                <span>Deterministic 17-Step CPU Execution Pipeline</span>
                <span className="font-mono text-[11px] text-[var(--text-muted)]">
                  {response.runtime_trace ? `${response.runtime_trace.filter(s => !s.skipped).length}/17 Executed` : '17 Steps'}
                </span>
              </div>
              <p className="text-[var(--text-secondary)] text-[11px] leading-relaxed">
                Every request traverses an ordered sequence of structural, taint, pattern, and ML filters under a strict 25ms server deadline. Zero external LLM calls.
              </p>
            </div>

            {response.runtime_trace && response.runtime_trace.length > 0 ? (
              <div className="space-y-2">
                {response.runtime_trace.map((step, idx) => (
                  <div
                    key={step.step_name}
                    className={`p-3 rounded-lg border text-xs transition-colors ${
                      step.skipped
                        ? 'bg-[var(--surface-secondary)]/50 border-[var(--border)] opacity-60'
                        : 'bg-[var(--surface-card)] border-[var(--border)] hover:border-[var(--border-strong)]'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-secondary)]">
                          {(idx + 1).toString().padStart(2, '0')}
                        </span>
                        <span className="font-semibold text-[var(--text-primary)] font-mono">
                          {step.step_name}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {step.skipped ? (
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 font-medium">
                            SKIPPED
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono font-medium text-[var(--text-secondary)]">
                            {step.duration_ms.toFixed(3)} ms
                          </span>
                        )}
                      </div>
                    </div>
                    <p className="text-[11px] text-[var(--text-secondary)] mt-1.5 leading-relaxed">
                      {step.description}
                    </p>
                    {step.skipped && step.skip_reason && (
                      <p className="text-[10px] font-mono text-amber-600 dark:text-amber-400 mt-1 italic">
                        ↳ Reason: {step.skip_reason}
                      </p>
                    )}
                    {Object.keys(step.output).length > 0 && !step.skipped && (
                      <div className="mt-2 pt-2 border-t border-[var(--border)] flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-mono text-[var(--text-muted)]">
                        {Object.entries(step.output).map(([k, v]) => (
                          <span key={k}>
                            <span className="text-[var(--text-secondary)]">{k}:</span> {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-6 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-xs text-[var(--text-secondary)] text-center font-mono">
                Pipeline execution trace available via detailed scanning mode (?detail=full).
              </div>
            )}
          </div>
        )}

        {activeTab === 'technical' && (
          <div className="space-y-3 text-xs font-mono">
            <div className="flex items-center justify-between pb-1">
              <span className="text-[var(--text-secondary)]">API Response Payload</span>
              <button
                onClick={handleCopyJson}
                className="flex items-center gap-1 text-[11px] text-[var(--text-primary)] hover:underline font-semibold"
              >
                {copiedJson ? <Check className="w-3 h-3 text-[var(--allow)]" /> : <Copy className="w-3 h-3" />}
                <span>{copiedJson ? 'Copied' : 'Copy JSON'}</span>
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div className="p-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
                <div className="text-[var(--text-muted)]">Detector Version</div>
                <div className="font-semibold text-[var(--text-primary)] mt-0.5">
                  {response.metadata?.detector_version || 'unknown'}
                </div>
              </div>
              <div className="p-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
                <div className="text-[var(--text-muted)]">Parser Status</div>
                <div className="font-semibold text-[var(--text-primary)] mt-0.5">
                  {response.metadata?.parser_status || 'SUCCESS'}
                </div>
              </div>
            </div>

            <pre className="p-3.5 rounded-lg bg-[#171B19] dark:bg-[var(--surface)] text-[#D8DFD7] dark:text-[var(--text-primary)] text-[11px] overflow-x-auto leading-relaxed border border-[#272D29] dark:border-[var(--border)]">
              {JSON.stringify(response, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
