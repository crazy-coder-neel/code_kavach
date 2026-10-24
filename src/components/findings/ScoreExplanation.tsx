import React from 'react';
import { GuardResponse } from '../../types/guard';
import { THREAT_TAXONOMY } from '../../lib/constants/taxonomy';
import { ShieldCheck, ShieldAlert, Cpu, Calculator, CheckCircle2, XCircle } from 'lucide-react';

interface Contributor {
  rule_id: string;
  category: string;
  lines: number[];
  severity: string;
  severity_weight: number;
  confidence: number;
  contribution: number;
}

const ALL_CATEGORIES = [
  'secret_access',
  'data_exfiltration',
  'destructive_command',
  'persistence_or_privesc',
  'obfuscated_execution',
  'dependency_risk',
  'resource_exhaustion',
  'ssrf_network_exfil',
  'ai_targeted_instructions',
] as const;

export function ScoreExplanation({
  response,
  onSelectLine,
}: {
  response: GuardResponse;
  onSelectLine: (line: number) => void;
}) {
  const trace = response.score_trace as Record<string, any> | undefined;
  if (!trace || trace.method !== 'severity-noisy-or-v1') {
    return (
      <div className="p-4 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-xs text-[var(--text-secondary)]">
        This scan result does not contain a live Noisy-OR score trace. Run an active scan to inspect detailed math.
      </div>
    );
  }

  const contributors = (trace.contributors || []) as Contributor[];
  const scores = (trace.category_scores || {}) as Record<string, number>;
  const mlProbs = (trace.ml_category_probs || {}) as Record<string, number>;
  const mlProb = typeof trace.ml_probability === 'number' ? trace.ml_probability : null;
  const number = (key: string) => Number(trace[key] ?? 0).toFixed(4);

  return (
    <section className="space-y-4 text-xs text-[var(--text-primary)]" aria-label="Score calculation and decision evidence">
      {/* Overview Card */}
      <div className="rounded-lg border border-[var(--border)] p-3.5 space-y-2 bg-[var(--surface-card)]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 font-semibold">
            <Calculator className="w-4 h-4 text-[var(--primary)]" />
            <span>Deterministic Severity Noisy-OR Aggregation</span>
          </div>
          <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-secondary)]">
            v1.0 (PRD-compliant)
          </span>
        </div>
        <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
          Risk is a calibrated severity index computed deterministically from verified findings and bounded CPU ML adjustments—never an unverified LLM hallucination.
        </p>
        <div className="p-2 rounded bg-[var(--surface-secondary)] font-mono text-[10px] text-[var(--text-secondary)] overflow-x-auto border border-[var(--border)]">
          {String(trace.formula)}
        </div>
      </div>

      {/* 9 Categories Multi-Signal Matrix */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <h4 className="font-semibold text-xs flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-[var(--primary)]" />
            <span>Complete 9-Category Threat Matrix</span>
          </h4>
          <span className="text-[10px] text-[var(--text-muted)] font-mono">
            Deterministic AST + CPU ML (100% Offline)
          </span>
        </div>

        <div className="border border-[var(--border)] rounded-lg overflow-hidden bg-[var(--surface)]">
          <table className="w-full text-left border-collapse text-[11px]">
            <thead>
              <tr className="bg-[var(--surface-secondary)] text-[var(--text-secondary)] border-b border-[var(--border)]">
                <th className="p-2 font-semibold">Category</th>
                <th className="p-2 font-semibold text-center">AST Score</th>
                <th className="p-2 font-semibold text-center">ML Prob</th>
                <th className="p-2 font-semibold text-right">Verdict State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {ALL_CATEGORIES.map((catKey) => {
                const meta = THREAT_TAXONOMY[catKey];
                const astScore = scores[catKey] ?? 0;
                const mlP = mlProbs[catKey];
                const isFlagged = response.categories.includes(catKey as any);

                return (
                  <tr
                    key={catKey}
                    className={`transition-colors ${
                      isFlagged ? 'bg-[var(--block-background)]/30 font-medium' : 'hover:bg-[var(--surface-secondary)]/40'
                    }`}
                  >
                    <td className="p-2">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[var(--text-primary)]">{meta?.name || catKey}</span>
                        {meta?.cwe && (
                          <span className="font-mono text-[9px] text-[var(--text-muted)] hidden sm:inline">
                            [{meta.cwe}]
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-2 text-center font-mono">
                      {astScore > 0 ? (
                        <span className="text-[var(--block)] font-semibold">{astScore.toFixed(3)}</span>
                      ) : (
                        <span className="text-[var(--text-muted)]">0.000</span>
                      )}
                    </td>
                    <td className="p-2 text-center font-mono">
                      {typeof mlP === 'number' ? (
                        <span className={mlP >= 0.5 ? 'text-[var(--block)] font-semibold' : 'text-[var(--text-muted)]'}>
                          {(mlP * 100).toFixed(1)}%
                        </span>
                      ) : (
                        <span className="text-[var(--text-muted)]">-</span>
                      )}
                    </td>
                    <td className="p-2 text-right">
                      {isFlagged ? (
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-[var(--block-background)] text-[var(--block)] border border-[var(--block-background)]">
                          <XCircle className="w-2.5 h-2.5" /> BLOCKED
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono text-[var(--allow)] bg-[var(--allow-background)] border border-[var(--allow-background)]">
                          <CheckCircle2 className="w-2.5 h-2.5" /> CLEAR
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Contributing Findings Table */}
      {contributors.length > 0 && (
        <div className="space-y-2">
          <h4 className="font-semibold text-xs">Active Rule Findings</h4>
          <div className="border border-[var(--border)] rounded-lg overflow-hidden">
            <table className="w-full text-left border-collapse text-[11px]">
              <thead>
                <tr className="bg-[var(--surface-secondary)] text-[var(--text-secondary)] border-b border-[var(--border)]">
                  <th className="p-2">Rule / Location</th>
                  <th className="p-2">Severity &amp; Weight</th>
                  <th className="p-2">Confidence</th>
                  <th className="p-2 text-right">Contribution</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {contributors.map((item, i) => (
                  <tr key={`${item.rule_id}-${i}`} className="hover:bg-[var(--surface-secondary)]/30">
                    <td className="p-2">
                      <div className="font-mono font-medium">{item.rule_id}</div>
                      <div className="flex gap-1 mt-0.5">
                        {item.lines.map((line) => (
                          <button
                            key={line}
                            onClick={() => onSelectLine(line)}
                            className="font-mono text-[10px] text-[var(--primary)] underline hover:opacity-80"
                            title={`Jump to line ${line}`}
                          >
                            Line {line}
                          </button>
                        ))}
                      </div>
                    </td>
                    <td className="p-2 font-mono">
                      {item.severity.toUpperCase()} ({item.severity_weight.toFixed(2)})
                    </td>
                    <td className="p-2 font-mono">{(item.confidence * 100).toFixed(0)}%</td>
                    <td className="p-2 font-mono text-right font-semibold">{item.contribution.toFixed(4)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Aggregate Score Math Metrics */}
      <dl className="grid grid-cols-2 gap-2 p-3 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-[11px]">
        <div>
          <dt className="text-[var(--text-muted)]">Largest Category Base (S_max)</dt>
          <dd className="font-mono font-semibold mt-0.5">{number('base')}</dd>
        </div>
        <div>
          <dt className="text-[var(--text-muted)]">Verified Chain Bonus (+Δ_chain)</dt>
          <dd className="font-mono font-semibold mt-0.5">+{number('chain_bonus')}</dd>
        </div>
        <div>
          <dt className="text-[var(--text-muted)]">Bounded ML Adjustment (±Δ_ML)</dt>
          <dd className="font-mono font-semibold mt-0.5">
            {trace.ml_adjustment !== undefined ? `${Number(trace.ml_adjustment) >= 0 ? '+' : ''}${number('ml_adjustment')}` : '0.0000'}
          </dd>
        </div>
        <div>
          <dt className="text-[var(--text-muted)]">Critical Severity Floor</dt>
          <dd className="font-mono font-semibold mt-0.5">{number('critical_floor')}</dd>
        </div>
        <div>
          <dt className="text-[var(--text-muted)]">Final Calibrated Score</dt>
          <dd className="font-mono font-bold text-sm text-[var(--text-primary)] mt-0.5">
            {response.risk_score.toFixed(2)}
          </dd>
        </div>
        <div>
          <dt className="text-[var(--text-muted)]">Decision Basis</dt>
          <dd className="font-mono font-semibold mt-0.5 text-[var(--text-primary)]">
            {String(trace.decision_basis || 'score_threshold')}
          </dd>
        </div>
      </dl>

      {/* CPU ML Classifier Status */}
      <div className="p-3 rounded-lg bg-[var(--surface-card)] border border-[var(--border)] space-y-1.5 text-[11px]">
        <div className="flex items-center justify-between font-semibold">
          <span className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-[var(--primary)]" />
            <span>M1/M2 CPU Machine Learning Layer</span>
          </span>
          <span className="font-mono text-[10px] text-[var(--text-muted)]">Zero External LLMs</span>
        </div>
        <p className="text-[var(--text-secondary)]">
          Status: <span className="font-mono font-medium text-[var(--text-primary)]">{String(trace.ml_status || 'active')}</span>
        </p>
        {mlProb !== null && (
          <div className="flex items-center justify-between pt-1 border-t border-[var(--border)]">
            <span className="text-[var(--text-secondary)]">Malicious Probability:</span>
            <span className="font-mono font-semibold text-[var(--text-primary)]">
              {(mlProb * 100).toFixed(1)}%
            </span>
          </div>
        )}
        {trace.model_signals && (trace.model_signals as string[]).length > 0 && (
          <div className="flex items-center gap-1 pt-1 text-[10px] font-mono text-[var(--text-muted)]">
            <span>Model Signals:</span>
            <span className="text-[var(--text-secondary)]">{(trace.model_signals as string[]).join(', ')}</span>
          </div>
        )}
      </div>

      {/* Explainable Decision Cards */}
      {response.decision_cards && response.decision_cards.length > 0 && (
        <div className="space-y-2 pt-2">
          <h4 className="font-semibold text-xs">Explainable AI (XAI) Decision Cards</h4>
          {response.decision_cards.map((card, index) => (
            <details
              key={`${card.rule_id}-${index}`}
              className="rounded-lg border border-[var(--border)] p-3 bg-[var(--surface-card)] group"
            >
              <summary className="cursor-pointer font-semibold text-xs flex items-center justify-between">
                <span>{card.rule_id} · {card.decision}</span>
                <span className="font-mono text-[10px] text-[var(--text-muted)] group-open:hidden">Details ▾</span>
              </summary>
              <div className="space-y-2 mt-2 pt-2 border-t border-[var(--border)] text-[11px] text-[var(--text-secondary)] leading-relaxed">
                <p><strong className="text-[var(--text-primary)]">Root Cause:</strong> {card.why}</p>
                <p><strong className="text-[var(--text-primary)]">Evidence:</strong> {card.evidence.redacted_snippet}</p>
                <p><strong className="text-[var(--text-primary)]">Remediation:</strong> {card.remediation}</p>
                {card.guards_checked && card.guards_checked.length > 0 ? (
                  <div>
                    <strong className="text-[var(--text-primary)]">Guards Evaluated:</strong>
                    <ul className="list-disc pl-4 mt-0.5 space-y-0.5">
                      {card.guards_checked.map((g) => (
                        <li key={g.guard} className="font-mono text-[10px]">
                          {g.guard}: {g.result ? 'satisfied' : 'not satisfied'}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : (
                  <p className="text-[10px] font-mono text-[var(--text-muted)]">{card.guard_evidence_status}</p>
                )}
                {card.alternatives_considered && card.alternatives_considered.length > 0 && (
                  <div>
                    <strong className="text-[var(--text-primary)]">Benign Lookalikes Considered:</strong>
                    <ul className="list-disc pl-4 mt-0.5 space-y-0.5 font-mono text-[10px]">
                      {card.alternatives_considered.map((alt) => (
                        <li key={alt}>{alt}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {card.references && card.references.length > 0 && (
                  <p className="font-mono text-[10px] text-[var(--text-muted)]">
                    Taxonomy References: {card.references.join(', ')}
                  </p>
                )}
              </div>
            </details>
          ))}
        </div>
      )}
    </section>
  );
}
