import React from 'react';
import { GuardResponse } from '../../types/guard';

interface Contributor {
  rule_id: string; category: string; lines: number[]; severity: string;
  severity_weight: number; confidence: number; contribution: number;
}

export function ScoreExplanation({ response, onSelectLine }: {
  response: GuardResponse; onSelectLine: (line: number) => void;
}) {
  const trace = response.score_trace;
  if (!trace || trace.method !== 'severity-noisy-or-v1') {
    return <p className="text-xs text-[var(--text-secondary)]">This saved or demo result has no current scoring breakdown. Run a live scan to obtain one.</p>;
  }
  const contributors = trace.contributors as Contributor[];
  const scores = trace.category_scores as Record<string, number>;
  const number = (key: string) => Number(trace[key]).toFixed(4);
  return <section className="space-y-4 text-xs text-[var(--text-primary)]" aria-label="Score calculation and decision evidence">
    <div className="rounded-lg border border-[var(--border)] p-3 space-y-2">
      <h3 className="font-semibold">Why this score and verdict?</h3>
      <p>Risk is a severity score, not the probability of an attack and not the judge’s competition score.</p>
      <p className="font-mono break-words">{String(trace.formula)}</p>
      <p>{String(trace.confidence_basis)}</p>
    </div>
    <div className="overflow-x-auto">
      <table className="w-full text-left border-collapse">
        <caption className="text-left font-semibold mb-2">Every contributing finding</caption>
        <thead><tr>{['Rule / lines', 'Severity weight', 'Confidence', 'Contribution'].map(label => <th key={label} className="p-2 border-b border-[var(--border)]">{label}</th>)}</tr></thead>
        <tbody>{contributors.map((item, i) => <tr key={`${item.rule_id}-${i}`}>
          <td className="p-2 border-b border-[var(--border)]"><div>{item.rule_id}</div><div>{item.lines.map(line => <button key={line} onClick={() => onSelectLine(line)} className="underline mr-2" aria-label={`Go to source line ${line}`}>L{line}</button>)}</div></td>
          <td className="p-2">{item.severity}: {item.severity_weight.toFixed(2)}</td>
          <td className="p-2">{item.confidence.toFixed(2)}</td>
          <td className="p-2 font-mono">{item.contribution.toFixed(4)}</td>
        </tr>)}</tbody>
      </table>
      {!contributors.length && <p className="py-2">No finding contributes a severity score.</p>}
    </div>
    <div className="space-y-2">
      <h4 className="font-semibold">Per-category aggregation</h4>
      <p>For each category: 1 − the product of (1 − each contribution). Separate findings may be correlated.</p>
      {Object.entries(scores).map(([category, score]) => <div key={category} className="flex justify-between gap-3"><span className="break-all">{category}</span><span className="font-mono">{score.toFixed(4)}</span></div>)}
    </div>
    <dl className="grid grid-cols-2 gap-2 p-3 rounded-lg bg-[var(--surface-secondary)]">
      <dt>Largest category score</dt><dd>{number('base')}</dd>
      <dt>Verified chain bonus</dt><dd>{number('chain_bonus')}</dd>
      <dt>ML adjustment</dt><dd>{number('ml_adjustment')} (disabled)</dd>
      <dt>Critical severity floor</dt><dd>{number('critical_floor')}</dd>
      <dt>Final rounded score</dt><dd>{response.risk_score.toFixed(2)}</dd>
      <dt>Block threshold</dt><dd>{number('threshold')}</dd>
      <dt>Decision basis</dt><dd className="break-all">{String(trace.decision_basis)}</dd>
      <dt>Analysis complete</dt><dd>{trace.analysis_complete ? 'Yes' : 'No — fail closed'}</dd>
    </dl>
    {(trace.chain_bonuses as {rule_id: string; why: string; amount: number}[]).map(bonus => <p key={bonus.rule_id}>{bonus.rule_id}: +{bonus.amount.toFixed(2)}. {bonus.why}</p>)}
    <p>{String(trace.policy)}</p><p>{String(trace.threshold_status)}</p><p>{String(trace.limitations)}</p>
    <h4 className="font-semibold">Decision evidence</h4>
    {response.decision_cards?.map((card, index) => <details key={`${card.rule_id}-${index}`} className="rounded-lg border border-[var(--border)] p-3">
      <summary className="cursor-pointer font-semibold">{card.rule_id} · {card.decision}</summary>
      <div className="space-y-2 mt-2"><p>{card.why}</p><p>{card.evidence.redacted_snippet}</p>
        <p>{card.remediation}</p>
        {card.guards_checked.length > 0 ? <ul>{card.guards_checked.map(guard => <li key={guard.guard}>{guard.guard}: {guard.result ? 'yes' : 'no'}</li>)}</ul> : <p>{card.guard_evidence_status}</p>}
        <p>{card.alternative_status}</p>
        <ul>{card.alternatives_considered.map(alternative => <li key={alternative}>{alternative}</li>)}</ul>
        <p>References: {card.references.join(', ')}</p>
      </div>
    </details>)}
  </section>;
}
