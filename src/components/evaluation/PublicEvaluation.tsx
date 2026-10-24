import React, { useState } from 'react';
import { apiClient } from '../../lib/api/client';

export function PublicEvaluation() {
  const [report, setReport] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function run() {
    setBusy(true); setError('');
    try {
      const res = await apiClient.fetchWithTimeout('/v1/evaluation', { method: 'POST' });
      if (!res.ok) throw new Error(`Evaluation unavailable (HTTP ${res.status}).`);
      const data = await res.json();
      if (!data.binary || !Array.isArray(data.results) || data.results.length !== data.sample_count) throw new Error('Invalid evaluation report.');
      setReport(data);
    } catch (e) { setError(e instanceof Error ? e.message : 'Evaluation failed'); }
    finally { setBusy(false); }
  }
  function download() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a'); a.href = url; a.download = 'public-evaluation.json'; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <section className="p-4 border-b border-[var(--border)] text-sm space-y-2">
    <div className="flex items-center gap-4">
      <strong>Public development set</strong>
      <button className="underline disabled:opacity-50" disabled={busy} onClick={run}>{busy ? 'Evaluating…' : 'Evaluate Python backend'}</button>
      {report && <button className="underline" onClick={download}>Download full report</button>}
    </div>
    <p className="text-xs text-[var(--text-secondary)]">Runs the bundled 42 samples through the Python analyzer without executing them. Development metrics, not a held-out score.</p>
    {error && <p role="alert">{error}</p>}
    {report && <>
      <div className="flex flex-wrap gap-4">{['precision', 'recall', 'f1', 'fpr'].map(key => <span key={key}>{key}: {report.binary[key] == null ? 'N/A' : `${(report.binary[key] * 100).toFixed(1)}%`}</span>)}<span>p95: {report.latency_ms.p95} ms</span></div>
      <details><summary className="cursor-pointer">Per-category metrics and sample results</summary><pre className="max-h-80 overflow-auto text-xs mt-2">{JSON.stringify({ per_category: report.per_category, results: report.results }, null, 2)}</pre></details>
    </>}
  </section>;
}
