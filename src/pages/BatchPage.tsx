import { PublicEvaluation } from '../components/evaluation/PublicEvaluation';
import React, { useState } from 'react';
import {
  Upload,
  Play,
  Download,
  CheckCircle2,
  XCircle,
  FileJson,
  Search,
  ChevronRight,
} from 'lucide-react';
import { BatchItem, BatchItemResult, BatchEvaluationResponse } from '../types/guard';
import { BENCHMARK_SUITE_SAMPLES, evaluateBatch } from '../lib/api/batch';
import { EvaluationMetricsChart } from '../components/charts/EvaluationMetricsChart';
import { ThreatCategoryChart } from '../components/charts/ThreatCategoryChart';

export const BatchPage: React.FC = () => {
  const [inputJson, setInputJson] = useState<string>(
    JSON.stringify(BENCHMARK_SUITE_SAMPLES, null, 2)
  );
  const [parsedItems, setParsedItems] = useState<BatchItem[]>(BENCHMARK_SUITE_SAMPLES);
  const [parseError, setParseError] = useState<string | null>(null);

  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [progress, setProgress] = useState<{ completed: number; total: number }>({
    completed: 0,
    total: 0,
  });
  const [evaluationResponse, setEvaluationResponse] = useState<BatchEvaluationResponse | null>(null);

  // Filters & search for results table
  const [searchQuery, setSearchQuery] = useState('');
  const [filterVerdict, setFilterVerdict] = useState<'ALL' | 'ALLOW' | 'BLOCK' | 'INDETERMINATE'>('ALL');
  const [selectedResult, setSelectedResult] = useState<BatchItemResult | null>(null);

  // Handle JSON input change
  const handleJsonChange = (val: string) => {
    setInputJson(val);
    try {
      const parsed = JSON.parse(val);
      if (!Array.isArray(parsed)) {
        setParseError('Batch input must be a JSON array of snippets.');
        setParsedItems([]);
        return;
      }
      setParseError(null);
      setParsedItems(parsed);
    } catch (err: unknown) {
      setParseError(err instanceof Error ? err.message : 'Invalid JSON syntax');
      setParsedItems([]);
    }
  };

  // Handle File Upload
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (evt) => {
      const content = evt.target?.result as string;
      handleJsonChange(content);
    };
    reader.readAsText(file);
  };

  // Load standard benchmark suite
  const handleLoadBenchmark = () => {
    const jsonStr = JSON.stringify(BENCHMARK_SUITE_SAMPLES, null, 2);
    setInputJson(jsonStr);
    setParsedItems(BENCHMARK_SUITE_SAMPLES);
    setParseError(null);
    setEvaluationResponse(null);
    setSelectedResult(null);
  };

  // Run Batch
  const handleRunEvaluation = async () => {
    if (parsedItems.length === 0) return;

    setIsRunning(true);
    setProgress({ completed: 0, total: parsedItems.length });
    setEvaluationResponse(null);

    try {
      const res = await evaluateBatch(parsedItems, (completed, total) => {
        setProgress({ completed, total });
      });
      setEvaluationResponse(res);
    } catch (err: unknown) {
      console.error('Batch evaluation failed', err);
    } finally {
      setIsRunning(false);
    }
  };

  // Export JSON
  const handleExportJson = () => {
    if (!evaluationResponse) return;
    const blob = new Blob([JSON.stringify(evaluationResponse, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kavach_batch_${evaluationResponse.batch_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Export CSV
  const handleExportCsv = () => {
    if (!evaluationResponse) return;
    const headers = [
      'ID',
      'Language',
      'Verdict',
      'Risk Score',
      'Categories',
      'Duration (ms)',
      'Reason',
      'Expected Verdict',
      'Ground Truth Match',
    ];
    const rows = evaluationResponse.results.map((r) => [
      r.id,
      r.code_language,
      r.verdict,
      r.risk_score,
      `"${r.categories.join(';')}"`,
      r.duration_ms,
      `"${r.reason.replace(/"/g, '""')}"`,
      r.expected_verdict || 'N/A',
      r.match !== undefined ? (r.match ? 'MATCH' : 'MISMATCH') : 'N/A',
    ]);

    const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kavach_batch_${evaluationResponse.batch_id}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filtered results
  const filteredResults = (evaluationResponse?.results || []).filter((r) => {
    const matchesSearch =
      r.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.categories.some((c) => c.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesVerdict = filterVerdict === 'ALL' || r.verdict === filterVerdict;
    return matchesSearch && matchesVerdict;
  });

  const summary = evaluationResponse?.summary;

  // Build category points for chart if batch evaluated
  const batchCategoryData = summary?.category_breakdown
    ? Object.entries(summary.category_breakdown)
        .filter(([_, val]) => val.count > 0)
        .map(([key, val]) => ({
          category: key.replace(/_/g, ' '),
          count: val.count,
        }))
    : [];

  return (
    <div className="flex-1 p-4 lg:p-8 space-y-6 max-w-7xl mx-auto w-full bg-[var(--surface)]">
      <PublicEvaluation />
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border)] pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-[var(--text-primary)]">
            Batch Evaluation Workspace
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Evaluate suites of AI-generated snippets, verify ground-truth alignments, and calculate performance metrics.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleLoadBenchmark}
            className="px-3 py-1.5 text-xs font-mono rounded-lg bg-[var(--surface)] hover:bg-[var(--surface-hover)] text-[var(--text-primary)] border border-[var(--border)] transition-colors"
          >
            Load PS3 Suite ({BENCHMARK_SUITE_SAMPLES.length} snippets)
          </button>

          <label className="cursor-pointer px-3 py-1.5 text-xs font-mono rounded-lg bg-[var(--surface)] hover:bg-[var(--surface-hover)] text-[var(--text-primary)] border border-[var(--border)] transition-colors flex items-center gap-1.5">
            <Upload className="w-3.5 h-3.5" />
            <span>Upload JSON</span>
            <input type="file" accept=".json" onChange={handleFileUpload} className="hidden" />
          </label>

          <button
            onClick={handleRunEvaluation}
            disabled={isRunning || parsedItems.length === 0}
            className="px-4 py-1.5 text-xs font-medium rounded-lg bg-[var(--primary)] hover:bg-[var(--primary-hover)] text-[var(--primary-foreground)] transition-colors flex items-center gap-1.5 shadow-xs disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isRunning ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Evaluating ({progress.completed}/{progress.total})...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Run Evaluation ({parsedItems.length})</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Input JSON Editor & Validation */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-8 flex flex-col space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-[var(--text-secondary)]">
            <span className="flex items-center gap-1.5 font-medium text-[var(--text-primary)]">
              <FileJson className="w-4 h-4 text-[var(--text-primary)]" />
              <span>Batch Input Specification (JSON Array)</span>
            </span>
            <span>{parsedItems.length} items parsed</span>
          </div>

          <textarea
            value={inputJson}
            onChange={(e) => handleJsonChange(e.target.value)}
            rows={8}
            className="w-full p-3 font-mono text-xs rounded-lg bg-[var(--surface-card)] text-[var(--text-primary)] border border-[var(--border)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)] resize-y"
            placeholder="[ { id: 'test-1', code: '...', code_language: 'python' } ]"
          />

          {parseError && (
            <div className="p-2.5 rounded-lg bg-[var(--block-background)] border border-[var(--block-background)] text-xs font-mono text-[var(--block)]">
              JSON Validation Error: {parseError}
            </div>
          )}
        </div>

        {/* Evaluation Progress & Schema Contract */}
        <div className="lg:col-span-4 p-4 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] flex flex-col justify-between text-xs shadow-xs">
          <div>
            <h4 className="font-semibold text-xs text-[var(--text-primary)] uppercase font-mono mb-2">
              Batch Format Contract
            </h4>
            <p className="text-[var(--text-secondary)] leading-relaxed mb-3">
              Each record must supply <code className="text-[var(--text-primary)] bg-[var(--surface-secondary)] px-1 py-0.5 rounded border border-[var(--border)]">id</code>,{' '}
              <code className="text-[var(--text-primary)] bg-[var(--surface-secondary)] px-1 py-0.5 rounded border border-[var(--border)]">code</code>, and{' '}
              <code className="text-[var(--text-primary)] bg-[var(--surface-secondary)] px-1 py-0.5 rounded border border-[var(--border)]">code_language</code>.
            </p>
            <p className="text-[var(--text-secondary)] leading-relaxed">
              Optionally specify <code className="text-[var(--text-primary)] bg-[var(--surface-secondary)] px-1 py-0.5 rounded border border-[var(--border)]">expected_verdict</code>{' '}
              (<code className="text-[var(--allow)] font-bold">ALLOW</code> or <code className="text-[var(--block)] font-bold">BLOCK</code>) to
              compute benchmark precision, recall, and false positive metrics.
            </p>
          </div>

          {isRunning && (
            <div className="mt-4 pt-3 border-t border-[var(--border)] space-y-1.5">
              <div className="flex justify-between font-mono text-[11px]">
                <span className="text-[var(--text-secondary)]">Evaluating Snippets</span>
                <span className="font-bold text-[var(--text-primary)]">
                  {progress.completed} / {progress.total}
                </span>
              </div>
              <div className="w-full h-1.5 bg-[var(--surface-hover)] rounded-full overflow-hidden">
                <div
                  className="h-full bg-[var(--primary)] transition-all duration-150 rounded-full"
                  style={{
                    width: `${Math.round((progress.completed / (progress.total || 1)) * 100)}%`,
                  }}
                />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Benchmark Summary Metrics & ApexCharts */}
      {summary && (
        <div className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-5 shadow-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] pb-3">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-[var(--text-primary)] font-mono">
                Evaluation Metrics Summary
              </h3>
              <span className="text-xs text-[var(--text-muted)]">
                (Batch {evaluationResponse?.batch_id})
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleExportCsv}
                className="px-2.5 py-1 text-xs font-mono rounded-md bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--surface-hover)] flex items-center gap-1 transition-colors"
              >
                <Download className="w-3 h-3" />
                <span>Export CSV</span>
              </button>
              <button
                onClick={handleExportJson}
                className="px-2.5 py-1 text-xs font-mono rounded-md bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--surface-hover)] flex items-center gap-1 transition-colors"
              >
                <Download className="w-3 h-3" />
                <span>Export JSON</span>
              </button>
            </div>
          </div>

          {/* Operational Metrics Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 font-mono">
            <div className="p-3.5 rounded-lg bg-[var(--surface-card)] border border-[var(--border)]">
              <div className="text-[11px] text-[var(--text-muted)]">Total Evaluated</div>
              <div className="text-lg font-bold text-[var(--text-primary)] tabular-nums">
                {summary.total_evaluated}
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[var(--surface-card)] border border-[var(--border)]">
              <div className="text-[11px] text-[var(--allow)]">Allowed</div>
              <div className="text-lg font-bold text-[var(--allow)] tabular-nums">
                {summary.allow_count}
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[var(--surface-card)] border border-[var(--border)]">
              <div className="text-[11px] text-[var(--block)]">Blocked</div>
              <div className="text-lg font-bold text-[var(--block)] tabular-nums">
                {summary.block_count}
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[var(--surface-card)] border border-[var(--border)]">
              <div className="text-[11px] text-[var(--text-muted)]">Avg Latency</div>
              <div className="text-lg font-bold text-[var(--text-primary)] tabular-nums">
                {summary.avg_latency_ms} <span className="text-xs font-normal">ms</span>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[var(--surface-card)] border border-[var(--border)]">
              <div className="text-[11px] text-[var(--text-muted)]">P50 Latency</div>
              <div className="text-lg font-bold text-[var(--text-primary)] tabular-nums">
                {summary.p50_latency_ms} <span className="text-xs font-normal">ms</span>
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[var(--surface-card)] border border-[var(--border)]">
              <div className="text-[11px] text-[var(--text-muted)]">P95 Latency</div>
              <div className="text-lg font-bold text-[var(--text-primary)] tabular-nums">
                {summary.p95_latency_ms} <span className="text-xs font-normal">ms</span>
              </div>
            </div>
          </div>

          {/* ApexCharts for Evaluation Metrics */}
          {summary.has_ground_truth && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pt-2">
              <div className="lg:col-span-6 p-4 rounded-xl bg-[var(--surface-card)] border border-[var(--border)]">
                <h4 className="font-semibold text-xs text-[var(--text-primary)] font-mono mb-2">
                  Ground-Truth Performance Alignment (ApexCharts)
                </h4>
                <EvaluationMetricsChart
                  precision={summary.precision ?? 1}
                  recall={summary.recall ?? 1}
                  f1Score={summary.f1_score ?? 1}
                  falsePositiveRate={summary.false_positive_rate ?? 0}
                  height={190}
                />
              </div>

              {batchCategoryData.length > 0 && (
                <div className="lg:col-span-6 p-4 rounded-xl bg-[var(--surface-card)] border border-[var(--border)]">
                  <h4 className="font-semibold text-xs text-[var(--text-primary)] font-mono mb-2">
                    Batch Threat Breakdown by Category
                  </h4>
                  <ThreatCategoryChart data={batchCategoryData} height={190} />
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Results Table Section */}
      {evaluationResponse && (
        <div className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-3 shadow-xs">
          {/* Table Controls */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Search className="w-4 h-4 text-[var(--text-muted)]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by ID, category, or reason..."
                className="py-1 px-2.5 text-xs rounded-md bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)]"
              />
            </div>

            <div className="flex items-center gap-1.5 text-xs font-mono">
              <span className="text-[var(--text-muted)]">Verdict:</span>
              {(['ALL', 'ALLOW', 'BLOCK', 'INDETERMINATE'] as const).map((v) => (
                <button
                  key={v}
                  onClick={() => setFilterVerdict(v)}
                  className={`px-2 py-0.5 rounded-md text-[11px] transition-colors ${
                    filterVerdict === v
                      ? 'bg-[var(--primary)] text-[var(--primary-foreground)] font-semibold'
                      : 'bg-[var(--surface-secondary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--border)]'
                  }`}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-sans">
              <thead className="bg-[var(--surface-secondary)] text-[var(--text-secondary)] font-mono text-[11px] border-b border-[var(--border)]">
                <tr>
                  <th className="py-2.5 px-3">Snippet ID</th>
                  <th className="py-2.5 px-3">Lang</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Categories</th>
                  <th className="py-2.5 px-3">Latency</th>
                  <th className="py-2.5 px-3">Alignment</th>
                  <th className="py-2.5 px-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {filteredResults.map((r) => {
                  const isBlocked = r.verdict === 'BLOCK';
                  return (
                    <tr
                      key={r.id}
                      onClick={() => setSelectedResult(r)}
                      className="hover:bg-[var(--surface-secondary)] cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 px-3 font-mono font-medium text-[var(--text-primary)]">
                        {r.id}
                      </td>
                      <td className="py-2.5 px-3 font-mono uppercase text-[var(--text-secondary)]">
                        {r.code_language}
                      </td>
                      <td className="py-2.5 px-3 font-mono font-semibold">
                        <span
                          className={
                            isBlocked
                              ? 'text-[var(--block)]'
                              : 'text-[var(--allow)]'
                          }
                        >
                          {r.verdict}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono tabular-nums text-[var(--text-secondary)]">
                        {r.risk_score.toFixed(2)}
                      </td>
                      <td className="py-2.5 px-3">
                        {r.categories.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {r.categories.map((c) => (
                              <span
                                key={c}
                                className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-secondary)]"
                              >
                                {c}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-[var(--text-muted)] font-mono text-[11px]">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 font-mono tabular-nums text-[var(--text-secondary)]">
                        {r.duration_ms} ms
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px]">
                        {r.match !== undefined ? (
                          r.match ? (
                            <span className="text-[var(--allow)] flex items-center gap-1 font-semibold">
                              <CheckCircle2 className="w-3 h-3" /> Match
                            </span>
                          ) : (
                            <span className="text-[var(--block)] flex items-center gap-1 font-semibold">
                              <XCircle className="w-3 h-3" /> Mismatch
                            </span>
                          )
                        ) : (
                          <span className="text-[var(--text-muted)]">Unlabeled</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <ChevronRight className="w-4 h-4 text-[var(--text-muted)] inline-block" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Row Details Modal */}
      {selectedResult && (
        <div className="fixed inset-0 bg-black/45 z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[var(--surface-card)] border border-[var(--border)] rounded-xl shadow-2xl p-5 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-sm text-[var(--text-primary)]">
                  Snippet Result: {selectedResult.id}
                </span>
              </div>
              <button
                onClick={() => setSelectedResult(null)}
                className="text-xs font-mono text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Close ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                <div className="p-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
                  <div className="text-[var(--text-muted)]">Verdict</div>
                  <div
                    className={`font-bold ${
                      selectedResult.verdict === 'BLOCK'
                        ? 'text-[var(--block)]'
                        : 'text-[var(--allow)]'
                    }`}
                  >
                    {selectedResult.verdict}
                  </div>
                </div>

                <div className="p-2.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
                  <div className="text-[var(--text-muted)]">Risk Score</div>
                  <div className="font-bold text-[var(--text-primary)] tabular-nums">
                    {selectedResult.risk_score.toFixed(2)} / 1.00
                  </div>
                </div>
              </div>

              <div>
                <div className="font-mono text-[var(--text-muted)] text-[11px] mb-1">Reason:</div>
                <p className="p-3 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)] leading-relaxed">
                  {selectedResult.reason}
                </p>
              </div>

              {selectedResult.vulnerable_lines.length > 0 && (
                <div>
                  <div className="font-mono text-[var(--text-muted)] text-[11px] mb-1">
                    Vulnerable Lines:
                  </div>
                  <div className="flex gap-1.5">
                    {selectedResult.vulnerable_lines.map((l) => (
                      <span
                        key={l}
                        className="px-2 py-0.5 rounded-md bg-[var(--block-background)] text-[var(--block)] font-mono text-xs font-semibold border border-[var(--block-background)]"
                      >
                        Line {l}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedResult(null)}
                className="px-4 py-1.5 rounded-lg bg-[var(--primary)] text-[var(--primary-foreground)] text-xs font-medium hover:bg-[var(--primary-hover)] transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
