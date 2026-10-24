import React, { useEffect, useState } from 'react';
import { AlertCircle, FileText, RefreshCw } from 'lucide-react';
import { fetchDecisions } from '../lib/api/governance';
import { DecisionsResponse, DesignDecision } from '../types/governance';

type LoadState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; data: DecisionsResponse };

function statusClasses(status: string): string {
  switch (status.toLowerCase()) {
    case 'accepted':
    case 'done':
    case 'implemented':
    case 'verified':
      return 'bg-[var(--allow-background)] text-[var(--allow)]';
    case 'superseded':
    case 'rejected':
    case 'deprecated':
    case 'blocked':
      return 'bg-[var(--block-background)] text-[var(--block)]';
    case 'proposed':
    case 'draft':
    case 'pending':
    case 'partial':
      return 'bg-[var(--critical-background)] text-[var(--critical)]';
    default:
      return 'bg-[var(--surface-secondary)] text-[var(--text-secondary)]';
  }
}

const Badge: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <span
    className={`inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border border-transparent ${statusClasses(
      value
    )}`}
  >
    <span className="opacity-70">{label}:</span>
    <span className="font-semibold uppercase">{value}</span>
  </span>
);

export const DecisionsPage: React.FC = () => {
  const [state, setState] = useState<LoadState>({ status: 'loading' });
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const load = async () => {
    setState({ status: 'loading' });
    try {
      const data = await fetchDecisions();
      setState({ status: 'ready', data });
      setSelectedId((current) => current ?? data.decisions[0]?.id ?? null);
    } catch (err: unknown) {
      setState({ status: 'error', message: err instanceof Error ? err.message : 'Backend unreachable' });
    }
  };

  useEffect(() => {
    load();
  }, []);

  const decisions: DesignDecision[] = state.status === 'ready' ? state.data.decisions : [];
  const active = decisions.find((d) => d.id === selectedId) ?? decisions[0] ?? null;

  return (
    <div className="flex-1 p-4 lg:p-8 space-y-6 max-w-7xl mx-auto w-full bg-[var(--surface)]">
      <div className="border-b border-[var(--border)] pb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)] flex items-center gap-2">
            <FileText className="w-5 h-5 text-[var(--text-secondary)]" aria-hidden="true" />
            <span>Design Decisions</span>
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Architecture decision records served from the backend at <code className="font-mono">/v1/docs/decisions</code>.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {state.status === 'ready' && (
            <span className="text-[11px] font-mono text-[var(--text-muted)]">{state.data.count} records</span>
          )}
          <button
            type="button"
            onClick={load}
            disabled={state.status === 'loading'}
            className="px-3 py-1.5 rounded-md bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] disabled:opacity-60 disabled:cursor-not-allowed border border-[var(--border)] text-[var(--text-primary)] text-xs font-medium transition-colors inline-flex items-center gap-1.5 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--border-strong)]"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${state.status === 'loading' ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span>Reload</span>
          </button>
        </div>
      </div>

      {state.status === 'loading' && (
        <div
          role="status"
          aria-live="polite"
          className="p-6 rounded-lg bg-[var(--surface-card)] border border-[var(--border)] flex items-center gap-3 text-xs text-[var(--text-secondary)]"
        >
          <div className="w-3.5 h-3.5 border-2 border-[var(--primary)] border-t-transparent rounded-full animate-spin" />
          <span>Loading decision records from backend…</span>
        </div>
      )}

      {state.status === 'error' && (
        <div
          role="alert"
          className="p-4 rounded-lg bg-[var(--block-background)] border border-[var(--block-background)] flex items-start gap-2.5 text-xs text-[var(--block)]"
        >
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
          <div className="space-y-1">
            <div className="font-semibold">Backend unavailable — decision records could not be loaded.</div>
            <div className="font-mono text-[11px] break-all">{state.message}</div>
          </div>
        </div>
      )}

      {state.status === 'ready' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <div className="lg:col-span-4 space-y-1 max-h-[75vh] overflow-y-auto pr-1">
            {decisions.length === 0 && (
              <div className="p-4 text-center text-xs text-[var(--text-muted)] font-mono">
                No decision records found on disk.
              </div>
            )}
            {decisions.map((decision) => {
              const isSelected = active?.id === decision.id;
              return (
                <button
                  key={decision.file}
                  type="button"
                  aria-pressed={isSelected}
                  onClick={() => setSelectedId(decision.id)}
                  className={`w-full text-left p-3 rounded-lg text-xs transition-colors border focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--border-strong)] ${
                    isSelected
                      ? 'bg-[var(--surface-secondary)] border-[var(--border-strong)] text-[var(--text-primary)] font-medium'
                      : 'bg-[var(--surface)] border-transparent hover:bg-[var(--sidebar-background)] text-[var(--text-secondary)]'
                  }`}
                >
                  <div className="flex items-start gap-2">
                    <span className="font-mono text-[var(--text-muted)] shrink-0">{decision.id}</span>
                    <span className="font-medium text-[var(--text-primary)]">{decision.title}</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5 mt-1.5">
                    <Badge label="status" value={decision.status} />
                    <Badge label="source" value={decision.source_status} />
                  </div>
                </button>
              );
            })}
          </div>

          <div className="lg:col-span-8 p-6 rounded-lg bg-[var(--surface-card)] border border-[var(--border)] space-y-4">
            {active ? (
              <>
                <div className="border-b border-[var(--border)] pb-4 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)]">
                      ADR {active.id}
                    </span>
                    <Badge label="status" value={active.status} />
                    <Badge label="source" value={active.source_status} />
                  </div>
                  <h2 className="text-lg font-bold text-[var(--text-primary)]">{active.title}</h2>
                  <div className="text-[11px] font-mono text-[var(--text-muted)]">docs/decisions/{active.file}</div>
                </div>
                <pre className="p-4 rounded-md bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-words overflow-x-auto">
                  {active.body}
                </pre>
              </>
            ) : (
              <div className="text-xs text-[var(--text-muted)] font-mono">Select a record to read it.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
