import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  AlertCircle,
  Info,
  ArrowRight,
  BookOpen,
  Wrench,
  Languages,
  Scan,
} from 'lucide-react';
import { fetchRules } from '../lib/api/governance';
import { CatalogueRule, RulesResponse } from '../types/governance';

type LoadState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; data: RulesResponse };

function severityClasses(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-[var(--block-background)] text-[var(--block)]';
    case 'high':
      return 'bg-[var(--critical-background)] text-[var(--critical)]';
    default:
      return 'bg-[var(--surface-secondary)] text-[var(--text-secondary)]';
  }
}

export const RulesPage: React.FC = () => {
  const [state, setState] = useState<LoadState>({ status: 'loading' });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;
    setState({ status: 'loading' });
    fetchRules()
      .then((data) => {
        if (cancelled) return;
        setState({ status: 'ready', data });
        setSelectedId((current) => current ?? data.rules[0]?.id ?? null);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const message = err instanceof Error ? err.message : 'Backend unreachable';
        setState({ status: 'error', message });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const rules: CatalogueRule[] = state.status === 'ready' ? state.data.rules : [];

  const filteredRules = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return rules;
    return rules.filter(
      (rule) =>
        rule.id.toLowerCase().includes(q) ||
        rule.category.toLowerCase().includes(q) ||
        rule.rationale.toLowerCase().includes(q)
    );
  }, [rules, searchQuery]);

  const activeRule =
    rules.find((rule) => rule.id === selectedId) ?? filteredRules[0] ?? rules[0] ?? null;

  return (
    <div className="flex-1 p-4 lg:p-8 space-y-6 max-w-7xl mx-auto w-full bg-[var(--surface)]">
      {/* Header */}
      <div className="border-b border-[var(--border)] pb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
            Security Rules & Threat Detections
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Live catalogue of every rule the engine implements, served from the backend at <code className="font-mono">/v1/rules</code>.
          </p>
        </div>
        {state.status === 'ready' && (
          <div className="text-[11px] font-mono text-[var(--text-muted)]">
            <span>{state.data.count} rules</span>
            <span className="mx-1.5 text-[var(--border)]">·</span>
            <span>ruleset {state.data.rules_version}</span>
          </div>
        )}
      </div>

      {state.status === 'loading' && (
        <div
          role="status"
          aria-live="polite"
          className="p-6 rounded-lg bg-[var(--surface-card)] border border-[var(--border)] flex items-center gap-3 text-xs text-[var(--text-secondary)]"
        >
          <div className="w-3.5 h-3.5 border-2 border-[var(--primary)] border-t-transparent rounded-full animate-spin" />
          <span>Loading rule catalogue from backend…</span>
        </div>
      )}

      {state.status === 'error' && (
        <div
          role="alert"
          className="p-4 rounded-lg bg-[var(--block-background)] border border-[var(--block-background)] flex items-start gap-2.5 text-xs text-[var(--block)]"
        >
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-semibold">Backend unavailable — rule catalogue could not be loaded.</div>
            <div className="font-mono text-[11px] break-all">{state.message}</div>
            <div className="text-[var(--text-secondary)]">
              Start the FastAPI service and reload. No placeholder rules are shown.
            </div>
          </div>
        </div>
      )}

      {state.status === 'ready' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Rule List & Search */}
          <div className="lg:col-span-4 space-y-3">
            <div className="relative">
              <label htmlFor="rules-search" className="sr-only">
                Filter rules by id, category, or rationale
              </label>
              <Search className="w-4 h-4 text-[var(--text-muted)] absolute left-3 top-2.5 pointer-events-none" />
              <input
                id="rules-search"
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by id, category, rationale…"
                className="w-full pl-9 pr-3 py-2 text-xs rounded-md bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--border-strong)]"
              />
            </div>

            <div className="text-[11px] font-mono text-[var(--text-muted)] px-1">
              {filteredRules.length} of {rules.length} shown
            </div>

            <div className="space-y-1 max-h-[70vh] overflow-y-auto pr-1">
              {filteredRules.length === 0 && (
                <div className="p-4 text-center text-xs text-[var(--text-muted)] font-mono">
                  No rules match this filter.
                </div>
              )}
              {filteredRules.map((rule) => {
                const isSelected = activeRule?.id === rule.id;
                return (
                  <button
                    key={rule.id}
                    type="button"
                    aria-pressed={isSelected}
                    onClick={() => setSelectedId(rule.id)}
                    className={`w-full text-left p-3 rounded-lg text-xs transition-colors border focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--border-strong)] ${
                      isSelected
                        ? 'bg-[var(--surface-secondary)] border-[var(--border-strong)] text-[var(--text-primary)] font-medium'
                        : 'bg-[var(--surface)] border-transparent hover:bg-[var(--sidebar-background)] text-[var(--text-secondary)]'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono font-medium text-[var(--text-primary)] truncate">
                        {rule.id}
                      </span>
                      <span
                        className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded shrink-0 ${severityClasses(
                          rule.severity
                        )}`}
                      >
                        {rule.severity}
                      </span>
                    </div>
                    <div className="text-[11px] text-[var(--text-muted)] mt-0.5 font-mono truncate">
                      {rule.category}
                    </div>
                    <p className="text-[11px] text-[var(--text-secondary)] mt-0.5 line-clamp-2">
                      {rule.rationale}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right Column: Rule Detail */}
          <div className="lg:col-span-8 p-6 rounded-lg bg-[var(--surface-card)] border border-[var(--border)] space-y-6">
            {activeRule ? (
              <>
                <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[var(--border)] pb-4">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs px-2 py-0.5 rounded bg-[var(--surface-secondary)] text-[var(--text-primary)] border border-[var(--border)]">
                        {activeRule.id}
                      </span>
                      <span
                        className={`text-[11px] font-mono font-medium uppercase px-2 py-0.5 rounded ${severityClasses(
                          activeRule.severity
                        )}`}
                      >
                        {activeRule.severity} severity
                      </span>
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--surface-secondary)] text-[var(--text-secondary)] border border-[var(--border)]">
                        {activeRule.matcher}
                      </span>
                    </div>
                    <h2 className="text-lg font-bold text-[var(--text-primary)] mt-1.5 font-mono break-words">
                      {activeRule.category}
                    </h2>
                  </div>

                  <button
                    type="button"
                    onClick={() => navigate('/app/scan')}
                    className="px-3.5 py-1.5 rounded-md bg-[var(--primary)] hover:bg-[var(--primary-hover)] text-[var(--primary-foreground)] text-xs font-medium transition-colors flex items-center gap-1.5 shrink-0"
                  >
                    <Scan className="w-3.5 h-3.5" />
                    <span>Open Scanner</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="space-y-1.5">
                  <h3 className="text-xs font-semibold text-[var(--text-primary)] uppercase tracking-wider font-mono">
                    Rationale
                  </h3>
                  <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                    {activeRule.rationale}
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <h3 className="text-xs font-semibold text-[var(--text-primary)] uppercase tracking-wider font-mono flex items-center gap-1.5">
                      <Languages className="w-3.5 h-3.5 text-[var(--text-muted)]" />
                      <span>Languages</span>
                    </h3>
                    <ul className="flex flex-wrap gap-1.5">
                      {activeRule.languages.map((lang) => (
                        <li
                          key={lang}
                          className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)]"
                        >
                          {lang}
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="space-y-2">
                    <h3 className="text-xs font-semibold text-[var(--text-primary)] uppercase tracking-wider font-mono flex items-center gap-1.5">
                      <BookOpen className="w-3.5 h-3.5 text-[var(--text-muted)]" />
                      <span>References</span>
                    </h3>
                    {activeRule.references.length > 0 ? (
                      <ul className="flex flex-wrap gap-1.5">
                        {activeRule.references.map((ref) => (
                          <li
                            key={ref}
                            className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)]"
                          >
                            {ref}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-[11px] text-[var(--text-muted)] font-mono">No references listed.</p>
                    )}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <h3 className="text-xs font-semibold text-[var(--text-primary)] uppercase tracking-wider font-mono flex items-center gap-1.5">
                    <Wrench className="w-3.5 h-3.5 text-[var(--text-muted)]" />
                    <span>Remediation</span>
                  </h3>
                  <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                    {activeRule.remediation}
                  </p>
                </div>

                <div className="p-3.5 rounded-md bg-[var(--surface-secondary)] border border-[var(--border)] space-y-1 text-xs">
                  <div className="font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5 text-[var(--text-muted)]" />
                    <span>Provenance</span>
                  </div>
                  <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px] font-mono text-[var(--text-secondary)]">
                    <dt className="text-[var(--text-muted)]">rule_id</dt>
                    <dd className="text-[var(--text-primary)]">{activeRule.rule_id}</dd>
                    <dt className="text-[var(--text-muted)]">matcher</dt>
                    <dd className="text-[var(--text-primary)]">{activeRule.matcher}</dd>
                    <dt className="text-[var(--text-muted)]">fixture</dt>
                    <dd className="text-[var(--text-primary)] break-all">{activeRule.fixture}</dd>
                  </dl>
                </div>
              </>
            ) : (
              <div className="text-xs text-[var(--text-muted)] font-mono">
                The backend returned an empty rule catalogue.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
