import React, { useCallback, useEffect, useState } from 'react';
import {
  Shield,
  Eye,
  AlertTriangle,
  Lock,
  UserCheck,
  Cpu,
  Scale,
  MessageSquareWarning,
  Link2,
  CheckCircle2,
  XCircle,
  AlertCircle,
  RefreshCw,
  FlaskConical,
} from 'lucide-react';
import {
  fetchInterceptResult,
  fetchRaiReport,
  submitFeedback,
  verifyAuditChain,
} from '../lib/api/governance';
import {
  AuditVerifyResponse,
  BinaryMetrics,
  FeedbackKind,
  FeedbackRecord,
  InterceptResult,
  RaiReport,
} from '../types/governance';

type LoadState<T> =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; data: T };

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'Backend unreachable';
}

function fmtRatio(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return 'n/a';
  return value.toFixed(3);
}

function fmtBool(value: boolean): string {
  return value ? 'Yes' : 'No';
}

function fmtTime(iso: string | undefined): string {
  if (!iso) return 'unknown';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

const cardClass =
  'p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-3 shadow-xs';
const headingClass = 'font-semibold text-sm text-[var(--text-primary)] font-mono';
const subHeadingClass =
  'text-[11px] font-semibold text-[var(--text-primary)] uppercase tracking-wider font-mono';
const thClass =
  'text-left text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] font-medium px-2 py-1.5 border-b border-[var(--border)]';
const tdClass = 'px-2 py-1.5 font-mono text-[11px] text-[var(--text-primary)] border-b border-[var(--border)]';
const inputClass =
  'w-full px-3 py-2 text-xs rounded-md bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--border-strong)]';
const labelClass = 'block text-[11px] font-medium text-[var(--text-secondary)] mb-1';
const primaryButtonClass =
  'px-3.5 py-1.5 rounded-md bg-[var(--primary)] hover:bg-[var(--primary-hover)] disabled:opacity-60 disabled:cursor-not-allowed text-[var(--primary-foreground)] text-xs font-medium transition-colors inline-flex items-center gap-1.5 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--border-strong)]';
const secondaryButtonClass =
  'px-3 py-1.5 rounded-md bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] disabled:opacity-60 disabled:cursor-not-allowed border border-[var(--border)] text-[var(--text-primary)] text-xs font-medium transition-colors inline-flex items-center gap-1.5 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--border-strong)]';

const PassFail: React.FC<{ ok: boolean; passLabel?: string; failLabel?: string }> = ({
  ok,
  passLabel = 'PASS',
  failLabel = 'FAIL',
}) => (
  <span
    className={`inline-flex items-center gap-1 text-[11px] font-mono font-semibold px-1.5 py-0.5 rounded ${
      ok ? 'bg-[var(--allow-background)] text-[var(--allow)]' : 'bg-[var(--block-background)] text-[var(--block)]'
    }`}
  >
    {ok ? <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" /> : <XCircle className="w-3.5 h-3.5" aria-hidden="true" />}
    <span>{ok ? passLabel : failLabel}</span>
  </span>
);

const ErrorBanner: React.FC<{ title: string; message: string }> = ({ title, message }) => (
  <div
    role="alert"
    className="p-3 rounded-lg bg-[var(--block-background)] border border-[var(--block-background)] flex items-start gap-2.5 text-xs text-[var(--block)]"
  >
    <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
    <div className="space-y-0.5">
      <div className="font-semibold">{title}</div>
      <div className="font-mono text-[11px] break-all">{message}</div>
    </div>
  </div>
);

const Spinner: React.FC<{ label: string }> = ({ label }) => (
  <div role="status" aria-live="polite" className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
    <div className="w-3.5 h-3.5 border-2 border-[var(--primary)] border-t-transparent rounded-full animate-spin" />
    <span>{label}</span>
  </div>
);

const BinaryMetricsTable: React.FC<{ metrics: BinaryMetrics }> = ({ metrics }) => (
  <div className="overflow-x-auto">
    <table className="w-full text-xs border-collapse">
      <caption className="sr-only">Binary allow/block evaluation metrics</caption>
      <thead>
        <tr>
          <th scope="col" className={thClass}>TP</th>
          <th scope="col" className={thClass}>FP</th>
          <th scope="col" className={thClass}>TN</th>
          <th scope="col" className={thClass}>FN</th>
          <th scope="col" className={thClass}>Precision</th>
          <th scope="col" className={thClass}>Recall</th>
          <th scope="col" className={thClass}>F1</th>
          <th scope="col" className={thClass}>FPR</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td className={tdClass}>{metrics.tp}</td>
          <td className={tdClass}>{metrics.fp}</td>
          <td className={tdClass}>{metrics.tn}</td>
          <td className={tdClass}>{metrics.fn}</td>
          <td className={tdClass}>{fmtRatio(metrics.precision)}</td>
          <td className={tdClass}>{fmtRatio(metrics.recall)}</td>
          <td className={tdClass}>{fmtRatio(metrics.f1)}</td>
          <td className={tdClass}>{fmtRatio(metrics.fpr)}</td>
        </tr>
      </tbody>
    </table>
  </div>
);

const AuditVerifyCard: React.FC<{ initial: AuditVerifyResponse }> = ({ initial }) => {
  const [result, setResult] = useState<AuditVerifyResponse>(initial);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [checkedAt, setCheckedAt] = useState<string | null>(null);

  const runVerify = async () => {
    setChecking(true);
    setError(null);
    try {
      const data = await verifyAuditChain();
      setResult(data);
      setCheckedAt(new Date().toISOString());
    } catch (err: unknown) {
      setError(errorMessage(err));
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className={cardClass}>
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--text-primary)]">
            <Link2 className="w-4 h-4" aria-hidden="true" />
          </div>
          <h3 className={headingClass}>Accountability · Audit hash chain</h3>
        </div>
        <button type="button" onClick={runVerify} disabled={checking} className={secondaryButtonClass}>
          <RefreshCw className={`w-3.5 h-3.5 ${checking ? 'animate-spin' : ''}`} aria-hidden="true" />
          <span>{checking ? 'Verifying…' : 'Verify audit chain'}</span>
        </button>
      </div>
      <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
        Every scan appends a SHA-256-chained record. Verification recomputes the chain on disk and reports the first broken index, if any.
      </p>
      {error && <ErrorBanner title="Verification request failed" message={error} />}
      <div aria-live="polite" className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs font-mono text-[var(--text-secondary)]">
        <PassFail ok={result.valid} />
        <span>
          Records: <span className="text-[var(--text-primary)] font-semibold">{result.records}</span>
        </span>
        <span>
          First broken index:{' '}
          <span className="text-[var(--text-primary)] font-semibold">
            {result.first_broken_index === null ? 'none' : result.first_broken_index}
          </span>
        </span>
        {checkedAt && <span className="text-[var(--text-muted)]">checked {fmtTime(checkedAt)}</span>}
      </div>
      <div className="text-[11px] text-[var(--text-secondary)]">{result.message}</div>
      {result.last_hash && (
        <div className="text-[10px] font-mono text-[var(--text-muted)] break-all">last_hash: {result.last_hash}</div>
      )}
    </div>
  );
};

const FeedbackCard: React.FC<{
  summary: RaiReport['contestability']['feedback'];
  onSubmitted: (record: FeedbackRecord) => void;
}> = ({ summary, onSubmitted }) => {
  const [requestId, setRequestId] = useState('');
  const [kind, setKind] = useState<FeedbackKind>('false_positive');
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = requestId.trim();
    if (!trimmed) {
      setError('request_id is required. It is returned with every scan verdict.');
      return;
    }
    setSubmitting(true);
    setError(null);
    setSuccess(null);
    try {
      const record = await submitFeedback({ request_id: trimmed, kind, note: note.trim() || undefined });
      onSubmitted(record);
      setSuccess(`Recorded as ${record.id} (status: ${record.status}).`);
      setRequestId('');
      setNote('');
    } catch (err: unknown) {
      setError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  const latest = [...summary.latest].reverse();

  return (
    <div className={cardClass}>
      <div className="flex items-center gap-2">
        <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--text-primary)]">
          <MessageSquareWarning className="w-4 h-4" aria-hidden="true" />
        </div>
        <h3 className={headingClass}>Contestability · Dispute a verdict</h3>
      </div>
      <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
        Report a false positive or missed threat. Only the request id, kind, and note are stored — raw code stored:{' '}
        <strong className="text-[var(--text-primary)]">{fmtBool(summary.raw_code_stored)}</strong>.
      </p>

      <form onSubmit={handleSubmit} className="grid grid-cols-1 md:grid-cols-2 gap-3" noValidate>
        <div>
          <label htmlFor="feedback-request-id" className={labelClass}>
            Request ID <span aria-hidden="true">*</span>
          </label>
          <input
            id="feedback-request-id"
            type="text"
            required
            value={requestId}
            onChange={(e) => setRequestId(e.target.value)}
            placeholder="request_id from a scan response"
            className={`${inputClass} font-mono`}
            maxLength={128}
          />
        </div>
        <div>
          <label htmlFor="feedback-kind" className={labelClass}>
            Kind
          </label>
          <select
            id="feedback-kind"
            value={kind}
            onChange={(e) => setKind(e.target.value as FeedbackKind)}
            className={inputClass}
          >
            <option value="false_positive">False positive (blocked safe code)</option>
            <option value="false_negative">False negative (allowed unsafe code)</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div className="md:col-span-2">
          <label htmlFor="feedback-note" className={labelClass}>
            Note <span className="text-[var(--text-muted)]">(optional, max 2000 chars)</span>
          </label>
          <textarea
            id="feedback-note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            rows={3}
            maxLength={2000}
            placeholder="What did the engine get wrong? Do not paste secrets."
            className={`${inputClass} resize-y`}
          />
        </div>
        <div className="md:col-span-2 flex flex-wrap items-center gap-3">
          <button type="submit" disabled={submitting} className={primaryButtonClass}>
            {submitting ? 'Submitting…' : 'Submit feedback'}
          </button>
          <div aria-live="polite" className="text-[11px]">
            {success && (
              <span className="inline-flex items-center gap-1 text-[var(--allow)]">
                <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                {success}
              </span>
            )}
          </div>
        </div>
      </form>
      {error && <ErrorBanner title="Feedback not recorded" message={error} />}

      <div className="pt-2 border-t border-[var(--border)] space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h4 className={subHeadingClass}>Latest feedback</h4>
          <div className="text-[11px] font-mono text-[var(--text-muted)]">
            total {summary.total}
            {Object.entries(summary.by_kind).map(([k, v]) => (
              <span key={k}>
                <span className="mx-1 text-[var(--border)]">·</span>
                {k} {v}
              </span>
            ))}
          </div>
        </div>
        {latest.length === 0 ? (
          <p className="text-[11px] text-[var(--text-muted)] font-mono">No feedback has been submitted yet.</p>
        ) : (
          <ul className="space-y-1.5">
            {latest.map((item) => (
              <li
                key={item.id}
                className="p-2.5 rounded-md bg-[var(--surface-secondary)] border border-[var(--border)] text-[11px] space-y-0.5"
              >
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono">
                  <span className="font-semibold text-[var(--text-primary)]">{item.kind}</span>
                  <span className="text-[var(--text-muted)]">req {item.request_id}</span>
                  <span className="text-[var(--text-muted)]">· {item.status}</span>
                  <span className="text-[var(--text-muted)] ml-auto">{fmtTime(item.created_at)}</span>
                </div>
                {item.note && <p className="text-[var(--text-secondary)] break-words">{item.note}</p>}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

const InterceptCard: React.FC<{ state: LoadState<InterceptResult>; onRetry: () => void }> = ({
  state,
  onRetry,
}) => (
  <div className={cardClass}>
    <div className="flex items-start justify-between gap-3 flex-wrap">
      <div className="flex items-center gap-2">
        <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--text-primary)]">
          <FlaskConical className="w-4 h-4" aria-hidden="true" />
        </div>
        <h3 className={headingClass}>Latest interception proof</h3>
      </div>
      <button type="button" onClick={onRetry} disabled={state.status === 'loading'} className={secondaryButtonClass}>
        <RefreshCw className={`w-3.5 h-3.5 ${state.status === 'loading' ? 'animate-spin' : ''}`} aria-hidden="true" />
        <span>Refresh</span>
      </button>
    </div>
    <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
      Result of the most recent <code className="font-mono">demo/intercept_check.py</code> run, which proves the guard sits between the model and the tool.
    </p>
    {state.status === 'loading' && <Spinner label="Loading interception result…" />}
    {state.status === 'error' && <ErrorBanner title="Could not load interception result" message={state.message} />}
    {state.status === 'ready' && !state.data.available && (
      <div className="p-3 rounded-md bg-[var(--surface-secondary)] border border-[var(--border)] text-xs text-[var(--text-secondary)] flex items-start gap-2">
        <AlertTriangle className="w-4 h-4 shrink-0 text-[var(--critical)]" aria-hidden="true" />
        <span>No result recorded yet. {state.data.message}</span>
      </div>
    )}
    {state.status === 'ready' && state.data.available && (
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs font-mono text-[var(--text-secondary)]">
          <PassFail ok={state.data.passed === true} />
          <span>mode: <span className="text-[var(--text-primary)]">{state.data.mode ?? 'unknown'}</span></span>
          <span>ran: <span className="text-[var(--text-primary)]">{fmtTime(state.data.ran_at)}</span></span>
        </div>
        <ul className="space-y-1">
          {(state.data.checks ?? []).map((check, i) => (
            <li
              key={`${check.step}-${i}`}
              className="flex items-start gap-2 p-2 rounded-md bg-[var(--surface-secondary)] border border-[var(--border)] text-[11px]"
            >
              <PassFail ok={check.ok} passLabel="OK" failLabel="FAIL" />
              <div className="min-w-0">
                <div className="font-mono font-medium text-[var(--text-primary)]">{check.step}</div>
                <div className="text-[var(--text-secondary)] break-words">{check.detail}</div>
              </div>
            </li>
          ))}
        </ul>
        {state.data.controlled_pair && (
          <div className="text-[11px] font-mono text-[var(--text-muted)]">controlled pair: {state.data.controlled_pair}</div>
        )}
      </div>
    )}
  </div>
);

export const ResponsibleAIPage: React.FC = () => {
  const [report, setReport] = useState<LoadState<RaiReport>>({ status: 'loading' });
  const [intercept, setIntercept] = useState<LoadState<InterceptResult>>({ status: 'loading' });

  const loadReport = useCallback(async () => {
    setReport({ status: 'loading' });
    try {
      const data = await fetchRaiReport();
      setReport({ status: 'ready', data });
    } catch (err: unknown) {
      setReport({ status: 'error', message: errorMessage(err) });
    }
  }, []);

  const loadIntercept = useCallback(async () => {
    setIntercept({ status: 'loading' });
    try {
      const data = await fetchInterceptResult();
      setIntercept({ status: 'ready', data });
    } catch (err: unknown) {
      setIntercept({ status: 'error', message: errorMessage(err) });
    }
  }, []);

  useEffect(() => {
    loadReport();
    loadIntercept();
  }, [loadReport, loadIntercept]);

  const handleFeedbackSubmitted = (record: FeedbackRecord) => {
    setReport((current) => {
      if (current.status !== 'ready') return current;
      const feed = current.data.contestability.feedback;
      const byKind = { ...feed.by_kind, [record.kind]: (feed.by_kind[record.kind] ?? 0) + 1 };
      return {
        status: 'ready',
        data: {
          ...current.data,
          contestability: {
            ...current.data.contestability,
            feedback: {
              ...feed,
              total: feed.total + 1,
              by_kind: byKind,
              latest: [...feed.latest, record].slice(-5),
            },
          },
        },
      };
    });
  };

  return (
    <div className="flex-1 p-4 lg:p-8 space-y-8 max-w-5xl mx-auto w-full bg-[var(--surface)]">
      {/* Editorial Title */}
      <div className="border-b border-[var(--border)] pb-5 space-y-2">
        <div className="text-xs font-mono uppercase text-[var(--text-primary)] font-semibold tracking-wider">
          Security Principles & Trust Charter
        </div>
        <h1 className="text-2xl lg:text-3xl font-bold font-mono tracking-tight text-[var(--text-primary)]">
          Responsible AI & Evaluation Governance
        </h1>
        <p className="text-sm text-[var(--text-secondary)] max-w-2xl leading-relaxed">
          Every number on this page is computed live by the backend from real evaluation runs and on-disk state. Where a measurement has not been taken, it says so.
        </p>
      </div>

      {/* Trust Philosophy Statement */}
      <div className="p-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] text-xs leading-relaxed text-[var(--text-primary)] space-y-2 shadow-xs">
        <div className="font-semibold text-sm flex items-center gap-2 text-[var(--text-primary)]">
          <Shield className="w-4 h-4 text-[var(--allow)]" aria-hidden="true" />
          <span>The Core Invariant: Security Decisions Must Be Explainable</span>
        </div>
        <p className="leading-relaxed text-[var(--text-secondary)]">
          A verdict is not an opaque probability. Every block links to deterministic rule IDs, line locations, and concrete remediation — and the evidence below is pulled from the engine, not written by hand.
        </p>
      </div>

      {report.status === 'loading' && (
        <div className="p-6 rounded-xl bg-[var(--surface-card)] border border-[var(--border)]">
          <Spinner label="Loading live responsible-AI report from backend…" />
        </div>
      )}

      {report.status === 'error' && (
        <div className="space-y-3">
          <ErrorBanner title="Backend unavailable — the governance report could not be loaded." message={report.message} />
          <button type="button" onClick={loadReport} className={secondaryButtonClass}>
            <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Retry</span>
          </button>
        </div>
      )}

      {report.status === 'ready' && (
        <>
          {/* Version strip */}
          <div className="p-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] flex flex-wrap items-center gap-x-6 gap-y-2 text-xs font-mono text-[var(--text-secondary)]">
            <div>
              Engine: <span className="font-semibold text-[var(--text-primary)]">{report.data.engine_version}</span>
            </div>
            <div>
              Rules: <span className="font-semibold text-[var(--text-primary)]">{report.data.rules_version}</span>
            </div>
            <div>
              Policy: <span className="font-semibold text-[var(--text-primary)]">{report.data.policy_version}</span>
            </div>
            <div>
              Model: <span className="font-semibold text-[var(--text-primary)]">{report.data.model_version}</span>
            </div>
            <div className="ml-auto text-[var(--text-muted)]">generated {fmtTime(report.data.generated_at)}</div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Transparency & Explainability */}
            <div className={cardClass}>
              <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--text-primary)]">
                <Eye className="w-4 h-4" aria-hidden="true" />
              </div>
              <h3 className={headingClass}>01. Transparency & Explainability</h3>
              <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1.5 text-xs">
                <dt className="text-[var(--text-secondary)]">Rule catalogue size</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{report.data.transparency.rule_catalogue_size}</dd>
                <dt className="text-[var(--text-secondary)]">Per-stage pipeline trace available</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{fmtBool(report.data.transparency.trace_available)}</dd>
                <dt className="text-[var(--text-secondary)]">Blocks in evaluation</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{report.data.explainability.blocked_in_evaluation}</dd>
                <dt className="text-[var(--text-secondary)]">Blocks with reason + lines</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{report.data.explainability.blocks_with_reason_and_lines}</dd>
                <dt className="text-[var(--text-secondary)]">Explanation coverage</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{fmtRatio(report.data.explainability.explanation_coverage)}</dd>
              </dl>
              {typeof report.data.transparency.trace_status === 'string' && (
                <p className="text-[11px] text-[var(--text-muted)]">{report.data.transparency.trace_status}</p>
              )}
              <p className="text-[11px] text-[var(--text-muted)]">
                Model card: <code className="font-mono">{report.data.transparency.model_card}</code>
              </p>
            </div>

            {/* Privacy */}
            <div className={cardClass}>
              <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--text-primary)]">
                <Lock className="w-4 h-4" aria-hidden="true" />
              </div>
              <h3 className={headingClass}>02. Privacy</h3>
              <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1.5 text-xs">
                <dt className="text-[var(--text-secondary)]">Raw code stored by default</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{fmtBool(report.data.privacy.raw_code_stored_by_default)}</dd>
                <dt className="text-[var(--text-secondary)]">Feedback stores raw code</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{fmtBool(report.data.privacy.feedback_raw_code_stored)}</dd>
                <dt className="text-[var(--text-secondary)]">Retention (days)</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">
                  {report.data.privacy.retention_days === null ? 'not set' : report.data.privacy.retention_days}
                </dd>
              </dl>
              <div>
                <h4 className={subHeadingClass}>Stored fields</h4>
                <ul className="flex flex-wrap gap-1.5 mt-1.5">
                  {report.data.privacy.stored_fields.map((field) => (
                    <li
                      key={field}
                      className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)]"
                    >
                      {field}
                    </li>
                  ))}
                </ul>
              </div>
              {report.data.privacy.retention_status && (
                <p className="text-[11px] text-[var(--text-muted)]">{report.data.privacy.retention_status}</p>
              )}
              <p className="text-[11px] text-[var(--text-secondary)]">{report.data.privacy.note}</p>
            </div>

            {/* Security of the guard */}
            <div className={cardClass}>
              <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--text-primary)]">
                <Cpu className="w-4 h-4" aria-hidden="true" />
              </div>
              <h3 className={headingClass}>03. Security of the Guard</h3>
              <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1.5 text-xs">
                <dt className="text-[var(--text-secondary)]">Max source bytes</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{report.data.security_of_guard.max_source_bytes.toLocaleString()}</dd>
                <dt className="text-[var(--text-secondary)]">AST node cap</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{report.data.security_of_guard.ast_node_cap.toLocaleString()}</dd>
                <dt className="text-[var(--text-secondary)]">AST depth cap</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{report.data.security_of_guard.ast_depth_cap}</dd>
                <dt className="text-[var(--text-secondary)]">Decode depth cap</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{report.data.security_of_guard.decode_depth_cap}</dd>
                <dt className="text-[var(--text-secondary)]">Per-request deadline (ms)</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{report.data.security_of_guard.per_request_deadline_ms}</dd>
                <dt className="text-[var(--text-secondary)]">Executes submitted code</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{fmtBool(report.data.security_of_guard.executes_submitted_code)}</dd>
                <dt className="text-[var(--text-secondary)]">Fail closed</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{fmtBool(report.data.reliability.fail_closed)}</dd>
              </dl>
              <p className="text-[11px] text-[var(--text-muted)]">
                No network in scan: {String(report.data.reliability.no_network_in_scan)}
              </p>
            </div>

            {/* Human oversight */}
            <div className={cardClass}>
              <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--text-primary)]">
                <UserCheck className="w-4 h-4" aria-hidden="true" />
              </div>
              <h3 className={headingClass}>04. Accountability & Oversight</h3>
              <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1.5 text-xs">
                <dt className="text-[var(--text-secondary)]">Audit chain valid (at report time)</dt>
                <dd className="text-right"><PassFail ok={report.data.accountability.chain_valid} /></dd>
                <dt className="text-[var(--text-secondary)]">Audit records</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{report.data.accountability.records}</dd>
                <dt className="text-[var(--text-secondary)]">Review queue</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{report.data.accountability.review_queue}</dd>
                <dt className="text-[var(--text-secondary)]">Feedback submissions</dt>
                <dd className="font-mono text-[var(--text-primary)] text-right">{report.data.contestability.feedback.total}</dd>
              </dl>
              <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
                Blocks ship with remediation guidance, and any verdict can be disputed through the feedback form below. Live chain verification is available on demand.
              </p>
            </div>
          </div>

          {/* Reliability: evaluation metrics */}
          <div className={`${cardClass} space-y-4`}>
            <h3 className={`${headingClass} flex items-center gap-2`}>
              <AlertTriangle className="w-4 h-4 text-[var(--critical)]" aria-hidden="true" />
              <span>Reliability · Evaluation on the public dev sample</span>
            </h3>
            <BinaryMetricsTable metrics={report.data.reliability.evaluation.binary} />
            <div className="flex flex-wrap gap-x-6 gap-y-1 text-[11px] font-mono text-[var(--text-secondary)]">
              <span>
                latency p50/p95/p99 (ms):{' '}
                <span className="text-[var(--text-primary)]">
                  {report.data.reliability.evaluation.latency_ms.p50} / {report.data.reliability.evaluation.latency_ms.p95} / {report.data.reliability.evaluation.latency_ms.p99}
                </span>
              </span>
              <span>
                incomplete: <span className="text-[var(--text-primary)]">{report.data.reliability.evaluation.incomplete_count}</span>
              </span>
              <span>
                errors: <span className="text-[var(--text-primary)]">{report.data.reliability.evaluation.error_count}</span>
              </span>
            </div>

            <details className="group">
              <summary className="cursor-pointer text-[11px] font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--border-strong)] rounded">
                Per-category breakdown ({Object.keys(report.data.reliability.evaluation.per_category).length} categories)
              </summary>
              <div className="overflow-x-auto mt-2">
                <table className="w-full text-xs border-collapse">
                  <caption className="sr-only">Per-category evaluation metrics</caption>
                  <thead>
                    <tr>
                      <th scope="col" className={thClass}>Category</th>
                      <th scope="col" className={thClass}>Support</th>
                      <th scope="col" className={thClass}>TP</th>
                      <th scope="col" className={thClass}>FP</th>
                      <th scope="col" className={thClass}>FN</th>
                      <th scope="col" className={thClass}>Precision</th>
                      <th scope="col" className={thClass}>Recall</th>
                      <th scope="col" className={thClass}>F1</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(report.data.reliability.evaluation.per_category).map(([cat, m]) => (
                      <tr key={cat}>
                        <th scope="row" className={`${tdClass} text-left font-medium`}>{cat}</th>
                        <td className={tdClass}>{m.support}</td>
                        <td className={tdClass}>{m.tp}</td>
                        <td className={tdClass}>{m.fp}</td>
                        <td className={tdClass}>{m.fn}</td>
                        <td className={tdClass}>{fmtRatio(m.precision)}</td>
                        <td className={tdClass}>{fmtRatio(m.recall)}</td>
                        <td className={tdClass}>{fmtRatio(m.f1)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          </div>

          {/* Fairness */}
          <div className={`${cardClass} space-y-4`}>
            <h3 className={`${headingClass} flex items-center gap-2`}>
              <Scale className="w-4 h-4 text-[var(--text-primary)]" aria-hidden="true" />
              <span>Fairness · Per-language behaviour</span>
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <caption className="sr-only">Recall and false-positive rate per language</caption>
                <thead>
                  <tr>
                    <th scope="col" className={thClass}>Language</th>
                    <th scope="col" className={thClass}>Support</th>
                    <th scope="col" className={thClass}>Recall</th>
                    <th scope="col" className={thClass}>FPR</th>
                    <th scope="col" className={thClass}>Within tolerance</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(report.data.fairness.by_language).map(([lang, row]) => {
                    const flagged = report.data.fairness.gaps_flagged.includes(lang);
                    const minSupport = report.data.fairness.tolerance.min_support ?? 0;
                    const tooSmall = row.support < minSupport;
                    return (
                      <tr key={lang}>
                        <th scope="row" className={`${tdClass} text-left font-medium`}>{lang}</th>
                        <td className={tdClass}>{row.support}</td>
                        <td className={tdClass}>{fmtRatio(row.recall)}</td>
                        <td className={tdClass}>{fmtRatio(row.fpr)}</td>
                        <td className={tdClass}>
                          {tooSmall ? (
                            <span className="text-[var(--text-muted)]">not assessed (support &lt; {minSupport})</span>
                          ) : (
                            <PassFail ok={!flagged} passLabel="OK" failLabel="GAP" />
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="flex flex-wrap gap-x-6 gap-y-1 text-[11px] font-mono text-[var(--text-secondary)]">
              {Object.entries(report.data.fairness.tolerance).map(([k, v]) => (
                <span key={k}>
                  {k}: <span className="text-[var(--text-primary)]">{v}</span>
                </span>
              ))}
            </div>
            <div className="text-xs">
              <span className="text-[var(--text-secondary)]">Gaps flagged: </span>
              {report.data.fairness.gaps_flagged.length === 0 ? (
                <span className="font-mono text-[var(--text-primary)]">none</span>
              ) : (
                <span className="font-mono text-[var(--block)]">{report.data.fairness.gaps_flagged.join(', ')}</span>
              )}
            </div>
            <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">{report.data.fairness.note}</p>
          </div>

          <AuditVerifyCard initial={report.data.reliability.audit_chain} />

          <InterceptCard state={intercept} onRetry={loadIntercept} />

          <FeedbackCard summary={report.data.contestability.feedback} onSubmitted={handleFeedbackSubmitted} />

          {/* Honest limits */}
          <div className={cardClass}>
            <h3 className={`${headingClass} flex items-center gap-2`}>
              <AlertTriangle className="w-4 h-4 text-[var(--critical)]" aria-hidden="true" />
              <span>Honest Limits</span>
            </h3>
            <ul className="text-xs text-[var(--text-secondary)] space-y-1.5 list-disc list-inside leading-relaxed">
              {report.data.honest_limits.map((limit) => (
                <li key={limit}>{limit}</li>
              ))}
            </ul>
          </div>
        </>
      )}

      {/* Interception card still useful if the report fails but the demo endpoint works */}
      {report.status === 'error' && <InterceptCard state={intercept} onRetry={loadIntercept} />}
    </div>
  );
};
