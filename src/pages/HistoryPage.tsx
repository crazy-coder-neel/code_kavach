import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  History,
  Search,
  Trash2,
  ChevronRight,
  ShieldCheck,
  ShieldX,
  Code2,
  AlertTriangle,
} from 'lucide-react';
import {
  getScanHistory,
  clearScanHistory,
  ScanHistoryRecord,
  isLocalHistoryEnabled,
  setLocalHistoryEnabled,
} from '../lib/storage/history';

export const HistoryPage: React.FC = () => {
  const [records, setRecords] = useState<ScanHistoryRecord[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterVerdict, setFilterVerdict] = useState<'ALL' | 'ALLOW' | 'BLOCK'>('ALL');
  const [filterLanguage, setFilterLanguage] = useState<string>('ALL');
  const [selectedRecord, setSelectedRecord] = useState<ScanHistoryRecord | null>(null);
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [historyEnabled, setHistoryEnabledState] = useState(true);

  const navigate = useNavigate();

  useEffect(() => {
    setRecords(getScanHistory());
    setHistoryEnabledState(isLocalHistoryEnabled());
  }, []);

  const handleClear = () => {
    clearScanHistory();
    setRecords([]);
    setSelectedRecord(null);
    setShowClearConfirm(false);
  };

  const handleToggleHistory = (val: boolean) => {
    setLocalHistoryEnabled(val);
    setHistoryEnabledState(val);
    if (!val) {
      setRecords([]);
      setSelectedRecord(null);
    }
  };

  const handleLoadInWorkbench = (_record: ScanHistoryRecord) => {
    navigate('/app/scan');
  };

  const filteredRecords = records.filter((r) => {
    const matchesSearch =
      r.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.code_snippet.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.categories.some((c) => c.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesVerdict = filterVerdict === 'ALL' || r.verdict === filterVerdict;
    const matchesLang = filterLanguage === 'ALL' || r.code_language.toLowerCase() === filterLanguage.toLowerCase();

    return matchesSearch && matchesVerdict && matchesLang;
  });

  return (
    <div className="flex-1 p-4 lg:p-8 space-y-6 max-w-7xl mx-auto w-full bg-[var(--surface)]">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border)] pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-[var(--text-primary)]">
            Scan Audit History
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Audit trail of analyzed snippets, assigned verdicts, and calibrated threat scores.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {records.length > 0 && (
            <button
              onClick={() => setShowClearConfirm(true)}
              className="px-3 py-1.5 text-xs font-mono rounded-lg bg-[var(--surface)] hover:bg-[var(--block-background)] text-[var(--block)] border border-[var(--border)] transition-colors flex items-center gap-1.5"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Erase History</span>
            </button>
          )}
        </div>
      </div>

      {/* Privacy Notice Strip */}
      <div className="p-3.5 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] flex flex-wrap items-center justify-between gap-3 text-xs text-[var(--text-secondary)]">
        <div>
          <strong className="text-[var(--text-primary)]">Privacy Boundary: </strong>
          Scan records are retained only in your local browser sandbox and never shared across tenants.
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 cursor-pointer">
            <input
              type="checkbox"
              checked={historyEnabled}
              onChange={(e) => handleToggleHistory(e.target.checked)}
              className="rounded accent-[var(--primary)]"
            />
            <span className="font-mono text-[11px] text-[var(--text-primary)]">
              Enable local audit logging
            </span>
          </label>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-1 max-w-sm">
          <Search className="w-4 h-4 text-[var(--text-muted)]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by ID, keyword, or category..."
            className="w-full py-1.5 px-3 text-xs rounded-md bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)]"
          />
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
          <div className="flex items-center gap-1">
            <span className="text-[var(--text-muted)]">Verdict:</span>
            {(['ALL', 'ALLOW', 'BLOCK'] as const).map((v) => (
              <button
                key={v}
                onClick={() => setFilterVerdict(v)}
                className={`px-2.5 py-0.5 rounded-md text-[11px] transition-colors ${
                  filterVerdict === v
                    ? 'bg-[var(--primary)] text-[var(--primary-foreground)] font-semibold'
                    : 'bg-[var(--surface-secondary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--border)]'
                }`}
              >
                {v}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1">
            <span className="text-[var(--text-muted)]">Language:</span>
            <select
              value={filterLanguage}
              onChange={(e) => setFilterLanguage(e.target.value)}
              className="py-1 px-2.5 text-xs rounded-md bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)]"
            >
              <option value="ALL">All Languages</option>
              <option value="python">Python</option>
              <option value="bash">Bash</option>
              <option value="javascript">JavaScript</option>
              <option value="sql">SQL</option>
            </select>
          </div>
        </div>
      </div>

      {/* History Records List - White card layout */}
      {filteredRecords.length > 0 ? (
        <div className="rounded-xl bg-[var(--surface)] border border-[var(--border)] divide-y divide-[var(--border)] overflow-hidden shadow-xs">
          {filteredRecords.map((r) => {
            const isBlocked = r.verdict === 'BLOCK';
            return (
              <div
                key={r.id}
                onClick={() => setSelectedRecord(r)}
                className="p-4 hover:bg-[var(--surface-secondary)] cursor-pointer transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="flex items-start gap-3">
                  <div
                    className={`p-2 rounded-md mt-0.5 ${
                      isBlocked
                        ? 'bg-[var(--block-background)] text-[var(--block)] border border-[var(--block-background)]'
                        : 'bg-[var(--allow-background)] text-[var(--allow)] border border-[var(--allow-background)]'
                    }`}
                  >
                    {isBlocked ? <ShieldX className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
                  </div>

                  <div className="space-y-1">
                    <div className="flex items-center gap-2 font-mono">
                      <span className="font-semibold text-sm text-[var(--text-primary)]">
                        {r.id}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-[var(--surface-secondary)] uppercase text-[var(--text-secondary)] border border-[var(--border)]">
                        {r.code_language}
                      </span>
                      <span
                        className={`font-bold ${
                          isBlocked
                            ? 'text-[var(--block)]'
                            : 'text-[var(--allow)]'
                        }`}
                      >
                        {r.verdict}
                      </span>
                      <span className="text-[var(--text-muted)]">
                        · Score {r.risk_score.toFixed(2)}
                      </span>
                    </div>

                    <p className="text-[var(--text-primary)] line-clamp-1">
                      {r.reason}
                    </p>

                    <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-[var(--text-muted)]">
                      <span>{new Date(r.timestamp).toLocaleString()}</span>
                      <span>·</span>
                      <span>{r.duration_ms} ms</span>
                      {r.categories.length > 0 && (
                        <>
                          <span>·</span>
                          <span className="text-[var(--block)] font-medium">
                            {r.categories.join(', ')}
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
                  <span className="text-xs text-[var(--text-primary)] hover:underline flex items-center gap-1 font-mono font-medium">
                    View Findings <ChevronRight className="w-3.5 h-3.5" />
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="p-12 text-center rounded-xl bg-[var(--surface)] border border-[var(--border)] space-y-2">
          <History className="w-8 h-8 text-[var(--text-muted)] mx-auto" />
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">No Scan Records Found</h3>
          <p className="text-xs text-[var(--text-secondary)] max-w-sm mx-auto">
            {records.length === 0
              ? 'Run an evaluation in the Security Workbench to record your first scan.'
              : 'No entries match your search query or filter criteria.'}
          </p>
        </div>
      )}

      {/* Record Inspection Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 bg-black/45 z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-[var(--surface-card)] border border-[var(--border)] rounded-xl shadow-2xl p-5 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
              <div className="flex items-center gap-2 font-mono">
                <span className="text-sm font-bold text-[var(--text-primary)]">
                  Scan Audit: {selectedRecord.id}
                </span>
                <span
                  className={`text-xs font-bold px-2 py-0.5 rounded-md ${
                    selectedRecord.verdict === 'BLOCK'
                      ? 'bg-[var(--block-background)] text-[var(--block)] border border-[var(--block-background)]'
                      : 'bg-[var(--allow-background)] text-[var(--allow)] border border-[var(--allow-background)]'
                  }`}
                >
                  {selectedRecord.verdict}
                </span>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="text-xs font-mono text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Close ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
                <div className="font-semibold text-[var(--text-primary)] mb-1">
                  Verdict Reason
                </div>
                <div className="text-[var(--text-secondary)] leading-relaxed">{selectedRecord.reason}</div>
              </div>

              <div>
                <div className="font-mono text-xs text-[var(--text-muted)] mb-1.5 flex items-center justify-between">
                  <span>Submitted Code Snippet ({selectedRecord.code_language}):</span>
                  <span>{new Date(selectedRecord.timestamp).toLocaleTimeString()}</span>
                </div>
                <pre className="p-3.5 rounded-lg bg-[#171B19] dark:bg-[var(--surface)] text-[#D8DFD7] dark:text-[var(--text-primary)] font-mono text-[11px] overflow-x-auto max-h-56 border border-[#272D29] dark:border-[var(--border)]">
                  {selectedRecord.full_code || selectedRecord.code_snippet}
                </pre>
              </div>

              {selectedRecord.categories.length > 0 && (
                <div>
                  <div className="font-mono text-xs text-[var(--text-muted)] mb-1">Flagged Categories:</div>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedRecord.categories.map((c) => (
                      <span
                        key={c}
                        className="px-2 py-0.5 rounded-md bg-[var(--block-background)] text-[var(--block)] border border-[var(--block-background)] font-mono text-xs font-semibold"
                      >
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="pt-2 border-t border-[var(--border)] flex items-center justify-between">
              <button
                onClick={() => handleLoadInWorkbench(selectedRecord)}
                className="px-3.5 py-1.5 rounded-lg bg-[var(--primary)] text-[var(--primary-foreground)] text-xs font-medium hover:bg-[var(--primary-hover)] flex items-center gap-1.5 transition-colors"
              >
                <Code2 className="w-3.5 h-3.5" />
                <span>Open in Workbench</span>
              </button>

              <button
                onClick={() => setSelectedRecord(null)}
                className="px-4 py-1.5 rounded-lg bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)] text-xs font-medium hover:bg-[var(--surface-secondary)] transition-colors"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Clear Confirmation Dialog */}
      {showClearConfirm && (
        <div className="fixed inset-0 bg-black/45 z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-[var(--surface-card)] border border-[var(--border)] rounded-xl shadow-2xl p-5 space-y-4">
            <div className="flex items-center gap-2.5 text-[var(--block)]">
              <AlertTriangle className="w-5 h-5" />
              <h3 className="font-semibold text-sm">Erase All Local Scan Records?</h3>
            </div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
              This will permanently delete all stored scan history from your browser cache. This action cannot be undone.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setShowClearConfirm(false)}
                className="px-3 py-1.5 text-xs rounded-lg bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--surface-secondary)] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleClear}
                className="px-3.5 py-1.5 text-xs rounded-lg bg-[var(--block)] text-[var(--primary-foreground)] font-medium hover:opacity-90 transition-colors"
              >
                Yes, Erase History
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
