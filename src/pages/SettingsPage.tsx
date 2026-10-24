import React, { useState, useEffect } from 'react';
import {
  Server,
  Code,
  Shield,
  Trash2,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';
import { apiClient } from '../lib/api/client';
import { checkBackendHealth } from '../lib/api/health';
import { clearScanHistory, isLocalHistoryEnabled, setLocalHistoryEnabled } from '../lib/storage/history';

export const SettingsPage: React.FC = () => {
  const [baseUrl, setBaseUrl] = useState('');
  const [useMock, setUseMock] = useState(true);
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
    version?: string;
  } | null>(null);

  // Editor prefs
  const [fontSize, setFontSize] = useState('13');
  const [wordWrap, setWordWrap] = useState('on');
  const [lineNumbers, setLineNumbers] = useState('on');
  const [defaultLanguage, setDefaultLanguage] = useState('python');

  // Privacy
  const [historyEnabled, setHistoryEnabledState] = useState(true);
  const [historyClearedNotice, setHistoryClearedNotice] = useState(false);

  useEffect(() => {
    const config = apiClient.getConfig();
    setBaseUrl(config.baseUrl);
    setUseMock(config.useMock);
    setHistoryEnabledState(isLocalHistoryEnabled());

    if (typeof window !== 'undefined') {
      setFontSize(localStorage.getItem('kavach_editor_font_size') || '13');
      setWordWrap(localStorage.getItem('kavach_editor_word_wrap') || 'on');
      setLineNumbers(localStorage.getItem('kavach_editor_line_numbers') || 'on');
      setDefaultLanguage(localStorage.getItem('kavach_editor_default_lang') || 'python');
    }
  }, []);

  const handleSaveApiSettings = () => {
    apiClient.updateConfig({ baseUrl, useMock });
    setTestResult({
      success: true,
      message: 'API configuration saved successfully.',
    });
    setTimeout(() => setTestResult(null), 3000);
  };

  const handleTestConnection = async () => {
    setIsTesting(true);
    setTestResult(null);

    // Temporarily apply current input for test
    apiClient.updateConfig({ baseUrl, useMock });

    try {
      const health = await checkBackendHealth();
      if (health.isConnected) {
        setTestResult({
          success: true,
          message: `Connection established to FastAPI backend (${health.data?.version || 'v1.0'})`,
          version: health.data?.version,
        });
      } else {
        setTestResult({
          success: false,
          message: health.error || 'Backend service unreachable. Check if FastAPI server is running.',
        });
      }
    } catch (err: unknown) {
      setTestResult({
        success: false,
        message: err instanceof Error ? err.message : 'Connection test failed',
      });
    } finally {
      setIsTesting(false);
    }
  };

  const handleSaveEditorPrefs = () => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('kavach_editor_font_size', fontSize);
      localStorage.setItem('kavach_editor_word_wrap', wordWrap);
      localStorage.setItem('kavach_editor_line_numbers', lineNumbers);
      localStorage.setItem('kavach_editor_default_lang', defaultLanguage);
    }
    setTestResult({
      success: true,
      message: 'Editor preferences saved.',
    });
    setTimeout(() => setTestResult(null), 2500);
  };

  const handleClearHistory = () => {
    clearScanHistory();
    setHistoryClearedNotice(true);
    setTimeout(() => setHistoryClearedNotice(false), 3000);
  };

  const handleToggleHistory = (enabled: boolean) => {
    setLocalHistoryEnabled(enabled);
    setHistoryEnabledState(enabled);
  };

  return (
    <div className="flex-1 p-4 lg:p-8 space-y-8 max-w-4xl mx-auto w-full bg-[var(--surface)]">
      {/* Header */}
      <div className="border-b border-[var(--border)] pb-4">
        <h1 className="text-xl font-bold font-mono tracking-tight text-[var(--text-primary)]">
          Settings & Engine Configuration
        </h1>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5">
          Manage backend integration boundaries, deterministic offline mock mode, and editor preferences.
        </p>
      </div>

      {/* Global alert feedback */}
      {testResult && (
        <div
          className={`p-3 rounded-lg text-xs flex items-center gap-2 font-mono ${
            testResult.success
              ? 'bg-[var(--allow-background)] text-[var(--allow)] border border-[var(--allow-background)]'
              : 'bg-[var(--block-background)] text-[var(--block)] border border-[var(--block-background)]'
          }`}
        >
          {testResult.success ? (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          ) : (
            <AlertCircle className="w-4 h-4 shrink-0" />
          )}
          <span>{testResult.message}</span>
        </div>
      )}

      {/* 1. API Backend Connection */}
      <div className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-4 shadow-xs">
        <div className="flex items-center gap-2 pb-2 border-b border-[var(--border)]">
          <Server className="w-4 h-4 text-[var(--text-primary)]" />
          <h2 className="text-sm font-semibold text-[var(--text-primary)] font-mono">
            Security Engine API Endpoint
          </h2>
        </div>

        <div className="space-y-4 text-xs">
          <div>
            <label className="block font-mono text-[var(--text-secondary)] mb-1">
              Backend Service URL:
            </label>
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="http://localhost:8000"
              className="w-full py-2 px-3 rounded-md font-mono bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)]"
            />
            <p className="text-[11px] text-[var(--text-muted)] mt-1">
              Target for POST /guard, POST /guard/batch, and GET /health requests.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="font-semibold text-[var(--text-primary)] font-mono">
                Deterministic Mock Engine
              </div>
              <p className="text-[11px] text-[var(--text-secondary)]">
                Analyze code locally with built-in AST heuristics and rules when the backend is offline.
              </p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={useMock}
                onChange={(e) => setUseMock(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-[var(--border-strong)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-[var(--border)] after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-[var(--surface)] after:border-[var(--border)] after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[var(--primary)]"></div>
            </label>
          </div>

          <div className="flex items-center gap-2 pt-2">
            <button
              onClick={handleSaveApiSettings}
              className="px-4 py-1.5 rounded-lg bg-[var(--primary)] text-[var(--primary-foreground)] text-xs font-medium hover:bg-[var(--primary-hover)] transition-colors shadow-xs"
            >
              Save API Config
            </button>

            <button
              onClick={handleTestConnection}
              disabled={isTesting}
              className="px-3 py-1.5 rounded-lg bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)] text-xs font-mono hover:bg-[var(--surface-hover)] flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              {isTesting ? (
                <>
                  <div className="w-3 h-3 border-2 border-[var(--primary)] border-t-transparent rounded-full animate-spin" />
                  <span>Testing...</span>
                </>
              ) : (
                <>
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Test Connection</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* 2. Editor Preferences */}
      <div className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-4 shadow-xs">
        <div className="flex items-center gap-2 pb-2 border-b border-[var(--border)]">
          <Code className="w-4 h-4 text-[var(--text-primary)]" />
          <h2 className="text-sm font-semibold text-[var(--text-primary)] font-mono">
            Workbench & Editor Preferences
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div>
            <label className="block font-mono text-[var(--text-secondary)] mb-1">Default Language:</label>
            <select
              value={defaultLanguage}
              onChange={(e) => setDefaultLanguage(e.target.value)}
              className="w-full py-1.5 px-3 rounded-md bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)]"
            >
              <option value="python">Python</option>
              <option value="bash">Bash</option>
              <option value="javascript">JavaScript</option>
              <option value="sql">SQL</option>
              <option value="yaml">YAML</option>
            </select>
          </div>

          <div>
            <label className="block font-mono text-[var(--text-secondary)] mb-1">Editor Font Size:</label>
            <select
              value={fontSize}
              onChange={(e) => setFontSize(e.target.value)}
              className="w-full py-1.5 px-3 rounded-md bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)]"
            >
              <option value="12">12 px (Compact)</option>
              <option value="13">13 px (Default)</option>
              <option value="14">14 px (Comfortable)</option>
              <option value="16">16 px (Large)</option>
            </select>
          </div>

          <div>
            <label className="block font-mono text-[var(--text-secondary)] mb-1">Word Wrapping:</label>
            <select
              value={wordWrap}
              onChange={(e) => setWordWrap(e.target.value)}
              className="w-full py-1.5 px-3 rounded-md bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)]"
            >
              <option value="on">Enabled (Wrap long lines)</option>
              <option value="off">Disabled (Horizontal scrolling)</option>
            </select>
          </div>

          <div>
            <label className="block font-mono text-[var(--text-secondary)] mb-1">Line Numbers:</label>
            <select
              value={lineNumbers}
              onChange={(e) => setLineNumbers(e.target.value)}
              className="w-full py-1.5 px-3 rounded-md bg-[var(--surface)] border border-[var(--border)] text-[var(--text-primary)]"
            >
              <option value="on">Visible (Recommended for line navigation)</option>
              <option value="off">Hidden</option>
            </select>
          </div>
        </div>

        <div className="pt-2">
          <button
            onClick={handleSaveEditorPrefs}
            className="px-4 py-1.5 rounded-lg bg-[var(--primary)] text-[var(--primary-foreground)] text-xs font-medium hover:bg-[var(--primary-hover)] transition-colors shadow-xs"
          >
            Save Editor Preferences
          </button>
        </div>
      </div>

      {/* 3. Privacy & Storage Management */}
      <div className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-4 shadow-xs">
        <div className="flex items-center gap-2 pb-2 border-b border-[var(--border)]">
          <Shield className="w-4 h-4 text-[var(--text-primary)]" />
          <h2 className="text-sm font-semibold text-[var(--text-primary)] font-mono">
            Privacy & Audit Storage
          </h2>
        </div>

        <div className="space-y-3 text-xs">
          <div className="flex items-center justify-between p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
            <div>
              <div className="font-semibold text-[var(--text-primary)] font-mono">
                Store Local Scan Audit History
              </div>
              <p className="text-[11px] text-[var(--text-secondary)]">
                Retains snippet hashes and verdict decisions in your browser session for audit review.
              </p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={historyEnabled}
                onChange={(e) => handleToggleHistory(e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-[var(--border-strong)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-[var(--border)] after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-[var(--surface)] after:border-[var(--border)] after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[var(--primary)]"></div>
            </label>
          </div>

          <div className="flex items-center justify-between pt-1">
            <span className="text-xs text-[var(--text-muted)]">
              {historyClearedNotice ? 'Local history has been cleared!' : 'Clear stored browser logs'}
            </span>
            <button
              onClick={handleClearHistory}
              className="px-3.5 py-1.5 rounded-lg bg-[var(--surface)] border border-[var(--border)] text-[var(--block)] hover:bg-[var(--block-background)] text-xs font-mono flex items-center gap-1.5 transition-colors font-medium"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Erase Local Scan Records</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
