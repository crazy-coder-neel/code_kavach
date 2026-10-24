import { GuardResponse } from '../../types/guard';

export interface ScanHistoryRecord {
  id: string;
  timestamp: string;
  code_snippet: string; // Truncated or stored locally if user opted-in
  full_code?: string;
  code_language: string;
  verdict: 'ALLOW' | 'BLOCK' | 'INDETERMINATE';
  risk_score: number;
  categories: string[];
  reason: string;
  vulnerable_lines: number[];
  duration_ms: number;
  is_mock: boolean;
}

const STORAGE_KEY = 'code_kavach_scan_history';
const OPT_IN_KEY = 'code_kavach_save_history_enabled';

export function isLocalHistoryEnabled(): boolean {
  if (typeof window === 'undefined') return false;
  const val = localStorage.getItem(OPT_IN_KEY);
  return val !== 'false'; // default to enabled for developer convenience, but easily cleared
}

export function setLocalHistoryEnabled(enabled: boolean) {
  if (typeof window === 'undefined') return;
  localStorage.setItem(OPT_IN_KEY, String(enabled));
  if (!enabled) {
    clearScanHistory();
  }
}

export function getScanHistory(): ScanHistoryRecord[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      // Seed 4 realistic demonstration records
      const seeds: ScanHistoryRecord[] = [
        {
          id: 'sc_init_91k',
          timestamp: new Date(Date.now() - 1000 * 60 * 14).toISOString(),
          code_snippet: 'shutil.rmtree(path, ignore_errors=True)\nprint(f"Purged target: {path}")',
          full_code: 'import os\nimport shutil\n\ndef wipe():\n    shutil.rmtree("/etc", ignore_errors=True)\n\nwipe()',
          code_language: 'python',
          verdict: 'BLOCK',
          risk_score: 0.89,
          categories: ['destructive_command'],
          reason: 'Execution blocked: Recursive Directory Removal on Sensitive Path detected on line 5.',
          vulnerable_lines: [5],
          duration_ms: 32,
          is_mock: true,
        },
        {
          id: 'sc_init_83m',
          timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
          code_snippet: 'def calculate_moving_average(prices: list[float], window_size: int = 7):',
          full_code: 'def calculate_moving_average(prices: list[float], window_size: int = 7):\n    return [sum(prices[i:i+window_size])/window_size for i in range(len(prices)-window_size+1)]',
          code_language: 'python',
          verdict: 'ALLOW',
          risk_score: 0.02,
          categories: [],
          reason: 'No supported threat indicators were detected. Code static structure passed safety heuristics.',
          vulnerable_lines: [],
          duration_ms: 19,
          is_mock: true,
        },
        {
          id: 'sc_init_72p',
          timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
          code_snippet: 'payload = "aW1wb3J0IG9zCg=="\nexec(base64.b64decode(payload))',
          full_code: 'import base64\npayload = "aW1wb3J0IG9zCg=="\nexec(base64.b64decode(payload))',
          code_language: 'python',
          verdict: 'BLOCK',
          risk_score: 0.78,
          categories: ['obfuscated_execution'],
          reason: 'Execution blocked: Dynamic Evaluation of Decoded Payload detected on line 3.',
          vulnerable_lines: [3],
          duration_ms: 24,
          is_mock: true,
        },
        {
          id: 'sc_init_65q',
          timestamp: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
          code_snippet: 'SELECT user_id, email, status FROM accounts WHERE status = ?',
          full_code: 'SELECT user_id, email, status FROM accounts WHERE status = ?;',
          code_language: 'sql',
          verdict: 'ALLOW',
          risk_score: 0.01,
          categories: [],
          reason: 'No supported threat indicators were detected. Parameterized query structure valid.',
          vulnerable_lines: [],
          duration_ms: 15,
          is_mock: true,
        },
      ];
      localStorage.setItem(STORAGE_KEY, JSON.stringify(seeds));
      return seeds;
    }
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

export function saveScanToHistory(code: string, response: GuardResponse): void {
  if (!isLocalHistoryEnabled() || typeof window === 'undefined') return;

  try {
    const history = getScanHistory();
    const record: ScanHistoryRecord = {
      id: response.scan_id,
      timestamp: response.metadata?.timestamp || new Date().toISOString(),
      code_snippet: code.slice(0, 180),
      full_code: code,
      code_language: response.code_language,
      verdict: response.verdict,
      risk_score: response.risk_score,
      categories: response.categories,
      reason: response.reason,
      vulnerable_lines: response.vulnerable_lines,
      duration_ms: response.metadata?.duration_ms || 25,
      is_mock: response.metadata?.is_mock ?? true,
    };

    // Prepend and cap at 50 records to prevent storage bloat
    const updated = [record, ...history.filter((h) => h.id !== record.id)].slice(0, 50);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch (err) {
    console.warn('Could not save scan history', err);
  }
}

export function clearScanHistory(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(STORAGE_KEY);
}
