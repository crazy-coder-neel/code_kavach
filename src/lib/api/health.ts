import { apiClient } from './client';
import { HealthCheckResponse } from '../../types/guard';

export async function checkBackendHealth(): Promise<{ isConnected: boolean; data?: HealthCheckResponse; error?: string }> {
  const config = apiClient.getConfig();

  if (config.useMock) {
    return {
      isConnected: false,
      data: {
        status: 'healthy',
        version: 'v0.9.4-local-engine',
        rules_version: '2026.10',
        supported_languages: ['python', 'bash', 'javascript', 'sql', 'yaml'],
        supported_categories: [
          'secret_access',
          'data_exfiltration',
          'destructive_command',
          'persistence_or_privesc',
          'obfuscated_execution',
          'dependency_risk',
          'resource_exhaustion',
          'ssrf_network_exfil',
          'ai_targeted_instructions',
        ],
      },
      error: 'Mock engine explicitly enabled in configuration.',
    };
  }

  try {
    const res = await apiClient.fetchWithTimeout('/readyz', { method: 'GET' });
    if (!res.ok) {
      return {
        isConnected: false,
        error: `HTTP ${res.status}: ${res.statusText}`,
      };
    }
    const raw = await res.json();
    if (raw.ready !== true || typeof raw.engine_version !== 'string') {
      throw new Error('Invalid backend health response.');
    }
    const data: HealthCheckResponse = {
      status: 'healthy', version: raw.engine_version, rules_version: raw.engine_version,
      supported_languages: ['python'], supported_categories: [],
    };
    return {
      isConnected: true,
      data,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Backend unreachable';
    return {
      isConnected: false,
      error: message,
    };
  }
}
