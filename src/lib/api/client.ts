// code_kavach API Client configuration and request handling

export interface ApiClientConfig {
  baseUrl: string;
  useMock: boolean;
  timeoutMs: number;
}

const DEFAULT_BASE_URL = import.meta.env?.VITE_API_BASE_URL || '';
const DEFAULT_USE_MOCK = import.meta.env?.VITE_USE_MOCK_API === 'true';

class ApiClient {
  private config: ApiClientConfig;

  constructor() {
    const savedBaseUrl = typeof window !== 'undefined' ? localStorage.getItem('code_kavach_api_url') : null;
    const savedUseMock = typeof window !== 'undefined' ? localStorage.getItem('code_kavach_use_mock') : null;

    this.config = {
      baseUrl: savedBaseUrl || DEFAULT_BASE_URL,
      useMock: savedUseMock !== null ? savedUseMock === 'true' : DEFAULT_USE_MOCK,
      timeoutMs: 8000,
    };
  }

  public getConfig(): ApiClientConfig {
    return { ...this.config };
  }

  public updateConfig(newConfig: Partial<ApiClientConfig>) {
    this.config = { ...this.config, ...newConfig };
    if (typeof window !== 'undefined') {
      localStorage.setItem('code_kavach_api_url', this.config.baseUrl);
      localStorage.setItem('code_kavach_use_mock', String(this.config.useMock));
    }
  }

  public async fetchWithTimeout(endpoint: string, options: RequestInit = {}): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    const url = `${this.config.baseUrl.replace(/\/+$/, '')}/${endpoint.replace(/^\/+/, '')}`;

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...options.headers,
        },
      });
      return response;
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') {
        throw new Error(`Connection to backend timed out after ${this.config.timeoutMs}ms.`);
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }
}

export const apiClient = new ApiClient();
