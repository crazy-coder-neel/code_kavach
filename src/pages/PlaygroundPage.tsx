import React, { useState } from 'react';
import {
  Terminal,
  Send,
  Copy,
  Check,
  RotateCcw,
  Clock,
  CheckCircle2,
  AlertCircle,
  FileCode,
} from 'lucide-react';
import { apiClient } from '../lib/api/client';
import { scanCode } from '../lib/api/guard';
import { checkBackendHealth } from '../lib/api/health';
import { evaluateBatch, BENCHMARK_SUITE_SAMPLES } from '../lib/api/batch';

type EndpointKey = 'POST_GUARD' | 'POST_BATCH' | 'GET_HEALTH';

export const PlaygroundPage: React.FC = () => {
  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointKey>('POST_GUARD');
  const [baseUrl, setBaseUrl] = useState(() => apiClient.getConfig().baseUrl);
  const [requestHeaders, setRequestHeaders] = useState('{\n  "Content-Type": "application/json"\n}');
  const [requestBody, setRequestBody] = useState(
    JSON.stringify(
      {
        code: "import os\nprint(os.environ.get('AWS_ACCESS_KEY_ID'))",
        code_language: "python",
      },
      null,
      2
    )
  );

  const [isLoading, setIsLoading] = useState(false);
  const [responseStatus, setResponseStatus] = useState<number | null>(null);
  const [statusText, setStatusText] = useState<string | null>(null);
  const [responseLatency, setResponseLatency] = useState<number | null>(null);
  const [responsePayload, setResponsePayload] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copiedResponse, setCopiedResponse] = useState(false);
  const [copiedRequest, setCopiedRequest] = useState(false);

  // Switch endpoint templates
  const handleSelectEndpoint = (key: EndpointKey) => {
    setSelectedEndpoint(key);
    setErrorMsg(null);
    setResponsePayload(null);
    setResponseStatus(null);

    if (key === 'POST_GUARD') {
      setRequestBody(
        JSON.stringify(
          {
            code: "import os\nprint(os.environ.get('AWS_ACCESS_KEY_ID'))",
            code_language: "python",
          },
          null,
          2
        )
      );
    } else if (key === 'POST_BATCH') {
      setRequestBody(
        JSON.stringify(
          [
            {
              id: "batch-1",
              code: "import math\nprint(math.sqrt(16))",
              code_language: "python",
              expected_verdict: "ALLOW",
            },
            {
              id: "batch-2",
              code: "import shutil\nshutil.rmtree('/etc')",
              code_language: "python",
              expected_verdict: "BLOCK",
            },
          ],
          null,
          2
        )
      );
    } else if (key === 'GET_HEALTH') {
      setRequestBody('// GET requests have no body payload');
    }
  };

  // Execute playground request
  const handleSendRequest = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    const start = performance.now();

    try {
      if (selectedEndpoint === 'POST_GUARD') {
        const parsed = JSON.parse(requestBody);
        const res = await scanCode({
          code: parsed.code || '',
          code_language: parsed.code_language || 'python',
        });
        const duration = Math.round(performance.now() - start);
        setResponseStatus(200);
        setStatusText('OK');
        setResponseLatency(duration);
        setResponsePayload(JSON.stringify(res, null, 2));
      } else if (selectedEndpoint === 'POST_BATCH') {
        const parsed = JSON.parse(requestBody);
        const res = await evaluateBatch(Array.isArray(parsed) ? parsed : [parsed]);
        const duration = Math.round(performance.now() - start);
        setResponseStatus(200);
        setStatusText('OK');
        setResponseLatency(duration);
        setResponsePayload(JSON.stringify(res, null, 2));
      } else if (selectedEndpoint === 'GET_HEALTH') {
        const health = await checkBackendHealth();
        const duration = Math.round(performance.now() - start);
        setResponseStatus(health.isConnected ? 200 : 503);
        setStatusText(health.isConnected ? 'OK' : 'Service Unavailable');
        setResponseLatency(duration);
        setResponsePayload(JSON.stringify(health, null, 2));
      }
    } catch (err: unknown) {
      const duration = Math.round(performance.now() - start);
      setResponseStatus(400);
      setStatusText('Bad Request');
      setResponseLatency(duration);
      const msg = err instanceof Error ? err.message : 'Request execution failed';
      setErrorMsg(msg);
      setResponsePayload(JSON.stringify({ error: msg }, null, 2));
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyRequest = () => {
    navigator.clipboard.writeText(requestBody);
    setCopiedRequest(true);
    setTimeout(() => setCopiedRequest(false), 2000);
  };

  const handleCopyResponse = () => {
    if (responsePayload) {
      navigator.clipboard.writeText(responsePayload);
      setCopiedResponse(true);
      setTimeout(() => setCopiedResponse(false), 2000);
    }
  };

  const isGet = selectedEndpoint === 'GET_HEALTH';

  return (
    <div className="flex-1 p-4 lg:p-8 space-y-6 max-w-7xl mx-auto w-full bg-[var(--surface)]">
      {/* Header */}
      <div className="border-b border-[var(--border)] pb-4">
        <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
          API Playground & Interactive Console
        </h1>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5">
          Send live requests to Code Kavach detection endpoints, inspect raw headers, and analyze structured JSON schemas.
        </p>
      </div>

      {/* Endpoint Selector Bar */}
      <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)] flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[var(--text-muted)]">Endpoint:</span>
          {(['POST_GUARD', 'POST_BATCH', 'GET_HEALTH'] as const).map((ep) => {
            const isSelected = selectedEndpoint === ep;
            const method = ep.startsWith('GET') ? 'GET' : 'POST';
            const path = ep === 'POST_GUARD' ? '/guard' : ep === 'POST_BATCH' ? '/guard/batch' : '/health';
            return (
              <button
                key={ep}
                onClick={() => handleSelectEndpoint(ep)}
                className={`px-3 py-1.5 rounded-md font-mono text-xs transition-colors flex items-center gap-1.5 border ${
                  isSelected
                    ? 'bg-[var(--surface)] text-[var(--text-primary)] border-[var(--border-strong)] font-semibold shadow-xs'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] border-transparent hover:bg-[var(--surface)]/50'
                }`}
              >
                <span
                  className={`text-[10px] font-bold px-1 rounded ${
                    'bg-[var(--surface-secondary)] text-[var(--text-secondary)]'
                  }`}
                >
                  {method}
                </span>
                <span>{path}</span>
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-[var(--text-muted)]">Target:</span>
          <span className="text-xs font-mono text-[var(--text-primary)] bg-[var(--surface)] px-2 py-1 rounded border border-[var(--border)]">
            {baseUrl}
          </span>
        </div>
      </div>

      {/* Main Split Console: Request (Left) + Response (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Request Pane */}
        <div className="lg:col-span-6 p-4 rounded-lg bg-[var(--surface-card)] border border-[var(--border)] space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[var(--border)]">
            <span className="font-mono text-xs font-semibold text-[var(--text-primary)]">
              Request Payload
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyRequest}
                className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] flex items-center gap-1"
                title="Copy request payload"
              >
                {copiedRequest ? <Check className="w-3.5 h-3.5 text-[var(--allow)]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedRequest ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-mono text-[var(--text-muted)] mb-1">
              JSON Body:
            </label>
            <textarea
              value={requestBody}
              disabled={isGet}
              onChange={(e) => setRequestBody(e.target.value)}
              rows={12}
              className="w-full p-3 font-mono text-xs rounded-md bg-[#171B19] dark:bg-[var(--surface)] text-[#D8DFD7] dark:text-[var(--text-primary)] border border-[#272D29] dark:border-[var(--border)] focus:outline-none focus:border-[var(--border-strong)] resize-y disabled:opacity-50"
            />
          </div>

          <div className="pt-2 flex justify-end">
            <button
              onClick={handleSendRequest}
              disabled={isLoading}
              className="px-4 py-2 rounded-md bg-[var(--primary)] hover:bg-[var(--primary-hover)] text-[var(--primary-foreground)] text-xs font-medium transition-colors flex items-center gap-2 shadow-xs disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Executing...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Send Request</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Response Pane */}
        <div className="lg:col-span-6 p-4 rounded-lg bg-[var(--surface-card)] border border-[var(--border)] space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[var(--border)]">
            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="font-semibold text-[var(--text-primary)]">Response</span>
              {responseStatus !== null && (
                <span
                  className={`px-1.5 py-0.2 rounded text-[11px] font-bold ${
                    responseStatus >= 200 && responseStatus < 300
                      ? 'bg-[var(--allow-background)] text-[var(--allow)]'
                      : 'bg-[var(--block-background)] text-[var(--block)]'
                  }`}
                >
                  {responseStatus} {statusText}
                </span>
              )}
              {responseLatency !== null && (
                <span className="text-[var(--text-muted)] text-[11px] flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {responseLatency}ms
                </span>
              )}
            </div>

            {responsePayload && (
              <button
                onClick={handleCopyResponse}
                className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] flex items-center gap-1 font-mono"
              >
                {copiedResponse ? <Check className="w-3.5 h-3.5 text-[var(--allow)]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedResponse ? 'Copied' : 'Copy'}</span>
              </button>
            )}
          </div>

          <div>
            <label className="block text-[11px] font-mono text-[var(--text-muted)] mb-1">
              Response Body:
            </label>
            {responsePayload ? (
              <pre className="p-3 rounded-md bg-[#171B19] dark:bg-[var(--surface)] text-[#D8DFD7] dark:text-[var(--text-primary)] font-mono text-xs overflow-x-auto max-h-[340px] leading-relaxed border border-[#272D29] dark:border-[var(--border)]">
                {responsePayload}
              </pre>
            ) : (
              <div className="p-12 text-center rounded-md bg-[var(--surface-secondary)] border border-dashed border-[var(--border)] text-xs text-[var(--text-muted)] font-mono">
                Click &quot;Send Request&quot; to inspect response status and payload.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
