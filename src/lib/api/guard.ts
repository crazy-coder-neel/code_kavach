import { GuardRequest, GuardResponse, VulnerabilityFinding } from '../../types/guard';
import { apiClient } from './client';
import { analyzeCodeDeterministically } from '../engine/analyzer';

export function normalizeGuardResponse(data: any): GuardResponse {
  if (!data || !['allow', 'block'].includes(data.verdict) ||
      typeof data.risk_score !== 'number' || !Number.isFinite(data.risk_score) ||
      data.risk_score < 0 || data.risk_score > 1 ||
      !Array.isArray(data.categories) || !data.categories.every((v: unknown) => typeof v === 'string') ||
      typeof data.code_language !== 'string' || typeof data.reason !== 'string' ||
      !Array.isArray(data.vulnerable_lines) ||
      !data.vulnerable_lines.every((v: unknown) => Number.isInteger(v) && Number(v) > 0)) {
    throw new Error('Invalid scanner response. No execution is authorized.');
  }
  return {
    scan_id: data.request_id || crypto.randomUUID(),
    verdict: data.verdict === 'allow' ? 'ALLOW' : 'BLOCK',
    risk_score: data.risk_score,
    categories: data.categories,
    code_language: data.code_language,
    reason: data.reason,
    vulnerable_lines: data.vulnerable_lines,
    findings: (data.findings || []).map((f: any, i: number): VulnerabilityFinding => ({
      id: `${f.rule_id}-${i}`, category: f.category, rule_id: f.rule_id,
      severity: f.severity.toUpperCase(), line_number: f.lines[0],
      end_line_number: f.lines.at(-1), title: f.title,
      evidence: f.why, snippet: f.evidence, remediation: f.remediation, fix: f.fix,
    })),
    analysis_complete: data.analysis_complete,
    cache_status: data.cache_status,
    score_trace: data.score_trace,
    decision_cards: data.decision_cards,
    metadata: {
      detector_version: data.engine_version || 'unknown',
      parser_status: data.analysis_complete === true ? 'SUCCESS' : 'FALLBACK',
      duration_ms: data.latency_ms ?? 0,
      timestamp: new Date().toISOString(), is_mock: false,
    },
  };
}

export async function scanCode(request: GuardRequest): Promise<GuardResponse> {
  if (apiClient.getConfig().useMock) return analyzeCodeDeterministically(request);
  const res = await apiClient.fetchWithTimeout('/v1/guard?detail=full', {
    method: 'POST', body: JSON.stringify({ code: request.code }),
  });
  if (!res.ok) throw new Error(`Scanner unavailable (HTTP ${res.status}). No execution is authorized.`);
  return normalizeGuardResponse(await res.json());
}
