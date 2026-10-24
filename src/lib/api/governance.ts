import { apiClient } from './client';
import {
  AuditVerifyResponse,
  DecisionsResponse,
  FeedbackRecord,
  FeedbackSubmission,
  FeedbackSummary,
  InterceptResult,
  ModelCard,
  PolicyResponse,
  RaiReport,
  RulesResponse,
} from '../../types/governance';

async function getJson<T>(endpoint: string): Promise<T> {
  const res = await apiClient.fetchWithTimeout(endpoint, { method: 'GET' });
  if (!res.ok) throw new Error(`Backend returned HTTP ${res.status} for ${endpoint}.`);
  return (await res.json()) as T;
}

export async function fetchRules(): Promise<RulesResponse> {
  const data = await getJson<RulesResponse>('/v1/rules');
  if (!Array.isArray(data.rules)) throw new Error('Invalid rules response from backend.');
  return data;
}

export async function fetchRaiReport(): Promise<RaiReport> {
  return getJson<RaiReport>('/v1/rai/report');
}

export async function verifyAuditChain(): Promise<AuditVerifyResponse> {
  const data = await getJson<AuditVerifyResponse>('/v1/audit/verify');
  if (typeof data.valid !== 'boolean') throw new Error('Invalid audit verification response.');
  return data;
}

export async function submitFeedback(body: FeedbackSubmission): Promise<FeedbackRecord> {
  const res = await apiClient.fetchWithTimeout('/v1/feedback', {
    method: 'POST',
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const err = await res.json();
      if (typeof err?.detail === 'string') detail = err.detail;
    } catch {
      // response had no JSON body; keep the status text
    }
    throw new Error(`Feedback was not accepted: ${detail}`);
  }
  return (await res.json()) as FeedbackRecord;
}

export async function fetchFeedbackSummary(): Promise<FeedbackSummary> {
  return getJson<FeedbackSummary>('/v1/feedback');
}

export async function fetchDecisions(): Promise<DecisionsResponse> {
  const data = await getJson<DecisionsResponse>('/v1/docs/decisions');
  if (!Array.isArray(data.decisions)) throw new Error('Invalid decisions response from backend.');
  return data;
}

export async function fetchInterceptResult(): Promise<InterceptResult> {
  return getJson<InterceptResult>('/v1/demo/intercept');
}

export async function fetchPolicy(): Promise<PolicyResponse> {
  return getJson<PolicyResponse>('/v1/policy');
}

export async function fetchModelCard(): Promise<ModelCard> {
  return getJson<ModelCard>('/v1/docs/model-card');
}
