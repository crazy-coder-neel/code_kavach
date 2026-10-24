// Types for the governance / transparency endpoints served by the FastAPI backend.

export type RuleSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface CatalogueRule {
  id: string;
  rule_id: string;
  category: string;
  severity: RuleSeverity | string;
  languages: string[];
  matcher: string;
  rationale: string;
  references: string[];
  remediation: string;
  fixture: string;
}

export interface RulesResponse {
  rules_version: string;
  count: number;
  rules: CatalogueRule[];
}

export interface BinaryMetrics {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  fpr: number | null;
}

export interface CategoryMetrics extends BinaryMetrics {
  support: number;
}

export interface LatencyMetrics {
  p50: number;
  p95: number;
  p99: number;
}

export interface LanguageFairness {
  support: number;
  recall: number | null;
  fpr: number | null;
}

export interface AuditVerifyResponse {
  valid: boolean;
  records: number;
  first_broken_index: number | null;
  last_hash?: string;
  message: string;
}

export type FeedbackKind = 'false_positive' | 'false_negative' | 'other';

export interface FeedbackRecord {
  id: string;
  request_id: string;
  kind: FeedbackKind | string;
  note: string;
  created_at: string;
  status: string;
}

export interface FeedbackSummary {
  total: number;
  by_kind: Record<string, number>;
  raw_code_stored: boolean;
  latest: FeedbackRecord[];
}

export interface FeedbackSubmission {
  request_id: string;
  kind: FeedbackKind;
  note?: string;
}

export interface RaiReport {
  generated_at: string;
  engine_version: string;
  rules_version: string;
  policy_version: string;
  model_version: string;
  transparency: {
    trace_available: boolean;
    rule_catalogue_size: number;
    model_card: string;
    [key: string]: unknown;
  };
  explainability: {
    blocked_in_evaluation: number;
    blocks_with_reason_and_lines: number;
    explanation_coverage: number | null;
  };
  fairness: {
    by_language: Record<string, LanguageFairness>;
    tolerance: Record<string, number>;
    gaps_flagged: string[];
    note: string;
  };
  reliability: {
    evaluation: {
      binary: BinaryMetrics;
      per_category: Record<string, CategoryMetrics>;
      latency_ms: LatencyMetrics;
      incomplete_count: number;
      error_count: number;
    };
    audit_chain: AuditVerifyResponse;
    http_metrics: Record<string, unknown>;
    audit_queue: Record<string, unknown>;
    fail_closed: boolean;
    no_network_in_scan: string | boolean;
  };
  privacy: {
    raw_code_stored_by_default: boolean;
    stored_fields: string[];
    retention_days: number | null;
    retention_status?: string;
    feedback_raw_code_stored: boolean;
    note: string;
  };
  security_of_guard: {
    max_source_bytes: number;
    ast_node_cap: number;
    ast_depth_cap: number;
    decode_depth_cap: number;
    per_request_deadline_ms: number;
    executes_submitted_code: boolean;
  };
  accountability: {
    chain_valid: boolean;
    records: number;
    review_queue: string;
    [key: string]: unknown;
  };
  contestability: {
    feedback: FeedbackSummary;
    [key: string]: unknown;
  };
  honest_limits: string[];
}

export interface DesignDecision {
  id: string;
  title: string;
  status: string;
  source_status: string;
  file: string;
  body: string;
}

export interface DecisionsResponse {
  count: number;
  decisions: DesignDecision[];
}

export interface InterceptCheck {
  step: string;
  ok: boolean;
  detail: string;
}

export interface InterceptResult {
  available: boolean;
  ran_at?: string;
  mode?: string;
  passed?: boolean;
  checks?: InterceptCheck[];
  controlled_pair?: string;
  message?: string;
}

export interface PolicyResponse {
  policy_version: string;
  mode: string;
  block_threshold: number;
  gray_band: { low: number; high: number };
  decision_rule: string;
  categories_enabled: string[];
  limits: Record<string, number>;
  allowlists: Record<string, string[]>;
  note: string;
}

export interface ModelCard {
  model: string;
  version: string;
  type: string;
  intended_use: string;
  not_intended: string;
  inputs: string;
  outputs: string;
  training_data: string;
  metrics: Record<string, unknown>;
  thresholds: Record<string, unknown>;
  known_limitations: string[];
  licence: string;
}
