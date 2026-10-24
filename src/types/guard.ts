export type Verdict = 'ALLOW' | 'BLOCK' | 'INDETERMINATE';

export type ThreatCategory =
  | 'secret_access'
  | 'data_exfiltration'
  | 'destructive_command'
  | 'persistence_or_privesc'
  | 'obfuscated_execution'
  | 'dependency_risk'
  | 'resource_exhaustion'
  | 'ssrf_network_exfil'
  | 'ai_targeted_instructions';

export type CodeLanguage = 'python' | 'bash' | 'javascript' | 'sql' | 'yaml' | 'markdown' | 'unknown';

export interface ThreatCategoryMeta {
  id: ThreatCategory;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cwe?: string;
}

export interface VulnerabilityFinding {
  id: string;
  category: ThreatCategory;
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  line_number: number;
  end_line_number?: number;
  title: string;
  evidence: string;
  remediation: string;
  snippet?: string;
  fix?: { title: string; steps: string[]; example: string | null; caveat: string }; 
}

export interface SourceSinkFlow {
  id: string;
  source: {
    description: string;
    line: number;
    code: string;
  };
  transform?: {
    description: string;
    line: number;
    code: string;
  };
  sink: {
    description: string;
    line: number;
    code: string;
  };
}

export interface GuardRequest {
  code: string;
  code_language: CodeLanguage;
  metadata?: {
    caller_id?: string;
    context?: string;
  };
}

export interface GuardResponse {
  scan_id: string;
  verdict: Verdict;
  risk_score: number; // 0.00 to 1.00
  categories: ThreatCategory[];
  code_language: CodeLanguage;
  reason: string;
  vulnerable_lines: number[];
  findings?: VulnerabilityFinding[];
  source_sink_flows?: SourceSinkFlow[];
  analysis_complete?: boolean;
  cache_status?: string;
  score_trace?: Record<string, unknown>;
  decision_cards?: DecisionCard[];
  runtime_trace?: RuntimeTraceStep[];
  metadata?: {
    detector_version: string;
    parser_status: 'SUCCESS' | 'PARTIAL' | 'FALLBACK';
    duration_ms: number;
    timestamp: string;
    is_mock: boolean;
  };
}

export interface RuntimeTraceStep {
  step_name: string;
  description: string;
  input: Record<string, unknown>;
  output: Record<string, unknown>;
  duration_ms: number;
  skipped: boolean;
  skip_reason?: string | null;
}

export interface DecisionCard {
  decision: string;
  why: string;
  rule_id: string;
  severity: string | null;
  confidence: number | null;
  evidence: { lines: number[]; redacted_snippet: string };
  guards_checked: { guard: string; result: boolean }[];
  guard_evidence_status?: string;
  alternatives_considered: string[];
  alternative_status?: string;
  references: string[];
  remediation: string;
}

export interface BatchItem {
  id: string;
  code: string;
  code_language: CodeLanguage;
  expected_verdict?: Verdict;
  expected_categories?: ThreatCategory[];
  description?: string;
}

export interface BatchItemResult {
  id: string;
  code_language: CodeLanguage;
  verdict: Verdict;
  risk_score: number;
  categories: ThreatCategory[];
  reason: string;
  vulnerable_lines: number[];
  duration_ms: number;
  error?: string;
  expected_verdict?: Verdict;
  match?: boolean;
}

export interface BatchEvaluationSummary {
  total_evaluated: number;
  allow_count: number;
  block_count: number;
  error_count: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  // Metrics when ground truth is provided
  has_ground_truth: boolean;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  false_positive_rate?: number;
  false_negative_rate?: number;
  category_breakdown?: Record<ThreatCategory, { count: number; true_positives: number }>;
}

export interface BatchEvaluationResponse {
  batch_id: string;
  results: BatchItemResult[];
  summary: BatchEvaluationSummary;
  timestamp: string;
}

export interface HealthCheckResponse {
  status: 'healthy' | 'degraded' | 'offline';
  version: string;
  rules_version: string;
  uptime_seconds?: number;
  supported_languages: CodeLanguage[];
  supported_categories: ThreatCategory[];
}
