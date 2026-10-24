import { BatchItemResult, BatchEvaluationSummary, ThreatCategory } from '../../types/guard';

export function calculateBatchMetrics(results: BatchItemResult[]): BatchEvaluationSummary {
  const total = results.length;
  if (total === 0) {
    return {
      total_evaluated: 0,
      allow_count: 0,
      block_count: 0,
      error_count: 0,
      avg_latency_ms: 0,
      p50_latency_ms: 0,
      p95_latency_ms: 0,
      has_ground_truth: false,
    };
  }

  let allowCount = 0;
  let blockCount = 0;
  let errorCount = 0;
  const latencies: number[] = [];

  let truePositives = 0; // expected BLOCK, predicted BLOCK
  let falsePositives = 0; // expected ALLOW, predicted BLOCK
  let trueNegatives = 0; // expected ALLOW, predicted ALLOW
  let falseNegatives = 0; // expected BLOCK, predicted ALLOW
  let itemsWithGroundTruth = 0;

  const categoryBreakdown: Record<ThreatCategory, { count: number; true_positives: number }> = {
    secret_access: { count: 0, true_positives: 0 },
    data_exfiltration: { count: 0, true_positives: 0 },
    destructive_command: { count: 0, true_positives: 0 },
    persistence_or_privesc: { count: 0, true_positives: 0 },
    obfuscated_execution: { count: 0, true_positives: 0 },
    dependency_risk: { count: 0, true_positives: 0 },
    resource_exhaustion: { count: 0, true_positives: 0 },
    ssrf_network_exfil: { count: 0, true_positives: 0 },
    ai_targeted_instructions: { count: 0, true_positives: 0 },
  };

  results.forEach((r) => {
    latencies.push(r.duration_ms);
    if (r.error) {
      errorCount++;
    } else if (r.verdict === 'ALLOW') {
      allowCount++;
    } else if (r.verdict === 'BLOCK') {
      blockCount++;
    }

    // Category tally
    r.categories.forEach((cat) => {
      if (categoryBreakdown[cat]) {
        categoryBreakdown[cat].count++;
        if (r.expected_verdict === 'BLOCK') {
          categoryBreakdown[cat].true_positives++;
        }
      }
    });

    if (r.expected_verdict) {
      itemsWithGroundTruth++;
      if (r.expected_verdict === 'BLOCK' && r.verdict === 'BLOCK') {
        truePositives++;
      } else if (r.expected_verdict === 'ALLOW' && r.verdict === 'BLOCK') {
        falsePositives++;
      } else if (r.expected_verdict === 'ALLOW' && r.verdict === 'ALLOW') {
        trueNegatives++;
      } else if (r.expected_verdict === 'BLOCK' && r.verdict === 'ALLOW') {
        falseNegatives++;
      }
    }
  });

  latencies.sort((a, b) => a - b);
  const avgLatency = Math.round(latencies.reduce((acc, curr) => acc + curr, 0) / (total || 1));
  const p50 = latencies[Math.floor(latencies.length * 0.5)] || 0;
  const p95 = latencies[Math.floor(latencies.length * 0.95)] || latencies[latencies.length - 1] || 0;

  const hasGroundTruth = itemsWithGroundTruth > 0;

  let accuracy: number | undefined;
  let precision: number | undefined;
  let recall: number | undefined;
  let f1Score: number | undefined;
  let fpr: number | undefined;
  let fnr: number | undefined;

  if (hasGroundTruth) {
    const totalPredictionsWithLabel = truePositives + falsePositives + trueNegatives + falseNegatives;
    accuracy = totalPredictionsWithLabel > 0 ? (truePositives + trueNegatives) / totalPredictionsWithLabel : 0;

    const predictedPositives = truePositives + falsePositives;
    precision = predictedPositives > 0 ? truePositives / predictedPositives : 1.0;

    const actualPositives = truePositives + falseNegatives;
    recall = actualPositives > 0 ? truePositives / actualPositives : 1.0;

    f1Score = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

    const actualNegatives = trueNegatives + falsePositives;
    fpr = actualNegatives > 0 ? falsePositives / actualNegatives : 0;
    fnr = actualPositives > 0 ? falseNegatives / actualPositives : 0;
  }

  return {
    total_evaluated: total,
    allow_count: allowCount,
    block_count: blockCount,
    error_count: errorCount,
    avg_latency_ms: avgLatency,
    p50_latency_ms: p50,
    p95_latency_ms: p95,
    has_ground_truth: hasGroundTruth,
    accuracy: accuracy !== undefined ? Math.round(accuracy * 1000) / 1000 : undefined,
    precision: precision !== undefined ? Math.round(precision * 1000) / 1000 : undefined,
    recall: recall !== undefined ? Math.round(recall * 1000) / 1000 : undefined,
    f1_score: f1Score !== undefined ? Math.round(f1Score * 1000) / 1000 : undefined,
    false_positive_rate: fpr !== undefined ? Math.round(fpr * 1000) / 1000 : undefined,
    false_negative_rate: fnr !== undefined ? Math.round(fnr * 1000) / 1000 : undefined,
    category_breakdown: categoryBreakdown,
  };
}
