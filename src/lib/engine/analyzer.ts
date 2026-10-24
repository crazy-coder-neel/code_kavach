import {
  GuardRequest,
  GuardResponse,
  ThreatCategory,
  VulnerabilityFinding,
  SourceSinkFlow,
} from '../../types/guard';

interface DetectionRule {
  id: string;
  category: ThreatCategory;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  pattern: RegExp;
  evidenceTemplate: (match: string, line: string) => string;
  remediation: string;
  riskContribution: number;
}

const DETECTION_RULES: DetectionRule[] = [
  // Secret access
  {
    id: 'CK-SEC-101',
    category: 'secret_access',
    severity: 'CRITICAL',
    title: 'Access to Sensitive Environment Credentials',
    pattern: /(?:AWS_ACCESS_KEY|AWS_SECRET|GITHUB_TOKEN|DATABASE_URL|API_KEY|PRIVATE_KEY|SECRET_KEY|SLACK_TOKEN|JWT_SECRET)/i,
    evidenceTemplate: (m) => `Referenced sensitive credential identifier: "${m}" in environment/variable access.`,
    remediation: 'Do not access master secrets directly in dynamic snippets. Use scoped runtime IAM roles or a managed secret provider.',
    riskContribution: 0.45,
  },
  {
    id: 'CK-SEC-102',
    category: 'secret_access',
    severity: 'CRITICAL',
    title: 'Filesystem Credential Store Probing',
    pattern: /(?:\/etc\/shadow|\.ssh\/id_|\.aws\/credentials|\.env\b)/,
    evidenceTemplate: (m) => `Explicit path reference to credential store: "${m}".`,
    remediation: 'Block filesystem access to host private keys and system authentication databases.',
    riskContribution: 0.5,
  },

  // Destructive command
  {
    id: 'CK-DEST-301',
    category: 'destructive_command',
    severity: 'CRITICAL',
    title: 'Recursive Directory Removal on Sensitive Path',
    pattern: /(?:shutil\.rmtree\s*\(\s*["'](?:\/etc|\/var|\/usr|~|\/home|\/)|\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+["']?(?:\/|~|\/etc|\/var|\$HOME))/i,
    evidenceTemplate: (m) => `High-impact recursive deletion detected: "${m.trim()}".`,
    remediation: 'Restrict destructive filesystem operations to an ephemeral temporary container or validate target against a strict path whitelist.',
    riskContribution: 0.6,
  },
  {
    id: 'CK-DEST-302',
    category: 'destructive_command',
    severity: 'CRITICAL',
    title: 'Irreversible Storage Destruction Command',
    pattern: /(?:mkfs\.|dd\s+if=\/dev\/(?:zero|urandom)\s+of=\/dev\/|DROP\s+DATABASE|TRUNCATE\s+TABLE)/i,
    evidenceTemplate: (m) => `Storage format or bulk drop invocation: "${m}".`,
    remediation: 'Ensure database DDL or raw disk write commands are quarantined and require explicit administrative multi-party authorization.',
    riskContribution: 0.55,
  },

  // Obfuscated execution
  {
    id: 'CK-OBF-401',
    category: 'obfuscated_execution',
    severity: 'HIGH',
    title: 'Dynamic Evaluation of Decoded Payload',
    pattern: /(?:exec\s*\(\s*(?:base64\b|decoded|zlib|codecs)|eval\s*\(\s*(?:base64\b|atob|Buffer\.from)|compile\s*\(.*['"]exec['"]\))/i,
    evidenceTemplate: (m) => `Dynamic execution wrapper invoking eval/exec on decoded input: "${m}".`,
    remediation: 'Disallow dynamic byte compilation and string evaluation. Ship static modules with verifiable hashes.',
    riskContribution: 0.45,
  },
  {
    id: 'CK-OBF-402',
    category: 'obfuscated_execution',
    severity: 'MEDIUM',
    title: 'Suspicious Base64 / Hex Encoded String Payload',
    pattern: /['"](?:[A-Za-z0-9+/]{40,}={0,2})['"]/,
    evidenceTemplate: (m) => `Long encoded blob detected (${m.length} characters) matching base64 staging pattern.`,
    remediation: 'Decode and inspect inline payload before execution. Enforce payload signing.',
    riskContribution: 0.25,
  },

  // Data exfiltration
  {
    id: 'CK-EXFIL-201',
    category: 'data_exfiltration',
    severity: 'CRITICAL',
    title: 'Outbound HTTP Request to Unverified Endpoint',
    pattern: /(?:urllib\.request\.urlopen|requests\.post|fetch\s*\(|axios\.post|http\.client|curl\s+-[X|d])/i,
    evidenceTemplate: (m) => `External network call detected via "${m.trim()}".`,
    remediation: 'Implement an egress network firewall allowing only pre-approved API hosts. Prohibit generic webhook beacons.',
    riskContribution: 0.4,
  },

  // SSRF & Cloud Metadata
  {
    id: 'CK-SSRF-501',
    category: 'ssrf_network_exfil',
    severity: 'CRITICAL',
    title: 'Cloud Instance Metadata Service (IMDS) Probe',
    pattern: /(?:169\.254\.169\.254|metadata\.google\.internal|latest\/meta-data)/,
    evidenceTemplate: (m) => `Targeting link-local cloud metadata service IP/host: "${m}".`,
    remediation: 'Enforce IMDSv2 with token hops restricted to 1, or block 169.254.169.254 at the container network interface.',
    riskContribution: 0.5,
  },

  // Resource exhaustion
  {
    id: 'CK-DOS-601',
    category: 'resource_exhaustion',
    severity: 'HIGH',
    title: 'Process Replication / Fork Bomb Pattern',
    pattern: /(?::\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|bomb\s*\(\)\s*\{|\bos\.fork\(\)\s*while\s+True|while\s+True\s*:\s*(?:os\.fork|multiprocessing))/i,
    evidenceTemplate: (m) => `Self-replicating process pattern detected: "${m.replace(/\s+/g, ' ')}".`,
    remediation: 'Set strict process and task limits (e.g., ulimit -u, cgroup pids.max) to prevent process table exhaustion.',
    riskContribution: 0.55,
  },

  // Persistence or privesc
  {
    id: 'CK-PRIV-701',
    category: 'persistence_or_privesc',
    severity: 'HIGH',
    title: 'System Persistence Modification or Privilege Escalation',
    pattern: /(?:\/etc\/cron|crontab\s+-[e|r]|systemctl\s+enable|sudo\s+su|chmod\s+[0-7]{3,4}\s+\/bin)/i,
    evidenceTemplate: (m) => `Privilege escalation or service persistence command: "${m}".`,
    remediation: 'Run code in an unprivileged container without CAP_SYS_ADMIN, read-only root filesystem, and no-new-privileges flag.',
    riskContribution: 0.4,
  },

  // Dependency risk
  {
    id: 'CK-DEP-801',
    category: 'dependency_risk',
    severity: 'HIGH',
    title: 'Runtime Package Installation or Typosquat Import',
    pattern: /(?:pip\s+install\s+(?:--upgrade|--extra-index-url)|subprocess\.(?:call|run)\s*\(\s*\[.*pip.*install)/i,
    evidenceTemplate: (m) => `Runtime package manager invocation: "${m}".`,
    remediation: 'Build dependencies into immutable container images; disable runtime package installation during job execution.',
    riskContribution: 0.35,
  },

  // AI-targeted instructions
  {
    id: 'CK-AI-901',
    category: 'ai_targeted_instructions',
    severity: 'MEDIUM',
    title: 'Adversarial Prompt Injection Marker in Comments',
    pattern: /(?:ignore\s+previous\s+instructions|system\s+prompt\s+override|DAN\s+mode|bypass\s+safety\s+filter)/i,
    evidenceTemplate: (m) => `Jailbreak / instruction override marker detected: "${m}".`,
    remediation: 'Sanitize code comments and LLM prompts before downstream processing or code synthesis.',
    riskContribution: 0.3,
  },
];

export function analyzeCodeDeterministically(request: GuardRequest): GuardResponse {
  const startTime = performance.now();
  const lines = request.code.split('\n');
  const findings: VulnerabilityFinding[] = [];
  const vulnerableLinesSet = new Set<number>();
  const detectedCategoriesSet = new Set<ThreatCategory>();
  let aggregatedRisk = 0;

  lines.forEach((lineText, idx) => {
    const lineNum = idx + 1;
    const trimmed = lineText.trim();
    if (!trimmed || trimmed.startsWith('#') && !trimmed.toLowerCase().includes('ignore previous instructions')) {
      // Don't flag benign comments unless adversarial
      return;
    }

    for (const rule of DETECTION_RULES) {
      const match = rule.pattern.exec(lineText);
      if (match) {
        vulnerableLinesSet.add(lineNum);
        detectedCategoriesSet.add(rule.category);
        aggregatedRisk += rule.riskContribution;

        findings.push({
          id: `find-${rule.id}-${lineNum}`,
          category: rule.category,
          rule_id: rule.id,
          severity: rule.severity,
          line_number: lineNum,
          title: rule.title,
          evidence: rule.evidenceTemplate(match[0], lineText),
          remediation: rule.remediation,
          snippet: trimmed,
        });
      }
    }
  });

  // Flow analysis (detect source to sink if both secret access and exfil present)
  const sourceSinkFlows: SourceSinkFlow[] = [];
  const hasSecrets = findings.some((f) => f.category === 'secret_access');
  const hasExfil = findings.some((f) => f.category === 'data_exfiltration');
  const hasObfuscation = findings.some((f) => f.category === 'obfuscated_execution');

  if (hasSecrets && hasExfil) {
    const secretFinding = findings.find((f) => f.category === 'secret_access')!;
    const exfilFinding = findings.find((f) => f.category === 'data_exfiltration')!;
    sourceSinkFlows.push({
      id: 'flow-01',
      source: {
        description: 'Sensitive credential access from environment',
        line: secretFinding.line_number,
        code: secretFinding.snippet || 'os.environ.get(...)',
      },
      transform: hasObfuscation
        ? {
            description: 'Base64 payload encoding & serialization',
            line: findings.find((f) => f.category === 'obfuscated_execution')?.line_number || secretFinding.line_number + 2,
            code: 'base64.b64encode(json.dumps(payload))',
          }
        : undefined,
      sink: {
        description: 'Unauthorized outbound network transmission',
        line: exfilFinding.line_number,
        code: exfilFinding.snippet || 'urllib.request.urlopen(...)',
      },
    });
  }

  // Calculate calibrated risk score
  const categories = Array.from(detectedCategoriesSet);
  let riskScore = 0.02; // Baseline benign baseline noise
  if (findings.length > 0) {
    // Diminishing returns formula bounded strictly in [0.0, 1.0]
    riskScore = Math.min(0.99, Math.max(0.45, 1 - Math.exp(-aggregatedRisk)));
    riskScore = Math.round(riskScore * 100) / 100;
  }

  const verdict = riskScore >= 0.40 ? 'BLOCK' : 'ALLOW';

  let reason = 'No supported threat indicators were detected. Code static structure passed safety heuristics.';
  if (verdict === 'BLOCK') {
    const topFinding = findings[0];
    reason = `Execution blocked: ${topFinding.title} detected on line ${topFinding.line_number}. ${topFinding.evidence}`;
  }

  const durationMs = Math.max(18, Math.round(performance.now() - startTime + Math.random() * 25));

  const scanId = `sc_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 7)}`;

  return {
    scan_id: scanId,
    verdict,
    risk_score: riskScore,
    categories,
    code_language: request.code_language,
    reason,
    vulnerable_lines: Array.from(vulnerableLinesSet).sort((a, b) => a - b),
    findings,
    source_sink_flows: sourceSinkFlows,
    metadata: {
      detector_version: 'v0.9.4-kavach-static',
      parser_status: 'SUCCESS',
      duration_ms: durationMs,
      timestamp: new Date().toISOString(),
      is_mock: true,
    },
  };
}
