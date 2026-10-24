import React, { useState } from 'react';
import {
  Code2,
  Terminal,
  GitBranch,
  Copy,
  Check,
  CheckCircle2,
  Clock,
  Layers,
  ArrowRight,
  ExternalLink,
} from 'lucide-react';

interface IntegrationMethod {
  id: string;
  name: string;
  status: 'Available' | 'Beta' | 'SDK Ready';
  description: string;
  language: string;
  snippet: string;
  installCommand?: string;
}

const INTEGRATIONS: IntegrationMethod[] = [
  {
    id: 'rest-api',
    name: 'REST API Pre-Execution Endpoint',
    status: 'Available',
    description: 'Direct HTTP integration to inspect code payloads before runtime execution in your backend or agent coordinator.',
    language: 'bash',
    installCommand: 'curl -X POST http://localhost:8000/guard ...',
    snippet: `curl -X POST http://localhost:8000/guard \\
  -H "Content-Type: application/json" \\
  -d '{
    "code": "import os\\nprint(os.environ.get(\\"AWS_KEY\\"))",
    "code_language": "python"
  }'`,
  },
  {
    id: 'python-decorator',
    name: 'Python Guard Decorator (@kavach.guard)',
    status: 'SDK Ready',
    description: 'Wrap agentic execution functions with an interceptor decorator that evaluates generated strings before calling exec().',
    language: 'python',
    installCommand: 'pip install code-kavach-guard',
    snippet: `import code_kavach

@code_kavach.guard(action_on_block="raise")
def execute_agent_code(generated_python_str: str):
    """Safely intercepted before exec() runtime invocation."""
    exec(generated_python_str)`,
  },
  {
    id: 'github-actions',
    name: 'CI/CD Pipeline (GitHub Actions)',
    status: 'Available',
    description: 'Run automated static code verification on pull requests containing AI-generated script contributions.',
    language: 'yaml',
    snippet: `name: Code Kavach Security Scan
on: [pull_request, push]

jobs:
  kavach-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Code Kavach Scan
        uses: code-kavach/action@v1
        with:
          api-url: \${{ secrets.KAVACH_API_URL }}
          fail-on: BLOCK
          scan-dir: ./scripts`,
  },
  {
    id: 'cli-tool',
    name: 'Code Kavach Terminal CLI',
    status: 'Beta',
    description: 'Command-line pre-commit hook and developer tool to scan local scripts before git commits.',
    language: 'bash',
    installCommand: 'pip install code-kavach-cli',
    snippet: `# Scan a single script
kavach scan ./src/tasks/worker.py

# Scan an entire directory recursively
kavach scan ./scripts/ --fail-fast --format json`,
  },
  {
    id: 'node-client',
    name: 'TypeScript / Node.js SDK',
    status: 'Available',
    description: 'Client library for Node.js agent runners, LangChain, and AI Studio server backends.',
    language: 'typescript',
    installCommand: 'npm install @code-kavach/sdk',
    snippet: `import { KavachClient } from '@code-kavach/sdk';

const kavach = new KavachClient({ baseUrl: 'http://localhost:8000' });

const { verdict, risk_score, vulnerable_lines } = await kavach.scan({
  code: generatedCodeString,
  code_language: 'python'
});

if (verdict === 'BLOCK') {
  throw new SecurityQuarantineError('Blocked by Code Kavach');
}`,
  },
];

export const IntegrationsPage: React.FC = () => {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="flex-1 p-4 lg:p-8 space-y-6 max-w-6xl mx-auto w-full bg-[var(--surface)]">
      {/* Header */}
      <div className="border-b border-[var(--border)] pb-4">
        <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
          Developer Integrations & Runtimes
        </h1>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5">
          Integrate Code Kavach pre-execution inspection into Python decorators, CI/CD pipelines, and agent runtimes.
        </p>
      </div>

      {/* Grid of integrations */}
      <div className="grid grid-cols-1 gap-6">
        {INTEGRATIONS.map((item) => (
          <div
            key={item.id}
            className="p-5 rounded-lg bg-[var(--surface-card)] border border-[var(--border)] space-y-3 shadow-xs"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] pb-3">
              <div className="flex items-center gap-2.5">
                <h2 className="text-sm font-semibold text-[var(--text-primary)]">
                  {item.name}
                </h2>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                    item.status === 'Available'
                      ? 'bg-[var(--allow-background)] text-[var(--allow)]'
                      : item.status === 'SDK Ready'
                      ? 'bg-[var(--surface-secondary)] text-[var(--text-secondary)]'
                      : 'bg-[var(--critical-background)] text-[var(--critical)]'
                  }`}
                >
                  {item.status}
                </span>
              </div>

              <button
                onClick={() => handleCopy(item.id, item.snippet)}
                className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] flex items-center gap-1 font-mono"
              >
                {copiedId === item.id ? <Check className="w-3.5 h-3.5 text-[var(--allow)]" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedId === item.id ? 'Copied' : 'Copy Code'}</span>
              </button>
            </div>

            <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
              {item.description}
            </p>

            {item.installCommand && (
              <div className="flex items-center gap-2 p-2 rounded bg-[var(--surface-secondary)] font-mono text-xs text-[var(--text-primary)] border border-[var(--border)]">
                <Terminal className="w-3.5 h-3.5 text-[var(--text-muted)]" />
                <span className="flex-1">{item.installCommand}</span>
              </div>
            )}

            <pre className="p-3.5 rounded bg-[#171B19] dark:bg-[var(--surface)] text-[#D8DFD7] dark:text-[var(--text-primary)] font-mono text-xs overflow-x-auto leading-relaxed border border-[#272D29] dark:border-[var(--border)]">
              {item.snippet}
            </pre>
          </div>
        ))}
      </div>
    </div>
  );
};
