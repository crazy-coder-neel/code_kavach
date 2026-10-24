import React from 'react';
import {
  Shield,
  Eye,
  AlertTriangle,
  Lock,
  UserCheck,
  Cpu,
} from 'lucide-react';

export const ResponsibleAIPage: React.FC = () => {
  return (
    <div className="flex-1 p-4 lg:p-8 space-y-8 max-w-5xl mx-auto w-full bg-[var(--surface)]">
      {/* Editorial Title */}
      <div className="border-b border-[var(--border)] pb-5 space-y-2">
        <div className="text-xs font-mono uppercase text-[var(--text-primary)] font-semibold tracking-wider">
          Security Principles & Trust Charter
        </div>
        <h1 className="text-2xl lg:text-3xl font-bold font-mono tracking-tight text-[var(--text-primary)]">
          Responsible AI & Evaluation Governance
        </h1>
        <p className="text-sm text-[var(--text-secondary)] max-w-2xl leading-relaxed">
          How code_kavach approaches explainability, deterministic verification, privacy boundaries, and false-positive reduction without opaque LLM-as-a-judge arbiters.
        </p>
      </div>

      {/* Trust Philosophy Statement */}
      <div className="p-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] text-xs leading-relaxed text-[var(--text-primary)] space-y-2 shadow-xs">
        <div className="font-semibold text-sm flex items-center gap-2 text-[var(--text-primary)]">
          <Shield className="w-4 h-4 text-[var(--allow)]" />
          <span>The Core Invariant: Security Decisions Must Be Explainable</span>
        </div>
        <p className="leading-relaxed text-[var(--text-secondary)]">
          Security cannot rely on hallucinations. A scan verdict in code_kavach is not an opaque numerical probability emitted by a black-box model. Every verdict links directly to deterministic AST observations, identified rule IDs, line locations, and concrete remediation instructions.
        </p>
      </div>

      {/* Four Pillars Grid - Pure White Cards with subtle borders */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* 1. Transparency */}
        <div className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-3 shadow-xs">
          <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--text-primary)]">
            <Eye className="w-4 h-4" />
          </div>
          <h3 className="font-semibold text-sm text-[var(--text-primary)] font-mono">
            01. Total Transparency & Evidence Trails
          </h3>
          <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
            Every scan returns an explicit breakdown of:
          </p>
          <ul className="text-xs text-[var(--text-secondary)] space-y-1.5 list-disc list-inside leading-relaxed">
            <li><strong className="text-[var(--text-primary)]">Verdict:</strong> Binary ALLOW / BLOCK decision.</li>
            <li><strong className="text-[var(--text-primary)]">Taxonomy Tags:</strong> Mapped to the 9 PS3 threat categories and relevant CWEs.</li>
            <li><strong className="text-[var(--text-primary)]">Evidence:</strong> The exact code structure, variable access, or syscall matched.</li>
            <li><strong className="text-[var(--text-primary)]">Gutter Highlights:</strong> Exact line numbers so developers can verify immediately.</li>
          </ul>
        </div>

        {/* 2. Reliability & Limitations */}
        <div className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-3 shadow-xs">
          <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--critical)]">
            <AlertTriangle className="w-4 h-4" />
          </div>
          <h3 className="font-semibold text-sm text-[var(--text-primary)] font-mono">
            02. Honest Reliability & Limits
          </h3>
          <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
            Static analysis is fundamentally subject to Rice’s Theorem: it is mathematically impossible for a static tool to predict every runtime path without executing it.
          </p>
          <ul className="text-xs text-[var(--text-secondary)] space-y-1.5 list-disc list-inside leading-relaxed">
            <li>A verdict is a <strong className="text-[var(--text-primary)]">security assessment</strong>, never a mathematical guarantee of safety.</li>
            <li>Highly convoluted multi-stage reflections or compiled dynamic extensions may produce false negatives.</li>
            <li>Legitimate system administration scripts (e.g. log cleanup) may trigger false-positive alerts by design.</li>
          </ul>
        </div>

        {/* 3. Privacy Boundary */}
        <div className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-3 shadow-xs">
          <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--text-primary)]">
            <Lock className="w-4 h-4" />
          </div>
          <h3 className="font-semibold text-sm text-[var(--text-primary)] font-mono">
            03. Privacy & Zero-Retention
          </h3>
          <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
            Developer code contains proprietary IP and potential organizational secrets.
          </p>
          <ul className="text-xs text-[var(--text-secondary)] space-y-1.5 list-disc list-inside leading-relaxed">
            <li>Code submitted to code_kavach is held in memory solely for the duration of the analysis pass.</li>
            <li>Submitted code is never used to train or fine-tune public language models.</li>
            <li>Client history is stored only in the developer’s local browser storage, and can be purged instantly.</li>
          </ul>
        </div>

        {/* 4. Human Oversight */}
        <div className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-3 shadow-xs">
          <div className="w-8 h-8 rounded-lg bg-[var(--surface-secondary)] flex items-center justify-center text-[var(--text-primary)]">
            <UserCheck className="w-4 h-4" />
          </div>
          <h3 className="font-semibold text-sm text-[var(--text-primary)] font-mono">
            04. Developer Oversight & Overrides
          </h3>
          <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
            Automated guardrails must empower developers, not lock them out of productive workflows.
          </p>
          <ul className="text-xs text-[var(--text-secondary)] space-y-1.5 list-disc list-inside leading-relaxed">
            <li>When code_kavach blocks a script, it provides remediation guidance rather than a silent failure.</li>
            <li>Developers can inspect findings, verify whether the flagged pattern was intentional, and adjust security contexts accordingly.</li>
          </ul>
        </div>
      </div>

      {/* Evaluation Methodology Section */}
      <div className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-4 shadow-xs">
        <h3 className="font-semibold text-sm text-[var(--text-primary)] font-mono flex items-center gap-2">
          <Cpu className="w-4 h-4 text-[var(--text-primary)]" />
          <span>Evaluation Methodology & Metrics Standards</span>
        </h3>
        <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
          In CodeGuard PS3 benchmark evaluations, metric integrity is preserved through explicit mathematical definitions:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
            <div className="font-bold text-[var(--text-primary)]">Precision</div>
            <div className="text-[var(--text-muted)] text-[11px] mt-1">TP / (TP + FP)</div>
            <p className="text-[var(--text-secondary)] text-[10px] mt-1.5 font-sans leading-relaxed">
              Ensures that when a block is issued, it reflects genuine threat indicators with minimal false alarms.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
            <div className="font-bold text-[var(--text-primary)]">Recall</div>
            <div className="text-[var(--text-muted)] text-[11px] mt-1">TP / (TP + FN)</div>
            <p className="text-[var(--text-secondary)] text-[10px] mt-1.5 font-sans leading-relaxed">
              Measures the proportion of actual malicious behaviors successfully caught before execution.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border)]">
            <div className="font-bold text-[var(--text-primary)]">False Positive Rate (FPR)</div>
            <div className="text-[var(--text-muted)] text-[11px] mt-1">FP / (FP + TN)</div>
            <p className="text-[var(--text-secondary)] text-[10px] mt-1.5 font-sans leading-relaxed">
              Critical for developer usability—minimizing nuisance blocks on benign computational code.
            </p>
          </div>
        </div>
      </div>

      {/* Metadata & Audit Credentials */}
      <div className="p-4 rounded-xl bg-[var(--surface-secondary)] border border-[var(--border)] flex flex-wrap items-center justify-between gap-4 text-xs font-mono text-[var(--text-secondary)]">
        <div>
          <span>Engine: </span>
          <span className="font-semibold text-[var(--text-primary)]">
            code_kavach v0.9.4-static-ast
          </span>
        </div>
        <div>
          <span>Ruleset Version: </span>
          <span className="font-semibold text-[var(--text-primary)]">2026.10-PS3</span>
        </div>
        <div>
          <span>Mode: </span>
          <span className="font-semibold text-[var(--allow)]">
            Zero-Telemetry Local AST
          </span>
        </div>
      </div>
    </div>
  );
};
