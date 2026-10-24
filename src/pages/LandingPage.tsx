import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowRight,
  CheckCircle2,
  ShieldCheck,
  ShieldX,
} from 'lucide-react';
import { Logo } from '../components/brand/Logo';
import { ThemeSelector } from '../components/layout/ThemeSelector';
import { THREAT_TAXONOMY } from '../lib/constants/taxonomy';
import { ThreatCategory } from '../types/guard';

const HERO_SENTENCE =
  'An explainable pre-execution security layer for AI-generated and user-submitted code. Inspect abstract syntax trees, pinpoint suspicious syscalls, and enforce deterministic verdicts before execution begins.';

// Module-level flag to guarantee single execution per app session
let hasHeroAnimatedThisSession = false;

export const LandingPage: React.FC = () => {
  const navigate = useNavigate();
  const [activeHeroTab, setActiveHeroTab] = useState<'block' | 'allow'>('block');

  // Typing animation state for homepage hero
  const [displayedHeroText, setDisplayedHeroText] = useState<string>(() => {
    if (typeof window !== 'undefined') {
      const alreadyTyped =
        sessionStorage.getItem('kavach_hero_typed') === 'true' || hasHeroAnimatedThisSession;
      if (alreadyTyped) {
        return HERO_SENTENCE;
      }
      const prefersReducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches;
      if (prefersReducedMotion) {
        return HERO_SENTENCE;
      }
    }
    return '';
  });

  const [isTyping, setIsTyping] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      const alreadyTyped =
        sessionStorage.getItem('kavach_hero_typed') === 'true' || hasHeroAnimatedThisSession;
      if (alreadyTyped) {
        return false;
      }
      const prefersReducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches;
      if (prefersReducedMotion) {
        return false;
      }
      return true;
    }
    return false;
  });

  useEffect(() => {
    if (!isTyping) {
      hasHeroAnimatedThisSession = true;
      try {
        sessionStorage.setItem('kavach_hero_typed', 'true');
      } catch {
        // Ignore storage errors in restricted contexts
      }
      return;
    }

    let currentIndex = 0;
    const speedMs = 24; // 24ms per char (~4.5s total natural typing)

    const interval = setInterval(() => {
      currentIndex += 1;
      if (currentIndex <= HERO_SENTENCE.length) {
        setDisplayedHeroText(HERO_SENTENCE.slice(0, currentIndex));
      }
      if (currentIndex >= HERO_SENTENCE.length) {
        clearInterval(interval);
        setIsTyping(false);
        hasHeroAnimatedThisSession = true;
        try {
          sessionStorage.setItem('kavach_hero_typed', 'true');
        } catch {
          // Ignore
        }
      }
    }, speedMs);

    return () => clearInterval(interval);
  }, [isTyping]);

  const heroBlockSnippet = `import os
import shutil

def purge_system_artifacts():
    # Attempting recursive removal of critical system paths
    critical_target = "/etc/systemd"
    if os.path.exists(critical_target):
        shutil.rmtree(critical_target, ignore_errors=True)
        print("Purged.")`;

  const heroAllowSnippet = `import math

def calculate_moving_average(prices: list[float], window: int = 7):
    # Pure computational rolling statistics
    if not prices or len(prices) < window:
        return []
    return [sum(prices[i:i+window])/window for i in range(len(prices)-window+1)]`;

  const workflowSteps = [
    {
      num: '01',
      title: 'Code Ingestion',
      desc: 'Intercept AI-generated or developer code at the pre-execution boundary before runtime process invocation.',
    },
    {
      num: '02',
      title: 'AST & Static Traversal',
      desc: 'Parse syntax tree, identify sensitive module imports, variable assignments, and unverified socket sinks.',
    },
    {
      num: '03',
      title: 'Evidence Extraction',
      desc: 'Extract concrete evidence: exact source lines, invoked syscalls, and target file system paths.',
    },
    {
      num: '04',
      title: 'Calibrated Risk Scoring',
      desc: 'Compute bounded score (0.00 to 1.00) based on severity, context, and potential damage potential.',
    },
    {
      num: '05',
      title: 'Explainable Verdict',
      desc: 'Return binary ALLOW or BLOCK decision paired with line-level references and explicit remediation steps.',
    },
    {
      num: '06',
      title: 'Interception Enforcement',
      desc: 'Quarantine dangerous payloads before execution; allow verified computational tasks without friction.',
    },
  ];

  return (
    <div className="min-h-screen bg-[var(--surface)] text-[var(--text-primary)] flex flex-col font-sans transition-colors duration-150">
      {/* Top Bar - Pure white header */}
      <header className="h-16 border-b border-[var(--border)] bg-[var(--surface)] sticky top-0 z-40 px-4 sm:px-6 lg:px-12 flex items-center justify-between gap-3 md:gap-8">
        {/* Zone 1: Wordmark */}
        <Link to="/" className="flex items-center gap-2.5 whitespace-nowrap shrink-0 group">
          <Logo variant="full" size="md" />
        </Link>

        {/* Zone 2: Navigation Links */}
        <nav className="hidden lg:flex items-center gap-8 text-xs font-mono text-[var(--text-secondary)]">
          <Link to="/app/rules" className="hover:text-[var(--text-primary)] transition-colors whitespace-nowrap shrink-0">
            Rules & Detections
          </Link>
          <Link to="/app/playground" className="hover:text-[var(--text-primary)] transition-colors whitespace-nowrap shrink-0">
            API Playground
          </Link>
          <Link to="/app/integrations" className="hover:text-[var(--text-primary)] transition-colors whitespace-nowrap shrink-0">
            Integrations
          </Link>
          <Link to="/app/batch" className="hover:text-[var(--text-primary)] transition-colors whitespace-nowrap shrink-0">
            Batch Evaluation
          </Link>
          <Link to="/app/responsible-ai" className="hover:text-[var(--text-primary)] transition-colors whitespace-nowrap shrink-0">
            Trust Charter
          </Link>
        </nav>

        {/* Zone 3: Primary Action */}
        <div className="flex items-center gap-3 shrink-0">
          <ThemeSelector />
          <button
            onClick={() => navigate('/app/scan')}
            aria-label="Open Workbench"
            className="px-2.5 sm:px-4 py-2 text-xs font-medium text-[var(--primary-foreground)] bg-[var(--primary)] hover:bg-[var(--primary-hover)] rounded-lg transition-colors whitespace-nowrap shrink-0 shadow-xs flex items-center gap-1.5"
          >
            <span className="hidden sm:inline">Open Workbench</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      {/* Hero Section: Split Layout (Desktop Baseline 1440px) */}
      <section className="px-6 lg:px-12 py-12 lg:py-16 max-w-7xl mx-auto w-full flex-1 bg-[var(--surface)]">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
          {/* Left Column: Editorial Value Proposition */}
          <div className="lg:col-span-6 space-y-6">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-[var(--surface-secondary)] border border-[var(--border)] text-xs font-mono text-[var(--text-primary)] font-medium">
              <span>PRE-EXECUTION SECURITY</span>
              <span className="text-[var(--text-muted)]">·</span>
              <span>CODEGUARD PS3</span>
            </div>

            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold font-mono tracking-tight text-[var(--text-primary)] leading-[1.15]">
              Know what your code will do before it runs.
            </h1>

            {/* Zero-Layout-Shift Typed Hero Sentence */}
            <div className="relative text-base text-[var(--text-secondary)] leading-relaxed max-w-xl">
              {/* Invisible spacer guarantees zero layout shift */}
              <p className="invisible select-none pointer-events-none" aria-hidden="true">
                {HERO_SENTENCE}
              </p>
              {/* Visible animated typed text */}
              <p className="absolute inset-0">
                <span>{displayedHeroText}</span>
                {isTyping && (
                  <span
                    className="inline-block w-[2px] h-[1em] bg-[var(--primary)] ml-0.5 align-middle animate-pulse"
                    aria-hidden="true"
                  />
                )}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                onClick={() => navigate('/app/scan')}
                className="px-5 py-2.5 rounded-lg bg-[var(--primary)] hover:bg-[var(--primary-hover)] text-[var(--primary-foreground)] text-xs font-semibold tracking-wide transition-colors flex items-center gap-2 shadow-xs"
              >
                <span>Open Security Workbench</span>
                <ArrowRight className="w-4 h-4" />
              </button>

              <Link
                to="/app/rules"
                className="px-4 py-2.5 rounded-lg bg-[var(--surface)] hover:bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)] text-xs font-mono transition-colors"
              >
                Explore Rules & Taxonomy
              </Link>
            </div>

            {/* Trust statement */}
            <div className="pt-4 border-t border-[var(--border)] flex items-center gap-2.5 text-xs text-[var(--text-secondary)] font-mono">
              <CheckCircle2 className="w-4 h-4 text-[var(--allow)] shrink-0" />
              <span>Zero-LLM Judge · Deterministic AST Heuristics &lt;30ms · Grounded Line References</span>
            </div>
          </div>

          {/* Right Column: Live Interactive Product Preview */}
          <div className="lg:col-span-6">
            <div className="rounded-xl bg-[var(--surface)] border border-[var(--border)] shadow-xs overflow-hidden">
              {/* Preview Header & Scenario Selector */}
              <div className="p-3 bg-[var(--surface)] border-b border-[var(--border)] flex items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-[var(--border-strong)]" />
                  <span className="w-2.5 h-2.5 rounded-full bg-[var(--border-strong)]" />
                  <span className="w-2.5 h-2.5 rounded-full bg-[var(--border-strong)]" />
                  <span className="font-mono text-[11px] text-[var(--text-muted)] ml-2">
                    pre_execution_guard.py
                  </span>
                </div>

                <div className="flex items-center p-0.5 bg-[var(--surface-secondary)] rounded-lg border border-[var(--border)] text-[11px] font-mono">
                  <button
                    onClick={() => setActiveHeroTab('block')}
                    className={`px-2.5 py-1 rounded-md transition-colors ${
                      activeHeroTab === 'block'
                        ? 'bg-[var(--surface)] text-[var(--block)] font-semibold shadow-xs'
                        : 'text-[var(--text-secondary)]'
                    }`}
                  >
                    Threat Sample
                  </button>
                  <button
                    onClick={() => setActiveHeroTab('allow')}
                    className={`px-2.5 py-1 rounded-md transition-colors ${
                      activeHeroTab === 'allow'
                        ? 'bg-[var(--surface)] text-[var(--allow)] font-semibold shadow-xs'
                        : 'text-[var(--text-secondary)]'
                    }`}
                  >
                    Benign Sample
                  </button>
                </div>
              </div>

              {/* Code Surface */}
              <div className="p-4 bg-[#171B19] dark:bg-[var(--surface)] font-mono text-xs text-[#D8DFD7] dark:text-[var(--text-primary)] overflow-x-auto leading-relaxed border-b border-[#272D29] dark:border-[var(--border)]">
                <pre>
                  {activeHeroTab === 'block' ? heroBlockSnippet : heroAllowSnippet}
                </pre>
              </div>

              {/* Simulated Verdict Result Card */}
              <div className="p-4 bg-[var(--surface)]">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-3">
                    {activeHeroTab === 'block' ? (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-[var(--block-background)] text-[var(--block)] border border-[var(--block-background)]">
                        <ShieldX className="w-3.5 h-3.5" />
                        <span>BLOCK</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-[var(--allow-background)] text-[var(--allow)] border border-[var(--allow-background)]">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>ALLOW</span>
                      </span>
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-mono text-[var(--text-secondary)]">
                          Risk: {activeHeroTab === 'block' ? '0.89' : '0.02'}
                        </span>
                        <span className="text-[10px] text-[var(--text-muted)] font-mono">· 18ms latency</span>
                      </div>
                      <p className="text-xs text-[var(--text-primary)] mt-1 leading-snug">
                        {activeHeroTab === 'block'
                          ? 'Recursive directory removal detected on line 8 targeting /etc/systemd.'
                          : 'No threat indicators detected. Memory and computational operations valid.'}
                      </p>
                    </div>
                  </div>

                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-[var(--surface-secondary)] text-[var(--text-secondary)] shrink-0 border border-[var(--border)]">
                    Live Engine
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Detection Pipeline Sequence */}
      <section id="pipeline" className="px-6 lg:px-12 py-16 bg-[var(--surface)] border-y border-[var(--border)]">
        <div className="max-w-7xl mx-auto space-y-10">
          <div className="text-center max-w-xl mx-auto space-y-2">
            <h2 className="text-xs font-mono uppercase tracking-wider text-[var(--text-muted)] font-semibold">
              Pre-Execution Architecture
            </h2>
            <h3 className="text-2xl lg:text-3xl font-bold text-[var(--text-primary)] tracking-tight">
              The Six-Stage Safety Pipeline
            </h3>
            <p className="text-xs text-[var(--text-secondary)]">
              How code_kavach verifies code safety deterministically before allowing execution in production environments.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {workflowSteps.map((step) => (
              <div
                key={step.num}
                className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-2 hover:border-[var(--border-strong)] transition-colors shadow-xs"
              >
                <div className="text-xs font-mono font-bold text-[var(--text-primary)]">
                  {step.num}.
                </div>
                <h4 className="text-sm font-semibold text-[var(--text-primary)]">
                  {step.title}
                </h4>
                <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                  {step.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Threat Taxonomy Section */}
      <section id="taxonomy" className="px-6 lg:px-12 py-16 max-w-7xl mx-auto w-full space-y-10 bg-[var(--surface)]">
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
          <div className="max-w-xl space-y-2">
            <h2 className="text-xs font-mono uppercase tracking-wider text-[var(--text-muted)] font-semibold">
              Supported Threat Taxonomy
            </h2>
            <h3 className="text-2xl lg:text-3xl font-bold text-[var(--text-primary)] tracking-tight">
              Nine Rigorous Threat Classifications
            </h3>
            <p className="text-xs text-[var(--text-secondary)]">
              Grounding detections in Common Weakness Enumerations (CWE) and empirical adversarial behaviors.
            </p>
          </div>

          <Link
            to="/app/rules"
            className="text-xs font-mono text-[var(--text-primary)] hover:underline shrink-0 flex items-center gap-1"
          >
            <span>View All Rules & Code Examples</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {(Object.keys(THREAT_TAXONOMY) as ThreatCategory[]).map((catKey) => {
            const cat = THREAT_TAXONOMY[catKey];
            return (
              <div
                key={cat.id}
                className="p-5 rounded-xl bg-[var(--surface-card)] border border-[var(--border)] space-y-2 text-xs shadow-xs hover:border-[var(--border-strong)] transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-sm text-[var(--text-primary)]">
                    {cat.name}
                  </span>
                  <span className="font-mono text-[10px] text-[var(--block)] font-semibold">
                    {cat.cwe}
                  </span>
                </div>
                <p className="text-[var(--text-secondary)] leading-relaxed">
                  {cat.description}
                </p>
                <div className="pt-2 text-[10px] font-mono text-[var(--text-muted)]">
                  Severity: <span className="uppercase text-[var(--text-primary)] font-semibold">{cat.severity}</span>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Footer - Clean white */}
      <footer className="border-t border-[var(--border)] bg-[var(--surface)] px-6 lg:px-12 py-8 text-xs text-[var(--text-secondary)]">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 font-mono">
          <div className="flex items-center gap-2">
            <Logo variant="mark" size="sm" />
            <span className="font-bold text-[var(--text-primary)]">code_kavach</span>
            <span className="text-[var(--text-muted)]">·</span>
            <span>Pre-Execution Security</span>
          </div>

          <div className="flex flex-wrap items-center gap-6">
            <Link to="/app/rules" className="hover:text-[var(--text-primary)]">
              Rules
            </Link>
            <Link to="/app/playground" className="hover:text-[var(--text-primary)]">
              Playground
            </Link>
            <Link to="/app/integrations" className="hover:text-[var(--text-primary)]">
              Integrations
            </Link>
            <Link to="/app/batch" className="hover:text-[var(--text-primary)]">
              Batch Suite
            </Link>
            <Link to="/app/responsible-ai" className="hover:text-[var(--text-primary)]">
              Trust Charter
            </Link>
            <Link to="/app/settings" className="hover:text-[var(--text-primary)]">
              Settings
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
};
