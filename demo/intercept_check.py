#!/usr/bin/env python3
"""CodeGuard interception proof (mandatory judging floor).

Proves that the guard actually gates execution: a blocked snippet is never
executed, verified through an observable side effect (a marker file) and an
executor call counter. Includes a negative control that must detect leakage.

The organizer's controlled safe/unsafe pair is not available yet, so clearly
marked placeholder files are used. Their executable bodies only write a marker.

Usage:
    python demo/intercept_check.py                 # in-process engine
    python demo/intercept_check.py --base-url URL  # against the live endpoint
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk"))
sys.path.insert(0, str(ROOT / "backend"))

from codeguard import BlockedByCodeGuard, Guard, GuardedExecutor, guarded_execute  # noqa: E402

CONTROLLED = ROOT / "demo" / "controlled"
RUN_DIR = ROOT / "demo" / ".runtime"
SAFE = (CONTROLLED / "safe_placeholder.py").read_text(encoding="utf-8")
UNSAFE = (CONTROLLED / "unsafe_placeholder.py").read_text(encoding="utf-8")

results = []


def record(step, ok, detail):
    results.append((step, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {step}: {detail}")


def clean(*paths):
    for path in paths:
        Path(path).unlink(missing_ok=True)


def bypass_wrapper(code, executor):
    """Negative control: a deliberately broken wrapper that skips the verdict."""
    return executor(code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=None,
                        help="Live CodeGuard endpoint, e.g. http://127.0.0.1:8000")
    args = parser.parse_args()

    RUN_DIR.mkdir(parents=True, exist_ok=True)
    safe_marker = RUN_DIR / "marker_safe.txt"
    unsafe_marker = RUN_DIR / "marker_unsafe.txt"
    clean(safe_marker, unsafe_marker)

    guard = Guard(base_url=args.base_url)
    mode = f"HTTP {args.base_url}" if args.base_url else "in-process engine"
    print(f"CodeGuard interception proof | engine: {mode}")
    print("Step 1: removed stale marker files.\n")

    # --- Test A: safe snippet must execute and leave a marker -----------------
    safe_executor = GuardedExecutor(workdir=RUN_DIR, argv=[str(safe_marker)])
    executed = False
    try:
        guarded_execute(SAFE, executor=safe_executor, guard_client=guard)
        executed = True
    except BlockedByCodeGuard as error:
        record("A safe execution", False, f"safe snippet was blocked: {error.reason}")
    except Exception as error:  # executor failure is a real failure here
        record("A safe execution", False, f"executor raised {type(error).__name__}: {error}")
    if executed:
        record("A safe execution", safe_marker.exists() and safe_executor.calls == 1,
               f"executed=True calls={safe_executor.calls} marker={'present' if safe_marker.exists() else 'absent'}")

    # --- Test B: unsafe snippet must be blocked and never executed ------------
    unsafe_executor = GuardedExecutor(workdir=RUN_DIR, argv=[str(unsafe_marker)])
    blocked = False
    verdict = {}
    try:
        guarded_execute(UNSAFE, executor=unsafe_executor, guard_client=guard)
    except BlockedByCodeGuard as error:
        blocked = True
        verdict = error.verdict or {}
    record("B1 unsafe blocked", blocked,
           f"verdict={verdict.get('verdict', 'allow')} categories={verdict.get('categories', [])}")
    record("B2 unsafe not executed",
           (not unsafe_marker.exists()) and unsafe_executor.calls == 0,
           f"calls={unsafe_executor.calls} "
           f"marker={'present' if unsafe_marker.exists() else 'absent'}"
           f" (executor must never be entered)")

    # --- Step 4: negative control --------------------------------------------
    # A wrapper that ignores the verdict must leak. If the marker does NOT
    # appear here, the test cannot detect leakage and is therefore invalid.
    clean(unsafe_marker)
    control_executor = GuardedExecutor(workdir=RUN_DIR, argv=[str(unsafe_marker)])
    try:
        bypass_wrapper(UNSAFE, control_executor)
        leaked = unsafe_marker.exists()
    except Exception as error:
        leaked = False
        print(f"  negative-control executor error: {type(error).__name__}: {error}")
    record("C negative control", leaked,
           f"bypassed wrapper produced marker={'present' if leaked else 'absent'} "
           f"(leakage must be observable)")

    # --- Summary -------------------------------------------------------------
    clean(safe_marker, unsafe_marker)
    failed = [step for step, ok, _ in results if not ok]
    print("\n" + "-" * 64)
    if failed:
        print(f"RESULT: FAIL ({len(failed)} check(s) failed: {', '.join(failed)})")
        return 1
    print(f"RESULT: PASS ({len(results)}/{len(results)} checks) — "
          "blocked code never executed; negative control detected leakage.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
