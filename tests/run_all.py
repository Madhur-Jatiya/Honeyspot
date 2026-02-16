"""
Master test runner for the HoneySpot API test suite.
Runs all test modules in order, aggregates results, prints grand summary.

Usage:
    python tests/run_all.py
    python -m tests.run_all
"""

import os
import sys
import time

# ── Windows UTF-8 fix ────────────────────────────────────────────────────────
os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from tests.helpers import (
    clear_results,
    get_critical_failures,
    get_results,
    print_summary,
    section,
)


def _collect_and_reset():
    """Snapshot current results and reset for the next module."""
    results = get_results()
    failures = get_critical_failures()
    clear_results()
    return results, failures


def main() -> int:
    """Run all test modules and return exit code (0=pass, 1=fail)."""
    suite_start = time.perf_counter()

    all_results = []
    all_failures = []

    banner = (
        "\n"
        "\033[96m" + "=" * 74 + "\033[0m\n"
        "  \033[1mHONEYSPOT API - FULL TEST SUITE\033[0m\n"
        "\033[96m" + "=" * 74 + "\033[0m"
    )
    print(banner)

    # ── Module 1: Health Endpoint ─────────────────────────────────────────
    print("\n\033[93m>>> Running: test_health\033[0m")
    clear_results()
    from tests import test_health
    test_health.run()
    r, f = _collect_and_reset()
    all_results.extend(r)
    all_failures.extend(f)

    # ── Module 2: Auth & Validation ──────────────────────────────────────
    print("\n\033[93m>>> Running: test_auth\033[0m")
    clear_results()
    from tests import test_auth
    test_auth.run()
    r, f = _collect_and_reset()
    all_results.extend(r)
    all_failures.extend(f)

    # ── Module 3: Scam Detection ─────────────────────────────────────────
    print("\n\033[93m>>> Running: test_scam_detection\033[0m")
    clear_results()
    from tests import test_scam_detection
    test_scam_detection.run()
    r, f = _collect_and_reset()
    all_results.extend(r)
    all_failures.extend(f)

    # ── Module 4: False Positive Tests ────────────────────────────────────
    print("\n\033[93m>>> Running: test_false_positives\033[0m")
    clear_results()
    from tests import test_false_positives
    test_false_positives.run()
    r, f = _collect_and_reset()
    all_results.extend(r)
    all_failures.extend(f)

    # ── Module 5: Adversarial / Evasion Tests ─────────────────────────────
    print("\n\033[93m>>> Running: test_adversarial\033[0m")
    clear_results()
    from tests import test_adversarial
    test_adversarial.run()
    r, f = _collect_and_reset()
    all_results.extend(r)
    all_failures.extend(f)

    # ── Module 6: Multi-Turn ─────────────────────────────────────────────
    print("\n\033[93m>>> Running: test_multiturn\033[0m")
    clear_results()
    from tests import test_multiturn
    test_multiturn.run()
    r, f = _collect_and_reset()
    all_results.extend(r)
    all_failures.extend(f)

    # ── Module 7: Intelligence Extraction Accuracy ────────────────────────
    print("\n\033[93m>>> Running: test_intel_extraction\033[0m")
    clear_results()
    from tests import test_intel_extraction
    test_intel_extraction.run()
    r, f = _collect_and_reset()
    all_results.extend(r)
    all_failures.extend(f)

    # ── Module 8: Stress & Edge Cases ────────────────────────────────────
    print("\n\033[93m>>> Running: test_stress\033[0m")
    clear_results()
    from tests import test_stress
    test_stress.run()
    r, f = _collect_and_reset()
    all_results.extend(r)
    all_failures.extend(f)

    # ── Module 9: Edge Cases (Language Match, Injection, Role Reversal) ─
    print("\n\033[93m>>> Running: test_edge_cases\033[0m")
    clear_results()
    from tests import test_edge_cases
    test_edge_cases.run()
    r, f = _collect_and_reset()
    all_results.extend(r)
    all_failures.extend(f)

    # ── Grand Summary ────────────────────────────────────────────────────
    elapsed = round((time.perf_counter() - suite_start) * 1000)
    failed = print_summary(
        all_results,
        all_failures,
        f"GRAND SUMMARY  (total time: {elapsed}ms)",
    )

    total = len(all_results)
    passed = total - failed
    if failed == 0:
        print(f"  \033[92mALL {total} TESTS PASSED\033[0m")
    else:
        print(f"  \033[91m{failed} TESTS FAILED\033[0m out of {total}")

    print(f"\n\033[96m{'=' * 74}\033[0m")
    print(f"  \033[1mHONEYSPOT TEST SUITE COMPLETE\033[0m")
    print(f"\033[96m{'=' * 74}\033[0m\n")

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
