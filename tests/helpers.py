"""
Shared helpers for the HoneySpot API test suite.
Provides HTTP utilities, result tracking, schema validation, and reporting.
"""

import os
import sys
import time
from typing import Any, Dict, List, Tuple

# ── Windows UTF-8 fix ────────────────────────────────────────────────────────
os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import httpx  # noqa: E402

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_URL = "http://localhost:8080"
API_KEY = "TechjaysSuperSecret123!"
HEADERS = {"Content-Type": "application/json", "x-api-key": API_KEY}
TIMEOUT_FAST = 10     # Auth / validation (no Gemini call expected)
TIMEOUT_GEMINI = 60   # Gemini-dependent requests

# ── Result tracking ───────────────────────────────────────────────────────────
_results: List[Dict[str, Any]] = []
_critical_failures: List[Dict[str, str]] = []


def get_results() -> List[Dict[str, Any]]:
    """Return a copy of all recorded results."""
    return list(_results)


def get_critical_failures() -> List[Dict[str, str]]:
    """Return a copy of all critical failures."""
    return list(_critical_failures)


def clear_results() -> None:
    """Clear results and critical failures (used between modules in run_all)."""
    _results.clear()
    _critical_failures.clear()


# ── HTTP helpers ──────────────────────────────────────────────────────────────
def post(
    body: Dict[str, Any],
    timeout: int = TIMEOUT_GEMINI,
) -> Tuple[httpx.Response, int]:
    """POST to /honeypot with default auth headers. Returns (response, latency_ms)."""
    start = time.perf_counter()
    r = httpx.post(
        f"{BASE_URL}/honeypot",
        headers=HEADERS,
        json=body,
        timeout=timeout,
    )
    latency = round((time.perf_counter() - start) * 1000)
    return r, latency


def post_raw(
    headers: Dict[str, str],
    body: Any,
    timeout: int = TIMEOUT_FAST,
) -> Tuple[httpx.Response, int]:
    """POST to /honeypot with custom headers/body. For auth & validation tests."""
    start = time.perf_counter()
    if isinstance(body, (bytes, str)):
        r = httpx.post(
            f"{BASE_URL}/honeypot",
            headers=headers,
            content=body if isinstance(body, bytes) else body.encode(),
            timeout=timeout,
        )
    else:
        r = httpx.post(
            f"{BASE_URL}/honeypot",
            headers=headers,
            json=body,
            timeout=timeout,
        )
    latency = round((time.perf_counter() - start) * 1000)
    return r, latency


def get_health(timeout: int = TIMEOUT_FAST) -> Tuple[httpx.Response, int]:
    """GET /health."""
    start = time.perf_counter()
    r = httpx.get(f"{BASE_URL}/health", headers=HEADERS, timeout=timeout)
    latency = round((time.perf_counter() - start) * 1000)
    return r, latency


# ── Result recording ──────────────────────────────────────────────────────────
def record(
    name: str,
    passed: bool,
    latency: int,
    detail: str = "",
    category: str = "GENERAL",
) -> None:
    """Record a single test result and print it."""
    tag = "\033[92mPASS\033[0m" if passed else "\033[91mFAIL\033[0m"
    _results.append({
        "test": name,
        "passed": passed,
        "latency_ms": latency,
        "detail": detail,
        "category": category,
    })
    short = (detail[:90] + "...") if len(detail) > 90 else detail
    print(f"  [{tag}] {name} | {latency}ms | {short}")
    if not passed:
        _critical_failures.append({"test": name, "detail": detail})


# ── Schema validation ─────────────────────────────────────────────────────────
REQUIRED_TOP = [
    "status", "reply", "scamDetected",
    "engagementMetrics", "extractedIntelligence", "agentNotes",
]
REQUIRED_METRICS = ["engagementDurationSeconds", "totalMessagesExchanged"]
REQUIRED_INTEL = [
    "bankAccounts", "upiIds", "phishingLinks",
    "phoneNumbers", "suspiciousKeywords",
]


def validate_schema(
    data: Dict[str, Any],
    test_name: str,
    latency: int,
) -> bool:
    """Validate ALL required response fields. Records pass/fail."""
    missing_top = [f for f in REQUIRED_TOP if f not in data]
    if missing_top:
        record(
            f"{test_name} [schema]",
            False, latency,
            f"Missing top-level: {missing_top}",
            "SCHEMA",
        )
        return False

    em = data.get("engagementMetrics")
    if em is not None:
        missing_em = [f for f in REQUIRED_METRICS if f not in em]
        if missing_em:
            record(
                f"{test_name} [schema]",
                False, latency,
                f"Missing in engagementMetrics: {missing_em}",
                "SCHEMA",
            )
            return False

    ei = data.get("extractedIntelligence")
    if ei is not None:
        missing_ei = [f for f in REQUIRED_INTEL if f not in ei]
        if missing_ei:
            record(
                f"{test_name} [schema]",
                False, latency,
                f"Missing in extractedIntelligence: {missing_ei}",
                "SCHEMA",
            )
            return False

    record(f"{test_name} [schema]", True, latency, "All fields present", "SCHEMA")
    return True


# ── Pretty printing ───────────────────────────────────────────────────────────
def section(title: str) -> None:
    """Print a section header."""
    print(f"\n\033[96m{'=' * 74}\033[0m")
    print(f"  \033[1m{title}\033[0m")
    print(f"\033[96m{'=' * 74}\033[0m")


def _percentile(sorted_vals: List[int], pct: float) -> int:
    """Return the value at the given percentile from a sorted list."""
    if not sorted_vals:
        return 0
    idx = int(len(sorted_vals) * pct)
    idx = min(idx, len(sorted_vals) - 1)
    return sorted_vals[idx]


def print_summary(
    results: List[Dict[str, Any]],
    critical_failures: List[Dict[str, str]],
    title: str = "TEST REPORT",
) -> int:
    """
    Print a formatted summary.
    Returns the number of failed tests (0 = all pass).
    """
    section(title)

    total = len(results)
    if total == 0:
        print("  No tests recorded.")
        return 0

    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    pct = round(passed / total * 100, 1)

    print(f"\n  Total    : {total}")
    print(f"  Passed   : \033[92m{passed}\033[0m")
    print(f"  Failed   : \033[91m{failed}\033[0m")
    print(f"  Pass Rate: {pct}%")

    # ── Category breakdown ────────────────────────────────────────────────
    cats: Dict[str, Dict[str, int]] = {}
    for r in results:
        cat = r.get("category", "OTHER")
        if cat not in cats:
            cats[cat] = {"total": 0, "passed": 0}
        cats[cat]["total"] += 1
        if r["passed"]:
            cats[cat]["passed"] += 1

    print(f"\n  {'Category':<22} {'Passed':<10} {'Total':<10} {'Rate'}")
    print(f"  {'-' * 22} {'-' * 10} {'-' * 10} {'-' * 8}")
    for cat in sorted(cats):
        d = cats[cat]
        rate = round(d["passed"] / d["total"] * 100) if d["total"] else 0
        print(f"  {cat:<22} {d['passed']:<10} {d['total']:<10} {rate}%")

    # ── Latency stats ─────────────────────────────────────────────────────
    latencies = sorted(
        r["latency_ms"] for r in results if r["latency_ms"] > 100
    )
    if latencies:
        avg = round(sum(latencies) / len(latencies))
        print(f"\n  --- Latency Stats (API-dependent, >100ms) ---")
        print(f"  Count    : {len(latencies)}")
        print(f"  Min      : {latencies[0]}ms")
        print(f"  Max      : {latencies[-1]}ms")
        print(f"  Average  : {avg}ms")
        print(f"  Median   : {_percentile(latencies, 0.50)}ms")
        print(f"  P90      : {_percentile(latencies, 0.90)}ms")
        print(f"  P95      : {_percentile(latencies, 0.95)}ms")

        under_2 = sum(1 for v in latencies if v < 2000)
        under_5 = sum(1 for v in latencies if v < 5000)
        under_10 = sum(1 for v in latencies if v < 10000)
        print(f"  Under 2s : {under_2}/{len(latencies)}"
              f" ({round(under_2 / len(latencies) * 100)}%)")
        print(f"  Under 5s : {under_5}/{len(latencies)}"
              f" ({round(under_5 / len(latencies) * 100)}%)")
        print(f"  Under 10s: {under_10}/{len(latencies)}"
              f" ({round(under_10 / len(latencies) * 100)}%)")

    # ── Critical failures ─────────────────────────────────────────────────
    if critical_failures:
        print(f"\n  \033[91m--- CRITICAL FAILURES ---\033[0m")
        for f in critical_failures:
            print(f"  FAIL: {f['test']}")
            short = (f["detail"][:100] + "...") if len(f["detail"]) > 100 else f["detail"]
            print(f"        {short}")
    else:
        print(f"\n  \033[92mNO CRITICAL FAILURES\033[0m")

    print(f"\n\033[96m{'=' * 74}\033[0m")
    return failed
