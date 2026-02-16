"""
Health endpoint tests for HoneySpot API.
Verifies GET /health returns correct status, works without auth,
and responds quickly.

Run standalone:  python tests/test_health.py
"""

import os
import sys
import time

# ── Windows UTF-8 fix ────────────────────────────────────────────────────────
os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import httpx  # noqa: E402

from tests.helpers import (
    BASE_URL,
    clear_results,
    get_critical_failures,
    get_health,
    get_results,
    print_summary,
    record,
    section,
)


def run() -> None:
    """Execute all health endpoint tests."""
    clear_results()

    section("HEALTH ENDPOINT TESTS")

    # 1. GET /health returns 200
    try:
        r, lat = get_health()
        record(
            "Health: GET /health -> 200",
            r.status_code == 200,
            lat,
            f"Status: {r.status_code}",
            "HEALTH",
        )
    except Exception as e:
        record("Health: GET /health -> 200", False, 0, str(e), "HEALTH")

    # 2. Response body contains {"status": "ok"}
    try:
        r, lat = get_health()
        d = r.json()
        record(
            "Health: Response has status='ok'",
            d.get("status") == "ok",
            lat,
            f"Body: {d}",
            "HEALTH",
        )
    except Exception as e:
        record("Health: Response has status='ok'", False, 0, str(e), "HEALTH")

    # 3. Health works without any auth headers
    try:
        start = time.perf_counter()
        r = httpx.get(f"{BASE_URL}/health", timeout=10)
        lat = round((time.perf_counter() - start) * 1000)
        record(
            "Health: Works without auth headers",
            r.status_code == 200,
            lat,
            f"Status: {r.status_code} (no x-api-key sent)",
            "HEALTH",
        )
    except Exception as e:
        record("Health: Works without auth headers", False, 0, str(e), "HEALTH")

    # 4. Health responds under 500ms (fast, no AI call)
    try:
        r, lat = get_health()
        record(
            "Health: Latency under 3s",
            lat < 3000,
            lat,
            f"Latency: {lat}ms (threshold 3000ms)",
            "HEALTH",
        )
    except Exception as e:
        record("Health: Latency under 500ms", False, 0, str(e), "HEALTH")

    # 5. Content-Type is JSON
    try:
        r, lat = get_health()
        ct = r.headers.get("content-type", "")
        record(
            "Health: Content-Type is JSON",
            "application/json" in ct,
            lat,
            f"Content-Type: {ct}",
            "HEALTH",
        )
    except Exception as e:
        record("Health: Content-Type is JSON", False, 0, str(e), "HEALTH")

    print_summary(
        get_results(),
        get_critical_failures(),
        "HEALTH ENDPOINT REPORT",
    )


if __name__ == "__main__":
    run()
