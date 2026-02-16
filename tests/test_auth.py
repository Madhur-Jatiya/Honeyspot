"""
Auth, input validation, and timestamp format tests for HoneySpot API.
~15 tests covering security, schema validation, and timestamp parsing.

Run standalone:  python tests/test_auth.py
"""

import os
import sys

# ── Windows UTF-8 fix ────────────────────────────────────────────────────────
os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Allow running from project root or tests/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from tests.helpers import (
    HEADERS,
    TIMEOUT_FAST,
    clear_results,
    get_critical_failures,
    get_results,
    post,
    post_raw,
    print_summary,
    record,
    section,
    validate_schema,
)


# ── Minimal valid body for auth tests (avoids Gemini call on 422/401) ────────
BODY_BASIC = {
    "sessionId": "auth-test-001",
    "message": {
        "sender": "scammer",
        "text": "Your bank account is blocked. Share OTP now.",
        "timestamp": "2026-01-21T10:15:30Z",
    },
    "conversationHistory": [],
    "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
}


def run() -> None:
    """Execute all auth and validation tests."""
    clear_results()

    # ==================================================================
    #  AUTH TESTS
    # ==================================================================
    section("AUTH & SECURITY TESTS")

    # 1. No API key
    r, lat = post_raw(
        {"Content-Type": "application/json"},
        BODY_BASIC,
    )
    record("No API key -> 401", r.status_code == 401, lat,
           f"Got {r.status_code}", "AUTH")

    # 2. Wrong API key
    r, lat = post_raw(
        {"Content-Type": "application/json", "x-api-key": "wrong-key-xyz"},
        BODY_BASIC,
    )
    record("Wrong API key -> 401", r.status_code == 401, lat,
           f"Got {r.status_code}", "AUTH")

    # 3. Empty API key
    r, lat = post_raw(
        {"Content-Type": "application/json", "x-api-key": ""},
        BODY_BASIC,
    )
    record("Empty API key -> 401", r.status_code == 401, lat,
           f"Got {r.status_code}", "AUTH")

    # 4. Correct API key -> 200
    r, lat = post(BODY_BASIC)
    record("Correct API key -> 200", r.status_code == 200, lat,
           f"Got {r.status_code}", "AUTH")

    # ==================================================================
    #  INPUT VALIDATION TESTS
    # ==================================================================
    section("INPUT VALIDATION TESTS")

    # 5. Empty body -> 422
    r, lat = post_raw(HEADERS, b"{}", TIMEOUT_FAST)
    record("Empty body -> 422", r.status_code == 422, lat,
           f"Got {r.status_code}", "VALIDATION")

    # 6. Missing sessionId -> 422
    r, lat = post(
        {"message": {"sender": "scammer", "text": "test", "timestamp": "2026-01-21T10:15:30Z"}},
        timeout=TIMEOUT_FAST,
    )
    record("Missing sessionId -> 422", r.status_code == 422, lat,
           f"Got {r.status_code}", "VALIDATION")

    # 7. Missing message -> 422
    r, lat = post({"sessionId": "test"}, timeout=TIMEOUT_FAST)
    record("Missing message -> 422", r.status_code == 422, lat,
           f"Got {r.status_code}", "VALIDATION")

    # 8. Invalid sender "unknown" -> 422
    r, lat = post({
        "sessionId": "test",
        "message": {"sender": "unknown", "text": "hi", "timestamp": "2026-01-21T10:00:00Z"},
    }, timeout=TIMEOUT_FAST)
    record("Invalid sender 'unknown' -> 422", r.status_code == 422, lat,
           f"Got {r.status_code}", "VALIDATION")

    # 9. Missing timestamp -> 422
    r, lat = post({
        "sessionId": "test",
        "message": {"sender": "scammer", "text": "hi"},
    }, timeout=TIMEOUT_FAST)
    record("Missing timestamp -> 422", r.status_code == 422, lat,
           f"Got {r.status_code}", "VALIDATION")

    # 10. Empty conversationHistory -> 200 (OK)
    r, lat = post({
        "sessionId": "test-empty-hist",
        "message": {
            "sender": "scammer",
            "text": "Your account is blocked. Share OTP.",
            "timestamp": "2026-01-21T10:00:00Z",
        },
        "conversationHistory": [],
    })
    record("Empty conversationHistory -> 200", r.status_code == 200, lat,
           f"Got {r.status_code}", "VALIDATION")

    # 11. No metadata field -> 200 (optional)
    r, lat = post({
        "sessionId": "test-no-meta",
        "message": {
            "sender": "scammer",
            "text": "Your account is blocked. Share OTP.",
            "timestamp": "2026-01-21T10:00:00Z",
        },
        "conversationHistory": [],
    })
    record("No metadata -> 200", r.status_code == 200, lat,
           f"Got {r.status_code}", "VALIDATION")

    # 12. Extra unknown fields ignored -> 200
    r, lat = post({
        "sessionId": "test-extra",
        "message": {
            "sender": "scammer",
            "text": "Your account is blocked. Share OTP.",
            "timestamp": "2026-01-21T10:00:00Z",
        },
        "conversationHistory": [],
        "unknownField": "should be ignored",
        "anotherField": 12345,
    })
    record("Extra fields ignored -> 200", r.status_code == 200, lat,
           f"Got {r.status_code}", "VALIDATION")

    # ==================================================================
    #  TIMESTAMP FORMAT TESTS
    # ==================================================================
    section("TIMESTAMP FORMAT TESTS")

    ts_cases = [
        ("ISO 8601 with Z", "2026-01-21T10:15:30Z"),
        ("ISO 8601 with offset +05:30", "2026-01-21T10:15:30+05:30"),
        ("ISO 8601 no timezone", "2026-01-21T10:15:30"),
        ("Epoch ms (int)", 1737451530000),
        ("Epoch ms (float)", 1737451530000.0),
        ("Large epoch ms", 1800000000000),
    ]

    for name, ts_val in ts_cases:
        try:
            r, lat = post({
                "sessionId": f"ts-{name.replace(' ', '-').lower()}",
                "message": {
                    "sender": "scammer",
                    "text": "Your bank account is blocked. Share OTP.",
                    "timestamp": ts_val,
                },
                "conversationHistory": [],
            })
            passed = r.status_code == 200
            record(f"Timestamp: {name} -> 200", passed, lat,
                   f"Got {r.status_code}", "TIMESTAMP")
            if passed:
                validate_schema(r.json(), f"Timestamp: {name}", lat)
        except Exception as e:
            record(f"Timestamp: {name}", False, 0, str(e), "TIMESTAMP")

    # ==================================================================
    #  SUMMARY
    # ==================================================================
    print_summary(get_results(), get_critical_failures(), "AUTH & VALIDATION REPORT")


if __name__ == "__main__":
    run()
