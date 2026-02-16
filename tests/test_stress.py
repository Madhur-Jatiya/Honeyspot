"""
Stress tests and edge cases for HoneySpot API.
Edge cases, channel validation, concurrent load, rapid requests,
boundary inputs, and response quality checks.

Run standalone:  python tests/test_stress.py
"""

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    HEADERS,
    clear_results,
    get_critical_failures,
    get_results,
    post,
    print_summary,
    record,
    section,
    validate_schema,
)


def _make_body(session_id: str, text: str, **kwargs):
    """Build a minimal valid request body."""
    body = {
        "sessionId": session_id,
        "message": {
            "sender": kwargs.get("sender", "scammer"),
            "text": text,
            "timestamp": kwargs.get("timestamp", "2026-02-10T10:00:00Z"),
        },
        "conversationHistory": kwargs.get("history", []),
    }
    meta = kwargs.get("metadata")
    if meta:
        body["metadata"] = meta
    return body


def run() -> None:
    """Execute all stress and edge case tests."""
    clear_results()

    # ==================================================================
    #  EDGE CASE TESTS
    # ==================================================================
    section("EDGE CASE TESTS")

    # 1. Very long message (3000+ chars)
    long_text = (
        "Your account has been compromised. " * 90
        + "Transfer money to 9999888877776666 via UPI fraud@ybl now."
    )
    r, lat = post(_make_body("stress-long-msg", long_text))
    record(
        "Stress: Very long message (3000+ chars)",
        r.status_code == 200,
        lat,
        f"Status: {r.status_code}, msgLen={len(long_text)}",
        "STRESS",
    )
    if r.status_code == 200:
        validate_schema(r.json(), "Very long message", lat)

    # 2. Very short message
    r, lat = post(_make_body("stress-short-msg", "Pay now"))
    record(
        "Stress: Very short message ('Pay now')",
        r.status_code == 200,
        lat,
        f"scamDetected={r.json().get('scamDetected') if r.status_code == 200 else 'N/A'}",
        "STRESS",
    )

    # 3. Single character
    r, lat = post(_make_body("stress-1char", "?"))
    record(
        "Stress: Single character '?'",
        r.status_code == 200,
        lat,
        f"Status: {r.status_code}",
        "STRESS",
    )

    # 4. Unicode + emoji heavy
    emoji_text = (
        "\U0001f6a8\U0001f6a8 ALERT \U0001f6a8\U0001f6a8 "
        "\u0906\u092a\u0915\u093e \u0905\u0915\u093e\u0909\u0902\u091f "
        "\U0001f3e6 \u092c\u094d\u0932\u0949\u0915 \u274c "
        "\u0939\u094b \u0917\u092f\u093e! OTP "
        "\u092d\u0947\u091c\u094b \U0001f4f1 "
        "+91-9999000011 \u260e\ufe0f"
    )
    r, lat = post(_make_body(
        "stress-unicode", emoji_text,
        metadata={"channel": "WhatsApp", "language": "Hindi", "locale": "IN"},
    ))
    record(
        "Stress: Unicode + emoji message",
        r.status_code == 200,
        lat,
        f"scamDetected={r.json().get('scamDetected') if r.status_code == 200 else 'N/A'}",
        "STRESS",
    )

    # 5. Large conversation history (20 messages)
    large_history = []
    for i in range(20):
        sender = "scammer" if i % 2 == 0 else "user"
        large_history.append({
            "sender": sender,
            "text": f"Message number {i + 1} about your blocked account",
            "timestamp": f"2026-02-10T10:{i:02d}:00Z",
        })
    r, lat = post(_make_body(
        "stress-large-hist",
        "Final warning! Share your bank details now!",
        history=large_history,
        metadata={"channel": "SMS", "language": "English", "locale": "IN"},
    ))
    record(
        "Stress: 20-message history",
        r.status_code == 200,
        lat,
        f"Latency with large context: {lat}ms",
        "STRESS",
    )

    # 6. Special characters
    special_text = (
        "Your A/C #1234-5678-9012 is <BLOCKED>! "
        'Call "support" at +91-9876543210 & share OTP = 123456; PIN: 5678'
    )
    r, lat = post(_make_body("stress-special", special_text))
    record(
        "Stress: Special chars (<>&\"#=;:)",
        r.status_code == 200,
        lat,
        f"Status: {r.status_code}",
        "STRESS",
    )

    # 7. sender="user" with scam content
    r, lat = post(_make_body(
        "stress-user-sender",
        "Someone sent me this: Transfer Rs 50000 to account 1111222233334444",
        sender="user",
    ))
    record(
        "Stress: sender='user' with scam content",
        r.status_code == 200,
        lat,
        "Handled gracefully",
        "STRESS",
    )

    # 8. Empty string message text
    r, lat = post(_make_body("stress-empty-text", ""))
    passed = r.status_code in (200, 422)
    record(
        "Stress: Empty string message text",
        passed,
        lat,
        f"Status: {r.status_code} (200 or 422 acceptable)",
        "STRESS",
    )

    # 9. Numbers-only message
    r, lat = post(_make_body(
        "stress-numbers-only",
        "9876543210 1234567890123456 verify@paytm",
    ))
    record(
        "Stress: Numbers-only + UPI message",
        r.status_code == 200,
        lat,
        f"scamDetected={r.json().get('scamDetected') if r.status_code == 200 else 'N/A'}",
        "STRESS",
    )

    # ==================================================================
    #  METADATA CHANNEL TESTS
    # ==================================================================
    section("METADATA CHANNEL TESTS")

    for channel in ["SMS", "WhatsApp", "Email", "Chat"]:
        r, lat = post(_make_body(
            f"stress-ch-{channel.lower()}",
            "Your account is blocked. Share OTP now.",
            metadata={"channel": channel, "language": "English", "locale": "IN"},
        ))
        record(
            f"Channel: {channel} -> 200",
            r.status_code == 200,
            lat,
            f"Status: {r.status_code}",
            "CHANNEL",
        )

    # ==================================================================
    #  RAPID REQUESTS (same session, 3 back-to-back)
    # ==================================================================
    section("RAPID REQUESTS (Same Session, 3 Back-to-Back)")

    rapid_latencies = []
    for i in range(3):
        r, lat = post(_make_body(
            "stress-rapid-same-session",
            f"Urgent message #{i + 1}! Share OTP now or account blocked.",
            timestamp=f"2026-02-10T10:{30 + i}:00Z",
        ))
        rapid_latencies.append(lat)
        record(
            f"Rapid #{i + 1}: same session",
            r.status_code == 200,
            lat,
            f"Status: {r.status_code}",
            "RAPID",
        )

    avg_rapid = round(sum(rapid_latencies) / len(rapid_latencies))
    print(f"\n  >> Rapid request latencies: {rapid_latencies}")
    print(f"  >> Avg rapid latency: {avg_rapid}ms")

    # ==================================================================
    #  CONCURRENT LOAD (5 parallel requests)
    # ==================================================================
    section("CONCURRENT LOAD (5 Parallel Requests)")

    def _concurrent_request(idx: int):
        body = _make_body(
            f"concurrent-{idx}",
            f"Urgent! Your account #{idx} will be blocked. Share OTP now.",
            metadata={"channel": "SMS", "language": "English", "locale": "IN"},
        )
        start = time.perf_counter()
        resp = httpx.post(
            f"{BASE_URL}/honeypot",
            headers=HEADERS,
            json=body,
            timeout=120,
        )
        ms = round((time.perf_counter() - start) * 1000)
        return idx, resp.status_code, ms, resp.json().get("scamDetected")

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(_concurrent_request, i) for i in range(5)]
        for fut in as_completed(futures):
            idx, code, lat, detected = fut.result()
            record(
                f"Concurrent #{idx}: 200 + scamDetected",
                code == 200 and detected is True,
                lat,
                f"Status={code}, scamDetected={detected}",
                "CONCURRENT",
            )

    # ==================================================================
    #  LATENCY SLA ASSERTIONS
    # ==================================================================
    section("LATENCY SLA ASSERTIONS")

    # Collect all API-dependent latencies recorded so far
    all_lats = sorted(
        r["latency_ms"] for r in get_results() if r["latency_ms"] > 100
    )
    if all_lats:
        p95_idx = min(int(len(all_lats) * 0.95), len(all_lats) - 1)
        p95_val = all_lats[p95_idx]
        record(
            "SLA: P95 latency under 30s",
            p95_val < 30000,
            p95_val,
            f"P95={p95_val}ms (threshold 30000ms)",
            "SLA",
        )
        avg_val = round(sum(all_lats) / len(all_lats))
        record(
            "SLA: Average latency under 15s",
            avg_val < 15000,
            avg_val,
            f"Avg={avg_val}ms (threshold 15000ms)",
            "SLA",
        )
    else:
        record("SLA: No API latencies collected", False, 0,
               "Cannot compute SLA", "SLA")

    # ==================================================================
    #  IDEMPOTENCY TEST (same message twice, same session)
    # ==================================================================
    section("IDEMPOTENCY TEST (Duplicate Message)")

    idem_body = _make_body(
        "stress-idempotent-001",
        "Your bank account is compromised! Share OTP and Aadhaar now. "
        "Call +91-9999000011 urgently!",
        metadata={"channel": "SMS", "language": "English", "locale": "IN"},
    )

    r1, lat1 = post(idem_body)
    r2, lat2 = post(idem_body)

    record(
        "Idempotent: 1st request -> 200",
        r1.status_code == 200,
        lat1,
        f"Status: {r1.status_code}",
        "IDEMPOTENT",
    )
    record(
        "Idempotent: 2nd request -> 200",
        r2.status_code == 200,
        lat2,
        f"Status: {r2.status_code}",
        "IDEMPOTENT",
    )

    d1 = r1.json() if r1.status_code == 200 else {}
    d2 = r2.json() if r2.status_code == 200 else {}

    record(
        "Idempotent: Both detect scam",
        d1.get("scamDetected", False) is True
        and d2.get("scamDetected", False) is True,
        lat2,
        f"1st={d1.get('scamDetected')}, 2nd={d2.get('scamDetected')}",
        "IDEMPOTENT",
    )
    record(
        "Idempotent: Both have valid replies",
        len(d1.get("reply", "")) > 0 and len(d2.get("reply", "")) > 0,
        lat2,
        f"Reply1 len={len(d1.get('reply', ''))}, "
        f"Reply2 len={len(d2.get('reply', ''))}",
        "IDEMPOTENT",
    )

    # ==================================================================
    #  RESPONSE QUALITY CHECKS
    # ==================================================================
    section("RESPONSE QUALITY CHECKS")

    r, lat = post(_make_body(
        "quality-001",
        "I am from SBI. Your fixed deposit of Rs 5,00,000 has matured. "
        "Share your account number for credit.",
        metadata={"channel": "SMS", "language": "English", "locale": "IN"},
    ))
    d = r.json()
    reply = d.get("reply", "")

    record(
        "Quality: Reply is non-empty",
        len(reply) > 0,
        lat,
        f"Reply length: {len(reply)}",
        "QUALITY",
    )
    record(
        "Quality: Reply length 10-1000 chars",
        10 <= len(reply) <= 1000,
        lat,
        f"Reply length: {len(reply)}",
        "QUALITY",
    )

    # Reply should contain ASCII alpha (English content)
    has_alpha = any(c.isascii() and c.isalpha() for c in reply)
    record(
        "Quality: Reply contains text",
        has_alpha,
        lat,
        f"Reply: {reply[:60]}...",
        "QUALITY",
    )

    # AI persona not exposed
    ai_reveals = [
        "i am an ai", "i'm an ai", "artificial intelligence",
        "language model", "as an ai", "i am a honeypot",
        "scam detected", "i know this is a scam",
    ]
    exposed = any(phrase in reply.lower() for phrase in ai_reveals)
    record(
        "Quality: AI identity not exposed",
        not exposed,
        lat,
        "EXPOSED!" if exposed else "Persona maintained",
        "QUALITY",
    )

    # agentNotes present
    notes = d.get("agentNotes", "")
    record(
        "Quality: agentNotes is non-empty",
        len(notes) > 0 if notes else False,
        lat,
        f"Notes: {(notes or '')[:80]}...",
        "QUALITY",
    )

    # ==================================================================
    #  SUMMARY
    # ==================================================================
    print_summary(
        get_results(),
        get_critical_failures(),
        "STRESS & EDGE CASE REPORT",
    )


if __name__ == "__main__":
    run()
