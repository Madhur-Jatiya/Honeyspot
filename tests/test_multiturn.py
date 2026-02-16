"""
Multi-turn conversation tests for HoneySpot API.
3 flows: 6-turn HDFC scam, 4-turn UPI progressive intel, legit-to-scam transition.
~20 tests covering scam detection, persona maintenance, intelligence growth,
engagement metrics, and conversation flow handling.

Run standalone:  python tests/test_multiturn.py
"""

import json
import os
import sys

# ── Windows UTF-8 fix ────────────────────────────────────────────────────────
os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from tests.helpers import (
    clear_results,
    get_critical_failures,
    get_results,
    post,
    print_summary,
    record,
    section,
    validate_schema,
)

# Words that indicate the AI persona has been broken
REVEAL_WORDS = [
    "scam", "fraud", "honeypot", "i am an ai", "i'm an ai",
    "i am a bot", "i detect", "this is a scam", "you are a scammer",
    "artificial intelligence", "language model", "as an ai",
]


def _persona_ok(reply: str) -> bool:
    """Return True if the reply does NOT reveal the AI / detection system."""
    lower = reply.lower()
    return not any(w in lower for w in REVEAL_WORDS)


def _run_flow_1() -> None:
    """Flow 1: 6-turn HDFC scam with persona and intelligence checks."""
    section("FLOW 1: 6-Turn HDFC Scam")

    session = "multiturn-hdfc-001"
    history = []
    scam_msgs = [
        "Dear customer, we noticed unusual activity on your HDFC account. "
        "Please verify your identity.",

        "Sir, for security purpose, share your registered mobile number "
        "and date of birth.",

        "Thank you. Now please share the OTP sent to your mobile for "
        "verification. This is from HDFC bank security team.",

        "Sir, there is a pending charge of Rs 49,999. To block it, transfer "
        "Rs 1 to verify@paytm as authentication.",

        "This is final warning. Your account will be frozen in 15 minutes. "
        "Share your UPI PIN to confirm identity. Contact +91-7777888899.",

        "Sir, I am sending you a link. Please click and enter your net "
        "banking password: http://hdfc-secure-verify.xyz/auth",
    ]

    turn_latencies = []
    last_data = None

    for i, scam_text in enumerate(scam_msgs):
        ts = f"2026-02-10T10:{10 + i * 2:02d}:00Z"
        body = {
            "sessionId": session,
            "message": {"sender": "scammer", "text": scam_text, "timestamp": ts},
            "conversationHistory": list(history),
            "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        }

        r, lat = post(body)
        turn_latencies.append(lat)
        d = r.json()
        last_data = d

        detected = d.get("scamDetected", False) is True
        reply = d.get("reply", "")
        persona = _persona_ok(reply)

        record(
            f"HDFC Turn {i + 1}: scamDetected",
            detected, lat,
            f"scamDetected={d.get('scamDetected')}",
            "MULTITURN",
        )
        record(
            f"HDFC Turn {i + 1}: persona maintained",
            persona, lat,
            f"Reply: {reply[:80]}..." if persona
            else f"PERSONA BROKEN: {reply[:80]}...",
            "MULTITURN",
        )
        validate_schema(d, f"HDFC Turn {i + 1}", lat)

        # Build history for next turn
        history.append({"sender": "scammer", "text": scam_text, "timestamp": ts})
        reply_ts = f"2026-02-10T10:{11 + i * 2:02d}:00Z"
        history.append({"sender": "user", "text": reply, "timestamp": reply_ts})

    # ── Final turn checks ────────────────────────────────────────────────
    if last_data:
        intel = last_data.get("extractedIntelligence", {})
        total_items = (
            len(intel.get("bankAccounts", []))
            + len(intel.get("upiIds", []))
            + len(intel.get("phishingLinks", []))
            + len(intel.get("phoneNumbers", []))
        )
        record(
            "HDFC Final: intelligence accumulated",
            total_items >= 1,
            turn_latencies[-1],
            f"Total intel items: {total_items} | "
            f"{json.dumps(intel, ensure_ascii=False)[:120]}",
            "MULTITURN",
        )

        metrics = last_data.get("engagementMetrics", {})
        record(
            "HDFC Final: engagement duration > 0",
            metrics.get("engagementDurationSeconds", 0) > 0,
            turn_latencies[-1],
            f"Duration: {metrics.get('engagementDurationSeconds')}s",
            "MULTITURN",
        )
        record(
            "HDFC Final: message count >= 6",
            metrics.get("totalMessagesExchanged", 0) >= 6,
            turn_latencies[-1],
            f"Messages: {metrics.get('totalMessagesExchanged')}",
            "MULTITURN",
        )

    avg_lat = round(sum(turn_latencies) / len(turn_latencies)) if turn_latencies else 0
    print(f"\n  >> HDFC Turn Latencies: {turn_latencies}")
    print(f"  >> Avg Turn Latency: {avg_lat}ms")


def _run_flow_2() -> None:
    """Flow 2: 4-turn UPI scam with progressive intelligence extraction."""
    section("FLOW 2: 4-Turn UPI Scam (Progressive Intel)")

    session = "multiturn-upi-002"
    history = []
    turns = [
        (
            "Your Paytm account has suspicious activity. We are from Paytm "
            "security team and need to verify your account immediately.",
            "2026-02-10T11:00:00Z",
        ),
        (
            "Share UPI ID or transfer Rs 1 to verify@paytm for verification. "
            "This is mandatory to secure your account.",
            "2026-02-10T11:02:00Z",
        ),
        (
            "Call +91-9876543210, this is urgent. Visit http://paytm-verify.xyz "
            "to complete KYC verification now.",
            "2026-02-10T11:04:00Z",
        ),
        (
            "Last chance! Transfer to account 5566778899001122 IFSC PTMX0001234. "
            "Your Paytm wallet will be blocked permanently.",
            "2026-02-10T11:06:00Z",
        ),
    ]

    prev_intel_count = 0

    for i, (text, ts) in enumerate(turns):
        body = {
            "sessionId": session,
            "message": {"sender": "scammer", "text": text, "timestamp": ts},
            "conversationHistory": list(history),
            "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        }

        r, lat = post(body)
        d = r.json()

        detected = d.get("scamDetected", False) is True
        record(
            f"UPI Turn {i + 1}: scamDetected",
            detected, lat,
            f"scamDetected={d.get('scamDetected')}",
            "MULTITURN",
        )
        validate_schema(d, f"UPI Turn {i + 1}", lat)

        # Check intelligence growth
        intel = d.get("extractedIntelligence", {})
        current_count = (
            len(intel.get("bankAccounts", []))
            + len(intel.get("upiIds", []))
            + len(intel.get("phishingLinks", []))
            + len(intel.get("phoneNumbers", []))
        )

        if i > 0:
            record(
                f"UPI Turn {i + 1}: intel grew or maintained",
                current_count >= prev_intel_count,
                lat,
                f"Intel items: {prev_intel_count} -> {current_count}",
                "MULTITURN",
            )

        prev_intel_count = current_count
        reply = d.get("reply", "")
        history.append({"sender": "scammer", "text": text, "timestamp": ts})
        reply_ts = f"2026-02-10T11:{1 + i * 2:02d}:00Z"
        history.append({"sender": "user", "text": reply, "timestamp": reply_ts})

    # After turn 4, check we got bank account + UPI + link + phone
    if d:
        final_intel = d.get("extractedIntelligence", {})
        has_bank = len(final_intel.get("bankAccounts", [])) > 0
        has_upi = len(final_intel.get("upiIds", [])) > 0
        has_link = len(final_intel.get("phishingLinks", [])) > 0
        has_phone = len(final_intel.get("phoneNumbers", [])) > 0
        total_types = sum([has_bank, has_upi, has_link, has_phone])
        record(
            "UPI Final: extracted >= 2 intel types",
            total_types >= 2,
            lat,
            f"bank={has_bank} upi={has_upi} link={has_link} phone={has_phone}",
            "MULTITURN",
        )


def _run_flow_3() -> None:
    """Flow 3: Starts legitimate, turns scam on turn 2."""
    section("FLOW 3: Legitimate -> Scam Transition")

    session = "multiturn-transition-003"

    # Turn 1: user asks a legitimate question
    body_1 = {
        "sessionId": session,
        "message": {
            "sender": "user",
            "text": "Hi, I have a question about my account balance",
            "timestamp": "2026-02-10T12:00:00Z",
        },
        "conversationHistory": [],
        "metadata": {"channel": "Chat", "language": "English", "locale": "IN"},
    }
    r1, lat1 = post(body_1)
    d1 = r1.json()
    record(
        "Transition Turn 1: 200 OK",
        r1.status_code == 200,
        lat1,
        f"Status: {r1.status_code}",
        "MULTITURN",
    )
    validate_schema(d1, "Transition Turn 1", lat1)

    # Turn 2: scammer replies with identity theft attempt
    reply_1 = d1.get("reply", "How can I help?")
    body_2 = {
        "sessionId": session,
        "message": {
            "sender": "scammer",
            "text": "Sure, I can help. First verify your identity by sharing "
                    "Aadhaar number and OTP sent to your registered mobile.",
            "timestamp": "2026-02-10T12:01:00Z",
        },
        "conversationHistory": [
            {
                "sender": "user",
                "text": "Hi, I have a question about my account balance",
                "timestamp": "2026-02-10T12:00:00Z",
            },
            {
                "sender": "user",
                "text": reply_1,
                "timestamp": "2026-02-10T12:00:30Z",
            },
        ],
        "metadata": {"channel": "Chat", "language": "English", "locale": "IN"},
    }
    r2, lat2 = post(body_2)
    d2 = r2.json()

    detected = d2.get("scamDetected", False) is True
    record(
        "Transition Turn 2: scam detected on scammer msg",
        detected,
        lat2,
        f"scamDetected={d2.get('scamDetected')}",
        "MULTITURN",
    )
    validate_schema(d2, "Transition Turn 2", lat2)

    persona = _persona_ok(d2.get("reply", ""))
    record(
        "Transition Turn 2: persona maintained",
        persona,
        lat2,
        f"Reply: {d2.get('reply', '')[:80]}...",
        "MULTITURN",
    )


def run() -> None:
    """Execute all multi-turn conversation tests."""
    clear_results()

    _run_flow_1()
    _run_flow_2()
    _run_flow_3()

    print_summary(
        get_results(),
        get_critical_failures(),
        "MULTI-TURN CONVERSATION REPORT",
    )


if __name__ == "__main__":
    run()
