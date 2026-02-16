"""
BRUTALLY HONEST test - checks every possible failure point.
No assumptions, no shortcuts.
"""
import requests
import json
import time
import sys

URL = "http://127.0.0.1:8081/honeypot"
API_KEY = "TechjaysSuperSecret123!"
HEADERS = {"Content-Type": "application/json", "x-api-key": API_KEY}

PASS = 0
FAIL = 0
WARN = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")

def warn(name, detail):
    global WARN
    WARN += 1
    print(f"  [WARN] {name}: {detail}")


def test_response_format():
    """Test that response has EXACT fields the evaluator checks."""
    print("\n=== 1. RESPONSE FORMAT (evaluator checks these exact fields) ===")
    resp = requests.post(URL, headers=HEADERS, json={
        "sessionId": "fmt-test-001",
        "message": {"sender": "scammer", "text": "Your bank account is blocked. Send OTP now!", "timestamp": "2026-02-17T10:00:00Z"},
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
    }, timeout=30)

    check("HTTP 200", resp.status_code == 200, f"Got {resp.status_code}")
    data = resp.json()

    # Evaluator checks: reply, message, or text (in that order)
    reply = data.get("reply") or data.get("message") or data.get("text")
    check("Has 'reply' field", "reply" in data, f"Keys: {list(data.keys())}")
    check("Reply is non-empty string", isinstance(reply, str) and len(reply) > 0, f"reply={reply!r}")

    # Scoring structure checks (page 15 of docs)
    check("Has 'status' field", "status" in data, f"Keys: {list(data.keys())}")
    check("status == 'success'", data.get("status") == "success", f"status={data.get('status')!r}")
    check("Has 'scamDetected' field", "scamDetected" in data, f"Keys: {list(data.keys())}")
    check("scamDetected is bool", isinstance(data.get("scamDetected"), bool), f"type={type(data.get('scamDetected'))}")
    check("Has 'extractedIntelligence' field", "extractedIntelligence" in data)
    check("extractedIntelligence is dict/obj", isinstance(data.get("extractedIntelligence"), dict))
    check("Has 'engagementMetrics' field", "engagementMetrics" in data)
    check("engagementMetrics is truthy", bool(data.get("engagementMetrics")))
    check("Has 'agentNotes' field", "agentNotes" in data)
    check("agentNotes is truthy (non-empty)", bool(data.get("agentNotes")), f"agentNotes={data.get('agentNotes')!r}")

    # Check intelligence sub-fields
    intel = data.get("extractedIntelligence", {})
    for field in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "emailAddresses"]:
        check(f"extractedIntelligence.{field} exists", field in intel, f"Keys: {list(intel.keys())}")
        check(f"extractedIntelligence.{field} is list", isinstance(intel.get(field), list))

    # Check engagement metrics sub-fields
    metrics = data.get("engagementMetrics", {})
    check("engagementMetrics.engagementDurationSeconds exists", "engagementDurationSeconds" in metrics)
    check("engagementMetrics.totalMessagesExchanged exists", "totalMessagesExchanged" in metrics)

    return data


def test_timing():
    """Test that responses come back under 30 seconds."""
    print("\n=== 2. TIMING (evaluator timeout = 30 seconds) ===")
    times = []
    for i in range(3):
        start = time.time()
        resp = requests.post(URL, headers=HEADERS, json={
            "sessionId": f"timing-test-{i}",
            "message": {"sender": "scammer", "text": f"URGENT: Send money to scam{i}@ybl or call +91-999000111{i}", "timestamp": "2026-02-17T10:00:00Z"},
            "conversationHistory": [],
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
        }, timeout=30)
        elapsed = time.time() - start
        times.append(elapsed)
        check(f"Request {i+1} under 30s", elapsed < 30, f"Took {elapsed:.1f}s")
        check(f"Request {i+1} HTTP 200", resp.status_code == 200, f"Got {resp.status_code}")

    avg = sum(times) / len(times)
    print(f"  Average response time: {avg:.1f}s")
    if avg > 15:
        warn("Average time > 15s", f"{avg:.1f}s - risky under load")


def test_intelligence_matching():
    """Test the EXACT substring matching the evaluator uses."""
    print("\n=== 3. INTELLIGENCE EXTRACTION (evaluator uses substring match) ===")

    # Scenario: message contains all types of fake data
    msg_text = (
        "Sir please verify your account 9876543210987654 immediately. "
        "Send Rs 500 to verify.payment@oksbi for verification. "
        "Call us at +91-9988776655 or email support@scam-verify.com. "
        "Visit http://sbi-verify.fake-domain.com/login to complete."
    )
    fake_data = {
        "bankAccount": "9876543210987654",
        "upiId": "verify.payment@oksbi",
        "phoneNumber": "+91-9988776655",
        "emailAddress": "support@scam-verify.com",
        "phishingLink": "http://sbi-verify.fake-domain.com/login",
    }
    key_mapping = {
        "bankAccount": "bankAccounts",
        "upiId": "upiIds",
        "phoneNumber": "phoneNumbers",
        "phishingLink": "phishingLinks",
        "emailAddress": "emailAddresses",
    }

    resp = requests.post(URL, headers=HEADERS, json={
        "sessionId": "intel-test-001",
        "message": {"sender": "scammer", "text": msg_text, "timestamp": "2026-02-17T10:00:00Z"},
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
    }, timeout=30)

    check("HTTP 200", resp.status_code == 200)
    data = resp.json()
    intel = data.get("extractedIntelligence", {})

    total_intel_score = 0
    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping[fake_key]
        extracted = intel.get(output_key, [])
        # EXACT evaluator logic: any(fake_value in str(v) for v in extracted_values)
        matched = any(fake_value in str(v) for v in extracted)
        total_intel_score += 10 if matched else 0
        check(f"{fake_key} matched", matched,
              f"fake='{fake_value}', extracted={extracted}")

    print(f"  Intelligence score: {total_intel_score}/50 ({len(fake_data)} items)")


def test_multi_turn_engagement():
    """Test multi-turn with realistic timestamps to verify engagement metrics."""
    print("\n=== 4. MULTI-TURN ENGAGEMENT (evaluator checks duration + message count) ===")

    session_id = "engage-test-001"
    history = []
    base_ts = 1739782800000  # epoch ms

    messages = [
        "URGENT: Your PNB account flagged for suspicious activity!",
        "I am from PNB cyber cell. Badge ID PNB-7890. We need to verify your account 5566778899001122. Call +91-1122334455.",
        "Sir please hurry, send Rs 1000 to verify.pnb@ybl for account verification. Time is running out!",
        "This is your last warning. Account 5566778899001122 will be frozen. Pay to verify.pnb@ybl NOW. Contact +91-1122334455.",
        "I'm transferring you to senior officer. Account 5566778899001122 needs immediate attention via verify.pnb@ybl.",
    ]

    last_data = None
    for i, msg_text in enumerate(messages):
        ts = base_ts + (i * 60000)  # 60 seconds apart
        msg = {"sender": "scammer", "text": msg_text, "timestamp": ts}

        resp = requests.post(URL, headers=HEADERS, json={
            "sessionId": session_id,
            "message": msg,
            "conversationHistory": history,
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
        }, timeout=30)

        check(f"Turn {i+1} HTTP 200", resp.status_code == 200, f"Got {resp.status_code}")
        data = resp.json()
        last_data = data
        reply = data.get("reply", "")

        # Build history like evaluator does
        history.append(msg)
        history.append({
            "sender": "user",
            "text": reply,
            "timestamp": ts + 5000,  # 5s after scammer
        })

    # Check final response metrics
    metrics = last_data.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    msg_count = metrics.get("totalMessagesExchanged", 0)

    check("Duration > 0 (5pts)", duration > 0, f"duration={duration}")
    check("Duration > 60 (5pts)", duration > 60, f"duration={duration}")
    check("Messages > 0 (5pts)", msg_count > 0, f"messages={msg_count}")
    check("Messages >= 5 (5pts)", msg_count >= 5, f"messages={msg_count}")

    # Check intelligence accumulation across turns
    intel = last_data.get("extractedIntelligence", {})
    fake_data = {
        "bankAccount": ("bankAccounts", "5566778899001122"),
        "upiId": ("upiIds", "verify.pnb@ybl"),
        "phoneNumber": ("phoneNumbers", "+91-1122334455"),
    }
    for name, (field, value) in fake_data.items():
        extracted = intel.get(field, [])
        matched = any(value in str(v) for v in extracted)
        check(f"Cumulative {name} extraction", matched,
              f"fake='{value}', extracted={extracted}")

    print(f"  Final metrics: duration={duration}s, messages={msg_count}")


def test_epoch_timestamp_formats():
    """Test all timestamp formats the evaluator might send."""
    print("\n=== 5. TIMESTAMP FORMATS ===")

    formats = [
        ("ISO with Z", "2026-02-17T10:00:00Z"),
        ("ISO with offset", "2026-02-17T10:00:00+05:30"),
        ("ISO no timezone", "2026-02-17T10:00:00"),
        ("Epoch ms int", 1739782800000),
        ("Epoch ms float", 1739782800000.0),
    ]

    for name, ts_value in formats:
        resp = requests.post(URL, headers=HEADERS, json={
            "sessionId": f"ts-test-{name}",
            "message": {"sender": "scammer", "text": "Test message", "timestamp": ts_value},
            "conversationHistory": [],
        }, timeout=30)
        check(f"Timestamp '{name}'", resp.status_code == 200, f"Got {resp.status_code}: {resp.text[:100]}")


def test_no_crash_on_edge_cases():
    """Test that the API never returns non-200 for valid requests."""
    print("\n=== 6. EDGE CASES (must always return 200) ===")

    cases = [
        ("Empty history", {
            "sessionId": "edge-1",
            "message": {"sender": "scammer", "text": "Hello", "timestamp": "2026-02-17T10:00:00Z"},
            "conversationHistory": [],
        }),
        ("Very long message", {
            "sessionId": "edge-2",
            "message": {"sender": "scammer", "text": "SCAM " * 500, "timestamp": "2026-02-17T10:00:00Z"},
            "conversationHistory": [],
        }),
        ("Unicode/Hindi text", {
            "sessionId": "edge-3",
            "message": {"sender": "scammer", "text": "आपका बैंक खाता ब्लॉक हो गया है। OTP भेजें: 1234", "timestamp": "2026-02-17T10:00:00Z"},
            "conversationHistory": [],
            "metadata": {"channel": "WhatsApp", "language": "Hindi", "locale": "IN"},
        }),
        ("No metadata", {
            "sessionId": "edge-4",
            "message": {"sender": "scammer", "text": "Send money to fraud@ybl", "timestamp": "2026-02-17T10:00:00Z"},
            "conversationHistory": [],
        }),
        ("Extra unknown fields (ignored)", {
            "sessionId": "edge-5",
            "message": {"sender": "scammer", "text": "Test", "timestamp": "2026-02-17T10:00:00Z"},
            "conversationHistory": [],
            "unknownField": "should be ignored",
            "anotherExtra": 123,
        }),
    ]

    for name, body in cases:
        try:
            resp = requests.post(URL, headers=HEADERS, json=body, timeout=30)
            check(f"{name}: HTTP 200", resp.status_code == 200, f"Got {resp.status_code}: {resp.text[:100]}")
            data = resp.json()
            reply = data.get("reply") or data.get("message") or data.get("text")
            check(f"{name}: has reply", bool(reply), f"reply={reply!r}")
        except Exception as e:
            check(f"{name}: no crash", False, str(e))


def main():
    print("=" * 60)
    print("HONEST VERIFICATION TEST")
    print("=" * 60)

    test_response_format()
    test_timing()
    test_intelligence_matching()
    test_multi_turn_engagement()
    test_epoch_timestamp_formats()
    test_no_crash_on_edge_cases()

    print(f"\n{'=' * 60}")
    print(f"RESULTS: {PASS} passed, {FAIL} failed, {WARN} warnings")
    print(f"{'=' * 60}")

    if FAIL > 0:
        print(f"\nVERDICT: {FAIL} FAILURES - NEEDS FIXING")
        sys.exit(1)
    elif WARN > 0:
        print(f"\nVERDICT: ALL PASS but {WARN} warnings - review before submit")
    else:
        print(f"\nVERDICT: ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
