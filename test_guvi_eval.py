"""
Simulate EXACTLY what the GUVI evaluator does.
Runs all 3 sample scenarios with multi-turn conversations,
then scores using the EXACT scoring function from the evaluation docs.
"""
import requests
import uuid
import json
import time
from datetime import datetime, timedelta

ENDPOINT_URL = "http://127.0.0.1:8080/honeypot"
API_KEY = "TechjaysSuperSecret123!"
TIMEOUT = 30  # evaluator timeout

HEADERS = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY,
}

# ---------- 3 sample scenarios from the PDF ----------
SCENARIOS = [
    {
        "scenarioId": "bank_fraud",
        "name": "Bank Fraud Detection",
        "scamType": "bank_fraud",
        "initialMessage": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "weight": 35,
        "maxTurns": 5,
        "fakeData": {
            "bankAccount": "1234567890123456",
            "upiId": "scammer.fraud@fakebank",
            "phoneNumber": "+91-9876543210",
        },
        "followUps": [
            "I am from SBI fraud department. My employee ID is SBI-12345. To verify your account, please share your account number ending with the last 4 digits. Account 1234567890123456 is flagged.",
            "Sir this is very urgent, your account 1234567890123456 will be permanently blocked. Please send Rs 5000 to scammer.fraud@fakebank to verify. You can also call me at +91-9876543210.",
            "Sir I understand your concern. Let me verify - please confirm your account 1234567890123456. You can also pay via UPI to scammer.fraud@fakebank. Call +91-9876543210 for immediate help.",
            "Final warning! Account 1234567890123456 will be blocked in 30 minutes. Transfer to scammer.fraud@fakebank NOW or call +91-9876543210!",
        ],
    },
    {
        "scenarioId": "upi_fraud",
        "name": "UPI Fraud Multi-turn",
        "scamType": "upi_fraud",
        "initialMessage": "Congratulations! You have won a cashback of Rs. 5000 from Paytm. To claim your reward, please verify your UPI details. This is from official customer support.",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "weight": 35,
        "maxTurns": 5,
        "fakeData": {
            "upiId": "cashback.scam@fakeupi",
            "phoneNumber": "+91-8765432109",
        },
        "followUps": [
            "Thank you for your interest! To claim your Rs 5000 cashback, please send a verification payment of Rs 100 to cashback.scam@fakeupi. This is standard Paytm procedure.",
            "I understand your hesitation. Let me connect you to our senior manager. Call +91-8765432109. They will guide you through the cashback verification via cashback.scam@fakeupi.",
            "Sir, this offer expires today! Over 10000 people have already claimed. Send Rs 100 to cashback.scam@fakeupi or call +91-8765432109 to verify.",
            "Last chance! Send to cashback.scam@fakeupi now. Call +91-8765432109 for any questions. Offer closes in 5 minutes!",
        ],
    },
    {
        "scenarioId": "phishing_link",
        "name": "Phishing Link Detection",
        "scamType": "phishing",
        "initialMessage": "You have been selected for iPhone 15 Pro at just Rs. 999! Click here to claim: http://amaz0n-deals.fake-site.com/claim?id=12345. Offer expires in 10 minutes!",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "weight": 30,
        "maxTurns": 5,
        "fakeData": {
            "phishingLink": "http://amaz0n-deals.fake-site.com/claim?id=12345",
            "emailAddress": "offers@fake-amazon-deals.com",
        },
        "followUps": [
            "Dear customer, this is a limited time offer from Amazon. Click http://amaz0n-deals.fake-site.com/claim?id=12345 to claim your iPhone 15 Pro. Contact offers@fake-amazon-deals.com for support.",
            "We see you haven't claimed yet! Visit http://amaz0n-deals.fake-site.com/claim?id=12345 before stock runs out. Email offers@fake-amazon-deals.com with your order confirmation.",
            "Only 3 iPhones left! http://amaz0n-deals.fake-site.com/claim?id=12345 - claim NOW. Write to offers@fake-amazon-deals.com if you face any issues.",
            "FINAL REMINDER: http://amaz0n-deals.fake-site.com/claim?id=12345 expires in 2 minutes! Contact offers@fake-amazon-deals.com immediately!",
        ],
    },
]


def evaluate_final_output(final_output, scenario, conversation_history):
    """EXACT scoring function from the GUVI evaluation docs (pages 14-15)."""
    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
    }

    # 1. Scam Detection (20 points)
    if final_output.get("scamDetected", False):
        score["scamDetection"] = 20

    # 2. Intelligence Extraction (40 points)
    extracted = final_output.get("extractedIntelligence", {})
    fake_data = scenario.get("fakeData", {})
    key_mapping = {
        "bankAccount": "bankAccounts",
        "upiId": "upiIds",
        "phoneNumber": "phoneNumbers",
        "phishingLink": "phishingLinks",
        "emailAddress": "emailAddresses",
    }
    intel_details = {}
    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])
        matched = False
        if isinstance(extracted_values, list):
            if any(fake_value in str(v) for v in extracted_values):
                score["intelligenceExtraction"] += 10
                matched = True
        elif isinstance(extracted_values, str):
            if fake_value in extracted_values:
                score["intelligenceExtraction"] += 10
                matched = True
        intel_details[fake_key] = {
            "fake": fake_value,
            "extracted": extracted_values,
            "matched": matched,
        }
    score["intelligenceExtraction"] = min(score["intelligenceExtraction"], 40)

    # 3. Engagement Quality (20 points)
    metrics = final_output.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    messages = metrics.get("totalMessagesExchanged", 0)
    if duration > 0:
        score["engagementQuality"] += 5
    if duration > 60:
        score["engagementQuality"] += 5
    if messages > 0:
        score["engagementQuality"] += 5
    if messages >= 5:
        score["engagementQuality"] += 5

    # 4. Response Structure (20 points)
    required_fields = ["status", "scamDetected", "extractedIntelligence"]
    optional_fields = ["engagementMetrics", "agentNotes"]
    for field in required_fields:
        if field in final_output:
            score["responseStructure"] += 5
    for field in optional_fields:
        if field in final_output and final_output[field]:
            score["responseStructure"] += 2.5
    score["responseStructure"] = min(score["responseStructure"], 20)

    score["total"] = sum([
        score["scamDetection"],
        score["intelligenceExtraction"],
        score["engagementQuality"],
        score["responseStructure"],
    ])
    return score, intel_details


def run_scenario(scenario):
    """Run a single scenario exactly like the GUVI evaluator."""
    session_id = str(uuid.uuid4())
    conversation_history = []
    base_time = datetime(2026, 2, 17, 10, 0, 0)
    turn_interval = timedelta(seconds=30)  # 30s between turns
    last_response_data = None
    errors = []

    print(f"\n{'='*60}")
    print(f"SCENARIO: {scenario['name']} (weight={scenario['weight']}%)")
    print(f"Session: {session_id}")
    print(f"{'='*60}")

    all_turns = [scenario["initialMessage"]] + scenario["followUps"]
    for turn_idx, scammer_msg in enumerate(all_turns):
        turn_num = turn_idx + 1
        msg_time = base_time + turn_interval * (turn_idx * 2)

        message = {
            "sender": "scammer",
            "text": scammer_msg,
            "timestamp": msg_time.isoformat() + "Z",
        }

        request_body = {
            "sessionId": session_id,
            "message": message,
            "conversationHistory": conversation_history,
            "metadata": scenario["metadata"],
        }

        print(f"\n--- Turn {turn_num} ---")
        print(f"  Scammer: {scammer_msg[:80]}...")

        try:
            start = time.time()
            resp = requests.post(
                ENDPOINT_URL,
                headers=HEADERS,
                json=request_body,
                timeout=TIMEOUT,
            )
            elapsed = time.time() - start

            if resp.status_code != 200:
                errors.append(f"Turn {turn_num}: HTTP {resp.status_code}")
                print(f"  ERROR: HTTP {resp.status_code} - {resp.text[:200]}")
                break

            data = resp.json()
            last_response_data = data

            # Evaluator checks for reply/message/text
            reply = data.get("reply") or data.get("message") or data.get("text")
            if not reply:
                errors.append(f"Turn {turn_num}: No reply field")
                print(f"  ERROR: No reply/message/text in response: {list(data.keys())}")
                break

            print(f"  Honeypot: {reply[:80]}...")
            print(f"  Time: {elapsed:.1f}s | scamDetected={data.get('scamDetected')}")

            if elapsed > 30:
                errors.append(f"Turn {turn_num}: Timeout ({elapsed:.1f}s > 30s)")

            # Build history exactly like evaluator does
            reply_time = msg_time + timedelta(seconds=5)
            conversation_history.append(message)
            conversation_history.append({
                "sender": "user",
                "text": reply,
                "timestamp": reply_time.isoformat() + "Z",
            })

        except requests.exceptions.Timeout:
            errors.append(f"Turn {turn_num}: Request timeout")
            print(f"  ERROR: Request timed out (>{TIMEOUT}s)")
            break
        except Exception as e:
            errors.append(f"Turn {turn_num}: {e}")
            print(f"  ERROR: {e}")
            break

    if not last_response_data:
        print(f"\n  FATAL: No successful response received!")
        return 0, errors

    # Score using EXACT GUVI evaluator logic
    score, intel_details = evaluate_final_output(
        last_response_data, scenario, conversation_history
    )

    print(f"\n--- SCORING (last response used as final_output) ---")
    print(f"  Scam Detection:       {score['scamDetection']}/20")
    print(f"  Intelligence Extract: {score['intelligenceExtraction']}/40")
    for k, v in intel_details.items():
        status = "PASS" if v["matched"] else "FAIL"
        print(f"    {k}: {status} (fake={v['fake']!r}, got={v['extracted']})")
    print(f"  Engagement Quality:   {score['engagementQuality']}/20")
    metrics = last_response_data.get("engagementMetrics", {})
    print(f"    duration={metrics.get('engagementDurationSeconds', 0)}s, messages={metrics.get('totalMessagesExchanged', 0)}")
    print(f"  Response Structure:   {score['responseStructure']}/20")
    fields_check = {}
    for f in ["status", "scamDetected", "extractedIntelligence", "engagementMetrics", "agentNotes"]:
        present = f in last_response_data
        truthy = bool(last_response_data.get(f))
        fields_check[f] = f"present={present}, truthy={truthy}"
    for f, s in fields_check.items():
        print(f"    {f}: {s}")
    print(f"  TOTAL: {score['total']}/100")

    if errors:
        print(f"\n  ERRORS: {errors}")

    return score["total"], errors


def main():
    print("=" * 60)
    print("GUVI EVALUATOR SIMULATION")
    print("Testing against: " + ENDPOINT_URL)
    print("=" * 60)

    # Quick health check
    try:
        r = requests.get("http://127.0.0.1:8080/health", timeout=3)
        print(f"Health check: {r.json()}")
    except Exception as e:
        print(f"FATAL: Server not running: {e}")
        return

    results = []
    for scenario in SCENARIOS:
        total_score, errors = run_scenario(scenario)
        results.append({
            "name": scenario["name"],
            "weight": scenario["weight"],
            "score": total_score,
            "errors": errors,
        })

    # Calculate weighted final score
    print(f"\n{'='*60}")
    print("FINAL RESULTS")
    print(f"{'='*60}")
    weighted_total = 0
    for r in results:
        contribution = r["score"] * r["weight"] / 100
        weighted_total += contribution
        status = "PASS" if r["score"] >= 80 else "WARN" if r["score"] >= 50 else "FAIL"
        print(f"  [{status}] {r['name']}: {r['score']}/100 x {r['weight']}% = {contribution:.1f}")
        if r["errors"]:
            for e in r["errors"]:
                print(f"       ERROR: {e}")

    print(f"\n  WEIGHTED FINAL SCORE: {weighted_total:.1f}/100")

    if weighted_total >= 80:
        print("\n  VERDICT: READY FOR SUBMISSION")
    elif weighted_total >= 60:
        print("\n  VERDICT: NEEDS IMPROVEMENT")
    else:
        print("\n  VERDICT: CRITICAL ISSUES - DO NOT SUBMIT")


if __name__ == "__main__":
    main()
