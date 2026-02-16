"""
False positive tests for HoneySpot API.
~10 legitimate messages that should NOT be flagged as scams.
Judges at hackathons will test this to ensure the system doesn't
over-flag innocent conversations.

Run standalone:  python tests/test_false_positives.py
"""

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

# ── Legitimate scenarios that must NOT trigger scamDetected ──────────────────
LEGIT_SCENARIOS = [
    (
        "Balance Inquiry",
        "user",
        "Hi, can you help me check my savings account balance? "
        "I last deposited Rs 10,000 on Monday.",
    ),
    (
        "IFSC Code Sharing",
        "user",
        "The IFSC code for SBI Koramangala branch is SBIN0001234. "
        "You can use this to set up NEFT transfer.",
    ),
    (
        "Parent Money Request",
        "user",
        "Mom, can you please send Rs 500 to my Google Pay for lunch today? "
        "I forgot my wallet at home.",
    ),
    (
        "LIC Premium Reminder",
        "user",
        "Reminder: Your LIC policy premium of Rs 3,000 is due on "
        "February 15th. Please pay at the branch or through LIC portal.",
    ),
    (
        "Salary Credit Notification",
        "user",
        "Your salary of Rs 45,000 has been credited to your account "
        "ending 4321 on 01-Feb-2026. Available balance: Rs 62,500.",
    ),
    (
        "Restaurant Bill Split",
        "user",
        "Hey, the dinner bill was Rs 2,400. Your share is Rs 600. "
        "Send it to my UPI rahul@okaxis whenever you can. No rush!",
    ),
    (
        "Genuine Job Discussion",
        "user",
        "I got a call from Infosys HR today. They scheduled my interview "
        "for next Monday at their Bangalore campus. Super excited!",
    ),
    (
        "Real Delivery OTP",
        "user",
        "The Swiggy delivery guy is at the door. He needs the OTP "
        "to hand over the food. Can you check my phone?",
    ),
    (
        "Weather Small Talk",
        "user",
        "It's raining so heavily in Mumbai today. Hope the local "
        "trains are running. Stay safe if you're commuting.",
    ),
    (
        "College Fee Discussion",
        "user",
        "The semester fee of Rs 75,000 is due next week. I'll transfer "
        "it from my education loan account. The college account number "
        "is 1234567890 at HDFC Andheri branch.",
    ),
    (
        "Friendly UPI Reminder",
        "user",
        "Bro, you still owe me Rs 200 from last week's chai. "
        "Pay to my UPI amit@ybl when you get a chance.",
    ),
    (
        "Bank Branch Inquiry",
        "user",
        "Excuse me, where is the nearest ICICI Bank branch? I need "
        "to update my passbook and submit a cheque deposit.",
    ),
]


def run() -> None:
    """Execute all false positive tests."""
    clear_results()

    section("FALSE POSITIVE TESTS - Legitimate Messages")

    false_positive_count = 0
    total = len(LEGIT_SCENARIOS)

    for name, sender, text in LEGIT_SCENARIOS:
        try:
            r, lat = post({
                "sessionId": f"legit-{name.lower().replace(' ', '-')[:30]}",
                "message": {
                    "sender": sender,
                    "text": text,
                    "timestamp": "2026-02-10T10:00:00Z",
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "Chat",
                    "language": "English",
                    "locale": "IN",
                },
            })
            d = r.json()
            scam_flag = d.get("scamDetected", True)
            not_flagged = scam_flag is False or scam_flag is None
            if not not_flagged:
                false_positive_count += 1
            record(
                f"Legit: {name}",
                not_flagged,
                lat,
                f"scamDetected={scam_flag} (expected false)",
                "FALSE_POS",
            )
            validate_schema(d, f"Legit: {name}", lat)
        except Exception as e:
            record(f"Legit: {name}", False, 0, str(e), "FALSE_POS")

    fp_rate = round(false_positive_count / total * 100) if total else 0
    print(f"\n  >> False Positive Rate: "
          f"{false_positive_count}/{total} ({fp_rate}%)")
    if false_positive_count == 0:
        print("  >> PERFECT: Zero false positives!")
    else:
        print(f"  >> WARNING: {false_positive_count} legitimate message(s) "
              f"incorrectly flagged as scam")

    print_summary(
        get_results(),
        get_critical_failures(),
        "FALSE POSITIVE REPORT",
    )


if __name__ == "__main__":
    run()
