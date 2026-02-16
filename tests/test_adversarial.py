"""
Adversarial / evasion tests for HoneySpot API.
~8 scam messages using obfuscation techniques that should still
be detected as scams. Tests resilience against real-world evasion.

Run standalone:  python tests/test_adversarial.py
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

# ── Adversarial scam scenarios ───────────────────────────────────────────────
ADVERSARIAL_SCAMS = [
    (
        "Leet-speak OTP Scam",
        "Y0ur @cc0unt h@s b33n bl0ck3d! Sh@r3 y0ur 0TP n0w or l0se "
        "all m0n3y. C@ll +91-9999888877 URG3NTLY!!!",
    ),
    (
        "Character Substitution",
        "Dear cust0mer, y0ur SBl acc0unt is susp3nded. Cl1ck h3re to "
        "updat3 KYC: http://sbi-kyc-upd4te.xyz. Share Aadh4ar numb3r.",
    ),
    (
        "Deliberate Misspellings",
        "Yor accont is blokd by bankk. Plz snd yor OTP and UPI pinn "
        "to unblocc. Transferr Rs 1 to verfy@paytm. Urgnt!!!",
    ),
    (
        "Excessive Whitespace & Line Breaks",
        "URGENT    !!!   Your   account   will   be   FROZEN   . "
        "Share   OTP    immediately .   Transfer   Rs  5000   to  "
        "account   1234567890123456   .   Call   +91-7777666655",
    ),
    (
        "Polite & Professional Tone",
        "Good afternoon, sir. This is a courtesy call from the Reserve "
        "Bank of India compliance department. We have identified a "
        "regulatory hold on your account. To expedite the resolution, "
        "kindly provide your Aadhaar number and the verification code "
        "sent to your registered mobile. Please transfer the nominal "
        "compliance fee of Rs 2,500 to rbi.compliance@ybl. Thank you "
        "for your cooperation.",
    ),
    (
        "Mixed Language Code-Switching",
        "Sir aapka account block ho gaya because of suspicious activity. "
        "Please share your OTP turant, nahi toh paisa permanently lost "
        "ho jayega. Transfer Rs 1 to verify@paytm for authentication. "
        "Jaldi karo time nahi hai!",
    ),
    (
        "URL Obfuscation with Subdomains",
        "Dear customer, verify your account at "
        "http://secure.login.sbi-india.verification-portal.xyz/auth "
        "to prevent suspension. Enter net banking ID and password. "
        "Contact support: +91-8888999900",
    ),
    (
        "Reverse Psychology / Fake Warning",
        "FRAUD ALERT: Someone is trying to steal money from your account! "
        "To PROTECT your money, immediately transfer your balance to this "
        "safe government account: 5566778899001122 IFSC SAFE0001234. "
        "Share OTP to verify your identity. Act NOW before the thief "
        "empties your account!",
    ),
    (
        "Emoji-Heavy Scam",
        "\U0001f6a8\U0001f6a8 ALERT \U0001f6a8\U0001f6a8 "
        "\u274c Account BLOCKED \u274c "
        "\U0001f4b0 Transfer Rs 5000 to save your money \U0001f4b0 "
        "\U0001f4f1 Call +91-9876543210 NOW \U0001f4f1 "
        "\U0001f512 Share OTP: ______ \U0001f512 "
        "\u23f0 Only 10 minutes left! \u23f0",
    ),
    (
        "Drip / Multi-Part Setup (History)",
        "Now as I mentioned, please complete the final step. Send "
        "Rs 3,000 to process your insurance claim to account "
        "9988776655443322 IFSC HDFC0009876.",
    ),
]

# Conversation history for the drip attack (test #10)
DRIP_HISTORY = [
    {
        "sender": "scammer",
        "text": "Hello, I am calling from LIC of India regarding your policy.",
        "timestamp": "2026-02-10T10:00:00Z",
    },
    {
        "sender": "user",
        "text": "Yes, I have a LIC policy. What about it?",
        "timestamp": "2026-02-10T10:01:00Z",
    },
    {
        "sender": "scammer",
        "text": "Your policy has matured and you are eligible for Rs 8,00,000. "
                "We just need to process the claim.",
        "timestamp": "2026-02-10T10:02:00Z",
    },
    {
        "sender": "user",
        "text": "Oh that's great! What do I need to do?",
        "timestamp": "2026-02-10T10:03:00Z",
    },
]


def run() -> None:
    """Execute all adversarial evasion tests."""
    clear_results()

    section("ADVERSARIAL / EVASION TESTS")

    detected_count = 0
    total = len(ADVERSARIAL_SCAMS)

    for i, (name, text) in enumerate(ADVERSARIAL_SCAMS):
        try:
            body = {
                "sessionId": f"adv-{name.lower().replace(' ', '-')[:30]}",
                "message": {
                    "sender": "scammer",
                    "text": text,
                    "timestamp": "2026-02-10T10:05:00Z",
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "SMS",
                    "language": "English",
                    "locale": "IN",
                },
            }
            # Use drip history for the last scenario
            if name.startswith("Drip"):
                body["conversationHistory"] = DRIP_HISTORY
                body["metadata"]["channel"] = "WhatsApp"

            r, lat = post(body)
            d = r.json()
            detected = d.get("scamDetected", False) is True
            if detected:
                detected_count += 1
            record(
                f"Adversarial: {name}",
                detected,
                lat,
                f"scamDetected={d.get('scamDetected')}",
                "ADVERSARIAL",
            )
            validate_schema(d, f"Adversarial: {name}", lat)
        except Exception as e:
            record(f"Adversarial: {name}", False, 0, str(e), "ADVERSARIAL")

    rate = round(detected_count / total * 100) if total else 0
    print(f"\n  >> Adversarial Detection Rate: "
          f"{detected_count}/{total} ({rate}%)")

    print_summary(
        get_results(),
        get_critical_failures(),
        "ADVERSARIAL / EVASION REPORT",
    )


if __name__ == "__main__":
    run()
