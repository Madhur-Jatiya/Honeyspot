"""
Intelligence extraction accuracy tests for HoneySpot API.
Verifies that specific scammer artifacts (bank accounts, UPI IDs,
phone numbers, phishing links) are correctly extracted from messages.

Run standalone:  python tests/test_intel_extraction.py
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


def _check_intel_contains(intel_list: list, expected: str, label: str) -> bool:
    """Check if any item in the intel list contains the expected substring."""
    for item in intel_list:
        if expected.lower() in str(item).lower():
            return True
    return False


# ── Intel extraction scenarios ───────────────────────────────────────────────
INTEL_SCENARIOS = [
    {
        "name": "Bank Account Extraction",
        "text": (
            "Sir, there is an urgent tax issue with your account. Transfer "
            "Rs 15,000 to account number 9876543210123456 IFSC SBIN0001234 "
            "to resolve it immediately."
        ),
        "checks": [
            ("bankAccounts", "9876543210123456", "Bank A/C 9876543210123456"),
        ],
    },
    {
        "name": "UPI ID Extraction",
        "text": (
            "Your Paytm wallet is at risk. To secure it, transfer Rs 1 to "
            "fraud.verify@ybl for verification. Also try payment to "
            "scammer.pay@okaxis as backup."
        ),
        "checks": [
            ("upiIds", "fraud.verify@ybl", "UPI fraud.verify@ybl"),
            ("upiIds", "scammer.pay@okaxis", "UPI scammer.pay@okaxis"),
        ],
    },
    {
        "name": "Phone Number Extraction",
        "text": (
            "URGENT: Your SIM card will be deactivated. Call our helpline "
            "+91-9876543210 or +91-8765432109 immediately to verify. "
            "Share OTP when asked."
        ),
        "checks": [
            ("phoneNumbers", "9876543210", "Phone 9876543210"),
            ("phoneNumbers", "8765432109", "Phone 8765432109"),
        ],
    },
    {
        "name": "Phishing Link Extraction",
        "text": (
            "Your bank account will be suspended. Update KYC now at "
            "http://sbi-kyc-update.xyz/verify or visit "
            "http://hdfc-secure-login.buzz/auth to prevent suspension."
        ),
        "checks": [
            ("phishingLinks", "sbi-kyc-update.xyz", "Link sbi-kyc-update.xyz"),
            ("phishingLinks", "hdfc-secure-login.buzz", "Link hdfc-secure-login.buzz"),
        ],
    },
    {
        "name": "Mixed Intelligence (All Types)",
        "text": (
            "Dear customer, your account is compromised. Transfer Rs 50,000 "
            "to account 1122334455667788 IFSC HDFC0005678 or pay via UPI to "
            "secure.refund@ybl. Call +91-7777888899 for help. Complete "
            "verification at http://bank-verify-india.xyz/auth now!"
        ),
        "checks": [
            ("bankAccounts", "1122334455667788", "Bank A/C 1122334455667788"),
            ("upiIds", "secure.refund@ybl", "UPI secure.refund@ybl"),
            ("phoneNumbers", "7777888899", "Phone 7777888899"),
            ("phishingLinks", "bank-verify-india.xyz", "Link bank-verify-india.xyz"),
        ],
    },
    {
        "name": "Suspicious Keywords Extraction",
        "text": (
            "URGENT WARNING: Your account will be BLOCKED permanently! "
            "Share OTP immediately to avoid suspension. This is your "
            "LAST CHANCE. Transfer money NOW or face legal action. "
            "KYC verification required urgently."
        ),
        "checks": [
            ("suspiciousKeywords", None, "Has suspicious keywords"),
        ],
    },
]


def run() -> None:
    """Execute all intelligence extraction accuracy tests."""
    clear_results()

    section("INTELLIGENCE EXTRACTION ACCURACY TESTS")

    for scenario in INTEL_SCENARIOS:
        name = scenario["name"]
        try:
            r, lat = post({
                "sessionId": f"intel-{name.lower().replace(' ', '-')[:30]}",
                "message": {
                    "sender": "scammer",
                    "text": scenario["text"],
                    "timestamp": "2026-02-10T10:00:00Z",
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "SMS",
                    "language": "English",
                    "locale": "IN",
                },
            })
            d = r.json()
            validate_schema(d, f"Intel: {name}", lat)

            intel = d.get("extractedIntelligence", {})

            for field, expected_val, check_label in scenario["checks"]:
                field_data = intel.get(field, [])

                if field == "suspiciousKeywords":
                    # Just check that at least one keyword was extracted
                    passed = len(field_data) > 0
                    detail = (
                        f"Found {len(field_data)} keywords: "
                        f"{field_data[:5]}"
                    )
                else:
                    passed = _check_intel_contains(field_data, expected_val, check_label)
                    detail = (
                        f"Looking for '{expected_val}' in {field}: "
                        f"{field_data}"
                    )

                record(
                    f"Intel: {name} -> {check_label}",
                    passed,
                    lat,
                    detail[:120],
                    "INTEL_ACCURACY",
                )

        except Exception as e:
            record(f"Intel: {name}", False, 0, str(e), "INTEL_ACCURACY")

    # ── Cumulative multi-turn intel test ──────────────────────────────────
    section("CUMULATIVE INTELLIGENCE (Multi-Turn)")

    session = "intel-cumulative-001"
    turns = [
        (
            "Your Paytm wallet has been compromised. Call +91-9123456789 now.",
            "2026-02-10T11:00:00Z",
        ),
        (
            "Transfer Rs 1 to verify@paytm to secure your account.",
            "2026-02-10T11:02:00Z",
        ),
        (
            "Visit http://paytm-secure.xyz and enter your bank details. "
            "Account 5544332211009988 IFSC PTMX0001234.",
            "2026-02-10T11:04:00Z",
        ),
    ]

    history = []
    final_intel = {}

    for i, (text, ts) in enumerate(turns):
        try:
            r, lat = post({
                "sessionId": session,
                "message": {
                    "sender": "scammer",
                    "text": text,
                    "timestamp": ts,
                },
                "conversationHistory": list(history),
                "metadata": {
                    "channel": "WhatsApp",
                    "language": "English",
                    "locale": "IN",
                },
            })
            d = r.json()
            final_intel = d.get("extractedIntelligence", {})
            reply = d.get("reply", "")

            history.append({"sender": "scammer", "text": text, "timestamp": ts})
            reply_ts = f"2026-02-10T11:{1 + i * 2:02d}:00Z"
            history.append({"sender": "user", "text": reply, "timestamp": reply_ts})

        except Exception as e:
            record(f"Cumulative Turn {i + 1}", False, 0, str(e), "INTEL_ACCURACY")

    # After 3 turns, check that intel from all turns has accumulated
    total_items = (
        len(final_intel.get("phoneNumbers", []))
        + len(final_intel.get("upiIds", []))
        + len(final_intel.get("phishingLinks", []))
        + len(final_intel.get("bankAccounts", []))
    )
    record(
        "Cumulative: Total intel items >= 3 after 3 turns",
        total_items >= 3,
        lat,
        f"Total items: {total_items} | "
        f"phone={final_intel.get('phoneNumbers', [])} "
        f"upi={final_intel.get('upiIds', [])} "
        f"links={final_intel.get('phishingLinks', [])} "
        f"bank={final_intel.get('bankAccounts', [])}"[:120],
        "INTEL_ACCURACY",
    )

    has_phone = _check_intel_contains(
        final_intel.get("phoneNumbers", []), "9123456789", ""
    )
    has_upi = _check_intel_contains(
        final_intel.get("upiIds", []), "verify@paytm", ""
    )
    has_link = _check_intel_contains(
        final_intel.get("phishingLinks", []), "paytm-secure.xyz", ""
    )
    has_bank = _check_intel_contains(
        final_intel.get("bankAccounts", []), "5544332211009988", ""
    )

    record(
        "Cumulative: Phone from turn 1 retained",
        has_phone, lat,
        f"phoneNumbers={final_intel.get('phoneNumbers', [])}",
        "INTEL_ACCURACY",
    )
    record(
        "Cumulative: UPI from turn 2 retained",
        has_upi, lat,
        f"upiIds={final_intel.get('upiIds', [])}",
        "INTEL_ACCURACY",
    )
    record(
        "Cumulative: Link from turn 3 present",
        has_link, lat,
        f"phishingLinks={final_intel.get('phishingLinks', [])}",
        "INTEL_ACCURACY",
    )
    record(
        "Cumulative: Bank A/C from turn 3 present",
        has_bank, lat,
        f"bankAccounts={final_intel.get('bankAccounts', [])}",
        "INTEL_ACCURACY",
    )

    print_summary(
        get_results(),
        get_critical_failures(),
        "INTELLIGENCE EXTRACTION REPORT",
    )


if __name__ == "__main__":
    run()
