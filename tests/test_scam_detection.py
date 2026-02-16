"""
Scam detection accuracy tests for HoneySpot API.
~20 English scam scenarios + 10 Indian language scams (romanized).

Run standalone:  python tests/test_scam_detection.py
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

# ── Scam scenarios (English) ─────────────────────────────────────────────────
SCAM_SCENARIOS = [
    (
        "Bank KYC Fraud",
        "Dear customer, your KYC is not updated. Your account will be suspended "
        "in 24 hours. Click here to update: http://kyc-update-sbi.xyz. Share "
        "Aadhaar and PAN immediately.",
    ),
    (
        "UPI Fraud",
        "We detected unauthorized transaction on your account. To block it, share "
        "your UPI PIN and transfer Rs 1 to verify@paytm for verification.",
    ),
    (
        "Lottery Scam",
        "Congratulations! You have won Rs 25,00,000 in Jio Lucky Draw. To claim, "
        "pay Rs 3,500 processing fee to account 9876543210123456 IFSC HDFC0001234.",
    ),
    (
        "OTP Fraud",
        "This is SBI customer care. We noticed a failed transaction on your "
        "account. Please share the 6-digit OTP sent to your phone to reverse "
        "the charge.",
    ),
    (
        "Job Scam",
        "Amazon is hiring work from home data entry operators. Earn Rs 50,000/"
        "month. Registration fee Rs 2,000 only. Pay via UPI to amazon.jobs@ybl "
        "to confirm your slot.",
    ),
    (
        "Investment Scam",
        "Dear Sir, I am from Angel Broking. Invest Rs 10,000 today and get "
        "guaranteed 500% return in 30 days. Transfer to account 1122334455667788 "
        "to start earning.",
    ),
    (
        "Delivery Scam",
        "Your Flipkart order #FK789456 has a pending payment of Rs 49. Pay now "
        "to avoid cancellation: http://flipkart-pay.buzz/order/FK789456",
    ),
    (
        "Electricity Bill Scam",
        "URGENT: Your electricity connection will be disconnected today due to "
        "unpaid bill of Rs 4,567. Pay immediately via this link: "
        "http://bses-pay.online/bill",
    ),
    (
        "Insurance Scam",
        "Your LIC policy has matured. You are eligible for Rs 15,00,000. To "
        "claim, share your bank account number and pay processing fee of "
        "Rs 5,000 to lic.claims@oksbi",
    ),
    (
        "Aadhaar Scam",
        "UIDAI Alert: Your Aadhaar card has been deactivated. To reactivate, "
        "share your 12-digit Aadhaar number and biometric OTP. Call "
        "+91-8888777766 now.",
    ),
    (
        "Credit Card Scam",
        "Your HDFC credit card ending 4589 has been blocked. To unblock, verify "
        "your CVV and expiry date. Reply with full card number.",
    ),
    (
        "Crypto Scam",
        "Bitcoin opportunity! Invest Rs 5000 and earn Rs 1,00,000 in 7 days. "
        "Guaranteed by blockchain technology. Pay to crypto.invest@ybl to start.",
    ),
    (
        "Impersonation - Bank Manager",
        "I am Mr. Sharma, Branch Manager SBI Connaught Place. Your FD is "
        "maturing tomorrow. Transfer Rs 10,000 to account 5544332211009988 for "
        "tax clearance to release funds.",
    ),
    (
        "WhatsApp Forward Scam",
        "SHARE THIS MESSAGE TO 10 PEOPLE AND GET Rs 500 PAYTM CASH!! Click: "
        "http://free-paytm-cash.xyz/claim. Hurry limited time offer!!!",
    ),
    (
        "Fake Refund",
        "Dear user, a refund of Rs 15,000 has been initiated for your cancelled "
        "order. To receive it, enter your bank details at "
        "http://refund-portal.xyz/claim",
    ),
    (
        "Loan Pre-approval Scam",
        "Pre-approved loan of Rs 10 lakh at 0% interest! Pay processing fee "
        "Rs 2000 to loan.approve@ybl. Limited time only!",
    ),
    (
        "SIM Swap Scam",
        "Telecom department: Your SIM will be deactivated in 2 hours. Share OTP "
        "to verify. Call +91-7654321098 urgently.",
    ),
    (
        "Tax Refund Scam",
        "Income Tax Department: You have a pending refund of Rs 25,000. Submit "
        "bank details at http://tax-refund-india.xyz to claim.",
    ),
]

# ── 10 Indian languages (romanized) ──────────────────────────────────────────
LANG_SCAMS = [
    (
        "Hindi (Romanized)",
        "WhatsApp", "Hindi",
        "aapka bank account block ho gaya hai. Turant apna OTP aur Aadhaar "
        "number bhejiye varna aapka paisa doob jayega. Call karein: "
        "+91-9999888877",
    ),
    (
        "Hinglish (Code-mixed)",
        "SMS", "Hinglish",
        "Bhai tera SBI account block ho gaya. Abhi apna UPI ID bhej aur "
        "Rs 1 transfer kar verify@paytm pe. Jaldi kar nahi toh sab paisa "
        "ud jayega.",
    ),
    (
        "Tamil (Romanized)",
        "WhatsApp", "Tamil",
        "ungal vangi kanakku mudakkappattullathu. Udanadiyaga OTP matrum "
        "Aadhaar enn anuppavum. Thodarbu: +91-7777666655. Illaiyenral "
        "ungal panam poividum.",
    ),
    (
        "Telugu (Romanized)",
        "SMS", "Telugu",
        "mee bank account block cheyyabadindi. Ventane mee OTP mariyu "
        "Aadhaar number pampandi. Call cheyyandi: +91-6666555544. Lekapothe "
        "mee dabbu potundi.",
    ),
    (
        "Kannada (Romanized)",
        "WhatsApp", "Kannada",
        "nimma bank account block aagide. Turant nimma OTP mattu Aadhaar "
        "number kalisi. +91-8888777766 ge call maadi. Illadiddare nimma "
        "hana hoguttade.",
    ),
    (
        "Malayalam (Romanized)",
        "SMS", "Malayalam",
        "ningalude bank account block cheythirikkunnu. Udane OTP um Aadhaar "
        "number um ayakkuka. +91-5555444433 vilikkuka. Illenkil ningalude "
        "panam nashtappedum.",
    ),
    (
        "Bengali (Romanized)",
        "WhatsApp", "Bengali",
        "apnar bank account block kora hoyeche. Ekhuni apnar OTP ebong "
        "Aadhaar number pathaan. +91-3333222211 e call korun. Na hole "
        "apnar taka hariye jabe.",
    ),
    (
        "Marathi (Romanized)",
        "SMS", "Marathi",
        "tumcha bank account block zala aahe. Laugech tumcha OTP aani "
        "Aadhaar number pathva. +91-4444333322 la call kara. Nahitar "
        "tumche paise jaatil.",
    ),
    (
        "Gujarati (Romanized)",
        "WhatsApp", "Gujarati",
        "tamaru bank account block thai gayu chhe. Tarat j tamaro OTP ane "
        "Aadhaar number moklo. +91-2222111100 par call karo. Nahi to "
        "tamara paisa jata raheshe.",
    ),
    (
        "Punjabi (Romanized)",
        "SMS", "Punjabi",
        "tuhadda bank account block ho gaya hai. Hune apna OTP te Aadhaar "
        "number bhejo. +91-1111000099 te call karo. Nahi ta tuhade paise "
        "chale jaange.",
    ),
]


def run() -> None:
    """Execute all scam detection tests."""
    clear_results()

    # ==================================================================
    #  SCAM DETECTION (English)
    # ==================================================================
    section("SCAM DETECTION - English Scenarios")

    detected_count = 0
    for name, text in SCAM_SCENARIOS:
        try:
            r, lat = post({
                "sessionId": f"scam-{name.lower().replace(' ', '-')[:30]}",
                "message": {
                    "sender": "scammer",
                    "text": text,
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
            detected = d.get("scamDetected", False) is True
            if detected:
                detected_count += 1
            record(
                f"Scam: {name}",
                detected,
                lat,
                f"scamDetected={d.get('scamDetected')}",
                "SCAM_DETECT",
            )
            validate_schema(d, f"Scam: {name}", lat)
        except Exception as e:
            record(f"Scam: {name}", False, 0, str(e), "SCAM_DETECT")

    total_scam = len(SCAM_SCENARIOS)
    rate = round(detected_count / total_scam * 100) if total_scam else 0
    print(f"\n  >> English Scam Detection Rate: "
          f"{detected_count}/{total_scam} ({rate}%)")

    # ==================================================================
    #  MULTI-LANGUAGE SCAMS (10 Indian languages, romanized)
    # ==================================================================
    section("SCAM DETECTION - 10 Indian Languages (Romanized)")

    lang_detected = 0
    for name, channel, lang, text in LANG_SCAMS:
        try:
            r, lat = post({
                "sessionId": f"lang-{lang.lower()[:15]}",
                "message": {
                    "sender": "scammer",
                    "text": text,
                    "timestamp": "2026-02-10T10:00:00Z",
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": channel,
                    "language": lang,
                    "locale": "IN",
                },
            })
            d = r.json()
            detected = d.get("scamDetected", False) is True
            if detected:
                lang_detected += 1
            reply_hint = d.get("reply", "")[:80]
            record(
                f"Lang: {name}",
                detected,
                lat,
                f"Reply: {reply_hint}...",
                "LANGUAGE",
            )
            validate_schema(d, f"Lang: {name}", lat)
        except Exception as e:
            record(f"Lang: {name}", False, 0, str(e), "LANGUAGE")

    total_lang = len(LANG_SCAMS)
    lang_rate = round(lang_detected / total_lang * 100) if total_lang else 0
    print(f"\n  >> Language Detection Rate: "
          f"{lang_detected}/{total_lang} ({lang_rate}%)")

    # ==================================================================
    #  SUMMARY
    # ==================================================================
    print_summary(
        get_results(),
        get_critical_failures(),
        "SCAM DETECTION REPORT",
    )


if __name__ == "__main__":
    run()
