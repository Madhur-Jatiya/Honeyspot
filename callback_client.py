from __future__ import annotations

from datetime import datetime

import httpx

from config import GUVI_CALLBACK_TIMEOUT_SECONDS, GUVI_CALLBACK_URL
from schemas import ExtractedIntelligence, HoneypotRequest


async def send_final_result_callback(
    request: HoneypotRequest,
    scam_detected: bool,
    total_messages_exchanged: int,
    intelligence: ExtractedIntelligence,
    agent_notes: str,
) -> None:
    intelligence_dict = {
        "bankAccounts": intelligence.bankAccounts,
        "upiIds": intelligence.upiIds,
        "phishingLinks": intelligence.phishingLinks,
        "phoneNumbers": intelligence.phoneNumbers,
        "suspiciousKeywords": intelligence.suspiciousKeywords,
    }

    payload = {
        "sessionId": request.sessionId,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages_exchanged,
        "extractedIntelligence": intelligence_dict,
        "agentNotes": agent_notes,
    }

    # Simple log so you can see in the server console that the callback was triggered.
    print("GUVI final callback payload:", payload, flush=True)

    async with httpx.AsyncClient(timeout=GUVI_CALLBACK_TIMEOUT_SECONDS) as client:
        try:
            await client.post(GUVI_CALLBACK_URL, json=payload)
        except Exception:
            # Swallow errors to avoid impacting main API response
            return

