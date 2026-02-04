from __future__ import annotations

import logging

import httpx

from config import GUVI_CALLBACK_TIMEOUT_SECONDS, GUVI_CALLBACK_URL
from schemas import ExtractedIntelligence, HoneypotRequest

logger = logging.getLogger("honeypot.callback")


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

    logger.info("Sending GUVI callback | sessionId=%s | scamDetected=%s | totalMessages=%d",
                request.sessionId, scam_detected, total_messages_exchanged)

    async with httpx.AsyncClient(timeout=GUVI_CALLBACK_TIMEOUT_SECONDS) as client:
        try:
            resp = await client.post(GUVI_CALLBACK_URL, json=payload)
            logger.info("GUVI callback done | sessionId=%s | status=%d",
                        request.sessionId, resp.status_code)
        except Exception as exc:
            logger.error("GUVI callback failed | sessionId=%s | error=%s",
                         request.sessionId, exc)

