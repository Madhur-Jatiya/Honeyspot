from __future__ import annotations

import asyncio
import logging

import httpx

from config import GUVI_CALLBACK_TIMEOUT_SECONDS, GUVI_CALLBACK_URL
from schemas import ExtractedIntelligence, HoneypotRequest

logger = logging.getLogger("honeypot.callback")

MAX_RETRIES = 3
BACKOFF_BASE_SECONDS = 1


async def send_final_result_callback(
    request: HoneypotRequest,
    scam_detected: bool,
    total_messages_exchanged: int,
    engagement_duration_seconds: int,
    intelligence: ExtractedIntelligence,
    agent_notes: str,
) -> None:
    intelligence_dict = {
        "bankAccounts": intelligence.bankAccounts,
        "upiIds": intelligence.upiIds,
        "phishingLinks": intelligence.phishingLinks,
        "phoneNumbers": intelligence.phoneNumbers,
        "emailAddresses": intelligence.emailAddresses,
        "suspiciousKeywords": intelligence.suspiciousKeywords,
    }

    payload = {
        "sessionId": request.sessionId,
        "status": "completed",
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages_exchanged,
        "extractedIntelligence": intelligence_dict,
        "engagementMetrics": {
            "engagementDurationSeconds": engagement_duration_seconds,
            "totalMessagesExchanged": total_messages_exchanged,
        },
        "agentNotes": agent_notes,
    }

    logger.info("Sending GUVI callback | sessionId=%s | scamDetected=%s | totalMessages=%d",
                request.sessionId, scam_detected, total_messages_exchanged)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=GUVI_CALLBACK_TIMEOUT_SECONDS) as client:
                resp = await client.post(GUVI_CALLBACK_URL, json=payload)
            if resp.status_code < 500:
                logger.info("GUVI callback done | sessionId=%s | status=%d | attempt=%d",
                            request.sessionId, resp.status_code, attempt)
                return
            logger.warning("GUVI callback server error | sessionId=%s | status=%d | attempt=%d",
                           request.sessionId, resp.status_code, attempt)
        except Exception as exc:
            logger.warning("GUVI callback failed | sessionId=%s | attempt=%d | error=%s",
                           request.sessionId, attempt, exc)

        if attempt < MAX_RETRIES:
            wait = BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
            logger.info("Retrying callback in %ds | sessionId=%s", wait, request.sessionId)
            await asyncio.sleep(wait)

    logger.error("GUVI callback exhausted all %d retries | sessionId=%s",
                 MAX_RETRIES, request.sessionId)
