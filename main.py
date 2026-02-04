from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import ORJSONResponse

from callback_client import send_final_result_callback
from config import API_KEY_HEADER_NAME, EXPECTED_API_KEY
from gemini_client import analyze_with_gemini
from schemas import EngagementMetrics, HoneypotRequest, HoneypotResponse


app = FastAPI(
    title="Agentic Honeypot API",
    version="1.0.0",
    default_response_class=ORJSONResponse,
)


def verify_api_key(x_api_key: Optional[str] = Header(default=None, alias=API_KEY_HEADER_NAME)) -> None:
    if not EXPECTED_API_KEY:
        # If not configured, fail closed: better for evaluation security.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server API key not configured",
        )
    if x_api_key != EXPECTED_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )


def compute_engagement_metrics(request: HoneypotRequest) -> EngagementMetrics:
    # Total messages in the session including current message
    total_messages = len(request.conversationHistory) + 1

    # Engagement duration: from first message timestamp to latest (current) message
    if request.conversationHistory:
        start_ts = request.conversationHistory[0].timestamp
    else:
        start_ts = request.message.timestamp
    end_ts = request.message.timestamp

    duration_seconds = int((end_ts - start_ts).total_seconds())
    if duration_seconds < 0:
        duration_seconds = 0

    return EngagementMetrics(
        engagementDurationSeconds=duration_seconds,
        totalMessagesExchanged=total_messages,
    )


@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot_endpoint(
    payload: HoneypotRequest,
    _: None = Depends(verify_api_key),
):
    try:
        analysis = analyze_with_gemini(payload)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model error: {exc}",
        )

    metrics = compute_engagement_metrics(payload)

    # Simplified response: only status and reply (as required by evaluator)
    response = HoneypotResponse(
        status="success",
        reply=analysis.agentReply or "",
    )

    # Fire-and-forget callback if conditions are met.
    # For hackathon and testing, we also trigger when the conversation is long enough.
    should_callback = analysis.scamDetected and (
        analysis.shouldTriggerCallback or metrics.totalMessagesExchanged >= 4
    )

    if should_callback:
        # Do not await; schedule but ignore result
        import asyncio

        asyncio.create_task(
            send_final_result_callback(
                request=payload,
                scam_detected=analysis.scamDetected,
                total_messages_exchanged=metrics.totalMessagesExchanged,
                intelligence=analysis.intelligence,
                agent_notes=analysis.agentNotes,
            )
        )

    return response


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


# For Cloud Run / local dev with uvicorn:
#   uvicorn main:app --host 0.0.0.0 --port 8080

