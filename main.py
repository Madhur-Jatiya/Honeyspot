from __future__ import annotations

import logging
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import ORJSONResponse

from callback_client import send_final_result_callback
from config import API_KEY_HEADER_NAME, EXPECTED_API_KEY
from gemini_client import analyze_with_gemini
from schemas import EngagementMetrics, HoneypotRequest, HoneypotResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("honeypot")


app = FastAPI(
    title="Agentic Honeypot API",
    version="1.0.0",
    default_response_class=ORJSONResponse,
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning("Validation failed: %s", exc.errors())
    return ORJSONResponse(
        status_code=422,
        content={
            "status": "error",
            "message": "Invalid request body",
            "details": exc.errors(),
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.warning("HTTP error %s: %s", exc.status_code, exc.detail)
    return ORJSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "message": exc.detail},
    )


def verify_api_key(x_api_key: Optional[str] = Header(default=None, alias=API_KEY_HEADER_NAME)) -> None:
    if not EXPECTED_API_KEY:
        logger.error("HONEYPOT_API_KEY not configured")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server API key not configured",
        )
    if x_api_key != EXPECTED_API_KEY:
        logger.warning("Invalid or missing API key")
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
    logger.info("Request received | sessionId=%s | message_sender=%s | history_len=%d",
                payload.sessionId, payload.message.sender, len(payload.conversationHistory))

    try:
        analysis = analyze_with_gemini(payload)
    except Exception as exc:
        logger.exception("Gemini error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model error: {exc}",
        )

    metrics = compute_engagement_metrics(payload)
    logger.info("Analysis done | sessionId=%s | scamDetected=%s | reply_len=%d | totalMessages=%d",
                payload.sessionId, analysis.scamDetected, len(analysis.agentReply or ""), metrics.totalMessagesExchanged)

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
        logger.info("Triggering GUVI callback | sessionId=%s | totalMessages=%d",
                    payload.sessionId, metrics.totalMessagesExchanged)
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

    logger.info("Response sent | sessionId=%s", payload.sessionId)
    return response


@app.get("/health")
async def health() -> dict:
    logger.debug("Health check")
    return {"status": "ok"}


# For Cloud Run / local dev with uvicorn:
#   uvicorn main:app --host 0.0.0.0 --port 8080

