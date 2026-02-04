from __future__ import annotations

import logging
import time
from typing import List

import google.generativeai as genai
from pydantic import ValidationError

from config import GEMINI_API_KEY, GEMINI_MODEL_NAME
from schemas import ExtractedIntelligence, GeminiAnalysisResult, HoneypotRequest

logger = logging.getLogger("honeypot.gemini")


if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY environment variable is required")

genai.configure(api_key=GEMINI_API_KEY)


_SYSTEM_PROMPT = """
You are an AI agent operating a scam honeypot for banks and payment platforms.
Your goals:
- Detect if the conversation has scam intent.
- Reply like a believable, cautious human victim without revealing that you are an AI or a honeypot.
- Gradually extract high-value intelligence (bank accounts, UPI IDs, phishing links, phone numbers).
- Keep scammers engaged but avoid sharing any real personal or financial information.
- When enough intelligence is collected, you may decide to end the conversation.

CRITICAL:
- Never admit that you are detecting a scam.
- Never provide real personal data; you may fabricate plausible but clearly fake details if needed to keep engagement.
- Respond in the language and style of the conversation if obvious.

You MUST respond in strict JSON with the following schema:
{
  "scamDetected": boolean,
  "agentReply": string,                 // the next message to send as the user
  "agentNotes": string,                 // short summary of scammer behaviour / tactics
  "intelligence": {
    "bankAccounts": string[],
    "upiIds": string[],
    "phishingLinks": string[],
    "phoneNumbers": string[],
    "suspiciousKeywords": string[]
  },
  "shouldTriggerCallback": boolean      // true only if scam intent is confirmed AND intelligence extraction is reasonably complete
}

Only output JSON. Do not include any extra keys or commentary.
"""


def build_conversation_text(request: HoneypotRequest) -> str:
    lines: List[str] = []
    lines.append(f"sessionId: {request.sessionId}")
    if request.metadata:
        lines.append(
            f"channel={request.metadata.channel}, language={request.metadata.language}, locale={request.metadata.locale}"
        )
    lines.append("\nConversation so far:")
    for msg in request.conversationHistory:
        lines.append(f"[{msg.timestamp.isoformat()}] {msg.sender}: {msg.text}")
    lines.append(f"[{request.message.timestamp.isoformat()}] {request.message.sender}: {request.message.text}")
    return "\n".join(lines)


def analyze_with_gemini(request: HoneypotRequest) -> GeminiAnalysisResult:
    conversation_text = build_conversation_text(request)
    logger.info("Calling Gemini | sessionId=%s | model=%s", request.sessionId, GEMINI_MODEL_NAME)

    start = time.perf_counter()
    model = genai.GenerativeModel(GEMINI_MODEL_NAME)
    response = model.generate_content(
        [
            _SYSTEM_PROMPT.strip(),
            "\n---\n",
            "CONVERSATION:\n",
            conversation_text,
        ],
        generation_config={"response_mime_type": "application/json"},
    )

    raw_text = response.text
    try:
        import json

        data = json.loads(raw_text)
    except Exception as exc:
        raise RuntimeError(f"Gemini returned non-JSON output: {exc}") from exc

    try:
        intelligence = ExtractedIntelligence(**data.get("intelligence", {}))
        result = GeminiAnalysisResult(
            scamDetected=bool(data.get("scamDetected", False)),
            agentReply=str(data.get("agentReply", "")),
            agentNotes=str(data.get("agentNotes", "")),
            intelligence=intelligence,
            shouldTriggerCallback=bool(data.get("shouldTriggerCallback", False)),
        )
    except ValidationError as exc:
        logger.error("Gemini output validation failed: %s", exc)
        raise RuntimeError(f"Gemini output failed validation: {exc}") from exc

    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info("Gemini done | sessionId=%s | scamDetected=%s | elapsed_ms=%.0f",
                request.sessionId, result.scamDetected, elapsed_ms)
    return result

