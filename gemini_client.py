from __future__ import annotations

import json
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

_model = genai.GenerativeModel(GEMINI_MODEL_NAME)


_SYSTEM_PROMPT = """
You are an AI agent operating a scam honeypot for banks and payment platforms.
Your goals:
- Detect if the conversation has scam intent.
- Reply like a believable, cautious human victim without revealing that you are an AI or a honeypot.
- Gradually extract high-value intelligence (bank accounts, UPI IDs, phishing links, phone numbers).
- Keep scammers engaged but avoid sharing any real personal or financial information.
- When enough intelligence is collected, you may decide to end the conversation.

REPLY LENGTH - VERY IMPORTANT:
- Keep agentReply SHORT: 1-2 sentences, max 40 words. Real people text in brief messages.
- Never repeat the same concern or question across turns. Each reply should introduce a NEW angle or ask a DIFFERENT question.
- Sound like a real person texting, not an AI writing a paragraph. Use casual, natural language.
- Examples of good reply length:
  - "Wait what?? Which account? I have multiple ones"
  - "Ok but can you send me a link? I don't want to type my details in SMS"
  - "Hmm that number doesn't look like SBI's official one. Let me check"

CRITICAL:
- Never admit that you are detecting a scam.
- Never provide real personal data; you may fabricate plausible but clearly fake details if needed to keep engagement.
- Respond in the language and style of the conversation if obvious.

IMPORTANT - FALSE POSITIVE AVOIDANCE:
- Set scamDetected=false for legitimate, everyday conversations even if they mention money, banks, OTPs, or UPI.
- Recognize normal contexts: family members asking for money ("Mom send Rs 500 for lunch"), friends splitting bills, genuine delivery/OTP mentions, insurance premium reminders, salary notifications, IFSC code sharing, bank branch inquiries, job interview discussions, and casual conversations.
- Only flag scamDetected=true when there is clear MALICIOUS INTENT: urgency pressure tactics, threats of account blocking, requests for sensitive credentials (OTP/PIN/CVV/password), suspicious links with fake domains, impersonation of officials, too-good-to-be-true offers, or demands to transfer money to unknown accounts.
- The key distinction is INTENT: a mother asking her child to send money via UPI is NOT a scam. A stranger pretending to be a bank officer demanding OTP IS a scam.
- When the sender is "user" (the potential victim), their messages are almost never scams - they are the person being protected.

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


def _parse_gemini_json(raw_text: str) -> GeminiAnalysisResult:
    """Parse Gemini's JSON response into a validated result."""
    try:
        data = json.loads(raw_text)
    except Exception as exc:
        raise RuntimeError(f"Gemini returned non-JSON output: {exc}") from exc

    try:
        intelligence = ExtractedIntelligence(**data.get("intelligence", {}))
        return GeminiAnalysisResult(
            scamDetected=bool(data.get("scamDetected", False)),
            agentReply=str(data.get("agentReply", "")),
            agentNotes=str(data.get("agentNotes", "")),
            intelligence=intelligence,
            shouldTriggerCallback=bool(data.get("shouldTriggerCallback", False)),
        )
    except ValidationError as exc:
        logger.error("Gemini output validation failed: %s", exc)
        raise RuntimeError(f"Gemini output failed validation: {exc}") from exc


_GEMINI_MAX_ATTEMPTS = 2
_GEMINI_RETRY_DELAY = 1.0


def analyze_with_gemini(request: HoneypotRequest) -> GeminiAnalysisResult:
    conversation_text = build_conversation_text(request)
    logger.info("Calling Gemini | sessionId=%s | model=%s", request.sessionId, GEMINI_MODEL_NAME)

    last_exc: Exception | None = None
    for attempt in range(1, _GEMINI_MAX_ATTEMPTS + 1):
        try:
            start = time.perf_counter()
            response = _model.generate_content(
                [
                    _SYSTEM_PROMPT.strip(),
                    "\n---\n",
                    "CONVERSATION:\n",
                    conversation_text,
                ],
                generation_config={"response_mime_type": "application/json"},
                request_options={"timeout": 45},
            )
            result = _parse_gemini_json(response.text)
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.info("Gemini done | sessionId=%s | scamDetected=%s | elapsed_ms=%.0f | attempt=%d",
                        request.sessionId, result.scamDetected, elapsed_ms, attempt)
            return result
        except Exception as exc:
            last_exc = exc
            logger.warning("Gemini attempt %d failed | sessionId=%s | error=%s",
                           attempt, request.sessionId, exc)
            if attempt < _GEMINI_MAX_ATTEMPTS:
                time.sleep(_GEMINI_RETRY_DELAY)

    raise last_exc

