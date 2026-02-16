# Honeypot API

## Description

An agentic AI honeypot system for scam detection and intelligence extraction. The API impersonates a cautious human victim to engage scammers across SMS, WhatsApp, Email, and Chat channels. It detects fraud patterns, extracts intelligence (phone numbers, bank accounts, UPI IDs, phishing links, email addresses), and reports findings via callback.

## Tech Stack

- **Language/Framework**: Python 3.12 / FastAPI
- **AI Model**: Google Gemini 2.5 Flash (via `google-generativeai` SDK)
- **HTTP Client**: httpx (async callbacks to GUVI evaluation endpoint)
- **Validation**: Pydantic v2
- **Deployment**: Docker + Google Cloud Run

## Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/Saravana-Rajan/Honeyspot.git
   cd Honeyspot
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set environment variables:
   ```bash
   cp .env.example .env
   # Edit .env and add your GEMINI_API_KEY and HONEYPOT_API_KEY
   ```

4. Run the application:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8080
   ```

## API Endpoint

- **URL**: `POST /honeypot`
- **Authentication**: `x-api-key` header
- **Health Check**: `GET /health`

### Request Format

```json
{
  "sessionId": "uuid-string",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your account has been compromised...",
    "timestamp": "2026-02-11T10:30:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Response Format

```json
{
  "status": "success",
  "reply": "Which account? I have multiple ones..."
}
```

## Approach

### Scam Detection
- Uses Gemini AI with a detailed system prompt to analyze conversation intent
- Detects urgency tactics, credential requests, phishing links, impersonation, and social engineering
- Supports 10+ Indian languages (Hindi, Tamil, Telugu, Bengali, etc.) with language-matched replies
- Robust against prompt injection, role reversal, and adversarial evasion techniques

### Intelligence Extraction
- Extracts bank accounts, UPI IDs, phone numbers, phishing links, and email addresses from every scammer message
- Cumulative extraction across multi-turn conversations
- Sends extracted intelligence to GUVI callback endpoint when scam is confirmed

### Engagement Strategy
- Replies as a cautious, believable human victim (short 1-2 sentence replies)
- Asks probing questions to elicit more intelligence from scammers
- Never reveals AI nature or shares real personal data
- Fabricates plausible fake details when needed to maintain engagement

## Testing

Run the full test suite (239 tests):
```bash
uvicorn main:app --host 0.0.0.0 --port 8080 &
python tests/run_all.py
```

Test categories: Health, Auth, Validation, Scam Detection (18 types), Multi-Language (10 languages), False Positives, Adversarial Evasion, Multi-Turn Conversations, Intelligence Extraction, Stress Tests, Edge Cases (Language Matching, Prompt Injection Defense, Role Reversal Defense).
