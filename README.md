# Honeyspot — Agentic Honeypot API

An AI-powered scam honeypot API built with FastAPI and Google Gemini. Honeyspot acts as an intelligent conversational agent that detects scam intent, engages with scammers as a believable victim, and extracts actionable intelligence such as bank accounts, UPI IDs, phishing links, and phone numbers.

Built for the GUVI Hackathon, this service is designed to deploy on Google Cloud Run.

## How It Works

Honeyspot receives conversation messages via a REST API and uses Google Gemini to analyze the conversation in real time. The AI agent plays the role of a cautious human victim — keeping scammers engaged while never revealing real information. When enough intelligence has been gathered and a scam is confirmed, Honeyspot triggers a callback to report the extracted data.

The analysis pipeline computes engagement metrics (duration, message count) and determines whether a callback should be fired based on scam detection confidence and conversation length.

## Tech Stack

- **Python 3.12**
- **FastAPI** — async web framework with automatic OpenAPI docs
- **Google Gemini (gemini-2.5-flash)** — LLM for conversation analysis and response generation
- **Pydantic** — request/response validation and schema definitions
- **HTTPX** — async HTTP client for callback delivery
- **ORJSON** — fast JSON serialization for API responses
- **Uvicorn** — ASGI server
- **Docker** — containerized for Cloud Run deployment

## Project Structure

```
Honeyspot/
├── main.py                # FastAPI app, endpoints, middleware, and request handling
├── gemini_client.py       # Google Gemini integration and prompt engineering
├── callback_client.py     # Async callback client for reporting results to GUVI
├── schemas.py             # Pydantic models for requests, responses, and analysis
├── config.py              # Environment-based configuration (API keys, model settings)
├── requirements.txt       # Python dependencies
├── Dockerfile             # Docker config for Cloud Run deployment
├── .dockerignore          # Files excluded from Docker build
└── honeypot.postman_collection.json  # Postman collection for API testing
```

## API Endpoints

### `POST /honeypot`

The main endpoint. Accepts a conversation payload, analyzes it with Gemini, and returns a reply.

**Headers:**
- `x-api-key` — required API key for authentication

**Request Body:**
```json
{
  "sessionId": "string",
  "message": {
    "sender": "scammer",
    "text": "string",
    "timestamp": 1706140800000
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "string",
    "language": "string",
    "locale": "string"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "string"
}
```

### `GET /health`

Health check endpoint. Returns `{"status": "ok"}`.

## Setup

### Prerequisites

- Python 3.12+
- A Google Gemini API key

### Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/Saravana-Rajan/Honeyspot.git
   cd Honeyspot
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file with your configuration:
   ```env
   HONEYPOT_API_KEY=your-api-key-here
   GEMINI_API_KEY=your-gemini-api-key
   GEMINI_MODEL_NAME=gemini-2.5-flash
   ```

4. Run the server:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8080
   ```

### Docker

```bash
docker build -t honeyspot .
docker run -p 8080:8080 \
  -e HONEYPOT_API_KEY=your-api-key \
  -e GEMINI_API_KEY=your-gemini-key \
  honeyspot
```

### Deploy to Cloud Run

Build and push the container image, then deploy:
```bash
gcloud run deploy honeyspot \
  --source . \
  --set-env-vars HONEYPOT_API_KEY=your-key,GEMINI_API_KEY=your-gemini-key
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `HONEYPOT_API_KEY` | API key for authenticating requests | _(required)_ |
| `GEMINI_API_KEY` | Google Gemini API key | _(required)_ |
| `GEMINI_MODEL_NAME` | Gemini model to use | `gemini-2.5-flash` |

## Intelligence Extraction

When a scam is detected, Honeyspot extracts and reports the following intelligence:

- **Bank Accounts** — account numbers mentioned by the scammer
- **UPI IDs** — payment identifiers shared during the conversation
- **Phishing Links** — suspicious URLs provided by the scammer
- **Phone Numbers** — contact numbers shared in the conversation
- **Suspicious Keywords** — key phrases indicating scam tactics

## License

This project is part of the GUVI Hackathon.
