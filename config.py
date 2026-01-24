import os

from dotenv import load_dotenv

load_dotenv()


API_KEY_HEADER_NAME = "x-api-key"
EXPECTED_API_KEY = os.getenv("HONEYPOT_API_KEY", "")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
# Default to a fast, widely available model. You can override via GEMINI_MODEL_NAME env.
GEMINI_MODEL_NAME = os.getenv("GEMINI_MODEL_NAME", "gemini-2.5-flash")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
GUVI_CALLBACK_TIMEOUT_SECONDS = 5

