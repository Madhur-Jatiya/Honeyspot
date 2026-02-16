from datetime import datetime, timezone
from typing import List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _parse_timestamp(v: object) -> datetime:
    """Accept epoch ms (int/float), ISO string, or datetime. GUVI sends epoch ms."""
    if isinstance(v, datetime):
        return v
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(float(v) / 1000.0, tz=timezone.utc)
    if isinstance(v, str):
        s = v.replace("Z", "+00:00") if v.endswith("Z") else v
        return datetime.fromisoformat(s)
    raise ValueError(f"Invalid timestamp: {type(v)}")


class Message(BaseModel):
    sender: Literal["scammer", "user"]
    text: str
    timestamp: datetime

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: object) -> datetime:
        return _parse_timestamp(v)

    @field_validator("sender", mode="before")
    @classmethod
    def normalize_sender(cls, v: object) -> str:
        if isinstance(v, str):
            return v.lower().strip()
        return v  # type: ignore


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneypotRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = None


class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int


class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    emailAddresses: List[str] = []
    suspiciousKeywords: List[str] = []


class HoneypotResponse(BaseModel):
    status: Literal["success", "error"]
    reply: str
   


class GeminiAnalysisResult(BaseModel):
    scamDetected: bool
    agentReply: str
    agentNotes: str
    intelligence: ExtractedIntelligence
    shouldTriggerCallback: bool = False

