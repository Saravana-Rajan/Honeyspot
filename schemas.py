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
    model_config = ConfigDict(extra="ignore")

    sender: str
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
        return str(v)


class Metadata(BaseModel):
    model_config = ConfigDict(extra="ignore")

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
    engagementDurationSeconds: int = 0
    totalMessagesExchanged: int = 0


class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    emailAddresses: List[str] = []
    caseIds: List[str] = []
    policyNumbers: List[str] = []
    orderNumbers: List[str] = []
    suspiciousKeywords: List[str] = []


class HoneypotResponse(BaseModel):
    # Per-turn fields (platform reads 'reply' for conversation continuation)
    status: Literal["success", "error"]
    reply: str
    # Scoring fields (included so the platform can score from the response too)
    sessionId: str = ""
    scamDetected: bool = False
    scamType: str = ""
    confidenceLevel: float = 0.0
    totalMessagesExchanged: int = 0
    engagementDurationSeconds: int = 0
    extractedIntelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    engagementMetrics: EngagementMetrics = Field(default_factory=EngagementMetrics)
    agentNotes: str = ""


class GeminiAnalysisResult(BaseModel):
    scamDetected: bool
    scamType: str = ""
    confidenceLevel: float = 0.85
    agentReply: str
    agentNotes: str
    intelligence: ExtractedIntelligence
    shouldTriggerCallback: bool = False
