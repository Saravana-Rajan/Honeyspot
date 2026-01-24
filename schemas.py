from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class Message(BaseModel):
    sender: Literal["scammer", "user"]
    text: str
    timestamp: datetime


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneypotRequest(BaseModel):
    sessionId: str = Field(..., alias="sessionId")
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None

    class Config:
        populate_by_name = True


class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int


class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []


class HoneypotResponse(BaseModel):
    status: Literal["success", "error"]
    scamDetected: bool
    engagementMetrics: EngagementMetrics
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str = ""
    # Additional but helpful field so the platform can send our reply back
    agentReply: Optional[str] = None


class GeminiAnalysisResult(BaseModel):
    scamDetected: bool
    agentReply: str
    agentNotes: str
    intelligence: ExtractedIntelligence
    shouldTriggerCallback: bool = False

