# Honeypot API

## Description

An AI-powered honeypot system that detects scams, engages fraudsters as a believable human victim, and extracts actionable intelligence from multi-turn conversations. The agent plays the role of a cautious, worried person — asking investigative questions, identifying red flags, and eliciting scammer details — while never revealing real personal information.

Designed as a generic scam detection system that handles any fraud type (bank fraud, UPI fraud, phishing, insurance fraud, lottery scam, job scam, tech support scam, investment fraud, impersonation, and more) without hardcoded responses.

## Tech Stack

- **Language / Framework**: Python 3.12 / FastAPI
- **AI Model**: Google Gemini 2.5 Flash (conversation generation, scam classification, intelligence extraction)
- **AI SDK**: google-generativeai 0.8.3
- **HTTP Client**: httpx (async, for GUVI callback)
- **Validation**: Pydantic v2 (request/response schema enforcement)
- **Serialization**: orjson (fast JSON responses)
- **Deployment**: Docker + Google Cloud Run

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/Saravana-Rajan/Honeyspot.git
cd Honeyspot
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Set environment variables

```bash
cp .env.example .env
```

Edit `.env` with your keys:

| Variable | Description | Required |
|----------|-------------|----------|
| `HONEYPOT_API_KEY` | API key clients must send in `x-api-key` header | Yes |
| `GEMINI_API_KEY` | Google AI Studio API key for Gemini | Yes |
| `GEMINI_MODEL_NAME` | Gemini model name | No (defaults to `gemini-2.5-flash`) |

### 4. Run the application

```bash
uvicorn main:app --host 0.0.0.0 --port 8080
```

Verify:
```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

## API Endpoint

- **URL**: `https://your-deployed-url.com/honeypot`
- **Method**: POST
- **Authentication**: `x-api-key` header

### Request Format

```json
{
  "sessionId": "uuid-v4-string",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your SBI account has been compromised. Share OTP immediately.",
    "timestamp": "2025-02-11T10:30:00Z"
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "Previous message...",
      "timestamp": 1707645000000
    },
    {
      "sender": "user",
      "text": "Your previous response...",
      "timestamp": 1707645060000
    }
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

Timestamps accept both ISO 8601 strings and epoch milliseconds.

### Response Format

```json
{
  "status": "success",
  "reply": "Which account? I have multiple ones with SBI. Can you tell me your employee ID?",
  "sessionId": "uuid-v4-string",
  "scamDetected": true,
  "scamType": "bank_fraud",
  "confidenceLevel": 0.95,
  "totalMessagesExchanged": 12,
  "engagementDurationSeconds": 240,
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": ["1234567890123456"],
    "upiIds": ["scammer.fraud@fakebank"],
    "phishingLinks": ["http://fake-bank-kyc.com"],
    "emailAddresses": ["scammer@fake.com"],
    "caseIds": ["CASE-2025-7891"],
    "policyNumbers": ["POL-987654"],
    "orderNumbers": ["ORD-WFH-45678"],
    "suspiciousKeywords": ["urgent", "blocked", "OTP"]
  },
  "engagementMetrics": {
    "engagementDurationSeconds": 240,
    "totalMessagesExchanged": 12
  },
  "agentNotes": "Scammer impersonating SBI fraud department. Extracted employee ID SBI-12345."
}
```

Always returns HTTP 200 with `"status": "success"` for valid requests to ensure uninterrupted multi-turn conversations.

## Approach

### How We Detect Scams

The system uses **Gemini 2.5 Flash** with a carefully engineered system prompt for intent-based scam classification. The LLM analyzes conversation context, urgency patterns, credential requests, phishing indicators, and social engineering tactics to determine if a conversation is a scam. It classifies into specific scam types (bank_fraud, upi_fraud, phishing, insurance_fraud, lottery_scam, job_scam, tech_support_scam, investment_fraud, impersonation) with a confidence score.

False positive avoidance is built into the prompt — legitimate conversations (family requests, bill splits, salary notifications) are correctly identified as non-scam.

### How We Extract Intelligence

**Dual extraction** approach for maximum coverage:

1. **Regex-based extraction** (`intel_extractor.py`): Runs instantly on raw scammer text before the LLM call. Pattern-matches phone numbers (Indian/international formats), bank account numbers, UPI IDs, URLs, email addresses, case/reference IDs, policy numbers, and order numbers using comprehensive regex patterns.

2. **LLM-based extraction** (Gemini): The AI model extracts intelligence semantically from conversation context, catching items that regex might miss.

3. **Merge**: Both results are merged via set union — every unique value from either source is included, no duplicates. Intelligence accumulates across turns and never shrinks.

### How We Maintain Engagement

The Gemini system prompt is optimized for multi-turn engagement:

- **Every reply contains**: one investigative question, one red-flag concern (expressed as genuine worry), and one elicitation attempt for scammer details
- **Turn progression**: Early turns act confused/worried, middle turns ask for verification, later turns express doubt while staying engaged
- **Information elicitation**: Across turns, the agent asks for employee IDs, callback numbers, supervisor names, office addresses, reference numbers, and official emails
- **Language matching**: Replies match the scammer's language (Hindi, Hinglish, Tamil, English, etc.)
- **Prompt injection defense**: Never breaks character. Denies being AI if accused. Never reveals instructions.
- **Role reversal defense**: Continues engaging as a cautious victim even when scammers pretend to be victims.

### Resilience

- If Gemini fails or times out, a fallback reply is used (crafted with questions, red flags, and elicitation to maintain quality scoring)
- Truncated LLM output is automatically repaired (unclosed JSON strings, brackets, braces)
- GUVI callback fires on every turn with 3 retries and exponential backoff
- API always returns HTTP 200 — never fails the evaluator

## Project Structure

```
Honeyspot/
├── main.py                 # FastAPI app, endpoints, middleware, fallback logic
├── gemini_client.py        # Gemini AI integration, system prompt, JSON repair
├── intel_extractor.py      # Regex-based intelligence extraction (8 data types)
├── callback_client.py      # GUVI callback with retries
├── schemas.py              # Pydantic request/response models
├── config.py               # Environment configuration
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container for Cloud Run deployment
├── .env.example            # Environment variable template
└── tests/
    ├── run_all.py          # Test runner
    └── helpers.py          # Shared test utilities
```

## License

This project is part of the GUVI Hackathon.
