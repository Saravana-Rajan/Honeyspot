# Honeyspot - Agentic AI Honeypot for Scam Detection

An AI-powered honeypot system that detects scams, engages fraudsters as a believable human victim, and extracts actionable intelligence (bank accounts, UPI IDs, phone numbers, phishing links, email addresses, case IDs, policy numbers, order numbers) across SMS, WhatsApp, Email, and Chat channels. Supports 10+ Indian languages.

Built for the GUVI Hackathon, designed to deploy on Google Cloud Run.

## Description

Honeyspot is a scam honeypot API that receives suspected scam messages and responds as a naive human victim. The system uses a dual-extraction strategy: Google Gemini AI for intelligent conversation and analysis, plus regex-based pattern matching as a safety net to ensure no intelligence is missed. Every reply is crafted to keep scammers engaged while probing for identifying information.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language / Framework | Python 3.12 / FastAPI |
| AI Model | Google Gemini 2.5 Flash |
| AI SDK | google-generativeai 0.8.3 |
| HTTP Client | httpx (async) |
| Validation | Pydantic v2 |
| Serialization | orjson |
| Deployment | Docker + Google Cloud Run |

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/Saravana-Rajan/Honeyspot.git
cd Honeyspot
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set environment variables

```bash
cp .env.example .env
```

Edit `.env` and fill in your keys:

| Variable | Description | Default |
|----------|-------------|---------|
| `HONEYPOT_API_KEY` | API key for authenticating requests | _(required)_ |
| `GEMINI_API_KEY` | Google Gemini API key | _(required)_ |
| `GEMINI_MODEL_NAME` | Gemini model to use | `gemini-2.5-flash` |

### 5. Run the application

```bash
uvicorn main:app --host 0.0.0.0 --port 8080
```

The server will be available at `http://localhost:8080`.

Verify it's running:

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

## API Endpoint

- **URL:** `https://your-deployed-url.com/honeypot`
- **Method:** POST
- **Authentication:** `x-api-key` header

### Headers

| Header | Required | Description |
|--------|----------|-------------|
| `x-api-key` | Yes | Must match `HONEYPOT_API_KEY` from `.env` |
| `Content-Type` | Yes | `application/json` |

### Request body

```json
{
  "sessionId": "session-001",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your SBI account will be blocked. Share OTP 4829 to verify. Call 9876543210.",
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

### Success response (200)

```json
{
  "status": "success",
  "reply": "Wait which account? I have multiple ones with SBI"
}
```

## Approach

### How We Detect Scams

Honeyspot uses intent-based classification through Gemini AI, not simple keyword matching. The system analyzes conversation context, sender behavior, and linguistic patterns to distinguish genuine messages from scam attempts.

**Detected scam types:** bank fraud, UPI fraud, phishing, tech support scams, lottery/prize scams, impersonation, insurance fraud, investment fraud, job scams.

**False positive avoidance:** Legitimate messages (family money requests, bill splits, salary notifications, genuine OTP mentions) are correctly identified as non-scams based on conversational context and intent analysis.

### How We Extract Intelligence

A dual-extraction strategy ensures maximum intelligence capture:

1. **Gemini AI extraction** — The LLM analyzes conversation context to identify and extract entities (phone numbers, bank accounts, UPI IDs, URLs, emails, case IDs, policy numbers, order numbers).

2. **Regex-based extraction** — Pattern matching runs on all scammer messages as a safety net, catching entities that the LLM might miss. Supports multiple formats:
   - Phone numbers: `+91-XXXX`, `91XXXXXXXX`, bare 10-digit, landlines
   - Bank accounts: 9-20 digit sequences, space/hyphen-separated formats
   - UPI IDs: `name@provider` format
   - URLs: `http://`, `https://`, `www.` prefixed
   - Emails: standard `user@domain.com` format
   - Case/Reference IDs: prefixed (`CASE-123`, `REF-001`) and natural language (`case no 12345`)
   - Policy numbers: prefixed (`POL-123`, `LIC-456`) and natural language (`policy no 12345`)
   - Order numbers: prefixed (`ORD-123`, `TXN-456`) and natural language (`order no 12345`)

3. **Intelligence merging** — Results from both extractors are unioned. Intelligence grows cumulatively across turns and never shrinks.

### How We Maintain Engagement

The system maximizes conversation length through several strategies:

- **Persona:** Acts as a naive, slightly confused, tech-illiterate victim who is cooperative but needs clarification.
- **Question rotation:** Every reply ends with an investigative question, rotating through identity verification, contact details, organizational info, reference numbers, and process details.
- **Red flag tracking:** Explicitly identifies and tracks all scam indicators (urgency, credential requests, impersonation, suspicious links, etc.) in structured agent notes.
- **Language matching:** Responds in the same language as the scammer (Hindi, Tamil, Telugu, Bengali, Marathi, Gujarati, Punjabi, Kannada, Malayalam, English, and Hinglish).
- **Never breaks character:** Defends against prompt injection and role reversal attacks.

### Resilience

- Gemini API calls have a 22-second timeout with a 25-second async wrapper
- Falls back to engaging question-based replies if Gemini is unavailable
- Validation errors and unhandled exceptions return HTTP 200 with fallback replies (evaluator compatibility)
- GUVI callback retries up to 2 times with exponential backoff
- Callbacks are fire-and-forget (non-blocking) and do not affect the API response

## Docker Deployment

### Build and run locally

```bash
docker build -t honeyspot .
docker run -p 8080:8080 --env-file .env honeyspot
```

### Deploy to Google Cloud Run

```bash
gcloud run deploy honeyspot \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "GEMINI_API_KEY=<your-key>,HONEYPOT_API_KEY=<your-key>"
```

## Testing

Start the server, then run the full test suite:

```bash
uvicorn main:app --host 0.0.0.0 --port 8080 &
python tests/run_all.py
```

Test categories: Health, Auth, Validation, Scam Detection (18 types), Multi-Language (10 languages), False Positives, Adversarial Evasion, Multi-Turn Conversations, Intelligence Extraction, Stress Tests, Edge Cases.

## Project Structure

```
Honeyspot/
├── main.py                 # FastAPI app, endpoints, middleware, exception handlers
├── gemini_client.py        # Gemini AI integration, system prompt, conversation analysis
├── intel_extractor.py      # Regex-based intelligence extraction (phone, bank, UPI, URL, email, case ID, policy, order)
├── callback_client.py      # GUVI evaluation callback with retry logic
├── schemas.py              # Pydantic request/response models (HoneypotRequest, HoneypotResponse, ExtractedIntelligence)
├── config.py               # Environment configuration (API keys, model name, callback URL)
├── requirements.txt        # Python dependencies
├── Dockerfile              # Cloud Run container
├── .dockerignore           # Files excluded from Docker build
├── .env.example            # Environment variable template
├── honeypot.postman_collection.json  # Postman collection for API testing
└── tests/
    ├── run_all.py           # Test runner (all categories)
    ├── helpers.py           # Shared test utilities
    ├── test_health.py       # Health endpoint tests
    ├── test_auth.py         # API key security tests
    ├── test_scam_detection.py   # 18 scam type tests
    ├── test_false_positives.py  # Legitimate message filtering
    ├── test_adversarial.py      # Evasion resistance
    ├── test_multiturn.py        # Multi-turn conversation tests
    ├── test_intel_extraction.py # Intelligence extraction accuracy
    ├── test_scoring.py          # Scoring verification
    └── test_edge_cases.py       # Language, injection, role reversal
```

## License

This project is part of the GUVI Hackathon.
