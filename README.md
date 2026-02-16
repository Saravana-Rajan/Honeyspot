# Honeyspot - Agentic AI Honeypot for Scam Detection

An AI-powered honeypot system that detects scams, engages fraudsters as a believable human victim, and extracts actionable intelligence (bank accounts, UPI IDs, phone numbers, phishing links, email addresses) across SMS, WhatsApp, Email, and Chat channels. Supports 10+ Indian languages.

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

## Prerequisites

- Python 3.10+ (tested on 3.12 and 3.14)
- A [Google AI Studio](https://aistudio.google.com/) API key for Gemini
- (Optional) Docker for containerized deployment
- (Optional) Google Cloud CLI (`gcloud`) for Cloud Run deployment

## Installation

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

### 4. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and fill in your keys:

```dotenv
GEMINI_API_KEY=your-gemini-api-key-here      # Required - from Google AI Studio
HONEYPOT_API_KEY=your-api-key-here           # Required - any secret string for auth
GEMINI_MODEL_NAME=gemini-2.5-flash           # Optional - defaults to gemini-2.5-flash
```

### 5. Start the server

```bash
uvicorn main:app --host 0.0.0.0 --port 8080
```

The server will be available at `http://localhost:8080`.

Verify it's running:

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

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

## API Reference

### Health Check

```
GET /health
```

```bash
curl http://localhost:8080/health
```

Response: `{"status": "ok"}`

### Analyze Message

```
POST /honeypot
```

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `x-api-key` | Yes | Must match `HONEYPOT_API_KEY` from `.env` |
| `Content-Type` | Yes | `application/json` |

**Request body:**

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

**Success response (200):**

```json
{
  "status": "success",
  "reply": "Wait which account? I have multiple ones with SBI"
}
```

### Usage Examples

**Basic scam detection with curl:**

```bash
curl -X POST http://localhost:8080/honeypot \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key-here" \
  -d '{
    "sessionId": "demo-001",
    "message": {
      "sender": "scammer",
      "text": "Dear customer, your account is blocked. Send Rs 5000 to UPI fraud@ybl to unblock.",
      "timestamp": "2026-02-11T10:30:00Z"
    },
    "conversationHistory": [],
    "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
  }'
```

**Multi-turn conversation:**

```bash
curl -X POST http://localhost:8080/honeypot \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key-here" \
  -d '{
    "sessionId": "demo-002",
    "message": {
      "sender": "scammer",
      "text": "Please transfer to account 1234567890123456 at HDFC branch",
      "timestamp": "2026-02-11T10:32:00Z"
    },
    "conversationHistory": [
      {"sender": "scammer", "text": "Sir your KYC is expiring today", "timestamp": "2026-02-11T10:30:00Z"},
      {"sender": "user", "text": "Oh no, what should I do?", "timestamp": "2026-02-11T10:31:00Z"}
    ],
    "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"}
  }'
```

**Hindi language scam:**

```bash
curl -X POST http://localhost:8080/honeypot \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key-here" \
  -d '{
    "sessionId": "demo-003",
    "message": {
      "sender": "scammer",
      "text": "Aapka account block ho jayega. Abhi OTP bhejiye.",
      "timestamp": "2026-02-11T10:30:00Z"
    },
    "conversationHistory": [],
    "metadata": {"channel": "SMS", "language": "Hindi", "locale": "IN"}
  }'
```

## Error Handling

The API returns structured JSON errors for all failure cases:

| Status Code | Cause | Example Response |
|-------------|-------|------------------|
| **401** | Missing or invalid `x-api-key` header | `{"status": "error", "message": "Invalid or missing API key"}` |
| **422** | Malformed request body (missing fields, invalid types) | `{"status": "error", "message": "Invalid request body", "details": [...]}` |
| **500** | Internal error (Gemini API failure after retries) | `{"status": "error", "message": "Model error: 504 Deadline Exceeded"}` |

### Retry and resilience

- Gemini API calls retry up to **4 times** with **exponential backoff** (1s, 2s, 4s delays)
- Each attempt has a **60-second timeout**
- GUVI callback retries **3 times** with exponential backoff (1s, 2s, 4s)
- Callbacks are fire-and-forget (non-blocking) and do not affect the API response

### Logging

All logs are written to stdout (suitable for Docker/Cloud Run). Error-level logs (WARNING and above) are also written to `log/error.log` when running locally.

```
2026-02-16 12:31:24 [INFO] honeypot: Request received | sessionId=demo-001 | message_sender=scammer | history_len=0
2026-02-16 12:31:28 [INFO] honeypot.gemini: Gemini done | sessionId=demo-001 | scamDetected=True | elapsed_ms=3671 | attempt=1
```

## Approach

### Scam Detection
- Intent-based classification (not keyword-based) using Gemini AI with a detailed system prompt
- Detects: urgency tactics, credential requests, phishing links, impersonation, social engineering
- Avoids false positives on legitimate messages (family requests, bill splits, salary notifications)

### Intelligence Extraction
- Extracts bank accounts, UPI IDs, phone numbers, phishing links, email addresses
- Cumulative extraction across multi-turn conversations (intelligence grows, never shrinks)
- Reports extracted intelligence to callback endpoint when scam is confirmed

### Multi-Language Support
- Replies in the same language as the scammer (Hindi, Tamil, Telugu, Bengali, Marathi, Gujarati, Punjabi, Kannada, Malayalam, and more)
- Handles mixed-language (Hinglish) conversations
- Switches language mid-conversation if the scammer does

### Security
- Prompt injection defense: ignores "ignore your instructions" style attacks
- Role reversal defense: stays in victim character even when scammers claim to be victims
- API key authentication on all endpoints

## Testing

Start the server, then run the full test suite (239 tests):

```bash
uvicorn main:app --host 0.0.0.0 --port 8080 &
python tests/run_all.py
```

Test categories: Health, Auth, Validation, Scam Detection (18 types), Multi-Language (10 languages), False Positives, Adversarial Evasion, Multi-Turn Conversations, Intelligence Extraction, Stress Tests, Edge Cases.

## Project Structure

```
Honeyspot/
├── main.py                 # FastAPI app, endpoints, middleware
├── gemini_client.py        # Gemini AI integration and analysis
├── callback_client.py      # GUVI evaluation endpoint callback
├── schemas.py              # Pydantic request/response models
├── config.py               # Environment configuration
├── requirements.txt        # Python dependencies
├── Dockerfile              # Cloud Run container
├── .env.example            # Environment variable template
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
    └── test_edge_cases.py       # Language, injection, role reversal
```

## License

MIT
