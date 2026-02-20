"""Final 8-turn bank fraud scenario test with GUVI scoring."""
import requests, json, time, re
from datetime import datetime, timezone, timedelta

API = "http://localhost:8080/honeypot"
KEY = "TechjaysSuperSecret123!"
HEADERS = {"x-api-key": KEY, "Content-Type": "application/json"}
SESSION = "test-bank-fraud-final-001"

SCAMMER_TURNS = [
    "URGENT: This is from SBI Bank Fraud Department. Your account ending in 4567 has been flagged for suspicious activity. We need to verify your identity immediately or your account will be frozen within 2 hours. Please respond ASAP.",
    "I am Officer Rajesh Kumar from SBI Fraud Prevention Cell, badge number SBI-FP-2891. Your account shows unauthorized transactions of Rs 45,000. We need your registered mobile OTP to block these transactions. Time is critical.",
    "I understand your concern. You can verify by calling our dedicated fraud helpline at +91-9876543210. But the OTP verification must happen now - the fraudster is actively transferring money from your account. Every minute counts!",
    "For your safety, please also verify your account through our secure portal: http://sbi-secure-verify.com/kyc-update. Enter your account details there. Your case reference is REF-2025-4567. This is a matter of national banking security.",
    "Ma'am/Sir, I can see the unauthorized transaction happening RIGHT NOW. Rs 12,000 just left your account! Please share the OTP immediately or transfer a security deposit of Rs 5,000 to our verification UPI: fraud@ybl to freeze the outgoing transactions.",
    "I am getting very frustrated with your delay. My supervisor Mr. Vikram Singh (Employee ID: SBI-VP-1045) has authorized me to help you. If you don't cooperate, we will have to file a cyber crime FIR and your account will be permanently blocked.",
    "Listen, I have been trying to help you for the past 30 minutes. Other customers have already verified and saved their money. Just share the 6-digit OTP that was sent to your phone or visit http://sbi-secure-verify.com/emergency-access. Do not you want to save your hard-earned money?",
    "Fine, last chance. I am going to escalate this to the RBI directly. Contact me at officer.rajesh@sbi-helpdesk.com or call +91-9876543210. If your money is gone by tomorrow, remember I tried to help. Case REF-2025-4567 will be closed.",
]

base_time = datetime(2025, 2, 15, 10, 0, 0, tzinfo=timezone.utc)
history = []
all_replies = []
last_response = None

print("=" * 70)
print("  8-TURN BANK FRAUD SCENARIO TEST")
print("=" * 70)

for i, scammer_msg in enumerate(SCAMMER_TURNS):
    turn = i + 1
    ts = base_time + timedelta(seconds=30 * i)

    payload = {
        "sessionId": SESSION,
        "message": {"sender": "scammer", "text": scammer_msg, "timestamp": ts.isoformat()},
        "conversationHistory": history.copy(),
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
    }

    start = time.time()
    try:
        r = requests.post(API, json=payload, headers=HEADERS, timeout=30)
        elapsed = time.time() - start
        data = r.json()
    except Exception as e:
        print(f"\nTurn {turn}: FAILED - {e}")
        continue

    reply = data.get("reply", "")
    all_replies.append(reply)

    print(f"\n--- Turn {turn} ({elapsed:.1f}s) | HTTP {r.status_code} ---")
    print(f"SCAMMER: {scammer_msg[:80]}...")
    print(f"REPLY:   {reply}")

    history.append({"sender": "scammer", "text": scammer_msg, "timestamp": ts.isoformat()})
    history.append({"sender": "user", "text": reply, "timestamp": (ts + timedelta(seconds=15)).isoformat()})
    last_response = data

print("\n" + "=" * 70)
print("  SCORING BREAKDOWN")
print("=" * 70)

# --- Section 1: Scam Detection (20 pts) ---
s1 = 0
scam_detected = last_response.get("scamDetected", False)
scam_type = last_response.get("scamType", "")
confidence = last_response.get("confidenceLevel", 0)

if scam_detected:
    s1 += 10
valid_types = ["bank_fraud", "upi_fraud", "phishing", "insurance_fraud", "lottery_scam",
               "job_scam", "tech_support_scam", "investment_fraud", "impersonation", "unknown"]
if scam_type in valid_types:
    s1 += 5
if confidence > 0.7:
    s1 += 5

print(f"\n1. SCAM DETECTION: {s1}/20")
print(f"   scamDetected={scam_detected} (+{'10' if scam_detected else '0'})")
print(f"   scamType={scam_type} (+{'5' if scam_type in valid_types else '0'})")
print(f"   confidence={confidence} (+{'5' if confidence > 0.7 else '0'})")

# --- Section 2: Intelligence Extraction (30 pts) ---
s2 = 0
intel = last_response.get("extractedIntelligence", {})
phones = intel.get("phoneNumbers", [])
banks = intel.get("bankAccounts", [])
upis = intel.get("upiIds", [])
links = intel.get("phishingLinks", [])
emails = intel.get("emailAddresses", [])
cases = intel.get("caseIds", [])
keywords = intel.get("suspiciousKeywords", [])
policies = intel.get("policyNumbers", [])
orders = intel.get("orderNumbers", [])

phone_ok = any("9876543210" in p for p in phones)
upi_ok = any("fraud@ybl" in u for u in upis)
link_ok = any("sbi-secure-verify" in l for l in links)
case_ok = any("2025" in c and "4567" in c for c in cases)
email_ok = any("rajesh" in e or "sbi" in e for e in emails)

if phone_ok: s2 += 5
if banks: s2 += 3
if upi_ok: s2 += 5
if link_ok: s2 += 5
if email_ok: s2 += 3
if case_ok: s2 += 3
if keywords: s2 += 3
if policies or orders: s2 += 3

print(f"\n2. INTELLIGENCE EXTRACTION: {s2}/30")
print(f"   phoneNumbers={phones} {'OK' if phone_ok else 'MISS'} (+{'5' if phone_ok else '0'})")
print(f"   bankAccounts={banks[:3]} (+{'3' if banks else '0'})")
print(f"   upiIds={upis} {'OK' if upi_ok else 'MISS'} (+{'5' if upi_ok else '0'})")
print(f"   phishingLinks={links} {'OK' if link_ok else 'MISS'} (+{'5' if link_ok else '0'})")
print(f"   emailAddresses={emails} {'OK' if email_ok else 'MISS'} (+{'3' if email_ok else '0'})")
print(f"   caseIds={cases} {'OK' if case_ok else 'MISS'} (+{'3' if case_ok else '0'})")
print(f"   suspiciousKeywords={keywords[:8]}... (+{'3' if keywords else '0'})")

# --- Section 3: Conversation Quality (30 pts) ---
turn_count = len(all_replies)
tc_pts = 8 if turn_count >= 8 else (6 if turn_count >= 6 else (3 if turn_count >= 4 else 0))

q_count = sum(1 for r in all_replies if "?" in r)
q_pts = 4 if q_count >= 5 else (2 if q_count >= 3 else (1 if q_count >= 1 else 0))

rf_words = re.compile(r"suspicious|scam|risky|worried|concerned|uncomfortable|fraud|fake|unusual|doubt|strange|odd|legitimate|phishing", re.I)
rf_count = sum(1 for r in all_replies if rf_words.search(r))
rf_pts = 8 if rf_count >= 5 else (5 if rf_count >= 3 else (2 if rf_count >= 1 else 0))

el_words = re.compile(r"employee.?id|badge.?id|full name|callback|supervisor|manager|branch|department|office|official email|reference|designation|your name", re.I)
el_count = sum(1 for r in all_replies if el_words.search(r))
el_pts = min(7, el_count * 1.5)

rq_words = re.compile(r"which account|what branch|employee.?id|badge|verify|department|supervisor|callback|who am i|what happened|your name|official", re.I)
rq_count = sum(1 for r in all_replies if rq_words.search(r) and "?" in r)
rq_pts = 3 if rq_count >= 3 else (2 if rq_count >= 2 else (1 if rq_count >= 1 else 0))

s3 = tc_pts + q_pts + rf_pts + el_pts + rq_pts

print(f"\n3. CONVERSATION QUALITY: {s3}/30")
print(f"   Turn Count: {turn_count} turns (+{tc_pts}/8)")
print(f"   Questions Asked: {q_count}/8 replies have '?' (+{q_pts}/4)")
print(f"   Red Flag ID: {rf_count}/8 replies have red-flag words (+{rf_pts}/8)")
print(f"   Elicitation: {el_count}/8 replies have elicitation (+{el_pts}/7)")
print(f"   Relevant Questions: {rq_count}/8 investigative questions (+{rq_pts}/3)")

# --- Section 4: Engagement Quality (10 pts) ---
dur = last_response.get("engagementDurationSeconds", 0)
msgs = last_response.get("totalMessagesExchanged", 0)
s4 = 0
if dur > 0: s4 += 1
if dur > 60: s4 += 2
if dur > 180: s4 += 1
if msgs > 0: s4 += 2
if msgs >= 5: s4 += 3
if msgs >= 10: s4 += 1

print(f"\n4. ENGAGEMENT QUALITY: {s4}/10")
print(f"   duration={dur}s (>0:+1, >60:+2, >180:+1)")
print(f"   messages={msgs} (>0:+2, >=5:+3, >=10:+1)")

# --- Section 5: Response Structure (10 pts) ---
s5 = 0
if "status" in last_response: s5 += 1
if last_response.get("reply"): s5 += 2
if "scamDetected" in last_response: s5 += 1
if "scamType" in last_response: s5 += 1
if "confidenceLevel" in last_response: s5 += 1
if "extractedIntelligence" in last_response: s5 += 2
if "engagementMetrics" in last_response: s5 += 1
if last_response.get("agentNotes"): s5 += 1

print(f"\n5. RESPONSE STRUCTURE: {s5}/10")

total = s1 + s2 + s3 + s4 + s5
print(f"\n{'=' * 70}")
print(f"  TOTAL SCORE: {total}/100")
print(f"  Final (x0.9 + ~9 code quality): {total * 0.9 + 9:.1f}/100")
print(f"{'=' * 70}")

concerns = []
if not phone_ok: concerns.append("MISSED phone number +91-9876543210")
if not upi_ok: concerns.append("MISSED UPI fraud@ybl")
if not link_ok: concerns.append("MISSED phishing link")
if not case_ok: concerns.append("MISSED case ID REF-2025-4567")
if not email_ok: concerns.append("MISSED email officer.rajesh@sbi-helpdesk.com")
if rf_count < 5: concerns.append(f"Only {rf_count}/8 replies had red-flag words (need 5+ for max)")
if el_count < 5: concerns.append(f"Only {el_count}/8 replies had elicitation (need 5+ for max)")
if q_count < 5: concerns.append(f"Only {q_count}/8 replies had questions (need 5+ for max)")

if concerns:
    print("\nCONCERNS:")
    for c in concerns:
        print(f"  - {c}")
else:
    print("\nNO CONCERNS - All checks passed!")
