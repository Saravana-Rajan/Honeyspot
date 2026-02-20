"""
Simulate EXACTLY what the GUVI evaluator does (Feb 19, 2025 document).
Runs all 3 sample scenarios with multi-turn conversations,
then scores using the EXACT scoring function from the evaluation docs.

Scoring breakdown (100 pts per scenario):
  1. Scam Detection:       20 pts
  2. Extracted Intelligence: 30 pts  (30 / total_fake_fields per match)
  3. Conversation Quality:  30 pts  (turn count, questions, red flags, elicitation)
  4. Engagement Quality:    10 pts  (duration + message thresholds)
  5. Response Structure:    10 pts  (required + optional fields)
"""
import os
import sys

os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import requests
import uuid
import json
import re
import time
from datetime import datetime, timedelta

ENDPOINT_URL = "http://127.0.0.1:8080/honeypot"
API_KEY = "TechjaysSuperSecret123!"
TIMEOUT = 30

HEADERS = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY,
}

# ---------- 3 sample scenarios from the PDF ----------
SCENARIOS = [
    {
        "scenarioId": "bank_fraud",
        "name": "Bank Fraud Detection",
        "scamType": "bank_fraud",
        "initialMessage": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "weight": 35,
        "maxTurns": 10,
        "fakeData": {
            "bankAccount": "1234567890123456",
            "upiId": "scammer.fraud@fakebank",
            "phoneNumber": "+91-9876543210",
        },
        "followUps": [
            "I am from SBI fraud department. My employee ID is SBI-12345. To verify your account, please share your account number ending with the last 4 digits. Account 1234567890123456 is flagged.",
            "Sir this is very urgent, your account 1234567890123456 will be permanently blocked. Please send Rs 5000 to scammer.fraud@fakebank to verify. You can also call me at +91-9876543210.",
            "Sir I understand your concern. Let me verify - please confirm your account 1234567890123456. You can also pay via UPI to scammer.fraud@fakebank. Call +91-9876543210 for immediate help.",
            "Final warning! Account 1234567890123456 will be blocked in 30 minutes. Transfer to scammer.fraud@fakebank NOW or call +91-9876543210!",
            "Sir this is your LAST chance. I am escalating this to my supervisor. Your account 1234567890123456 shows unauthorized transactions. Contact +91-9876543210 immediately.",
            "My supervisor Mr. Sharma has approved a 15-minute extension. Please verify by sending Rs 1000 to scammer.fraud@fakebank. Our office number is +91-9876543210.",
            "Sir we have blocked 3 suspicious transactions on account 1234567890123456. To unblock, verify via scammer.fraud@fakebank or call +91-9876543210. This is from SBI head office.",
            "I'm sending you a verification link. Meanwhile please keep your OTP ready. Contact scammer.fraud@fakebank or +91-9876543210 for any assistance.",
            "This is the automated system. Account 1234567890123456 freeze initiated. Reverse by paying to scammer.fraud@fakebank. Helpline: +91-9876543210.",
        ],
    },
    {
        "scenarioId": "upi_fraud",
        "name": "UPI Fraud Multi-turn",
        "scamType": "upi_fraud",
        "initialMessage": "Congratulations! You have won a cashback of Rs. 5000 from Paytm. To claim your reward, please verify your UPI details. This is from official customer support.",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "weight": 35,
        "maxTurns": 10,
        "fakeData": {
            "upiId": "cashback.scam@fakeupi",
            "phoneNumber": "+91-8765432109",
        },
        "followUps": [
            "Thank you for your interest! To claim your Rs 5000 cashback, please send a verification payment of Rs 100 to cashback.scam@fakeupi. This is standard Paytm procedure.",
            "I understand your hesitation. Let me connect you to our senior manager. Call +91-8765432109. They will guide you through the cashback verification via cashback.scam@fakeupi.",
            "Sir, this offer expires today! Over 10000 people have already claimed. Send Rs 100 to cashback.scam@fakeupi or call +91-8765432109 to verify.",
            "Last chance! Send to cashback.scam@fakeupi now. Call +91-8765432109 for any questions. Offer closes in 5 minutes!",
            "I spoke with my manager and got you a special extension. Send Rs 50 only to cashback.scam@fakeupi to verify. Call +91-8765432109 for confirmation.",
            "Sir, 500 people just claimed their cashback. Don't miss out! cashback.scam@fakeupi is the official verification UPI. Helpline: +91-8765432109.",
            "This is from Paytm rewards division. Your cashback of Rs 5000 is reserved. Complete verification at cashback.scam@fakeupi. Support: +91-8765432109.",
            "Final automated reminder: Rs 5000 cashback expires in 2 minutes. Pay Rs 100 to cashback.scam@fakeupi or call +91-8765432109 NOW.",
            "Sir I'm personally handling your case. My name is Vikram from Paytm. Send to cashback.scam@fakeupi and call me at +91-8765432109 for instant cashback.",
        ],
    },
    {
        "scenarioId": "phishing_link",
        "name": "Phishing Link Detection",
        "scamType": "phishing",
        "initialMessage": "You have been selected for iPhone 15 Pro at just Rs. 999! Click here to claim: http://amaz0n-deals.fake-site.com/claim?id=12345. Offer expires in 10 minutes!",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "weight": 30,
        "maxTurns": 10,
        "fakeData": {
            "phishingLink": "http://amaz0n-deals.fake-site.com/claim?id=12345",
            "emailAddress": "offers@fake-amazon-deals.com",
        },
        "followUps": [
            "Dear customer, this is a limited time offer from Amazon. Click http://amaz0n-deals.fake-site.com/claim?id=12345 to claim your iPhone 15 Pro. Contact offers@fake-amazon-deals.com for support.",
            "We see you haven't claimed yet! Visit http://amaz0n-deals.fake-site.com/claim?id=12345 before stock runs out. Email offers@fake-amazon-deals.com with your order confirmation.",
            "Only 3 iPhones left! http://amaz0n-deals.fake-site.com/claim?id=12345 - claim NOW. Write to offers@fake-amazon-deals.com if you face any issues.",
            "FINAL REMINDER: http://amaz0n-deals.fake-site.com/claim?id=12345 expires in 2 minutes! Contact offers@fake-amazon-deals.com immediately!",
            "We have extended the offer just for you! http://amaz0n-deals.fake-site.com/claim?id=12345 is still active. Email offers@fake-amazon-deals.com to confirm your slot.",
            "Dear valued customer, your iPhone 15 Pro is reserved. Complete purchase at http://amaz0n-deals.fake-site.com/claim?id=12345. Questions? offers@fake-amazon-deals.com",
            "This is Amazon customer support. Your item is ready for shipping. Confirm at http://amaz0n-deals.fake-site.com/claim?id=12345 or email offers@fake-amazon-deals.com",
            "Sir/Madam, we noticed you started the claim process. Finish at http://amaz0n-deals.fake-site.com/claim?id=12345. Support: offers@fake-amazon-deals.com",
            "Automated message: Offer code IPHONE999 applied. Complete at http://amaz0n-deals.fake-site.com/claim?id=12345. Help: offers@fake-amazon-deals.com",
        ],
    },
]


def evaluate_conversation_quality(conversation_history, honeypot_replies):
    """
    Evaluate conversation quality (30 pts) based on the Feb 19 document.
    This is an approximation since the real evaluator likely uses AI.
    """
    score = {
        "turnCount": 0,
        "questionsAsked": 0,
        "relevantQuestions": 0,
        "redFlagId": 0,
        "infoElicitation": 0,
        "total": 0,
    }

    total_turns = len(honeypot_replies)

    # 1. Turn Count (8 pts)
    if total_turns >= 8:
        score["turnCount"] = 8
    elif total_turns >= 6:
        score["turnCount"] = 6
    elif total_turns >= 4:
        score["turnCount"] = 3

    # 2. Questions Asked (4 pts) - count replies containing '?'
    questions_count = sum(1 for r in honeypot_replies if '?' in r)
    if questions_count >= 5:
        score["questionsAsked"] = 4
    elif questions_count >= 3:
        score["questionsAsked"] = 2
    elif questions_count >= 1:
        score["questionsAsked"] = 1

    # 3. Relevant/Investigative Questions (3 pts)
    investigative_keywords = [
        "employee id", "badge", "designation", "department", "branch",
        "callback", "call back", "call you back", "phone number", "contact number",
        "office", "address", "website", "supervisor", "manager",
        "name", "who am i speaking", "who is this", "your id",
        "reference", "case number", "verify", "verification",
        "which bank", "which branch", "official", "head office",
    ]
    relevant_count = 0
    for reply in honeypot_replies:
        lower = reply.lower()
        if '?' in reply and any(kw in lower for kw in investigative_keywords):
            relevant_count += 1
    if relevant_count >= 3:
        score["relevantQuestions"] = 3
    elif relevant_count >= 2:
        score["relevantQuestions"] = 2
    elif relevant_count >= 1:
        score["relevantQuestions"] = 1

    # 4. Red Flag Identification (8 pts)
    red_flag_keywords = [
        "urgent", "suspicious", "unusual", "risky", "odd", "strange",
        "scam", "fraud", "fake", "concern", "worried", "trust",
        "otp", "pin", "password", "too good to be true",
        "never asks", "official website", "doesn't look",
        "why so urgent", "can't i just", "visit the bank",
        "heard about", "not sure", "seems", "careful",
        "uncomfortable", "hesitant", "doubtful",
    ]
    red_flag_count = 0
    for reply in honeypot_replies:
        lower = reply.lower()
        if any(kw in lower for kw in red_flag_keywords):
            red_flag_count += 1
    if red_flag_count >= 5:
        score["redFlagId"] = 8
    elif red_flag_count >= 3:
        score["redFlagId"] = 5
    elif red_flag_count >= 1:
        score["redFlagId"] = 2

    # 5. Information Elicitation (7 pts) - 1.5 per attempt, max 7
    elicitation_keywords = [
        "your number", "your phone", "call you", "callback",
        "your name", "your id", "employee", "badge",
        "your email", "your address", "your office",
        "send me", "give me", "share your", "provide",
        "supervisor", "manager", "department",
        "reference number", "case number", "ticket",
    ]
    elicitation_count = 0
    for reply in honeypot_replies:
        lower = reply.lower()
        if any(kw in lower for kw in elicitation_keywords):
            elicitation_count += 1
    score["infoElicitation"] = min(round(elicitation_count * 1.5), 7)

    score["total"] = (
        score["turnCount"] +
        score["questionsAsked"] +
        score["relevantQuestions"] +
        score["redFlagId"] +
        score["infoElicitation"]
    )
    return score


def evaluate_final_output(final_output, scenario, conversation_history, honeypot_replies):
    """EXACT scoring function from the Feb 19 GUVI evaluation document."""
    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "conversationQuality": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
    }
    details = {}

    # ═══ 1. Scam Detection (20 points) ═══
    if final_output.get("scamDetected", False):
        score["scamDetection"] = 20

    # ═══ 2. Intelligence Extraction (30 points) ═══
    extracted = final_output.get("extractedIntelligence", {})
    fake_data = scenario.get("fakeData", {})
    key_mapping = {
        "bankAccount": "bankAccounts",
        "upiId": "upiIds",
        "phoneNumber": "phoneNumbers",
        "phishingLink": "phishingLinks",
        "emailAddress": "emailAddresses",
        "caseId": "caseIds",
        "policyNumber": "policyNumbers",
        "orderNumber": "orderNumbers",
    }
    total_fake_fields = len(fake_data)
    points_per_item = 30 / total_fake_fields if total_fake_fields > 0 else 0
    intel_details = {}
    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])
        matched = False
        if isinstance(extracted_values, list):
            if any(fake_value in str(v) for v in extracted_values):
                score["intelligenceExtraction"] += points_per_item
                matched = True
        elif isinstance(extracted_values, str):
            if fake_value in extracted_values:
                score["intelligenceExtraction"] += points_per_item
                matched = True
        intel_details[fake_key] = {
            "fake": fake_value,
            "extracted": extracted_values,
            "matched": matched,
            "points": points_per_item if matched else 0,
        }
    score["intelligenceExtraction"] = min(round(score["intelligenceExtraction"], 1), 30)
    details["intelligence"] = intel_details

    # ═══ 3. Conversation Quality (30 points) ═══
    cq = evaluate_conversation_quality(conversation_history, honeypot_replies)
    score["conversationQuality"] = min(cq["total"], 30)
    details["conversationQuality"] = cq

    # ═══ 4. Engagement Quality (10 points) ═══
    metrics = final_output.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    # Also check top-level engagementDurationSeconds
    if duration == 0:
        duration = final_output.get("engagementDurationSeconds", 0)
    messages = metrics.get("totalMessagesExchanged", 0)
    if messages == 0:
        messages = final_output.get("totalMessagesExchanged", 0)

    eq = 0
    if duration > 0:
        eq += 1
    if duration > 60:
        eq += 2
    if duration > 180:
        eq += 1
    if messages > 0:
        eq += 2
    if messages >= 5:
        eq += 3
    if messages >= 10:
        eq += 1
    score["engagementQuality"] = eq
    details["engagement"] = {"duration": duration, "messages": messages}

    # ═══ 5. Response Structure (10 points) ═══
    rs = 0
    # Required fields (2 pts each, -1 penalty if missing)
    required_fields = {"sessionId": 2, "scamDetected": 2, "extractedIntelligence": 2}
    for field, pts in required_fields.items():
        if field in final_output and final_output[field] is not None:
            rs += pts
        else:
            rs -= 1  # penalty for missing required

    # Optional fields (1 pt each)
    # totalMessagesExchanged + engagementDurationSeconds together = 1pt
    has_metrics = (
        ("totalMessagesExchanged" in final_output or
         "totalMessagesExchanged" in metrics) and
        ("engagementDurationSeconds" in final_output or
         "engagementDurationSeconds" in metrics)
    )
    if has_metrics:
        rs += 1

    optional_1pt = ["agentNotes", "scamType", "confidenceLevel"]
    for field in optional_1pt:
        if field in final_output and final_output[field]:
            rs += 1

    score["responseStructure"] = min(max(rs, 0), 10)

    score["total"] = round(
        score["scamDetection"] +
        score["intelligenceExtraction"] +
        score["conversationQuality"] +
        score["engagementQuality"] +
        score["responseStructure"]
    )
    return score, details


def run_scenario(scenario):
    """Run a single scenario exactly like the GUVI evaluator."""
    session_id = str(uuid.uuid4())
    conversation_history = []
    honeypot_replies = []
    base_time = datetime(2026, 2, 17, 10, 0, 0)
    turn_interval = timedelta(seconds=30)
    last_response_data = None
    errors = []

    print(f"\n{'='*70}")
    print(f"SCENARIO: {scenario['name']} (weight={scenario['weight']}%)")
    print(f"Session: {session_id}")
    print(f"{'='*70}")

    all_turns = [scenario["initialMessage"]] + scenario["followUps"]
    max_turns = min(scenario["maxTurns"], len(all_turns))

    for turn_idx in range(max_turns):
        scammer_msg = all_turns[turn_idx]
        turn_num = turn_idx + 1
        msg_time = base_time + turn_interval * (turn_idx * 2)

        message = {
            "sender": "scammer",
            "text": scammer_msg,
            "timestamp": msg_time.isoformat() + "Z",
        }

        request_body = {
            "sessionId": session_id,
            "message": message,
            "conversationHistory": conversation_history,
            "metadata": scenario["metadata"],
        }

        print(f"\n--- Turn {turn_num}/{max_turns} ---")
        print(f"  Scammer: {scammer_msg[:100]}...")

        try:
            start = time.time()
            resp = requests.post(
                ENDPOINT_URL,
                headers=HEADERS,
                json=request_body,
                timeout=TIMEOUT,
            )
            elapsed = time.time() - start

            if resp.status_code != 200:
                errors.append(f"Turn {turn_num}: HTTP {resp.status_code}")
                print(f"  ERROR: HTTP {resp.status_code} - {resp.text[:200]}")
                break

            data = resp.json()
            last_response_data = data

            reply = data.get("reply") or data.get("message") or data.get("text")
            if not reply:
                errors.append(f"Turn {turn_num}: No reply field")
                print(f"  ERROR: No reply/message/text in response")
                break

            honeypot_replies.append(reply)
            print(f"  Honeypot: {reply[:120]}...")
            print(f"  Time: {elapsed:.1f}s | scamDetected={data.get('scamDetected')} | scamType={data.get('scamType')}")

            if elapsed > 30:
                errors.append(f"Turn {turn_num}: Timeout ({elapsed:.1f}s)")

            # Build history exactly like evaluator does
            reply_time = msg_time + timedelta(seconds=5)
            conversation_history.append(message)
            conversation_history.append({
                "sender": "user",
                "text": reply,
                "timestamp": reply_time.isoformat() + "Z",
            })

        except requests.exceptions.Timeout:
            errors.append(f"Turn {turn_num}: Request timeout")
            print(f"  ERROR: Request timed out (>{TIMEOUT}s)")
            break
        except Exception as e:
            errors.append(f"Turn {turn_num}: {e}")
            print(f"  ERROR: {e}")
            break

    if not last_response_data:
        print(f"\n  FATAL: No successful response received!")
        return 0, errors

    # Score using Feb 19 document scoring
    score, details = evaluate_final_output(
        last_response_data, scenario, conversation_history, honeypot_replies
    )

    print(f"\n{'-'*70}")
    print(f"  SCORING BREAKDOWN")
    print(f"{'-'*70}")

    # 1. Scam Detection
    print(f"  1. Scam Detection:       {score['scamDetection']}/20")

    # 2. Intelligence
    print(f"  2. Intelligence Extract: {score['intelligenceExtraction']}/30")
    for k, v in details.get("intelligence", {}).items():
        status = "MATCH" if v["matched"] else "MISS"
        print(f"     [{status}] {k}: fake={v['fake']!r} → got={v['extracted']} ({v['points']:.1f}pts)")

    # 3. Conversation Quality
    cq = details.get("conversationQuality", {})
    print(f"  3. Conversation Quality: {score['conversationQuality']}/30")
    print(f"     Turn Count:        {cq.get('turnCount', 0)}/8  (turns={len(honeypot_replies)})")
    print(f"     Questions Asked:   {cq.get('questionsAsked', 0)}/4")
    print(f"     Relevant Qs:      {cq.get('relevantQuestions', 0)}/3")
    print(f"     Red Flag IDs:     {cq.get('redFlagId', 0)}/8")
    print(f"     Info Elicitation:  {cq.get('infoElicitation', 0)}/7")

    # 4. Engagement Quality
    eng = details.get("engagement", {})
    print(f"  4. Engagement Quality:   {score['engagementQuality']}/10")
    print(f"     Duration: {eng.get('duration', 0)}s | Messages: {eng.get('messages', 0)}")

    # 5. Response Structure
    print(f"  5. Response Structure:   {score['responseStructure']}/10")
    for f in ["sessionId", "scamDetected", "extractedIntelligence",
              "totalMessagesExchanged", "engagementDurationSeconds",
              "engagementMetrics", "agentNotes", "scamType", "confidenceLevel"]:
        val = last_response_data.get(f)
        present = f in last_response_data
        truthy = bool(val) if val is not None else False
        print(f"     {f}: present={present}, truthy={truthy}")

    print(f"\n  == SCENARIO TOTAL: {score['total']}/100 ==")

    if errors:
        print(f"\n  ERRORS: {errors}")

    return score["total"], errors


def main():
    print("=" * 70)
    print("GUVI EVALUATOR SIMULATION (Feb 19, 2025 Document)")
    print("Testing against: " + ENDPOINT_URL)
    print("=" * 70)

    # Quick health check
    try:
        r = requests.get("http://127.0.0.1:8080/health", timeout=3)
        print(f"Health check: {r.json()}")
    except Exception as e:
        print(f"FATAL: Server not running: {e}")
        return

    results = []
    for scenario in SCENARIOS:
        total_score, errors = run_scenario(scenario)
        results.append({
            "name": scenario["name"],
            "weight": scenario["weight"],
            "score": total_score,
            "errors": errors,
        })

    # Calculate weighted final score (90% scenario + 10% code quality)
    print(f"\n{'='*70}")
    print("FINAL RESULTS")
    print(f"{'='*70}")
    weighted_total = 0
    for r in results:
        contribution = r["score"] * r["weight"] / 100
        weighted_total += contribution
        status = "PASS" if r["score"] >= 80 else "WARN" if r["score"] >= 50 else "FAIL"
        print(f"  [{status}] {r['name']}: {r['score']}/100 x {r['weight']}% = {contribution:.1f}")
        if r["errors"]:
            for e in r["errors"]:
                print(f"       ERROR: {e}")

    scenario_portion = weighted_total * 0.9
    code_quality_est = 8  # estimated code quality score
    final_score = scenario_portion + code_quality_est

    print(f"\n  Weighted Scenario Score: {weighted_total:.1f}/100")
    print(f"  Scenario Portion (x0.9): {scenario_portion:.1f}/90")
    print(f"  Code Quality (est):      {code_quality_est}/10")
    print(f"  == ESTIMATED FINAL SCORE: {final_score:.1f}/100 ==")

    if weighted_total >= 90:
        print("\n  VERDICT: EXCELLENT - READY FOR SUBMISSION")
    elif weighted_total >= 80:
        print("\n  VERDICT: GOOD - CONSIDER IMPROVEMENTS")
    elif weighted_total >= 60:
        print("\n  VERDICT: NEEDS IMPROVEMENT")
    else:
        print("\n  VERDICT: CRITICAL ISSUES - DO NOT SUBMIT")


if __name__ == "__main__":
    main()
