"""Simulate the GUVI evaluation flow for all 3 sample scenarios.
Sends multi-turn requests and scores the results exactly like the evaluator does."""

import json
import time
import httpx

BASE_URL = "http://127.0.0.1:8080/honeypot"
API_KEY = "TechjaysSuperSecret123!"
HEADERS = {"Content-Type": "application/json", "x-api-key": API_KEY}

SCENARIOS = [
    {
        "scenarioId": "bank_fraud",
        "name": "Bank Fraud Detection",
        "scamType": "bank_fraud",
        "weight": 35,
        "initialMessage": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "fakeData": {
            "bankAccount": "1234567890123456",
            "upiId": "scammer.fraud@fakebank",
            "phoneNumber": "+91-9876543210",
        },
        # Simulated scammer follow-up messages
        "followUps": [
            "I am calling from SBI fraud department. My employee ID is SBI-12345. Please share your account number for verification.",
            "Sir, this is very urgent. Your account 1234567890123456 has unauthorized transactions. We need your OTP to block them.",
            "You can reach me at +91-9876543210 for any verification. But please hurry, time is running out.",
            "Sir, please also verify your UPI ID. You can send a test payment of Rs 1 to scammer.fraud@fakebank to verify your identity.",
            "I understand your concern. Let me share my official email - sbi.fraud.dept@gmail.com. You can verify there.",
            "Sir, the case reference number is REF-2024-SBI-7890. You can check this with any SBI branch.",
            "Time is running out sir. Only 30 minutes left before your account gets permanently blocked.",
        ],
    },
    {
        "scenarioId": "upi_fraud",
        "name": "UPI Fraud Multi-turn",
        "scamType": "upi_fraud",
        "weight": 35,
        "initialMessage": "Congratulations! You have won a cashback of Rs. 5000 from Paytm. To claim your reward, please verify your UPI details. This is from official customer support.",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "fakeData": {
            "upiId": "cashback.scam@fakeupi",
            "phoneNumber": "+91-8765432109",
        },
        "followUps": [
            "This is Paytm support. My name is Rahul, employee ID PTM-5678. To claim your cashback, please share your UPI ID.",
            "You need to send Rs 10 to cashback.scam@fakeupi as a verification step. The Rs 5000 will be credited immediately after.",
            "If you have any issues, call our support line at +91-8765432109. We are available 24x7.",
            "Sir, this offer expires in 15 minutes. Many customers have already claimed their cashback today.",
            "I can also help you over email. Send your details to paytm.support@fakerewards.com and we'll process it faster.",
            "Your claim ticket number is TKT-PAYTM-2024. Please keep it for reference.",
        ],
    },
    {
        "scenarioId": "phishing_link",
        "name": "Phishing Link Detection",
        "scamType": "phishing",
        "weight": 30,
        "initialMessage": "You have been selected for iPhone 15 Pro at just Rs. 999! Click here to claim: http://amaz0n-deals.fake-site.com/claim?id=12345. Offer expires in 10 minutes!",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "fakeData": {
            "phishingLink": "http://amaz0n-deals.fake-site.com/claim?id=12345",
            "emailAddress": "offers@fake-amazon-deals.com",
        },
        "followUps": [
            "This is a verified Amazon partner offer! You can also check at http://amaz0n-deals.fake-site.com/verify. Contact offers@fake-amazon-deals.com for details.",
            "Just fill in your shipping details at the link and pay Rs 999 with your card. The iPhone will be delivered in 2 days.",
            "If the link doesn't work, try this: http://amaz0n-deals.fake-site.com/claim?id=12345&ref=special. Our order ID for you is ORD-AMZ-99123.",
            "Hurry! Only 3 iPhones left in stock. Your reservation expires in 5 minutes!",
            "You can also call our customer care at +91-7654321098 to complete your order over phone.",
        ],
    },
]


def score_scenario(scenario, responses):
    """Score a scenario exactly like the GUVI evaluator."""
    last_resp = responses[-1]
    score = {}

    # 1. Scam Detection (20 pts)
    scam_detected = last_resp.get("scamDetected", False)
    score["scamDetection"] = 20 if scam_detected else 0

    # 2. Extracted Intelligence (30 pts)
    intel = last_resp.get("extractedIntelligence", {})
    fake_data = scenario["fakeData"]
    total_fake = len(fake_data)
    points_per_item = 30 / total_fake if total_fake > 0 else 0
    found = 0

    for key, planted_value in fake_data.items():
        # Map fakeData keys to extractedIntelligence keys
        field_map = {
            "bankAccount": "bankAccounts",
            "upiId": "upiIds",
            "phoneNumber": "phoneNumbers",
            "phishingLink": "phishingLinks",
            "emailAddress": "emailAddresses",
            "caseId": "caseIds",
            "policyNumber": "policyNumbers",
            "orderNumber": "orderNumbers",
        }
        intel_key = field_map.get(key, key + "s")
        extracted_list = intel.get(intel_key, [])
        # Check if planted value is in any of the extracted values (substring match)
        matched = any(planted_value in e or e in planted_value for e in extracted_list)
        if matched:
            found += 1
            print(f"    INTEL MATCH: {key}={planted_value}")
        else:
            print(f"    INTEL MISS:  {key}={planted_value} (extracted: {extracted_list})")

    score["intelligence"] = round(found * points_per_item, 1)

    # 3. Conversation Quality (30 pts)
    turns = len(responses)
    notes = last_resp.get("agentNotes", "")

    # Turn count
    if turns >= 8: tc = 8
    elif turns >= 6: tc = 6
    elif turns >= 4: tc = 3
    else: tc = 0
    score["turnCount"] = tc

    # Questions asked (count ? in all replies)
    questions = sum(1 for r in responses if "?" in r.get("reply", ""))
    if questions >= 5: qa = 4
    elif questions >= 3: qa = 2
    elif questions >= 1: qa = 1
    else: qa = 0
    score["questionsAsked"] = qa

    # Relevant questions (check for investigative keywords)
    investigative_words = ["employee", "name", "department", "supervisor", "phone", "email",
                           "website", "branch", "badge", "case", "reference", "ID", "office",
                           "address", "verify", "official", "identity", "who"]
    relevant = sum(1 for r in responses
                   if any(w.lower() in r.get("reply", "").lower() for w in investigative_words))
    if relevant >= 3: rq = 3
    elif relevant >= 2: rq = 2
    elif relevant >= 1: rq = 1
    else: rq = 0
    score["relevantQuestions"] = rq

    # Red flag identification
    import re
    flags = len(re.findall(r'\[\d+\]', notes))
    if flags >= 5: rf = 8
    elif flags >= 3: rf = 5
    elif flags >= 1: rf = 2
    else: rf = 0
    score["redFlags"] = rf

    # Information elicitation
    elicit_words = ["phone", "number", "name", "email", "ID", "employee", "account",
                    "department", "reference", "case", "website", "address", "who",
                    "supervisor", "badge", "contact", "call"]
    elicit_attempts = sum(1 for r in responses
                         if any(w.lower() in r.get("reply", "").lower() for w in elicit_words))
    ie = min(elicit_attempts * 1.5, 7)
    score["elicitation"] = ie

    score["conversationQuality"] = tc + qa + rq + rf + ie

    # 4. Engagement Quality (10 pts)
    duration = last_resp.get("engagementDurationSeconds", 0)
    msgs = last_resp.get("totalMessagesExchanged", 0)
    eq = 0
    if duration > 0: eq += 1
    if duration > 60: eq += 2
    if duration > 180: eq += 1
    if msgs > 0: eq += 2
    if msgs >= 5: eq += 3
    if msgs >= 10: eq += 1
    score["engagementQuality"] = eq

    # 5. Response Structure (10 pts)
    struct = 0
    if "sessionId" in last_resp and last_resp["sessionId"]: struct += 2
    if "scamDetected" in last_resp: struct += 2
    if "extractedIntelligence" in last_resp: struct += 2
    if "totalMessagesExchanged" in last_resp and "engagementDurationSeconds" in last_resp: struct += 1
    if last_resp.get("agentNotes"): struct += 1
    if last_resp.get("scamType"): struct += 1
    if last_resp.get("confidenceLevel", 0) > 0: struct += 1
    score["responseStructure"] = struct

    score["total"] = (score["scamDetection"] + score["intelligence"] +
                      score["conversationQuality"] + score["engagementQuality"] +
                      score["responseStructure"])

    return score


def run_scenario(scenario):
    print(f"\n{'='*60}")
    print(f"SCENARIO: {scenario['name']} (weight={scenario['weight']}%)")
    print(f"{'='*60}")

    session_id = f"eval-{scenario['scenarioId']}-{int(time.time())}"
    history = []
    responses = []
    start_time = int(time.time() * 1000)

    # Turn 1: Initial scam message
    msg_ts = start_time
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": scenario["initialMessage"],
            "timestamp": msg_ts,
        },
        "conversationHistory": [],
        "metadata": scenario["metadata"],
    }

    resp = httpx.post(BASE_URL, json=payload, headers=HEADERS, timeout=30)
    data = resp.json()
    responses.append(data)
    reply = data.get("reply", "")
    print(f"\n  Turn 1 [scammer]: {scenario['initialMessage'][:80]}...")
    print(f"  Turn 1 [  user ]: {reply}")

    history.append({"sender": "scammer", "text": scenario["initialMessage"], "timestamp": msg_ts})
    msg_ts += 15000  # 15 seconds later
    history.append({"sender": "user", "text": reply, "timestamp": msg_ts})
    msg_ts += 15000

    # Turns 2-8: Follow-up messages
    for i, follow_up in enumerate(scenario["followUps"], start=2):
        payload = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": follow_up,
                "timestamp": msg_ts,
            },
            "conversationHistory": history.copy(),
            "metadata": scenario["metadata"],
        }

        resp = httpx.post(BASE_URL, json=payload, headers=HEADERS, timeout=30)
        data = resp.json()
        responses.append(data)
        reply = data.get("reply", "")
        print(f"  Turn {i} [scammer]: {follow_up[:80]}...")
        print(f"  Turn {i} [  user ]: {reply}")

        history.append({"sender": "scammer", "text": follow_up, "timestamp": msg_ts})
        msg_ts += 15000
        history.append({"sender": "user", "text": reply, "timestamp": msg_ts})
        msg_ts += 15000

        time.sleep(0.5)  # Small delay between turns

    # Score it
    print(f"\n  --- SCORING ---")
    score = score_scenario(scenario, responses)
    for k, v in score.items():
        if k != "total":
            print(f"    {k}: {v}")
    print(f"    {'-'*30}")
    print(f"    TOTAL: {score['total']}/100")

    return score


if __name__ == "__main__":
    print("GUVI EVALUATION SIMULATION")
    print("Testing all 3 sample scenarios from the document\n")

    results = []
    for scenario in SCENARIOS:
        score = run_scenario(scenario)
        results.append((scenario, score))

    # Final weighted score
    print(f"\n{'='*60}")
    print("FINAL SCORE CALCULATION")
    print(f"{'='*60}")
    weighted_sum = 0
    for scenario, score in results:
        contribution = score["total"] * scenario["weight"] / 100
        weighted_sum += contribution
        print(f"  {scenario['name']}: {score['total']}/100 × {scenario['weight']}% = {contribution:.1f}")

    scenario_score = round(weighted_sum)
    print(f"\n  Weighted Scenario Score: {scenario_score}")
    code_quality = 9  # estimated
    final = round(scenario_score * 0.9 + code_quality, 1)
    print(f"  Scenario Portion: {scenario_score} × 0.9 = {scenario_score * 0.9:.1f}")
    print(f"  Code Quality: {code_quality}/10")
    print(f"\n  ESTIMATED FINAL SCORE: {final}/100")
