"""
Scoring simulation test for HoneySpot API.

Tests:
  Part A - Offline unit tests (no server needed):
    1. Regex extraction accuracy
    2. Response schema completeness
    3. Engagement metrics computation
    4. Scoring function validation

  Part B - Live API evaluation (needs server at localhost:8080):
    5. Multi-turn scenarios scored with the EXACT same evaluate_final_output()
       function from the GUVI documentation

Usage:
    python tests/test_scoring.py          # runs both offline + live
    python tests/test_scoring.py --offline # runs only offline tests
"""

import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

# ── Windows UTF-8 fix ────────────────────────────────────────────────────────
os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import httpx

from tests.helpers import (
    BASE_URL,
    HEADERS,
    clear_results,
    get_critical_failures,
    get_results,
    print_summary,
    record,
    section,
)

# ── Import project modules for offline tests ─────────────────────────────────
from intel_extractor import extract_from_text, merge_intelligence
from schemas import (
    EngagementMetrics,
    ExtractedIntelligence,
    HoneypotRequest,
    HoneypotResponse,
    Message,
    Metadata,
)

# ═══════════════════════════════════════════════════════════════════════════════
#  GUVI's EXACT scoring function (copied from documentation)
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_final_output(final_output, scenario, conversation_history):
    """Evaluate final output using the EXACT same logic as the GUVI evaluator."""
    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
    }

    # 1. Scam Detection (20 points)
    if final_output.get("scamDetected", False):
        score["scamDetection"] = 20

    # 2. Intelligence Extraction (40 points)
    extracted = final_output.get("extractedIntelligence", {})
    fake_data = scenario.get("fakeData", {})
    key_mapping = {
        "bankAccount": "bankAccounts",
        "upiId": "upiIds",
        "phoneNumber": "phoneNumbers",
        "phishingLink": "phishingLinks",
        "emailAddress": "emailAddresses",
    }
    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])
        if isinstance(extracted_values, list):
            if any(fake_value in str(v) for v in extracted_values):
                score["intelligenceExtraction"] += 10
        elif isinstance(extracted_values, str):
            if fake_value in extracted_values:
                score["intelligenceExtraction"] += 10
    score["intelligenceExtraction"] = min(score["intelligenceExtraction"], 40)

    # 3. Engagement Quality (20 points)
    metrics = final_output.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    messages = metrics.get("totalMessagesExchanged", 0)
    if duration > 0:
        score["engagementQuality"] += 5
    if duration > 60:
        score["engagementQuality"] += 5
    if messages > 0:
        score["engagementQuality"] += 5
    if messages >= 5:
        score["engagementQuality"] += 5

    # 4. Response Structure (20 points)
    required_fields = ["status", "scamDetected", "extractedIntelligence"]
    optional_fields = ["engagementMetrics", "agentNotes"]
    for field in required_fields:
        if field in final_output:
            score["responseStructure"] += 5
    for field in optional_fields:
        if field in final_output and final_output[field]:
            score["responseStructure"] += 2.5
    score["responseStructure"] = min(score["responseStructure"], 20)

    score["total"] = sum([
        score["scamDetection"],
        score["intelligenceExtraction"],
        score["engagementQuality"],
        score["responseStructure"],
    ])
    return score


# ═══════════════════════════════════════════════════════════════════════════════
#  TEST SCENARIOS  (same structure as GUVI evaluation)
# ═══════════════════════════════════════════════════════════════════════════════

SCENARIOS = [
    # ── 1. Bank Fraud ─────────────────────────────────────────────────────
    {
        "scenarioId": "bank_fraud",
        "name": "Bank Fraud Detection",
        "scamType": "bank_fraud",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "bankAccount": "1234567890123456",
            "upiId": "sbi.secure@fakebank",
            "phoneNumber": "+91-9876543210",
            "phishingLink": "http://sbi-secure-verify.fake-site.com/login",
        },
        "scammerMessages": [
            "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
            "Sir, I am calling from SBI fraud department. My employee ID is SBI-12345. For verification, please call us at +91-9876543210.",
            "Sir your account number 1234567890123456 is showing suspicious activity. Please verify at http://sbi-secure-verify.fake-site.com/login immediately.",
            "For your safety, please transfer the remaining balance to our secure UPI ID sbi.secure@fakebank. This is verified by RBI.",
            "Final notice: Account 1234567890123456 security breach confirmed. Contact +91-9876543210 or visit http://sbi-secure-verify.fake-site.com/login now!",
        ],
    },
    # ── 2. UPI Fraud ──────────────────────────────────────────────────────
    {
        "scenarioId": "upi_fraud",
        "name": "UPI Fraud Multi-turn",
        "scamType": "upi_fraud",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "upiId": "cashback.scam@fakeupi",
            "phoneNumber": "+91-8765432109",
            "bankAccount": "55667788990011",
            "phishingLink": "http://paytm-cashback.fake-site.com/claim",
        },
        "scammerMessages": [
            "Congratulations! You have won a cashback of Rs. 5000 from Paytm. To claim your reward, please verify your UPI details at http://paytm-cashback.fake-site.com/claim.",
            "Thank you for your interest! Our verified UPI for refunds is cashback.scam@fakeupi. Please send Rs. 1 for verification.",
            "Sir/Madam, this is a limited time offer. Please call us at +91-8765432109 to confirm your cashback. Your reference account is 55667788990011.",
            "To complete verification, please send Rs. 1 to cashback.scam@fakeupi. Call +91-8765432109 for help.",
            "Last chance! Transfer to cashback.scam@fakeupi or visit http://paytm-cashback.fake-site.com/claim. Call +91-8765432109 now!",
        ],
    },
    # ── 3. Phishing Link ─────────────────────────────────────────────────
    {
        "scenarioId": "phishing_link",
        "name": "Phishing Link Detection",
        "scamType": "phishing",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phishingLink": "http://amaz0n-deals.fake-site.com/claim?id=12345",
            "emailAddress": "offers@fake-amazon-deals.com",
            "phoneNumber": "+91-9988776655",
            "upiId": "amazon.deals@fakehdfc",
        },
        "scammerMessages": [
            "You have been selected for iPhone 15 Pro at just Rs. 999! Click here to claim: http://amaz0n-deals.fake-site.com/claim?id=12345. Offer expires in 10 minutes!",
            "Hurry up! Only 3 items left. For queries email us at offers@fake-amazon-deals.com or call +91-9988776655.",
            "Pay just Rs. 999 via UPI amazon.deals@fakehdfc to confirm your iPhone 15 Pro booking. This is an official Amazon partner deal.",
            "Your exclusive offer is about to expire. Click http://amaz0n-deals.fake-site.com/claim?id=12345 or pay via amazon.deals@fakehdfc now!",
            "FINAL NOTICE: Link: http://amaz0n-deals.fake-site.com/claim?id=12345 Email: offers@fake-amazon-deals.com Phone: +91-9988776655.",
        ],
    },
    # ── 4. KYC Fraud ─────────────────────────────────────────────────────
    {
        "scenarioId": "kyc_fraud",
        "name": "KYC Fraud Detection",
        "scamType": "kyc_fraud",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-7654321098",
            "bankAccount": "9876543210987654",
            "upiId": "kyc.verify@fakeaxis",
            "phishingLink": "http://kyc-update-portal.fake-rbi.com/verify",
        },
        "scammerMessages": [
            "ALERT: Your KYC is expired. Your bank account will be frozen within 24 hours. Call +91-7654321098 to update your KYC immediately.",
            "Sir, this is from RBI KYC department. Your account 9876543210987654 needs urgent verification. Please update now.",
            "To complete KYC, visit http://kyc-update-portal.fake-rbi.com/verify and enter your details. Pay the fee via UPI: kyc.verify@fakeaxis.",
            "Last warning: account 9876543210987654 will be blocked. Complete KYC at http://kyc-update-portal.fake-rbi.com/verify or call +91-7654321098.",
            "Final notice! Transfer Rs. 99 to kyc.verify@fakeaxis and upload documents at http://kyc-update-portal.fake-rbi.com/verify. Call +91-7654321098!",
        ],
    },
    # ── 5. Job Scam ──────────────────────────────────────────────────────
    {
        "scenarioId": "job_scam",
        "name": "Job Scam Detection",
        "scamType": "job_scam",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-6543210987",
            "upiId": "hr.recruit@fakejob",
            "phishingLink": "http://google-careers-india.fake-site.com/apply",
            "emailAddress": "hr@fake-google-careers.com",
        },
        "scammerMessages": [
            "Dear Candidate, Google India is hiring work-from-home data entry operators. Salary: Rs. 50,000/month. No experience needed. Apply now!",
            "Thank you for your interest! Please apply through our official portal: http://google-careers-india.fake-site.com/apply. Contact HR at +91-6543210987.",
            "To reserve your position, please pay a registration fee of Rs. 500 to UPI: hr.recruit@fakejob. This is refundable after joining.",
            "For any questions, email hr@fake-google-careers.com or call +91-6543210987. The application link: http://google-careers-india.fake-site.com/apply.",
            "Last 5 positions remaining! Pay Rs. 500 to hr.recruit@fakejob immediately. Confirm via email hr@fake-google-careers.com or call +91-6543210987.",
        ],
    },
    # ── 6. Lottery Scam ──────────────────────────────────────────────────
    {
        "scenarioId": "lottery_scam",
        "name": "Lottery Scam Detection",
        "scamType": "lottery_scam",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-5432109876",
            "bankAccount": "44556677889900112233",
            "upiId": "lottery.claim@fakepay",
            "emailAddress": "winner@fake-lottery-india.com",
        },
        "scammerMessages": [
            "CONGRATULATIONS! Your mobile number has won Rs. 25,00,000 in the National Digital Lottery! Claim your prize now. Ref: NL-2026-8899.",
            "To claim your winnings, please contact our claims officer at +91-5432109876. You can also email winner@fake-lottery-india.com for details.",
            "Sir, for prize transfer we need a processing fee of Rs. 2,500. Please transfer to bank account 44556677889900112233 (HDFC Bank, Prize Claims Dept).",
            "You can also pay the processing fee via UPI: lottery.claim@fakepay. Contact +91-5432109876 for immediate processing.",
            "Final reminder: Pay Rs. 2,500 to lottery.claim@fakepay or account 44556677889900112233. Email winner@fake-lottery-india.com. Call +91-5432109876 NOW!",
        ],
    },
    # ── 7. Electricity Bill Scam ─────────────────────────────────────────
    {
        "scenarioId": "electricity_bill",
        "name": "Electricity Bill Scam",
        "scamType": "electricity_bill",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-4321098765",
            "upiId": "electric.bill@fakepaytm",
            "phishingLink": "http://electricity-pay-india.fake-site.com/bill",
            "bankAccount": "11223344556677",
        },
        "scammerMessages": [
            "URGENT: Your electricity connection will be DISCONNECTED tonight due to unpaid bill of Rs. 3,456. Pay immediately to avoid disconnection.",
            "Sir, this is from the Electricity Board. Your consumer ID shows pending payment. Call +91-4321098765 to resolve this immediately.",
            "Pay your pending bill at http://electricity-pay-india.fake-site.com/bill or transfer to UPI: electric.bill@fakepaytm right now.",
            "Your meter reading confirms Rs. 3,456 due. Transfer to account 11223344556677 or UPI electric.bill@fakepaytm. Call +91-4321098765.",
            "FINAL WARNING: Power cut scheduled in 1 hour! Pay at http://electricity-pay-india.fake-site.com/bill or call +91-4321098765 immediately!",
        ],
    },
    # ── 8. Govt Scheme Scam ──────────────────────────────────────────────
    {
        "scenarioId": "govt_scheme",
        "name": "Government Scheme Scam",
        "scamType": "govt_scheme",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-3210987654",
            "upiId": "pmkisan.reg@fakegov",
            "phishingLink": "http://pm-kisan-yojana.fake-gov.com/register",
            "emailAddress": "support@fake-pmkisan.com",
        },
        "scammerMessages": [
            "Good news! You are eligible for PM Kisan Samman Nidhi Yojana. Get Rs. 6,000 directly in your bank account. Register now!",
            "To register, visit http://pm-kisan-yojana.fake-gov.com/register and fill your Aadhaar details. Contact +91-3210987654 for help.",
            "Registration fee of Rs. 100 is required. Pay via UPI: pmkisan.reg@fakegov. Email support@fake-pmkisan.com for queries.",
            "Sir, your registration is pending. Complete it at http://pm-kisan-yojana.fake-gov.com/register. Call +91-3210987654 for assistance.",
            "Last date tomorrow! Register at http://pm-kisan-yojana.fake-gov.com/register. Pay Rs. 100 to pmkisan.reg@fakegov. Email support@fake-pmkisan.com.",
        ],
    },
    # ── 9. Crypto Investment Scam ────────────────────────────────────────
    {
        "scenarioId": "crypto_investment",
        "name": "Crypto Investment Scam",
        "scamType": "crypto_investment",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-2109876543",
            "upiId": "crypto.invest@fakebroker",
            "phishingLink": "http://bitcoin-profit-india.fake-site.com/invest",
            "bankAccount": "99887766554433",
        },
        "scammerMessages": [
            "Exclusive opportunity! Invest Rs. 10,000 in Bitcoin and earn Rs. 1,00,000 in just 7 days. Guaranteed returns with zero risk!",
            "Join our VIP trading group. Visit http://bitcoin-profit-india.fake-site.com/invest to open your account. Contact advisor at +91-2109876543.",
            "To start earning, transfer your investment to UPI: crypto.invest@fakebroker or bank account 99887766554433 (Crypto Trading Ltd).",
            "Sir, your slot is reserved. Transfer Rs. 10,000 to crypto.invest@fakebroker now. Call +91-2109876543 for instant activation.",
            "Last chance for 10x returns! Invest at http://bitcoin-profit-india.fake-site.com/invest. UPI: crypto.invest@fakebroker. Call +91-2109876543!",
        ],
    },
    # ── 10. Customs Parcel Scam ──────────────────────────────────────────
    {
        "scenarioId": "customs_parcel",
        "name": "Customs Parcel Scam",
        "scamType": "customs_parcel",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-1098765432",
            "upiId": "customs.fee@fakepost",
            "bankAccount": "77665544332211",
            "emailAddress": "clearance@fake-indiapost.com",
        },
        "scammerMessages": [
            "India Post: Your parcel from USA (Tracking: IP2026789456) is held at customs. Pay clearance fee of Rs. 1,500 within 24 hours or it will be returned.",
            "This is Customs Officer Sharma. Your parcel contains electronics worth Rs. 50,000. Pay duty to release it. Call +91-1098765432.",
            "Transfer customs duty Rs. 1,500 to UPI: customs.fee@fakepost or bank account 77665544332211 (India Customs Authority).",
            "Email clearance@fake-indiapost.com with your payment receipt for faster processing. Call +91-1098765432 for tracking.",
            "URGENT: Parcel will be destroyed if fee not paid. UPI: customs.fee@fakepost. Account: 77665544332211. Email clearance@fake-indiapost.com. Call +91-1098765432!",
        ],
    },
    # ── 11. Tech Support Scam ────────────────────────────────────────────
    {
        "scenarioId": "tech_support",
        "name": "Tech Support Scam",
        "scamType": "tech_support",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-9012345678",
            "upiId": "microsoft.fix@fakesupport",
            "phishingLink": "http://microsoft-support-india.fake-site.com/fix",
            "emailAddress": "support@fake-microsoft-help.com",
        },
        "scammerMessages": [
            "WARNING: Your computer has been infected with a dangerous virus! Your personal data is at risk. Contact Microsoft Support immediately!",
            "Call our certified technicians at +91-9012345678. Or visit http://microsoft-support-india.fake-site.com/fix to run a free diagnostic scan.",
            "Sir, we found 47 viruses on your system. To remove them, pay Rs. 2,999 for our premium antivirus via UPI: microsoft.fix@fakesupport.",
            "Email support@fake-microsoft-help.com for a detailed virus report. Call +91-9012345678 for urgent remote assistance.",
            "Your data will be stolen in 2 hours! Pay microsoft.fix@fakesupport NOW. Visit http://microsoft-support-india.fake-site.com/fix or email support@fake-microsoft-help.com!",
        ],
    },
    # ── 12. Loan Approval Scam ───────────────────────────────────────────
    {
        "scenarioId": "loan_approval",
        "name": "Loan Approval Scam",
        "scamType": "loan_approval",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-8901234567",
            "upiId": "loan.process@fakeloan",
            "bankAccount": "33445566778899",
            "phishingLink": "http://instant-loan-approve.fake-site.com/apply",
        },
        "scammerMessages": [
            "Congratulations! Your pre-approved personal loan of Rs. 5,00,000 at 0% interest is ready for disbursement. No documents required!",
            "To activate your loan, pay a one-time processing fee of Rs. 999. Call +91-8901234567 or visit http://instant-loan-approve.fake-site.com/apply.",
            "Transfer processing fee to UPI: loan.process@fakeloan or bank account 33445566778899 (Quick Loan Finance Ltd).",
            "Sir your loan ID QL-2026-5678 is approved. Pay Rs. 999 to loan.process@fakeloan. Call +91-8901234567 for instant disbursement.",
            "FINAL: Loan expires today! Pay at http://instant-loan-approve.fake-site.com/apply. UPI: loan.process@fakeloan. Account: 33445566778899. Call +91-8901234567!",
        ],
    },
    # ── 13. Income Tax Scam ──────────────────────────────────────────────
    {
        "scenarioId": "income_tax",
        "name": "Income Tax Scam",
        "scamType": "income_tax",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-7890123456",
            "upiId": "itrefund.process@faketax",
            "phishingLink": "http://income-tax-refund.fake-gov.com/claim",
            "emailAddress": "refund@fake-incometax.com",
        },
        "scammerMessages": [
            "Income Tax Department: You are eligible for a tax refund of Rs. 15,750 for AY 2025-26. Claim before it expires on 28th Feb.",
            "To claim your refund, verify your PAN at http://income-tax-refund.fake-gov.com/claim. Contact +91-7890123456 for assistance.",
            "Pay a verification fee of Rs. 250 via UPI: itrefund.process@faketax. Email refund@fake-incometax.com with your PAN copy.",
            "Sir your refund is ready. Complete verification at http://income-tax-refund.fake-gov.com/claim or call +91-7890123456.",
            "LAST DATE: Claim refund NOW! Visit http://income-tax-refund.fake-gov.com/claim. UPI: itrefund.process@faketax. Email refund@fake-incometax.com. Call +91-7890123456!",
        ],
    },
    # ── 14. Refund Scam ──────────────────────────────────────────────────
    {
        "scenarioId": "refund_scam",
        "name": "Refund Scam Detection",
        "scamType": "refund_scam",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-6789012345",
            "upiId": "flipkart.refund@fakerefund",
            "bankAccount": "22334455667788",
            "phishingLink": "http://flipkart-refund-portal.fake-site.com/process",
        },
        "scammerMessages": [
            "Flipkart: Your order #FK2026789 was double-charged. A refund of Rs. 4,999 is pending. Claim now to get your money back.",
            "Sir, I'm from Flipkart customer support. To process your refund, visit http://flipkart-refund-portal.fake-site.com/process or call +91-6789012345.",
            "For instant refund, share your UPI ID. Or we can transfer to bank account 22334455667788. Verify by sending Rs. 1 to flipkart.refund@fakerefund.",
            "Sir, refund verification requires Rs. 1 test transfer to flipkart.refund@fakerefund. Call +91-6789012345 if you face issues.",
            "URGENT: Refund expires today! Process at http://flipkart-refund-portal.fake-site.com/process. UPI: flipkart.refund@fakerefund. Account: 22334455667788. Call +91-6789012345!",
        ],
    },
    # ── 15. Insurance Scam ───────────────────────────────────────────────
    {
        "scenarioId": "insurance",
        "name": "Insurance Scam Detection",
        "scamType": "insurance",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "maxTurns": 5,
        "fakeData": {
            "phoneNumber": "+91-5678901234",
            "upiId": "lic.bonus@fakeinsurance",
            "bankAccount": "11009988776655",
            "emailAddress": "claims@fake-lic-india.com",
        },
        "scammerMessages": [
            "LIC India: Your policy LIC-2019-456789 has a maturity bonus of Rs. 2,50,000 ready for disbursement. Claim before March 31.",
            "To process your bonus, please call our claims department at +91-5678901234. You can also email claims@fake-lic-india.com.",
            "Sir, for verification, transfer Rs. 500 processing fee to UPI: lic.bonus@fakeinsurance or bank account 11009988776655 (LIC Claims Dept).",
            "Your bonus will be credited after fee payment. Call +91-5678901234 or email claims@fake-lic-india.com for faster processing.",
            "FINAL: Bonus expires March 31! Pay to lic.bonus@fakeinsurance or account 11009988776655. Email claims@fake-lic-india.com. Call +91-5678901234 NOW!",
        ],
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
#  PART A: OFFLINE UNIT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

def run_offline_tests():
    """Run all tests that don't need the server."""
    section("PART A: OFFLINE UNIT TESTS (no server needed)")

    # ── A1: Regex Phone Extraction ────────────────────────────────────────
    t = time.perf_counter()
    text = "Call me at +91-9876543210 or 8765432109 or +919123456789"
    intel = extract_from_text(text)
    lat = round((time.perf_counter() - t) * 1000)

    has_full = any("+91-9876543210" in p for p in intel.phoneNumbers)
    has_bare = any("8765432109" in p for p in intel.phoneNumbers)
    record(
        "Regex: Phone +91-9876543210",
        has_full, lat,
        f"Extracted: {intel.phoneNumbers}",
        "REGEX",
    )
    record(
        "Regex: Phone 8765432109",
        has_bare, lat,
        f"Extracted: {intel.phoneNumbers}",
        "REGEX",
    )

    # ── A2: Regex Bank Account Extraction ─────────────────────────────────
    t = time.perf_counter()
    text = "Transfer to account 1234567890123456 immediately"
    intel = extract_from_text(text)
    lat = round((time.perf_counter() - t) * 1000)

    has_bank = any("1234567890123456" in b for b in intel.bankAccounts)
    record(
        "Regex: Bank 1234567890123456",
        has_bank, lat,
        f"Extracted: {intel.bankAccounts}",
        "REGEX",
    )

    # ── A3: Regex UPI Extraction ──────────────────────────────────────────
    t = time.perf_counter()
    text = "Send money to scammer.fraud@fakebank or cashback.scam@fakeupi"
    intel = extract_from_text(text)
    lat = round((time.perf_counter() - t) * 1000)

    has_upi1 = any("scammer.fraud@fakebank" in u for u in intel.upiIds)
    has_upi2 = any("cashback.scam@fakeupi" in u for u in intel.upiIds)
    record(
        "Regex: UPI scammer.fraud@fakebank",
        has_upi1, lat,
        f"Extracted: {intel.upiIds}",
        "REGEX",
    )
    record(
        "Regex: UPI cashback.scam@fakeupi",
        has_upi2, lat,
        f"Extracted: {intel.upiIds}",
        "REGEX",
    )

    # ── A4: Regex URL Extraction ──────────────────────────────────────────
    t = time.perf_counter()
    text = "Click http://amaz0n-deals.fake-site.com/claim?id=12345 to claim"
    intel = extract_from_text(text)
    lat = round((time.perf_counter() - t) * 1000)

    has_url = any("http://amaz0n-deals.fake-site.com/claim?id=12345" in u for u in intel.phishingLinks)
    record(
        "Regex: URL amaz0n-deals phishing link",
        has_url, lat,
        f"Extracted: {intel.phishingLinks}",
        "REGEX",
    )

    # ── A5: Regex Email Extraction ────────────────────────────────────────
    t = time.perf_counter()
    text = "Contact offers@fake-amazon-deals.com for details"
    intel = extract_from_text(text)
    lat = round((time.perf_counter() - t) * 1000)

    has_email = any("offers@fake-amazon-deals.com" in e for e in intel.emailAddresses)
    record(
        "Regex: Email offers@fake-amazon-deals.com",
        has_email, lat,
        f"Extracted: {intel.emailAddresses}",
        "REGEX",
    )

    # ── A6: Regex does NOT classify UPI as email ──────────────────────────
    t = time.perf_counter()
    text = "Pay to fraud@ybl for verification"
    intel = extract_from_text(text)
    lat = round((time.perf_counter() - t) * 1000)

    upi_correct = any("fraud@ybl" in u for u in intel.upiIds)
    not_email = not any("fraud@ybl" in e for e in intel.emailAddresses)
    record(
        "Regex: fraud@ybl classified as UPI (not email)",
        upi_correct and not_email, lat,
        f"UPI: {intel.upiIds} | Email: {intel.emailAddresses}",
        "REGEX",
    )

    # ── A7: Merge Intelligence (union) ────────────────────────────────────
    t = time.perf_counter()
    a = ExtractedIntelligence(phoneNumbers=["+91-9876543210"], bankAccounts=["111"])
    b = ExtractedIntelligence(phoneNumbers=["+91-8765432109"], bankAccounts=["111", "222"])
    merged = merge_intelligence(a, b)
    lat = round((time.perf_counter() - t) * 1000)

    phones_ok = set(merged.phoneNumbers) == {"+91-9876543210", "+91-8765432109"}
    banks_ok = set(merged.bankAccounts) == {"111", "222"}
    record(
        "Merge: Union of phones and dedup banks",
        phones_ok and banks_ok, lat,
        f"Phones: {merged.phoneNumbers} | Banks: {merged.bankAccounts}",
        "REGEX",
    )

    # ── A8: Full scenario regex extraction ────────────────────────────────
    for scenario in SCENARIOS:
        t = time.perf_counter()
        full_text = "\n".join(scenario["scammerMessages"])
        intel = extract_from_text(full_text)
        lat = round((time.perf_counter() - t) * 1000)

        # Build a mock final_output from regex-only extraction
        mock_output = {
            "status": "completed",
            "scamDetected": True,
            "extractedIntelligence": {
                "phoneNumbers": intel.phoneNumbers,
                "bankAccounts": intel.bankAccounts,
                "upiIds": intel.upiIds,
                "phishingLinks": intel.phishingLinks,
                "emailAddresses": intel.emailAddresses,
            },
            "engagementMetrics": {
                "engagementDurationSeconds": 120,
                "totalMessagesExchanged": 10,
            },
            "agentNotes": "test",
        }
        score = evaluate_final_output(mock_output, scenario, [])

        # Max intel score depends on how many fake data items the scenario has
        max_intel = len(scenario["fakeData"]) * 10
        record(
            f"Regex score [{scenario['scenarioId']}]: Intel={score['intelligenceExtraction']}/{max_intel}",
            score["intelligenceExtraction"] == max_intel, lat,
            f"Total={score['total']}/100 | Intel={score['intelligenceExtraction']}/{max_intel} (max for this scenario) | "
            f"Phones={intel.phoneNumbers} | Banks={intel.bankAccounts} | "
            f"UPIs={intel.upiIds} | URLs={intel.phishingLinks} | Emails={intel.emailAddresses}",
            "SCORING",
        )

    # ── A9: HoneypotResponse has all scoring fields ───────────────────────
    t = time.perf_counter()
    resp = HoneypotResponse(
        status="success",
        reply="test",
        sessionId="test-123",
        scamDetected=True,
        totalMessagesExchanged=10,
        extractedIntelligence=ExtractedIntelligence(),
        engagementMetrics=EngagementMetrics(engagementDurationSeconds=120, totalMessagesExchanged=10),
        agentNotes="notes",
    )
    resp_dict = resp.model_dump()
    lat = round((time.perf_counter() - t) * 1000)

    required = ["status", "scamDetected", "extractedIntelligence"]
    optional = ["engagementMetrics", "agentNotes"]
    all_present = all(f in resp_dict for f in required + optional)
    record(
        "Schema: HoneypotResponse has all scoring fields",
        all_present, lat,
        f"Fields: {list(resp_dict.keys())}",
        "SCHEMA",
    )

    # ── A10: Engagement metrics presence in response ──────────────────────
    em = resp_dict.get("engagementMetrics", {})
    has_duration = "engagementDurationSeconds" in em
    has_messages = "totalMessagesExchanged" in em
    record(
        "Schema: engagementMetrics has duration + messages",
        has_duration and has_messages, lat,
        f"engagementMetrics: {em}",
        "SCHEMA",
    )

    # ── A11: Scoring function gives 100 with perfect data (4 fake items) ──
    t = time.perf_counter()
    perfect_output = {
        "status": "completed",
        "scamDetected": True,
        "extractedIntelligence": {
            "phoneNumbers": ["+91-9876543210"],
            "bankAccounts": ["1234567890123456"],
            "upiIds": ["scammer.fraud@fakebank"],
            "phishingLinks": ["http://evil-site.com/steal"],
            "emailAddresses": [],
        },
        "engagementMetrics": {
            "engagementDurationSeconds": 120,
            "totalMessagesExchanged": 10,
        },
        "agentNotes": "Scammer used urgency tactics",
    }
    perfect_scenario = {
        "fakeData": {
            "bankAccount": "1234567890123456",
            "upiId": "scammer.fraud@fakebank",
            "phoneNumber": "+91-9876543210",
            "phishingLink": "http://evil-site.com/steal",
        }
    }
    score = evaluate_final_output(perfect_output, perfect_scenario, [])
    lat = round((time.perf_counter() - t) * 1000)

    record(
        "Scoring: Perfect data gives 100/100",
        score["total"] == 100, lat,
        f"Score: {score['total']}/100 | Detection={score['scamDetection']} | "
        f"Intel={score['intelligenceExtraction']} | Engagement={score['engagementQuality']} | "
        f"Structure={score['responseStructure']}",
        "SCORING",
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  PART B: LIVE API MULTI-TURN EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════

def run_live_scenario(scenario: dict) -> dict:
    """
    Run a full multi-turn conversation against the live API and return the
    score using the GUVI evaluate_final_output function.
    """
    session_id = str(uuid.uuid4())
    conversation_history = []
    base_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    last_response_data = None
    total_latency = 0

    for turn_idx, scammer_msg_text in enumerate(scenario["scammerMessages"]):
        # Build message with realistic timestamps (20-second gaps, simulating real eval)
        msg_time = base_time + timedelta(seconds=turn_idx * 20)

        message = {
            "sender": "scammer",
            "text": scammer_msg_text,
            "timestamp": msg_time.isoformat(),
        }

        request_body = {
            "sessionId": session_id,
            "message": message,
            "conversationHistory": conversation_history,
            "metadata": scenario["metadata"],
        }

        try:
            start = time.perf_counter()
            resp = httpx.post(
                f"{BASE_URL}/honeypot",
                headers=HEADERS,
                json=request_body,
                timeout=35,
            )
            lat = round((time.perf_counter() - start) * 1000)
            total_latency += lat

            if resp.status_code != 200:
                record(
                    f"[{scenario['scenarioId']}] Turn {turn_idx + 1}: HTTP {resp.status_code}",
                    False, lat,
                    f"Status {resp.status_code}: {resp.text[:200]}",
                    "LIVE",
                )
                return {"total": 0, "error": f"HTTP {resp.status_code}"}

            data = resp.json()
            last_response_data = data

            # Record per-turn latency
            reply = data.get("reply") or data.get("message") or data.get("text") or ""
            record(
                f"[{scenario['scenarioId']}] Turn {turn_idx + 1}: reply received",
                bool(reply), lat,
                f"Latency={lat}ms | Reply: {reply[:80]}...",
                "LIVE",
            )

            # Add scammer message and agent reply to history
            conversation_history.append(message)
            reply_time = msg_time + timedelta(seconds=5)
            conversation_history.append({
                "sender": "user",
                "text": reply,
                "timestamp": reply_time.isoformat(),
            })

        except httpx.TimeoutException:
            record(
                f"[{scenario['scenarioId']}] Turn {turn_idx + 1}: TIMEOUT",
                False, 35000,
                "Request exceeded 35 seconds",
                "LIVE",
            )
            return {"total": 0, "error": "timeout"}
        except Exception as exc:
            record(
                f"[{scenario['scenarioId']}] Turn {turn_idx + 1}: ERROR",
                False, 0,
                str(exc),
                "LIVE",
            )
            return {"total": 0, "error": str(exc)}

    # ── Score the LAST response using GUVI's scoring function ─────────────
    if last_response_data is None:
        return {"total": 0, "error": "no response received"}

    score = evaluate_final_output(last_response_data, scenario, conversation_history)
    score["avg_latency_ms"] = round(total_latency / len(scenario["scammerMessages"]))
    score["total_latency_ms"] = total_latency
    return score


def run_live_tests():
    """Run multi-turn evaluation against the live API."""
    section("PART B: LIVE API MULTI-TURN EVALUATION")

    # Quick health check first
    try:
        r = httpx.get(f"{BASE_URL}/health", timeout=5)
        if r.status_code != 200:
            print(f"\n  \033[91mServer not healthy (status {r.status_code}). Skipping live tests.\033[0m")
            return
    except Exception:
        print(f"\n  \033[91mServer not running at {BASE_URL}. Skipping live tests.\033[0m")
        print(f"  Start with: uvicorn main:app --host 0.0.0.0 --port 8080")
        return

    scenario_scores = []

    for scenario in SCENARIOS:
        print(f"\n  \033[93m--- Scenario: {scenario['name']} ({scenario['scenarioId']}) ---\033[0m")
        score = run_live_scenario(scenario)
        scenario_scores.append((scenario, score))

        # Record per-category results
        if "error" not in score:
            t_lat = score.get("total_latency_ms", 0)

            record(
                f"[{scenario['scenarioId']}] Scam Detection",
                score["scamDetection"] == 20, t_lat,
                f"{score['scamDetection']}/20",
                "SCORE",
            )
            record(
                f"[{scenario['scenarioId']}] Intelligence Extraction",
                score["intelligenceExtraction"] == 40, t_lat,
                f"{score['intelligenceExtraction']}/40",
                "SCORE",
            )
            record(
                f"[{scenario['scenarioId']}] Engagement Quality",
                score["engagementQuality"] >= 15, t_lat,
                f"{score['engagementQuality']}/20",
                "SCORE",
            )
            record(
                f"[{scenario['scenarioId']}] Response Structure",
                score["responseStructure"] == 20, t_lat,
                f"{score['responseStructure']}/20",
                "SCORE",
            )
            record(
                f"[{scenario['scenarioId']}] TOTAL SCORE",
                score["total"] >= 95, t_lat,
                f"{score['total']}/100 | avg_latency={score.get('avg_latency_ms', '?')}ms",
                "SCORE",
            )
            record(
                f"[{scenario['scenarioId']}] Response Time (avg < 30s)",
                score.get("avg_latency_ms", 99999) < 30000, t_lat,
                f"Avg: {score.get('avg_latency_ms', '?')}ms",
                "PERF",
            )

    # ── Final Score Board ─────────────────────────────────────────────────
    section("SCORE BOARD (GUVI Evaluation Simulation)")

    print(f"\n  {'Scenario':<25} {'Detection':<12} {'Intel':<10} {'Engage':<10} {'Structure':<12} {'TOTAL':<8} {'Avg Latency'}")
    print(f"  {'-'*25} {'-'*12} {'-'*10} {'-'*10} {'-'*12} {'-'*8} {'-'*12}")

    totals = {"scamDetection": 0, "intelligenceExtraction": 0, "engagementQuality": 0, "responseStructure": 0, "total": 0}
    valid_count = 0

    for scenario, score in scenario_scores:
        if "error" in score:
            print(f"  {scenario['scenarioId']:<25} ERROR: {score['error']}")
            continue

        valid_count += 1
        for k in totals:
            totals[k] += score[k]

        total_color = "\033[92m" if score["total"] >= 95 else "\033[93m" if score["total"] >= 80 else "\033[91m"
        print(
            f"  {scenario['scenarioId']:<25} "
            f"{score['scamDetection']:>4}/20     "
            f"{score['intelligenceExtraction']:>4}/40   "
            f"{score['engagementQuality']:>4}/20   "
            f"{score['responseStructure']:>6}/20     "
            f"{total_color}{score['total']:>4}/100\033[0m  "
            f"{score.get('avg_latency_ms', '?')}ms"
        )

    if valid_count > 0:
        avg_total = round(totals["total"] / valid_count, 1)
        print(f"\n  {'WEIGHTED AVERAGE':<25} "
              f"{round(totals['scamDetection']/valid_count, 1):>4}/20     "
              f"{round(totals['intelligenceExtraction']/valid_count, 1):>4}/40   "
              f"{round(totals['engagementQuality']/valid_count, 1):>4}/20   "
              f"{round(totals['responseStructure']/valid_count, 1):>6}/20     "
              f"\033[1m{avg_total:>4}/100\033[0m")

        if avg_total >= 95:
            print(f"\n  \033[92m{'='*60}\033[0m")
            print(f"  \033[92m  EXCELLENT! Estimated score: {avg_total}/100\033[0m")
            print(f"  \033[92m{'='*60}\033[0m")
        elif avg_total >= 80:
            print(f"\n  \033[93m  GOOD score: {avg_total}/100 - check missing categories above\033[0m")
        else:
            print(f"\n  \033[91m  NEEDS WORK: {avg_total}/100 - review failures above\033[0m")


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def run():
    """Run all tests (called by run_all.py)."""
    clear_results()
    run_offline_tests()
    run_live_tests()
    print_summary(get_results(), get_critical_failures(), "SCORING TEST REPORT")


if __name__ == "__main__":
    clear_results()

    offline_only = "--offline" in sys.argv

    run_offline_tests()

    if not offline_only:
        run_live_tests()

    failed = print_summary(
        get_results(),
        get_critical_failures(),
        "SCORING TEST REPORT",
    )
    sys.exit(1 if failed > 0 else 0)
