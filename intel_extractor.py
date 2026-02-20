"""Regex-based intelligence extraction to complement LLM extraction.

Scans raw scammer message text for phone numbers, bank accounts, UPI IDs,
phishing links, email addresses, case IDs, policy numbers, and order numbers.
Results are merged with Gemini output so that nothing the scammer shared is missed.
"""

from __future__ import annotations

import re
from typing import Set

from schemas import ExtractedIntelligence

# ---------------------------------------------------------------------------
# Phone numbers  (Indian & international formats)
# ---------------------------------------------------------------------------
_PHONE_PATTERNS = [
    # +91-98765-43210  /  +91 9876543210  /  +919876543210
    re.compile(r'\+\d{1,3}[-.\s]?\d{4,5}[-.\s]?\d{4,6}'),
    # 91-9876543210  /  919876543210
    re.compile(r'\b91[-.\s]?\d{10}\b'),
    # Landline with STD: 011-23456789
    re.compile(r'\b0\d{2,4}[-.\s]?\d{6,8}\b'),
    # Bare 10-digit Indian mobile
    re.compile(r'\b[6-9]\d{9}\b'),
]

# ---------------------------------------------------------------------------
# Bank account numbers  (9-18 digits)
# ---------------------------------------------------------------------------
_BANK_PLAIN = re.compile(r'\b\d{9,20}\b')
_BANK_FORMATTED = re.compile(r'\b\d{4}[\s\-]\d{4}[\s\-]\d{4}(?:[\s\-]\d{2,6})?\b')

# ---------------------------------------------------------------------------
# URLs / phishing links
# ---------------------------------------------------------------------------
_URL_PATTERN = re.compile(
    r'https?://[^\s<>\"\')\],;]+|www\.[^\s<>\"\')\],;]+',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Case IDs / Reference IDs
# ---------------------------------------------------------------------------
# Prefixed format: CASE-12345, REF-2024-001, FIR-9876, TKT-123, INC-456
_CASE_PREFIX_PATTERN = re.compile(
    r'\b(?:CASE|REF|FIR|TICKET|COMPLAINT|TKT|CR|SR|INC)[-\s]?\d[\w\-]{2,20}\b',
    re.IGNORECASE,
)
# Natural language: "case no 12345", "reference number ABC-123", "complaint id 789"
_CASE_NL_PATTERN = re.compile(
    r'(?:case|reference|complaint|ticket|FIR|incident)\s*(?:no\.?|number|num|id|#)\s*:?\s*([A-Z0-9][\w\-]{2,20})',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Policy numbers
# ---------------------------------------------------------------------------
# Prefixed: POL-123456, LIC-9876543, POLICY-12345, INS-789
_POLICY_PREFIX_PATTERN = re.compile(
    r'\b(?:POL|POLICY|LIC|INS|INSURANCE)[-\s]?\d[\w\-]{3,20}\b',
    re.IGNORECASE,
)
# Natural language: "policy no 12345", "insurance number ABC-123", "LIC number 456"
_POLICY_NL_PATTERN = re.compile(
    r'(?:policy|insurance|LIC)\s*(?:no\.?|number|num|id|#)\s*:?\s*([A-Z0-9][\w\-]{3,20})',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Order numbers
# ---------------------------------------------------------------------------
# Prefixed: ORD-12345, ORDER-9876, TXN-12345, AWB-789
_ORDER_PREFIX_PATTERN = re.compile(
    r'\b(?:ORD|ORDER|TXN|TRANS|TRANSACTION|AWB|SHIP|SHIPMENT)[-\s]?\d[\w\-]{3,20}\b',
    re.IGNORECASE,
)
# Natural language: "order no 12345", "transaction id ABC-123", "order number 456"
_ORDER_NL_PATTERN = re.compile(
    r'(?:order|transaction|shipment|AWB)\s*(?:no\.?|number|num|id|#)\s*:?\s*([A-Z0-9][\w\-]{3,20})',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# @-patterns  (emails & UPI IDs share the @ symbol)
# ---------------------------------------------------------------------------
_AT_PATTERN = re.compile(r'[\w.\-+]+@[\w.\-]+')


# ===================================================================
# Collectors
# ===================================================================

def _collect_phones(text: str) -> Set[str]:
    found: Set[str] = set()
    for pat in _PHONE_PATTERNS:
        for m in pat.finditer(text):
            found.add(m.group().strip())
    return found


def _collect_banks(text: str) -> Set[str]:
    found: Set[str] = set()
    for pat in [_BANK_PLAIN, _BANK_FORMATTED]:
        for m in pat.finditer(text):
            raw = m.group().strip()
            found.add(raw)
            # Also store the digits-only version so substring matching works
            cleaned = re.sub(r'[\s\-]', '', raw)
            if cleaned != raw:
                found.add(cleaned)
    return found


def _collect_urls(text: str) -> Set[str]:
    found: Set[str] = set()
    for m in _URL_PATTERN.finditer(text):
        url = m.group().rstrip('.,;:!?)')
        found.add(url)
    return found


def _collect_case_ids(text: str) -> Set[str]:
    found: Set[str] = set()
    # Prefixed patterns (full match)
    for m in _CASE_PREFIX_PATTERN.finditer(text):
        found.add(m.group().strip())
    # Natural language patterns (extract just the ID part)
    for m in _CASE_NL_PATTERN.finditer(text):
        found.add(m.group(1).strip())
    return found


def _collect_policy_numbers(text: str) -> Set[str]:
    found: Set[str] = set()
    for m in _POLICY_PREFIX_PATTERN.finditer(text):
        found.add(m.group().strip())
    for m in _POLICY_NL_PATTERN.finditer(text):
        found.add(m.group(1).strip())
    return found


def _collect_order_numbers(text: str) -> Set[str]:
    found: Set[str] = set()
    for m in _ORDER_PREFIX_PATTERN.finditer(text):
        found.add(m.group().strip())
    for m in _ORDER_NL_PATTERN.finditer(text):
        found.add(m.group(1).strip())
    return found


def _collect_at_patterns(text: str, urls: Set[str]) -> tuple[Set[str], Set[str]]:
    """Return (upi_ids, email_addresses)."""
    upis: Set[str] = set()
    emails: Set[str] = set()
    for m in _AT_PATTERN.finditer(text):
        val = m.group().rstrip('.')  # Strip trailing dots (sentence endings)
        if not val or '@' not in val:
            continue
        # Skip tokens that are part of a URL
        if any(val in u for u in urls):
            continue
        domain = val.split('@', 1)[1]
        # Email domains contain a dot (gmail.com); UPI domains do not (ybl, paytm)
        if '.' in domain:
            emails.add(val)
        else:
            upis.add(val)
    return upis, emails


# ===================================================================
# Public API
# ===================================================================

def extract_from_text(text: str) -> ExtractedIntelligence:
    """Run all regex extractors on *text* and return an ExtractedIntelligence."""
    phones = _collect_phones(text)
    banks = _collect_banks(text)
    urls = _collect_urls(text)
    upis, emails = _collect_at_patterns(text, urls)
    case_ids = _collect_case_ids(text)
    policy_numbers = _collect_policy_numbers(text)
    order_numbers = _collect_order_numbers(text)
    return ExtractedIntelligence(
        phoneNumbers=sorted(phones),
        bankAccounts=sorted(banks),
        upiIds=sorted(upis),
        phishingLinks=sorted(urls),
        emailAddresses=sorted(emails),
        caseIds=sorted(case_ids),
        policyNumbers=sorted(policy_numbers),
        orderNumbers=sorted(order_numbers),
    )


def merge_intelligence(
    a: ExtractedIntelligence,
    b: ExtractedIntelligence,
) -> ExtractedIntelligence:
    """Union two intelligence objects, keeping every unique value."""
    return ExtractedIntelligence(
        phoneNumbers=sorted(set(a.phoneNumbers) | set(b.phoneNumbers)),
        bankAccounts=sorted(set(a.bankAccounts) | set(b.bankAccounts)),
        upiIds=sorted(set(a.upiIds) | set(b.upiIds)),
        phishingLinks=sorted(set(a.phishingLinks) | set(b.phishingLinks)),
        emailAddresses=sorted(set(a.emailAddresses) | set(b.emailAddresses)),
        caseIds=sorted(set(a.caseIds) | set(b.caseIds)),
        policyNumbers=sorted(set(a.policyNumbers) | set(b.policyNumbers)),
        orderNumbers=sorted(set(a.orderNumbers) | set(b.orderNumbers)),
        suspiciousKeywords=sorted(set(a.suspiciousKeywords) | set(b.suspiciousKeywords)),
    )
