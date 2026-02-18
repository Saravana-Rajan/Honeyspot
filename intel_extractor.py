"""Regex-based intelligence extraction to complement LLM extraction.

Scans raw scammer message text for phone numbers, bank accounts, UPI IDs,
phishing links, and email addresses.  Results are merged with Gemini output
so that nothing the scammer shared is missed.
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
_BANK_FORMATTED = re.compile(r'\b\d{4}[\s\-]\d{4}[\s\-]\d{4}(?:[\s\-]\d{2,4})?\b')

# ---------------------------------------------------------------------------
# URLs / phishing links
# ---------------------------------------------------------------------------
_URL_PATTERN = re.compile(
    r'https?://[^\s<>\"\')\],;]+|www\.[^\s<>\"\')\],;]+',
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
    return ExtractedIntelligence(
        phoneNumbers=sorted(phones),
        bankAccounts=sorted(banks),
        upiIds=sorted(upis),
        phishingLinks=sorted(urls),
        emailAddresses=sorted(emails),
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
        suspiciousKeywords=sorted(set(a.suspiciousKeywords) | set(b.suspiciousKeywords)),
    )
