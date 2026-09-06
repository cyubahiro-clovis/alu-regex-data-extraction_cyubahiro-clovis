# ALU Regex Data Extraction & Secure Validation

A regex program that pulls structured data out of messy, untrusted text the kind an external API actually returns and writes a clean, redacted JSON report.

It handles all eight data types from the brief, validates the three ALU email domains, and treats every byte of input as hostile.

## Running it

Python 3.8+, no packages to install.

```bash
python3 src/main.py              
python3 src/main.py --self-test  
```

```
├── input/raw-text.txt          
├── src/main.py                 
├── output/sample-output.json   
└── README.md
```

## How it works

Three stages, kept deliberately separate:

1. **Sanitise**: normalise Unicode, strip control characters, quarantine over-long lines, scan for attack signatures.
2. **Extract**: regex finds candidates by *shape*.
3. **Validate and redact**: Python decides whether each candidate is *real*, then masks it.

The split matters. A regex describes shape, not meaning. It can tell you something looks like a 16-digit card number; it can't tell you the checksum is valid. Cramming all that into one giant pattern gives you something nobody can read or debug. So the regex finds candidates and ordinary code decides what's genuine.

## What it extracts

All eight types, though only four were required:

Emails 
URLs 
Phone numbers
Credit cards
Times
HTML tags
Hashtags
Currency
## ALU email validation

Three anchored validators: `@alueducation.com`, `@alumni.alueducation.com`, `@si.alueducation.com`.

**The anchors are the whole point.** Without `^` and `$`, a search would accept:

```
k.mugisha@alueducation.com.attacker.net
```

because the required text *is* in there it just isn't the whole string. That exact attack sits in the input file and the program rejects it, along with `@alumni.alueducation.co` (one letter short). This is the difference between searching and validating.

## Security

The input is never trusted. It's not executed, not run through a shell, not rendered as HTML, not used to build a query.

**Eleven threat signatures**: XSS, unsafe URI schemes, SQL and template and command injection, path traversal, CRLF, NoSQL operators, null bytes. The sample run catches 15 hostile constructs.

**Nothing sensitive appears in the output.** Cards show the last 4 digits only. Emails keep two characters and the domain. Hostile payloads are stored as SHA-256 fingerprints enough to audit a finding, useless to anyone who steals the report.

## About the input

`input/raw-text.txt` imitates a partner CRM export: agent-typed tickets, gateway logs, a hand-pasted CSV, and a block of untrusted CMS HTML. It's deliberately inconsistent mixed separators, stray spaces, both `12:00 PM` and `12:00` in the same document, because that's what production text looks like. Attack payloads are seeded throughout so the security path actually runs.



