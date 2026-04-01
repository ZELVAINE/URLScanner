# URLScanner

**A heuristic URL risk analyser for Firefox.**

URLScanner checks the current tab's URL — and optionally every link on a page — for patterns associated with phishing, domain spoofing, and social engineering attacks. It gives you a score, a breakdown of findings, and optionally queries VirusTotal for live threat intelligence.

It's designed to be a **transparent second opinion**, not a black-box verdict.

---

## Philosophy

- **Heuristic, not absolute.** URLScanner looks for patterns and indicators, not certainty. It flags risk — it doesn't make final decisions.
- **Transparent, not magic.** Every point added to the score has a reason. You can see exactly what was flagged and why.
- **Layered, not single-source.** Local heuristics run first (no API needed), with optional external lookups for domain age and live threat intel.
- **Educational.** The explanations are written to build intuition, not just report numbers.

---

## What it checks

### Local heuristics (no API key required)

| Check | What it looks for |
|---|---|
| Protocol | HTTP vs HTTPS |
| Raw IP address | IPv4 in place of a domain name |
| @ symbol | URL credential injection trick |
| Punycode / IDN | `xn--` encoded lookalike domains |
| Homoglyph characters | Non-Latin or full-width characters in the hostname |
| Brand impersonation | Known brand names appearing in a URL that isn't that brand's domain |
| High-risk TLD | `.tk`, `.ml`, `.xyz`, `.top` and others frequently used in phishing campaigns |
| Domain entropy | Algorithmically generated, high-randomness domain names |
| Subdomain depth | Excessive subdomain chaining to bury the real domain |
| URL length | Abnormally long URLs used to hide destination or encode payloads |
| Hyphen count | Hyphen-heavy domains imitating legitimate service names |
| URL shorteners | Services that mask the real destination |
| Suspicious keywords | Phishing-common words appearing in the domain name itself vs. the path (weighted differently) |
| Double slashes in path | URL parser confusion tricks |
| Data URIs | Inline content embedding used to host pages without a real server |

### External lookups (optional)

| Feature | Source | Key required? |
|---|---|---|
| Domain age | RDAP (ICANN open protocol) | No |
| Live threat intel | VirusTotal | Yes (free tier: 4 req/min) |

Domain age is queried automatically via RDAP — no account needed. VirusTotal requires a free API key, which you can paste into the Settings tab.

---

## Scoring

The risk score is 0–100, built by accumulating weighted points per finding:

- **0–29**: Low risk
- **30–64**: Medium risk — some indicators present, check carefully
- **65+**: High risk — multiple phishing-associated patterns detected

Findings that appear in the **domain name itself** are weighted more heavily than the same pattern in the URL path, since attackers have more control over the path.

---

## Features

- **Current tab scan** — runs on popup open, heuristics first, external lookups in background
- **Page link scanner** — analyses every external link on the page, sorted by risk score, click any entry to expand findings
- **VirusTotal integration** — live engine flagging count + reputation score
- **RDAP domain age** — newly registered domains flagged as high-risk indicator
- **Settings panel** — paste and store your VT API key locally (browser storage, never transmitted except to VT directly)

---

## Limitations

URLScanner is a heuristic tool and has real limits:

- It does **not** guarantee safety or danger — a clean score is not a green light
- It checks URLs, not page content — it won't detect malicious JavaScript or drive-by downloads
- Heuristic checks can produce false positives on legitimate sites that happen to match patterns
- VirusTotal data represents past analysis — a freshly deployed phishing page may not yet be flagged

The goal is **awareness and intuition**, not full protection.

---

## Setup

1. Clone or download this repository
2. Open Firefox and go to `about:debugging`
3. Click **This Firefox**
4. Click **Load Temporary Add-on**
5. Select `manifest.json`

Then open any website and click the extension icon.

### VirusTotal (optional)

1. Create a free account at [virustotal.com](https://www.virustotal.com)
2. Go to your profile → API key
3. Paste it into URLScanner's **Settings** tab

---

## Status

🟡 Active development. v2.0.

**Planned:**
- Customisable scoring thresholds
- Allowlist / blocklist
- Export findings as JSON
- Passive mode (background scanning of visited URLs)

---

## Notes

This is a learning project built to explore phishing detection concepts, browser extension architecture, and threat intelligence integration. It does not aim to replace dedicated security tools.
