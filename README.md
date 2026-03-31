# 🔐 URLScanner

**A simple, heuristic-based URL risk analyzer for Firefox.**

URLScanner is a lightweight browser extension that checks the current
tab's URL for common phishing-style patterns and explains why something
might be suspicious.

It's designed to be a **quick second opinion**, not a black-box "safe or
unsafe" tool.

---

## Philosophy

-   **Heuristic, not absolute.** URLScanner looks for patterns, not
    certainty. It highlights risk indicators rather than making final
    decisions.
-   **Transparent, not magic.** Every score is backed by clear
    explanations. You can see *why* something was flagged.
-   **Simple, not overengineered.** The goal is to be understandable and
    lightweight, not a full security suite.
-   **Educational, not just functional.** It should help you learn what
    suspicious URLs look like over time.

---

## What does it do?

URLScanner analyzes the current page URL and checks for things like:

-   Missing HTTPS
-   Raw IP addresses instead of domain names
-   Misleading characters (like `@`)
-   Punycode / lookalike domains
-   Excessive subdomains
-   Very long URLs
-   Suspicious keywords (login, verify, secure, etc.)
-   URL shorteners
-   Unusual domain formatting

It then returns:

-   A **risk score (0--100)**
-   A **risk level (Low / Medium / High)**
-   A list of **specific findings**
-   A short **summary of what the score means**

---

## Why this exists

Most attacks don't rely on breaking systems, they rely on tricking
people.

URLScanner is a small tool focused on that layer:

-   spotting suspicious links before clicking them
-   helping explain *why* a link feels off
-   building intuition around phishing patterns

It's not meant to replace real security tools, just to support quick
judgement.

---

## Current Features

-   Firefox extension popup UI
-   URL analysis of the active tab
-   Heuristic scoring system (0-100)
-   Clear breakdown of findings
-   Simple visual risk indicator
-   Works entirely locally (no external API calls)

---

## Limitations

This is a small, heuristic-based project, and it has important limits:

-   It does **not guarantee safety or danger**
-   It does **not check page content**, only the URL
-   It does **not use threat intelligence feeds or blacklists**
-   It may flag legitimate sites that happen to match patterns
-   It may miss more advanced or subtle phishing techniques

The goal is **awareness**, not full protection.

---

## Setup

1.  Clone or download this repository
2.  Open Firefox
3.  Go to `about:debugging`
4.  Click **This Firefox**
5.  Click **Load Temporary Add-on**
6.  Select the `manifest.json` file

Then open any website and click the extension icon.

---

## Status

🟡 Early project.

This was built as a small cybersecurity-focused project to explore
phishing detection concepts and browser extension development.

Future improvements may include:

-   scanning all links on a page\
-   customizable rules / thresholds\
-   better domain analysis\
-   improved scoring logic

---

## Notes

This is a learning project. The goal is understanding patterns, not
pretending to solve phishing completely.
