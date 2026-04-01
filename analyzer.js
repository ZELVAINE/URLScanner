// analyzer.js — URLScanner heuristic engine

// ─── Constants ───────────────────────────────────────────────────────────────

const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "secure", "update", "account", "bank", "signin",
  "confirm", "password", "wallet", "billing", "invoice", "ebayisapi",
  "webscr", "cmd", "dispatch", "credential", "authenticate", "validation",
  "recover", "unlock", "suspended", "limited", "unusual", "activity",
  "paypal", "apple-id", "microsoft-support", "amazon-security"
];

// TLDs heavily abused in phishing (free / cheap / lax registrars)
const SUSPICIOUS_TLDS = [
  "tk", "ml", "ga", "cf", "gq",   // Freenom freebies
  "xyz", "top", "club", "work", "date", "racing",
  "stream", "download", "win", "bid", "review",
  "loan", "click", "link", "men"
];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
  "is.gd", "tiny.cc", "rebrand.ly", "cutt.ly", "shorturl.at",
  "bl.ink", "rb.gy", "clck.ru"
];

// Legitimate domains that commonly get impersonated
const HIGH_VALUE_TARGETS = [
  "paypal", "amazon", "google", "microsoft", "apple", "facebook",
  "instagram", "netflix", "ebay", "bank", "chase", "wellsfargo",
  "barclays", "halifax", "lloyds", "hsbc", "natwest"
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getRegistrableDomain(hostname) {
  // Handles common two-part TLDs like co.uk, org.uk, etc.
  const parts = hostname.split(".");
  const twoPartTlds = ["co.uk", "org.uk", "me.uk", "net.uk", "co.jp", "com.au", "co.nz"];
  const joined = parts.slice(-2).join(".");
  if (twoPartTlds.includes(joined) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

function getTld(hostname) {
  const parts = hostname.split(".");
  return parts[parts.length - 1].toLowerCase();
}

function isIpv4(hostname) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) &&
    hostname.split(".").every(p => parseInt(p) <= 255);
}

function shannonEntropy(str) {
  // Higher entropy = more random-looking = more suspicious
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function hasHomoglyphs(hostname) {
  // Common homoglyph substitutions used in IDN attacks
  const homoglyphPattern = /[а-яА-ЯёЁ]|[ａ-ｚＡ-Ｚ]|[０-９]/;
  // Also catch mixed-script domains (Latin + Cyrillic etc)
  return homoglyphPattern.test(hostname);
}

function containsImpersonation(hostname, fullUrl) {
  const registrable = getRegistrableDomain(hostname);
  for (const brand of HIGH_VALUE_TARGETS) {
    // Brand word appears somewhere but NOT as the actual registrable domain
    if (fullUrl.includes(brand) && !registrable.startsWith(brand)) {
      return brand;
    }
  }
  return null;
}

// ─── Main Analyzer ───────────────────────────────────────────────────────────

function analyzeUrl(url) {
  let score = 0;
  const findings = [];

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return {
      score: 100,
      label: "High Risk",
      labelClass: "high",
      findings: [{ title: "Invalid URL", detail: "Could not parse this URL — treat it with caution.", severity: "high" }],
      summary: "This URL could not be read correctly, which itself can be a sign of an obfuscated or malformed link."
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = url.toLowerCase();
  const registrable = getRegistrableDomain(hostname);
  const tld = getTld(hostname);
  const domainLabel = registrable.split(".")[0]; // just the name part before TLD

  // ── Protocol ──────────────────────────────────────────────────────────────
  if (parsed.protocol !== "https:") {
    score += 15;
    findings.push({
      title: "Not using HTTPS",
      detail: "The connection is not encrypted. Any data sent to this site could be intercepted.",
      severity: "medium"
    });
  }

  // ── Raw IP address ────────────────────────────────────────────────────────
  if (isIpv4(hostname)) {
    score += 30;
    findings.push({
      title: "IP address instead of domain name",
      detail: "Legitimate services almost never use raw IP addresses. This is a common phishing tactic to avoid having a recognisable domain.",
      severity: "high"
    });
  }

  // ── @ symbol ──────────────────────────────────────────────────────────────
  if (fullUrl.includes("@")) {
    score += 25;
    findings.push({
      title: "Contains @ symbol",
      detail: "The @ character in a URL causes browsers to ignore everything before it. It's a classic trick to make a malicious URL look like it points somewhere legitimate.",
      severity: "high"
    });
  }

  // ── Punycode / IDN ────────────────────────────────────────────────────────
  if (hostname.includes("xn--")) {
    score += 25;
    findings.push({
      title: "Punycode / internationalised domain",
      detail: "Punycode (xn--) is used to represent non-ASCII characters in domain names. It's a known technique for lookalike domains — e.g. 'аpple.com' using a Cyrillic 'а'.",
      severity: "high"
    });
  }

  // ── Homoglyph characters ──────────────────────────────────────────────────
  if (hasHomoglyphs(hostname)) {
    score += 30;
    findings.push({
      title: "Non-Latin or lookalike characters in domain",
      detail: "The domain contains characters from a non-Latin script or full-width characters. These are used in homograph attacks to impersonate well-known domains visually.",
      severity: "high"
    });
  }

  // ── Brand impersonation ───────────────────────────────────────────────────
  const impersonated = containsImpersonation(hostname, fullUrl);
  if (impersonated) {
    score += 35;
    findings.push({
      title: `Possible brand impersonation (${impersonated})`,
      detail: `The word "${impersonated}" appears in the URL, but the actual domain is "${registrable}". Phishing sites often include a trusted brand name in the path or subdomain to appear legitimate.`,
      severity: "high"
    });
  }

  // ── Suspicious TLD ────────────────────────────────────────────────────────
  if (SUSPICIOUS_TLDS.includes(tld)) {
    score += 20;
    findings.push({
      title: `High-risk TLD (.${tld})`,
      detail: `.${tld} is frequently used in phishing and spam campaigns due to low or zero registration costs and minimal verification requirements.`,
      severity: "medium"
    });
  }

  // ── Domain entropy (randomness) ───────────────────────────────────────────
  const entropy = shannonEntropy(domainLabel);
  if (entropy > 3.8 && domainLabel.length > 8) {
    score += 20;
    findings.push({
      title: "Domain name looks randomly generated",
      detail: `"${registrable}" has a high character entropy (${entropy.toFixed(2)}), which is typical of algorithmically generated domains used in phishing or malware campaigns.`,
      severity: "medium"
    });
  }

  // ── Subdomain depth ───────────────────────────────────────────────────────
  const subdomainCount = hostname.split(".").length - registrable.split(".").length;
  if (subdomainCount >= 3) {
    score += 15;
    findings.push({
      title: `Excessive subdomains (${subdomainCount})`,
      detail: "A deep subdomain chain is sometimes used to bury the real domain and make a fake URL look more convincing at first glance.",
      severity: "medium"
    });
  } else if (subdomainCount === 2) {
    score += 5;
  }

  // ── URL length ────────────────────────────────────────────────────────────
  if (url.length >= 150) {
    score += 15;
    findings.push({
      title: "Extremely long URL",
      detail: `This URL is ${url.length} characters long. Very long URLs are often used to hide the real destination in a flood of noise, or to encode obfuscated payloads.`,
      severity: "medium"
    });
  } else if (url.length >= 100) {
    score += 8;
    findings.push({
      title: "Long URL",
      detail: `This URL is ${url.length} characters. Longer than typical — worth checking the domain carefully.`,
      severity: "low"
    });
  }

  // ── Hyphen count ──────────────────────────────────────────────────────────
  const hyphens = (hostname.match(/-/g) || []).length;
  if (hyphens >= 4) {
    score += 15;
    findings.push({
      title: `Many hyphens in domain (${hyphens})`,
      detail: "Domains with many hyphens are rarely legitimate. Attackers use them to string together keywords that imitate real service names.",
      severity: "medium"
    });
  } else if (hyphens >= 2) {
    score += 5;
  }

  // ── URL shortener ─────────────────────────────────────────────────────────
  if (URL_SHORTENERS.includes(hostname)) {
    score += 20;
    findings.push({
      title: "Link shortener detected",
      detail: `${hostname} is a URL shortening service. These mask the real destination — the actual URL could point anywhere.`,
      severity: "medium"
    });
  }

  // ── Suspicious keywords ───────────────────────────────────────────────────
  // Only flag keywords found in the domain/path, and weight by where they appear
  const pathAndDomain = hostname + parsed.pathname;
  const matchedWords = SUSPICIOUS_KEYWORDS.filter(w => pathAndDomain.includes(w));

  // Extra weight if keywords appear in the domain itself (not just path)
  const domainKeywords = SUSPICIOUS_KEYWORDS.filter(w => hostname.includes(w));
  const pathKeywords = matchedWords.filter(w => !domainKeywords.includes(w));

  if (domainKeywords.length > 0) {
    score += domainKeywords.length * 10;
    findings.push({
      title: "Suspicious keywords in domain name",
      detail: `Found in the domain itself: ${domainKeywords.join(", ")}. Legitimate services put these words in their path, not their domain name.`,
      severity: "high"
    });
  }

  if (pathKeywords.length > 0) {
    score += pathKeywords.length * 4;
    findings.push({
      title: "Suspicious keywords in URL path",
      detail: `Found: ${pathKeywords.join(", ")}. These words are commonly used in phishing page paths.`,
      severity: "low"
    });
  }

  // ── Double-slash tricks ───────────────────────────────────────────────────
  if (parsed.pathname.includes("//")) {
    score += 10;
    findings.push({
      title: "Double slash in path",
      detail: "Redundant slashes in a URL path can sometimes be used to confuse URL parsers or hide the actual destination.",
      severity: "low"
    });
  }

  // ── Data URI ──────────────────────────────────────────────────────────────
  if (url.startsWith("data:")) {
    score += 40;
    findings.push({
      title: "Data URI detected",
      detail: "Data URIs embed content directly in the URL and are sometimes used to host phishing pages without a traditional web server.",
      severity: "high"
    });
  }

  // ── Nothing found ─────────────────────────────────────────────────────────
  if (findings.length === 0) {
    findings.push({
      title: "No obvious warning signs",
      detail: "No common phishing indicators were detected. This does not guarantee the site is safe — sophisticated attacks may not trigger heuristic checks.",
      severity: "info"
    });
  }

  // ── Clamp score ───────────────────────────────────────────────────────────
  score = Math.min(score, 100);

  let label, labelClass, summary;

  if (score >= 65) {
    label = "High Risk";
    labelClass = "high";
    summary = "Multiple indicators of a potentially malicious URL were found. Treat this link with significant caution.";
  } else if (score >= 30) {
    label = "Medium Risk";
    labelClass = "medium";
    summary = "Some suspicious characteristics were detected. Check the domain carefully before proceeding.";
  } else {
    label = "Low Risk";
    labelClass = "low";
    summary = "No major phishing indicators detected, but heuristics alone cannot guarantee a site is safe.";
  }

  return { score, label, labelClass, findings, summary };
}
