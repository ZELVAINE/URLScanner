function analyzeUrl(url) {
  let score = 0;
  let findings = [];

  let parsedUrl;

  try {
    parsedUrl = new URL(url);
  } catch (error) {
    return {
      score: 100,
      label: "High risk",
      labelClass: "high",
      findings: [
        {
          title: "Invalid URL",
          detail: "The extension could not properly read this URL, so it should be treated carefully."
        }
      ],
      summary: "The URL could not be parsed correctly, which can sometimes happen with unusual or misleading links."
    };
  }

  let hostname = parsedUrl.hostname.toLowerCase();
  let fullUrl = url.toLowerCase();

  // check if the page is not https
  if (parsedUrl.protocol !== "https:") {
    score += 10;
    findings.push({
      title: "Not using HTTPS",
      detail: "This page is not using HTTPS, so the connection may be less trustworthy."
    });
  }

  // check if the host is just an ipv4 address
  if (isIpv4Address(hostname)) {
    score += 25;
    findings.push({
      title: "Uses an IP address instead of a normal domain",
      detail: "Phishing sites sometimes use raw IP addresses to avoid using a recognisable domain name."
    });
  }

  // check for @ symbol because it can hide the real destination
  if (fullUrl.includes("@")) {
    score += 20;
    findings.push({
      title: "Contains @ symbol",
      detail: "The @ symbol can be used in misleading URLs to hide where the link really goes."
    });
  }

  // punycode can sometimes be used for lookalike domains
  if (hostname.includes("xn--")) {
    score += 20;
    findings.push({
      title: "Contains punycode",
      detail: "Punycode is not always malicious, but it can be used for lookalike domain tricks."
    });
  }

  let subdomainCount = countSubdomains(hostname);
  if (subdomainCount >= 3) {
    score += 15;
    findings.push({
      title: "Has a lot of subdomains",
      detail: "A large number of subdomains can be used to make a fake site look more convincing."
    });
  }

  if (url.length >= 100) {
    score += 10;
    findings.push({
      title: "Very long URL",
      detail: "Long URLs can hide suspicious parts and make the full link harder to inspect."
    });
  }

  if (countHyphens(hostname) >= 3) {
    score += 10;
    findings.push({
      title: "Many hyphens in the domain",
      detail: "Some scam or phishing domains use a lot of hyphens to imitate real names."
    });
  }

  if (isKnownShortener(hostname)) {
    score += 15;
    findings.push({
      title: "Uses a shortened link service",
      detail: "Shortened links hide the final destination, so they need extra caution."
    });
  }

  let suspiciousWords = findSuspiciousWords(fullUrl);
  if (suspiciousWords.length > 0) {
    score += suspiciousWords.length * 5;

    if (score > 100) {
      score = 100;
    }

    findings.push({
      title: "Contains suspicious keywords",
      detail: "Found words often seen in phishing links: " + suspiciousWords.join(", ")
    });
  }

  // if nothing strange was found
  if (findings.length === 0) {
    findings.push({
      title: "No major warning signs found",
      detail: "This does not prove the site is safe. It only means obvious suspicious patterns were not detected."
    });
  }

  if (score > 100) {
    score = 100;
  }

  let label = "";
  let labelClass = "";
  let summary = "";

  if (score >= 70) {
    label = "High risk";
    labelClass = "high";
    summary = "This URL has several patterns that are often associated with phishing or misleading links.";
  } else if (score >= 35) {
    label = "Medium risk";
    labelClass = "medium";
    summary = "This URL has some suspicious characteristics and should be checked carefully before trusting it.";
  } else {
    label = "Low risk";
    labelClass = "low";
    summary = "This URL does not show many obvious phishing-style signs, but that still does not guarantee safety.";
  }

  return {
    score: score,
    label: label,
    labelClass: labelClass,
    findings: findings,
    summary: summary
  };
}

function isIpv4Address(hostname) {
  let parts = hostname.split(".");

  if (parts.length !== 4) {
    return false;
  }

  for (let i = 0; i < parts.length; i++) {
    let part = parts[i];

    if (part === "" || isNaN(part)) {
      return false;
    }

    let number = Number(part);

    if (number < 0 || number > 255) {
      return false;
    }
  }

  return true;
}

function countSubdomains(hostname) {
  let parts = hostname.split(".");

  if (parts.length <= 2) {
    return 0;
  }

  return parts.length - 2;
}

function countHyphens(hostname) {
  let matches = hostname.match(/-/g);

  if (!matches) {
    return 0;
  }

  return matches.length;
}

function isKnownShortener(hostname) {
  let shorteners = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "tiny.cc"
  ];

  for (let i = 0; i < shorteners.length; i++) {
    if (hostname === shorteners[i]) {
      return true;
    }
  }

  return false;
}

function findSuspiciousWords(url) {
  let suspiciousList = [
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "bank",
    "signin",
    "confirm",
    "password",
    "wallet",
    "billing",
    "invoice"
  ];

  let matches = [];

  for (let i = 0; i < suspiciousList.length; i++) {
    if (url.includes(suspiciousList[i])) {
      matches.push(suspiciousList[i]);
    }
  }

  return matches;
}
