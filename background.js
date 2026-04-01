// background.js — service worker for API calls that can't be made from the popup directly

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "VT_LOOKUP") {
    handleVirusTotalLookup(message.url, message.apiKey)
      .then(result => sendResponse({ ok: true, data: result }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true; // keep channel open for async response
  }

  if (message.type === "WHOIS_LOOKUP") {
    handleWhoisLookup(message.domain)
      .then(result => sendResponse({ ok: true, data: result }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }
});

async function handleVirusTotalLookup(url, apiKey) {
  // Submit URL to VirusTotal
  const encoded = btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const vtUrl = `https://www.virustotal.com/api/v3/urls/${encoded}`;

  const res = await fetch(vtUrl, {
    headers: { "x-apikey": apiKey }
  });

  if (res.status === 404) {
    // URL not in VT database — submit it
    await submitUrlToVt(url, apiKey);
    return { status: "submitted", message: "URL submitted to VirusTotal for the first time. Results may take a moment." };
  }

  if (!res.ok) {
    if (res.status === 401) throw new Error("Invalid VirusTotal API key.");
    if (res.status === 429) throw new Error("VirusTotal rate limit reached. Try again in a minute.");
    throw new Error(`VirusTotal returned status ${res.status}.`);
  }

  const data = await res.json();
  const stats = data?.data?.attributes?.last_analysis_stats;
  const votes = data?.data?.attributes?.total_votes;
  const categories = data?.data?.attributes?.categories || {};
  const reputation = data?.data?.attributes?.reputation ?? null;

  if (!stats) throw new Error("Unexpected response from VirusTotal.");

  return {
    status: "found",
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    clean: stats.undetected || 0,
    harmless: stats.harmless || 0,
    total: Object.values(stats).reduce((a, b) => a + b, 0),
    reputation,
    votes,
    categories: Object.values(categories).slice(0, 3)
  };
}

async function submitUrlToVt(url, apiKey) {
  const body = new URLSearchParams({ url });
  await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: {
      "x-apikey": apiKey,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });
}

async function handleWhoisLookup(domain) {
  // Use the free whois.freeaiapi.com endpoint — no key needed
  const res = await fetch(`https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName=${encodeURIComponent(domain)}&apiKey=free`);

  // Fallback: use rdap (ICANN's open protocol, no key needed)
  // rdap is the modern replacement for whois and has a public HTTPS API
  const rdapRes = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);

  if (!rdapRes.ok) {
    return { available: false, age: null, message: "Domain age lookup unavailable." };
  }

  const rdap = await rdapRes.json();

  // Find creation date from events array
  const events = rdap.events || [];
  const registrationEvent = events.find(e => e.eventAction === "registration");
  const expirationEvent = events.find(e => e.eventAction === "expiration");

  if (!registrationEvent) {
    return { available: false, age: null, registrar: null };
  }

  const created = new Date(registrationEvent.eventDate);
  const now = new Date();
  const ageInDays = Math.floor((now - created) / (1000 * 60 * 60 * 24));

  const registrar = rdap.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]
    ?.find(v => v[0] === "fn")?.[3] || null;

  return {
    available: false,
    ageInDays,
    created: created.toISOString().split("T")[0],
    expiration: expirationEvent ? new Date(expirationEvent.eventDate).toISOString().split("T")[0] : null,
    registrar
  };
}
