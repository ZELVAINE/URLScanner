// popup.js

// ─── State ────────────────────────────────────────────────────────────────────

let currentTab = null;
let currentResult = null;
let vtApiKey = null;
let activeView = "scan"; // "scan" | "links" | "settings"

// ─── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  vtApiKey = await Settings.getApiKey();

  setupNavigation();
  setupSettingsPanel();
  await runCurrentTabScan();
});

// ─── Navigation ───────────────────────────────────────────────────────────────

function setupNavigation() {
  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const view = btn.dataset.view;
      switchView(view);
    });
  });
}

function switchView(view) {
  activeView = view;

  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.view === view);
  });

  document.querySelectorAll(".view").forEach(v => {
    v.classList.toggle("hidden", v.id !== `view-${view}`);
  });

  if (view === "links" && currentTab) {
    runPageLinkScan();
  }
}

// ─── Current URL scan ─────────────────────────────────────────────────────────

async function runCurrentTabScan() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tabs || tabs.length === 0) return showScanError("Could not find active tab.");

  currentTab = tabs[0];
  const url = currentTab.url;

  if (!url || url.startsWith("about:") || url.startsWith("moz-extension:") || url.startsWith("chrome:")) {
    return showScanError("This type of page cannot be analysed.");
  }

  // Run heuristic analysis immediately
  currentResult = analyzeUrl(url);
  renderScanResult(url, currentResult);

  // Then optionally run VT + WHOIS in background
  if (vtApiKey) {
    runExternalLookups(url, currentResult);
  } else {
    showVtPrompt();
  }
}

function renderScanResult(url, result) {
  // URL display
  const urlEl = document.getElementById("url-display");
  try {
    const parsed = new URL(url);
    urlEl.innerHTML = `<span class="url-scheme">${parsed.protocol}//</span><span class="url-host">${parsed.hostname}</span><span class="url-path">${parsed.pathname}${parsed.search}</span>`;
  } catch {
    urlEl.textContent = url;
  }

  // Score gauge
  const scoreEl = document.getElementById("score-value");
  const gaugeEl = document.getElementById("gauge-fill");
  const labelEl = document.getElementById("risk-label");
  const summaryEl = document.getElementById("summary-text");

  scoreEl.textContent = result.score;
  scoreEl.className = `score-number ${result.labelClass}`;
  gaugeEl.style.width = result.score + "%";
  gaugeEl.className = `gauge-fill ${result.labelClass}`;
  labelEl.textContent = result.label;
  labelEl.className = `risk-label ${result.labelClass}`;
  summaryEl.textContent = result.summary;

  // Findings
  renderFindings(result.findings, "findings-list");
}

function renderFindings(findings, containerId) {
  const list = document.getElementById(containerId);
  list.innerHTML = "";

  for (const f of findings) {
    const item = document.createElement("div");
    item.className = `finding-item ${f.severity || "info"}`;

    const icon = severityIcon(f.severity);
    item.innerHTML = `
      <div class="finding-header">
        <span class="finding-icon">${icon}</span>
        <span class="finding-title">${f.title}</span>
      </div>
      <p class="finding-detail">${f.detail}</p>
    `;
    list.appendChild(item);
  }
}

function severityIcon(severity) {
  switch (severity) {
    case "high":   return "⛔";
    case "medium": return "⚠️";
    case "low":    return "🔎";
    default:       return "✅";
  }
}

function showScanError(message) {
  document.getElementById("url-display").textContent = message;
  document.getElementById("score-value").textContent = "--";
  document.getElementById("risk-label").textContent = "Unavailable";
}

// ─── External lookups (VT + WHOIS) ───────────────────────────────────────────

async function runExternalLookups(url, heuristicResult) {
  const externalSection = document.getElementById("external-section");
  externalSection.classList.remove("hidden");

  // WHOIS / domain age
  try {
    const hostname = new URL(url).hostname;
    document.getElementById("whois-status").textContent = "Checking domain age...";

    const whoisResp = await browser.runtime.sendMessage({ type: "WHOIS_LOOKUP", domain: hostname });

    if (whoisResp.ok && whoisResp.data.ageInDays !== null) {
      const age = whoisResp.data.ageInDays;
      const ageText = age < 30 ? `${age} days old` : age < 365 ? `${Math.floor(age / 30)} months old` : `${Math.floor(age / 365)} years old`;
      const registrar = whoisResp.data.registrar ? ` · ${whoisResp.data.registrar}` : "";

      let ageWarning = "";
      if (age < 14) {
        ageWarning = " — ⚠️ Very recently registered";
      } else if (age < 60) {
        ageWarning = " — Recently registered";
      }

      document.getElementById("whois-status").innerHTML =
        `<span class="whois-age ${age < 60 ? "whois-new" : "whois-ok"}">Domain registered ${ageText}${ageWarning}${registrar}</span>`;

      if (age < 30) {
        document.getElementById("findings-list").prepend(createNewDomainFinding(age));
      }
    } else {
      document.getElementById("whois-status").textContent = whoisResp.data?.message || "Domain age unavailable.";
    }
  } catch (e) {
    document.getElementById("whois-status").textContent = "Domain age lookup failed.";
  }

  // VirusTotal
  const vtEl = document.getElementById("vt-status");
  vtEl.textContent = "Checking VirusTotal...";

  try {
    const vtResp = await browser.runtime.sendMessage({ type: "VT_LOOKUP", url, apiKey: vtApiKey });

    if (!vtResp.ok) {
      vtEl.textContent = vtResp.error || "VirusTotal lookup failed.";
      return;
    }

    const vt = vtResp.data;

    if (vt.status === "submitted") {
      vtEl.textContent = "Submitted to VirusTotal — not yet in database.";
      return;
    }

    const { malicious, suspicious, clean, total } = vt;
    const flagged = malicious + suspicious;

    let vtClass = "vt-clean";
    if (malicious > 0) vtClass = "vt-malicious";
    else if (suspicious > 0) vtClass = "vt-suspicious";

    vtEl.innerHTML = `
      <span class="vt-result ${vtClass}">
        VirusTotal: ${flagged}/${total} engines flagged this URL
        ${vt.reputation !== null ? ` · Reputation score: ${vt.reputation}` : ""}
      </span>
    `;

    if (malicious > 0 || suspicious > 0) {
      document.getElementById("findings-list").prepend(createVtFinding(malicious, suspicious, total));
    }
  } catch (e) {
    vtEl.textContent = "VirusTotal lookup failed.";
  }
}

function createNewDomainFinding(age) {
  const item = document.createElement("div");
  item.className = "finding-item high";
  item.innerHTML = `
    <div class="finding-header">
      <span class="finding-icon">⛔</span>
      <span class="finding-title">Very recently registered domain (${age} days ago)</span>
    </div>
    <p class="finding-detail">Domain age is one of the strongest phishing indicators. Legitimate services have established domains — attackers register new ones for each campaign.</p>
  `;
  return item;
}

function createVtFinding(malicious, suspicious, total) {
  const item = document.createElement("div");
  item.className = `finding-item ${malicious > 0 ? "high" : "medium"}`;
  item.innerHTML = `
    <div class="finding-header">
      <span class="finding-icon">${malicious > 0 ? "⛔" : "⚠️"}</span>
      <span class="finding-title">VirusTotal: ${malicious + suspicious} of ${total} engines flagged this URL</span>
    </div>
    <p class="finding-detail">${malicious > 0
      ? `${malicious} security vendor${malicious > 1 ? "s" : ""} classify this URL as malicious.`
      : `${suspicious} vendor${suspicious > 1 ? "s" : ""} flagged this URL as suspicious.`
    } View the full report on VirusTotal for details.</p>
  `;
  return item;
}

function showVtPrompt() {
  const externalSection = document.getElementById("external-section");
  externalSection.classList.remove("hidden");
  document.getElementById("whois-status").textContent = "Checking domain age...";

  // Still do WHOIS (no key needed)
  if (currentTab) {
    try {
      const hostname = new URL(currentTab.url).hostname;
      browser.runtime.sendMessage({ type: "WHOIS_LOOKUP", domain: hostname }).then(resp => {
        if (resp.ok && resp.data.ageInDays !== null) {
          const age = resp.data.ageInDays;
          const ageText = age < 30 ? `${age} days` : age < 365 ? `${Math.floor(age / 30)} months` : `${Math.floor(age / 365)} years`;
          document.getElementById("whois-status").innerHTML =
            `<span class="whois-age ${age < 60 ? "whois-new" : "whois-ok"}">Domain registered ${ageText} ago</span>`;
        } else {
          document.getElementById("whois-status").textContent = "Domain age unavailable.";
        }
      });
    } catch {}
  }

  document.getElementById("vt-status").innerHTML =
    `<span class="vt-prompt">Add a VirusTotal API key in <button class="inline-link" id="vt-settings-link">Settings</button> for live threat intelligence.</span>`;

  document.getElementById("vt-settings-link")?.addEventListener("click", () => switchView("settings"));
}

// ─── Page link scan ───────────────────────────────────────────────────────────

async function runPageLinkScan() {
  const container = document.getElementById("links-container");

  if (!currentTab) {
    container.textContent = "No active tab.";
    return;
  }

  container.innerHTML = `<p class="loading-text">Scanning links on page...</p>`;

  let links;
  try {
    const results = await browser.scripting.executeScript({
      target: { tabId: currentTab.id },
      files: ["page-scanner.js"]
    });
    links = results?.[0]?.result;
  } catch (e) {
    container.innerHTML = `<p class="scan-error">Could not scan page links. This page may restrict script injection.</p>`;
    return;
  }

  if (!links || links.length === 0) {
    container.innerHTML = `<p class="scan-error">No external links found on this page.</p>`;
    return;
  }

  // Analyse all links
  const analysed = links.map(link => ({
    ...link,
    result: analyzeUrl(link.href)
  }));

  // Sort: high risk first
  analysed.sort((a, b) => b.result.score - a.result.score);

  const highCount = analysed.filter(l => l.result.score >= 65).length;
  const medCount = analysed.filter(l => l.result.score >= 30 && l.result.score < 65).length;

  container.innerHTML = `
    <div class="links-summary">
      Found <strong>${links.length}</strong> unique links —
      <span class="high">${highCount} high risk</span>,
      <span class="medium">${medCount} medium risk</span>,
      ${links.length - highCount - medCount} low risk
    </div>
  `;

  for (const link of analysed) {
    const item = document.createElement("div");
    item.className = `link-item ${link.result.labelClass}`;

    let displayHref = link.href;
    try {
      const p = new URL(link.href);
      displayHref = p.hostname + p.pathname.slice(0, 40) + (p.pathname.length > 40 ? "…" : "");
    } catch {}

    item.innerHTML = `
      <div class="link-item-header">
        <span class="link-score-badge ${link.result.labelClass}">${link.result.score}</span>
        <span class="link-url">${displayHref}</span>
      </div>
      ${link.text ? `<span class="link-text-label">"${link.text}"</span>` : ""}
    `;

    item.addEventListener("click", () => {
      const existing = item.querySelector(".link-findings");
      if (existing) {
        existing.remove();
        return;
      }
      const details = document.createElement("div");
      details.className = "link-findings";
      for (const f of link.result.findings) {
        const row = document.createElement("div");
        row.className = `link-finding-row ${f.severity || "info"}`;
        row.textContent = `${severityIcon(f.severity)} ${f.title}`;
        details.appendChild(row);
      }
      item.appendChild(details);
    });

    container.appendChild(item);
  }
}

// ─── Settings panel ───────────────────────────────────────────────────────────

function setupSettingsPanel() {
  const keyInput = document.getElementById("vt-key-input");
  const saveBtn = document.getElementById("save-key-btn");
  const clearBtn = document.getElementById("clear-key-btn");
  const statusEl = document.getElementById("key-status");

  if (vtApiKey) {
    keyInput.value = "•".repeat(20);
    keyInput.dataset.saved = "true";
    statusEl.textContent = "API key saved.";
    statusEl.className = "key-status ok";
  }

  keyInput.addEventListener("focus", () => {
    if (keyInput.dataset.saved === "true") {
      keyInput.value = "";
      keyInput.dataset.saved = "false";
    }
  });

  saveBtn.addEventListener("click", async () => {
    const key = keyInput.value.trim();
    if (!key) return;
    await Settings.setApiKey(key);
    vtApiKey = key;
    keyInput.value = "•".repeat(20);
    keyInput.dataset.saved = "true";
    statusEl.textContent = "API key saved.";
    statusEl.className = "key-status ok";
  });

  clearBtn.addEventListener("click", async () => {
    await Settings.clearApiKey();
    vtApiKey = null;
    keyInput.value = "";
    keyInput.dataset.saved = "false";
    statusEl.textContent = "API key cleared.";
    statusEl.className = "key-status neutral";
  });
}
