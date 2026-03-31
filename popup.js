async function loadCurrentTabInfo() {
  let urlText = document.getElementById("url-text");
  let riskScore = document.getElementById("risk-score");
  let riskLabel = document.getElementById("risk-label");
  let riskBar = document.getElementById("risk-bar");
  let findingsList = document.getElementById("findings-list");
  let summaryText = document.getElementById("summary-text");

  try {
    let tabs = await browser.tabs.query({
      active: true,
      currentWindow: true
    });

    if (!tabs || tabs.length === 0) {
      showErrorState("Could not find an active tab.");
      return;
    }

    let currentTab = tabs[0];

    if (!currentTab.url) {
      showErrorState("This tab does not have a readable URL.");
      return;
    }

    if (
      currentTab.url.startsWith("about:") ||
      currentTab.url.startsWith("moz-extension:") ||
      currentTab.url.startsWith("chrome:")
    ) {
      showErrorState("Firefox does not allow this kind of page to be analyzed.");
      return;
    }

    let result = analyzeUrl(currentTab.url);

    urlText.textContent = currentTab.url;
    riskScore.textContent = result.score;
    riskLabel.textContent = result.label;
    riskLabel.className = "risk-label " + result.labelClass;
    riskBar.style.width = result.score + "%";
    summaryText.textContent = result.summary;

    findingsList.innerHTML = "";

    for (let i = 0; i < result.findings.length; i++) {
      let finding = result.findings[i];

      let li = document.createElement("li");

      let title = document.createElement("strong");
      title.textContent = finding.title;

      let detail = document.createElement("span");
      detail.textContent = finding.detail;
      detail.className = "finding-detail";

      li.appendChild(title);
      li.appendChild(detail);

      findingsList.appendChild(li);
    }
  } catch (error) {
    showErrorState("Something went wrong while trying to analyze this tab.");
    console.error(error);
  }
}

function showErrorState(message) {
  let urlText = document.getElementById("url-text");
  let riskScore = document.getElementById("risk-score");
  let riskLabel = document.getElementById("risk-label");
  let riskBar = document.getElementById("risk-bar");
  let findingsList = document.getElementById("findings-list");
  let summaryText = document.getElementById("summary-text");

  urlText.textContent = message;
  riskScore.textContent = "--";
  riskLabel.textContent = "Unavailable";
  riskLabel.className = "risk-label neutral";
  riskBar.style.width = "0%";

  findingsList.innerHTML = "";
  let li = document.createElement("li");
  li.textContent = "Could not analyze this page.";
  findingsList.appendChild(li);

  summaryText.textContent = "Try opening a normal website and then click the extension again.";
}

loadCurrentTabInfo();
