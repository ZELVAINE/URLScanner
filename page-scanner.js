// page-scanner.js — injected into the active tab to collect all links

(function () {
  const anchors = document.querySelectorAll("a[href]");
  const links = [];

  for (const a of anchors) {
    const href = a.href;
    if (href && (href.startsWith("http://") || href.startsWith("https://") || href.startsWith("data:"))) {
      const text = (a.textContent || "").trim().slice(0, 80);
      links.push({ href, text });
    }
  }

  // Deduplicate by href
  const seen = new Set();
  const unique = [];
  for (const link of links) {
    if (!seen.has(link.href)) {
      seen.add(link.href);
      unique.push(link);
    }
  }

  return unique.slice(0, 100); // cap at 100 links
})();
