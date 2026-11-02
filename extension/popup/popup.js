// Popup: what Provenza knows about this page, whether the extension reports,
// and - unless the organization manages it - the server and key to report to.

const STATUS_TEXT = {
  blocked: ["⛔ ", " - not allowed in your organization", "#dc2626"],
  allowed: ["✓ ", " - approved by your organization", "#059669"],
  unknown: ["● ", " - AI service, not reviewed yet", "#d97706"]
};

function when(iso) {
  return iso ? new Date(iso).toLocaleString() : "never";
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  let host = "";
  try {
    host = tabs && tabs[0] && tabs[0].url ? new URL(tabs[0].url).hostname : "";
  } catch (e) {
    host = "";
  }
  chrome.runtime.sendMessage({ action: "status", host }, (s) => {
    if (!s) return;
    const tab = document.getElementById("current-tab-status");
    if (!host) {
      tab.textContent = "No web page";
    } else if (s.lookup) {
      const [mark, tail, color] = STATUS_TEXT[s.lookup.status] || STATUS_TEXT.unknown;
      tab.textContent = mark + s.lookup.name + tail;
      tab.style.color = color;
    } else {
      tab.textContent = "Not an AI service (" + host + ")";
      tab.style.color = "#64748b";
    }

    const conf = document.getElementById("config-state");
    conf.textContent = s.configured
      ? "✓ Reporting to " + new URL(s.apiUrl).host + (s.queued ? " (" + s.queued + " waiting)" : "")
      : "✗ Not configured — enter the server and ingestion key below";
    conf.className = "config-state " + (s.configured ? "config-ok" : "config-missing");

    const cat = document.getElementById("catalog-state");
    cat.textContent = s.catalogError
      ? "AI service list: could not refresh (" + s.catalogError + ")"
      : s.catalog.count + " AI services watched, " + s.catalog.blocked + " blocked · updated " + when(s.catalog.fetchedAt);

    document.getElementById("settings").hidden = s.managed;
    document.getElementById("managed-note").hidden = !s.managed;
  });
});

const apiUrlInput = document.getElementById("api-url");
const keyInput = document.getElementById("ingestion-key");
const saveStatus = document.getElementById("save-status");

chrome.storage.local.get(["apiUrl"], (stored) => {
  if (stored.apiUrl) apiUrlInput.value = stored.apiUrl;
});

document.getElementById("save-btn").addEventListener("click", () => {
  const apiUrl = apiUrlInput.value.trim();
  const ingestionKey = keyInput.value.trim();
  if (!apiUrl || !ingestionKey) {
    saveStatus.textContent = "Both fields are required.";
    return;
  }
  chrome.storage.local.set({ apiUrl, ingestionKey }, () => {
    keyInput.value = "";
    saveStatus.textContent = "Saved. Loading the AI service list…";
    chrome.runtime.sendMessage({ action: "configured" }, () => {
      saveStatus.textContent = "Saved.";
      window.location.reload();
    });
  });
});
