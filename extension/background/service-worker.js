// Provenza browser extension - background service worker (2.0).
//
//   - keeps the organization's AI domain catalog (server, hourly) and acts on it:
//       blocked  -> the page is replaced by blocked/blocked.html (a network rule)
//       allowed / unknown -> the visit is reported; the secret-paste warning
//                            runs on the page
//   - reports visits to Provenza in batches (domain_visit events, host only -
//     never a full URL), keeping unsent events across worker restarts and
//     retrying when the server cannot be reached
//
// Configuration, first found wins:
//   1. managed by the organization (Chrome / Edge policy, managed_schema.json):
//      serverUrl + ingestionKey - the user cannot change or remove it;
//   2. baked in by the server's download (/shadow-ai/extension/download);
//   3. set by hand in the popup.
// The defaults below are inert placeholders, so a raw checkout never carries a
// working key.

importScripts("../shared/domains.js");

const PLACEHOLDER_CONFIG = {
  apiUrl: "http://localhost:8000/api/v1/shadow-ai/ingest",
  ingestionKey: "" // intentionally empty - see note above
};

const INGEST_PATH = "/api/v1/shadow-ai/ingest";
const CATALOG_EVERY_MIN = 60;
const FLUSH_DELAY_MS = 5000;
const BATCH_MAX = 25;
const QUEUE_MAX = 500;
const CONTENT_SCRIPT_ID = "provenza-secret-warning";

// ---------------------------------------------------------------- config

async function managedConfig() {
  try {
    return (await chrome.storage.managed.get(["serverUrl", "ingestionKey"])) || {};
  } catch (e) {
    return {}; // no policy on this browser
  }
}

async function getConfig() {
  const managed = await managedConfig();
  if (managed.serverUrl && managed.ingestionKey) {
    return {
      apiUrl: managed.serverUrl.replace(/\/+$/, "") + INGEST_PATH,
      ingestionKey: managed.ingestionKey,
      managed: true
    };
  }
  const stored = await chrome.storage.local.get(["apiUrl", "ingestionKey"]);
  return {
    apiUrl: stored.apiUrl || PLACEHOLDER_CONFIG.apiUrl,
    ingestionKey: stored.ingestionKey || PLACEHOLDER_CONFIG.ingestionKey,
    managed: false
  };
}

function catalogUrl(apiUrl) {
  return apiUrl.replace(/\/ingest\/?$/, "/extension/catalog");
}

// One id per browser install, so a browser is one reporter across restarts.
async function getAgentId() {
  const { agentId } = await chrome.storage.local.get("agentId");
  if (agentId) return agentId;
  const fresh = "browser-ext-" + crypto.randomUUID();
  await chrome.storage.local.set({ agentId: fresh });
  return fresh;
}

// ---------------------------------------------------------------- catalog

async function getCatalog() {
  const { catalog } = await chrome.storage.local.get("catalog");
  return catalog && Array.isArray(catalog.domains) ? catalog : { version: "", domains: BUILTIN_DOMAINS, fetchedAt: null };
}

async function syncCatalog() {
  const config = await getConfig();
  if (!config.ingestionKey) return;
  try {
    const response = await fetch(catalogUrl(config.apiUrl), { headers: { "X-Ingestion-Key": config.ingestionKey } });
    if (!response.ok) {
      await chrome.storage.local.set({ catalogError: "HTTP " + response.status });
      return;
    }
    const data = await response.json();
    const domains = (data.domains || []).filter((d) => d && isPlainDomain(d.domain));
    const previous = await getCatalog();
    await chrome.storage.local.set({
      catalog: { version: data.version || "", domains, fetchedAt: new Date().toISOString() },
      catalogError: null
    });
    if (previous.version !== data.version) await applyCatalog(domains);
  } catch (err) {
    await chrome.storage.local.set({ catalogError: "server unreachable" });
  }
}

// Blocked domains: a network rule replaces the page before it loads.
// The others: the secret-paste warning is injected into their pages.
// One application at a time: the rules and scripts are replaced as a whole,
// and two syncs at once (install + startup) would trip over each other.
let applying = Promise.resolve();

function applyCatalog(domains) {
  applying = applying.then(() => applyNow(domains)).catch((err) => console.warn("[Provenza] could not apply the list:", err));
  return applying;
}

async function applyNow(domains) {
  const blocked = domains.filter((d) => d.status === "blocked");
  const watched = domains.filter((d) => d.status !== "blocked");

  const old = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: old.map((r) => r.id),
    addRules: blocked.map((d, i) => ({
      id: i + 1,
      priority: 1,
      action: {
        type: "redirect",
        redirect: { extensionPath: "/blocked/blocked.html?d=" + encodeURIComponent(d.domain) }
      },
      condition: { requestDomains: [d.domain], resourceTypes: ["main_frame"] }
    }))
  });

  try {
    await chrome.scripting.unregisterContentScripts({ ids: [CONTENT_SCRIPT_ID] });
  } catch (e) {
    /* not registered yet */
  }
  const matches = watched.flatMap((d) => ["*://" + d.domain + "/*", "*://*." + d.domain + "/*"]);
  if (matches.length) {
    await chrome.scripting.registerContentScripts([{
      id: CONTENT_SCRIPT_ID,
      matches,
      js: ["shared/domains.js", "shared/scanner.js", "content/content-script.js"],
      runAt: "document_idle",
      persistAcrossSessions: true
    }]);
  }
}

// ---------------------------------------------------------------- reporting

// The queue lives in session storage: a worker torn down before it flushed
// (Manifest V3 does that often) does not lose what it had.
async function readQueue() {
  const { queue } = await chrome.storage.session.get("queue");
  return Array.isArray(queue) ? queue : [];
}

async function writeQueue(queue) {
  await chrome.storage.session.set({ queue: queue.slice(-QUEUE_MAX) });
}

let flushTimer = null;

async function enqueue(event) {
  const queue = await readQueue();
  queue.push(event);
  await writeQueue(queue);
  if (queue.length >= BATCH_MAX) flush();
  else if (!flushTimer) flushTimer = setTimeout(flush, FLUSH_DELAY_MS);
}

async function flush() {
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
  const queue = await readQueue();
  if (queue.length === 0) return;
  const config = await getConfig();
  if (!config.ingestionKey) return; // kept until the extension is configured

  const batch = queue.slice(0, BATCH_MAX);
  let response;
  try {
    response = await fetch(config.apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Ingestion-Key": config.ingestionKey },
      body: JSON.stringify({ events: batch })
    });
  } catch (err) {
    return; // offline: kept, retried by the "flush" alarm
  }
  // sent, or refused for good (a wrong key, a malformed event): either way off
  // the queue; only "try later" answers (429, 5xx) keep it
  if (response.ok || (response.status >= 400 && response.status < 500 && response.status !== 429)) {
    const rest = (await readQueue()).slice(batch.length);
    await writeQueue(rest);
    await chrome.storage.local.set({ lastReport: { at: new Date().toISOString(), status: response.status } });
    if (rest.length) flush();
  }
}

const RISK = { blocked: 0.9, unknown: 0.6, allowed: 0.2 };

async function reportVisit(host, entry, blocked) {
  enqueue({
    event_id: crypto.randomUUID(),
    event_type: "domain_visit",
    agent_id: await getAgentId(),
    domain: host,
    risk_score: RISK[blocked ? "blocked" : entry.status] ?? 0.6,
    action_taken: blocked ? "blocked" : "monitored",
    // the host only: a path or a query of an AI tool's URL can hold content
    payload: { tool_name: entry.name, category: entry.category },
    timestamp: new Date().toISOString()
  });
}

// One visit is one event: tabs.onUpdated fires "complete" more than once per
// navigation (subframes, history updates), so the last host per tab is kept.
const lastReportedHostByTab = {};

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab || !tab.url) return;
  let host;
  try {
    const url = new URL(tab.url);
    if (url.protocol !== "https:" && url.protocol !== "http:") return;
    host = url.hostname;
  } catch (e) {
    return;
  }
  const entry = lookupDomain(host, (await getCatalog()).domains);
  if (!entry) {
    delete lastReportedHostByTab[tabId];
    return;
  }
  if (lastReportedHostByTab[tabId] === host) return;
  lastReportedHostByTab[tabId] = host;
  reportVisit(host, entry, false);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete lastReportedHostByTab[tabId];
});

// ---------------------------------------------------------------- messages

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message) return false;
  // the blocked page: report the attempt, and tell it what is allowed instead
  if (message.action === "blocked_visit" && sender.url && sender.url.startsWith(chrome.runtime.getURL("blocked/"))) {
    getCatalog().then(async ({ domains }) => {
      const entry = lookupDomain(message.domain, domains);
      if (entry && entry.status === "blocked") await reportVisit(message.domain, entry, true);
      sendResponse({
        name: entry ? entry.name : message.domain,
        // what a person can open instead: approved services, not API hosts
        allowed: domains
          .filter((d) => d.status === "allowed" && d.category !== "api_provider" && !d.domain.startsWith("api."))
          .map((d) => ({ name: d.name, domain: d.domain }))
      });
    });
    return true; // answers asynchronously
  }
  if (message.action === "status") {
    Promise.all([getConfig(), getCatalog(), chrome.storage.local.get(["catalogError", "lastReport"]), readQueue()])
      .then(([config, catalog, extra, queue]) => sendResponse({
        managed: config.managed,
        configured: !!config.ingestionKey,
        apiUrl: config.apiUrl,
        catalog: { version: catalog.version, fetchedAt: catalog.fetchedAt, count: catalog.domains.length,
                   blocked: catalog.domains.filter((d) => d.status === "blocked").length },
        catalogError: extra.catalogError || null,
        lastReport: extra.lastReport || null,
        queued: queue.length,
        lookup: message.host ? lookupDomain(message.host, catalog.domains) : null
      }));
    return true;
  }
  if (message.action === "configured") {
    syncCatalog().then(() => sendResponse({ ok: true }));
    return true;
  }
  return false;
});

// ---------------------------------------------------------------- schedule

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "catalog") syncCatalog();
  if (alarm.name === "flush") flush();
});

async function start() {
  await chrome.alarms.create("catalog", { periodInMinutes: CATALOG_EVERY_MIN });
  await chrome.alarms.create("flush", { periodInMinutes: 1 });
  const { catalog } = await chrome.storage.local.get("catalog");
  if (!catalog) await applyCatalog(BUILTIN_DOMAINS); // first run: watch the built-in list at once
  await syncCatalog();
  flush();
}

chrome.runtime.onInstalled.addListener(start);
chrome.runtime.onStartup.addListener(start);
// a policy that arrives (or changes) later takes effect without a restart
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "managed") syncCatalog();
});
