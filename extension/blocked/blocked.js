// Shown instead of an AI service the organization blocked (a network rule of
// the background worker redirects here). Reports the attempt and lists the
// services the organization allows instead.
const domain = (new URLSearchParams(location.search).get("d") || "").toLowerCase();
document.getElementById("host").textContent = domain || "this service";

chrome.runtime.sendMessage({ action: "blocked_visit", domain }, (answer) => {
  if (!answer) return;
  document.getElementById("title").textContent = answer.name + " is not allowed";
  const allowed = answer.allowed || [];
  if (allowed.length) {
    const list = document.getElementById("allowed");
    for (const a of allowed) {
      const li = document.createElement("li");
      const link = document.createElement("a");
      link.href = "https://" + a.domain + "/";
      link.textContent = a.name;
      li.appendChild(link);
      list.appendChild(li);
    }
    document.getElementById("instead").hidden = false;
  }
});
