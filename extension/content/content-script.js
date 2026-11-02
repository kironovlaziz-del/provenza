// Content script: injected only into the AI services the organization's
// catalog lists (the background worker registers it for those domains).
// Warns the user in-page when they are about to send a secret into the AI
// tool. The warning stays in the browser: nothing about it is reported.
(function () {
  const currentHost = window.location.hostname;
  const aiTool = lookupDomain(currentHost) || { name: currentHost };

  // ---- in-page warning banner ----------------------------------------
  function showWarningBanner(findings) {
    const existing = document.getElementById("provenza-warning-modal");
    if (existing) existing.remove();

    const banner = document.createElement("div");
    banner.id = "provenza-warning-modal";
    banner.style.cssText = [
      "position:fixed",
      "top:20px",
      "right:20px",
      "z-index:2147483647",
      "background:#1e1e24",
      "color:#ffffff",
      "border:2px solid #ef4444",
      "border-radius:8px",
      "padding:16px 20px",
      "box-shadow:0 10px 25px rgba(0,0,0,0.5)",
      "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
      "font-size:14px",
      "max-width:380px"
    ].join(";");

    // Build DOM with textContent (no innerHTML with interpolated data) so
    // nothing user- or page-derived can inject markup.
    const header = document.createElement("div");
    header.style.cssText = "display:flex;align-items:center;margin-bottom:8px;";
    const icon = document.createElement("span");
    icon.style.cssText = "font-size:18px;margin-right:8px;";
    icon.textContent = "\u26A0\uFE0F";
    const title = document.createElement("strong");
    title.style.cssText = "color:#f87171;font-size:15px;";
    title.textContent = "Sensitive data detected";
    header.appendChild(icon);
    header.appendChild(title);

    const msg = document.createElement("p");
    msg.style.cssText = "margin:0 0 10px 0;line-height:1.4;color:#cbd5e1;";
    msg.textContent = "You may be about to send confidential data into " + aiTool.name + ":";

    const list = document.createElement("div");
    list.style.cssText =
      "background:#0f172a;padding:8px;border-radius:4px;margin-bottom:12px;font-family:monospace;font-size:12px;color:#fca5a5;";
    findings.forEach((f) => {
      const line = document.createElement("div");
      line.textContent = "\u2022 " + f.label;
      list.appendChild(line);
    });

    const actions = document.createElement("div");
    actions.style.cssText = "display:flex;justify-content:flex-end;gap:8px;";
    const dismiss = document.createElement("button");
    dismiss.textContent = "Dismiss";
    dismiss.style.cssText =
      "background:#334155;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;";
    dismiss.onclick = () => banner.remove();
    actions.appendChild(dismiss);

    banner.appendChild(header);
    banner.appendChild(msg);
    banner.appendChild(list);
    banner.appendChild(actions);
    document.body.appendChild(banner);

    setTimeout(() => {
      if (banner.parentNode) banner.remove();
    }, 8000);
  }


  // Avoid re-warning for the exact same set of finding types in quick
  // succession (e.g. paste then keystroke of the same content).
  let lastSignature = "";
  let lastWarnAt = 0;
  function maybeWarn(text) {
    if (!text) return;
    const findings = scanTextForPII(text);
    if (findings.length === 0) return;

    const signature = findings.map((f) => f.type).sort().join(",");
    const now = Date.now();
    if (signature === lastSignature && now - lastWarnAt < 4000) return;
    lastSignature = signature;
    lastWarnAt = now;

    showWarningBanner(findings);
  }

  // ---- paste detection ------------------------------------------------
  document.addEventListener(
    "paste",
    function (e) {
      const text = e.clipboardData ? e.clipboardData.getData("text") : "";
      maybeWarn(text);
    },
    true
  );

  // ---- typing detection (throttled) -----------------------------------
  // Paste-only misses secrets typed or edited by hand. We also scan the
  // value of the focused editable field, but throttled and only on the
  // field's current contents - we never keylog individual characters,
  // and the text never leaves the page (only finding metadata does).
  let typeTimer = null;
  function scheduleTypingScan(target) {
    if (typeTimer) return; // throttle: at most one scan per interval
    typeTimer = setTimeout(() => {
      typeTimer = null;
      let text = "";
      if (target) {
        if (typeof target.value === "string") text = target.value;
        else if (target.isContentEditable) text = target.innerText || "";
      }
      maybeWarn(text);
    }, 1200);
  }

  document.addEventListener(
    "input",
    function (e) {
      const t = e.target;
      if (!t) return;
      const editable =
        (typeof t.value === "string" && (t.tagName === "TEXTAREA" || t.tagName === "INPUT")) ||
        t.isContentEditable;
      if (editable) scheduleTypingScan(t);
    },
    true
  );
})();
