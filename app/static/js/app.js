/* TrafficWatch UI — Socket.IO + filters + home override + highlight sync */

(function () {

  // Session cookie (HttpOnly). Never read a token from HTML.
  function twHeaders(extra) {
    return Object.assign({}, extra || {});
  }
  function twFetch(url, opts) {
    opts = opts || {};
    opts.headers = twHeaders(opts.headers || {});
    opts.credentials = "include";
    return fetch(url, opts);
  }
  function mapOk() {
    return !!(window.TWMap && typeof window.TWMap.upsert === "function");
  }
  function withMap(fn) {
    if (!mapOk()) return;
    try { fn(window.TWMap); } catch (err) {
      console.warn("TrafficWatch: TWMap call failed", err);
    }
  }

  // --- Phase C toasts (high severity; session-deduped) --------------------
  const toastHost = document.getElementById("tw-toasts");
  const seenToasts = new Set(); // this session
  try {
    const raw = sessionStorage.getItem("tw_toasts_seen");
    if (raw) JSON.parse(raw).forEach((k) => seenToasts.add(k));
  } catch (_) {}
  function rememberToast(key) {
    seenToasts.add(key);
    try {
      sessionStorage.setItem("tw_toasts_seen", JSON.stringify([...seenToasts].slice(-200)));
    } catch (_) {}
  }
  function showToast(title, body, opts) {
    opts = opts || {};
    const key = opts.key || title + "|" + body;
    if (seenToasts.has(key)) return;
    rememberToast(key);
    if (!toastHost) return;
    const el = document.createElement("div");
    el.className = "tw-toast " + (opts.sev === "info" ? "sev-info" : "sev-high");
    el.innerHTML =
      '<button type="button" class="tw-toast-close" aria-label="Dismiss">×</button>' +
      '<div class="tw-toast-title"></div><div class="tw-toast-body"></div>';
    el.querySelector(".tw-toast-title").textContent = title;
    el.querySelector(".tw-toast-body").textContent = body || "";
    el.querySelector(".tw-toast-close").addEventListener("click", () => el.remove());
    toastHost.appendChild(el);
    setTimeout(() => {
      try { el.remove(); } catch (_) {}
    }, opts.ttl || 8000);
  }
  // In-app confirm (replaces window.confirm). Resolves true on OK, false on Cancel/Escape/backdrop.
  function twConfirm(title, text, okLabel) {
    const modal = document.getElementById("confirm-modal");
    if (!modal) return Promise.resolve(false);
    const ok = document.getElementById("confirm-ok");
    const cancel = document.getElementById("confirm-cancel");
    document.getElementById("confirm-title").textContent = title || "Confirm";
    document.getElementById("confirm-text").textContent = text || "";
    ok.textContent = okLabel || "OK";
    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    cancel.focus();
    return new Promise((resolve) => {
      function done(result) {
        modal.classList.add("hidden");
        modal.setAttribute("aria-hidden", "true");
        ok.removeEventListener("click", onOk);
        cancel.removeEventListener("click", onCancel);
        modal.removeEventListener("click", onBackdrop);
        document.removeEventListener("keydown", onKey, true);
        resolve(result);
      }
      function onOk() { done(true); }
      function onCancel() { done(false); }
      function onBackdrop(e) { if (e.target === modal) done(false); }
      function onKey(e) { if (e.key === "Escape") { e.stopPropagation(); done(false); } }
      ok.addEventListener("click", onOk);
      cancel.addEventListener("click", onCancel);
      modal.addEventListener("click", onBackdrop);
      document.addEventListener("keydown", onKey, true);
    });
  }
  function fmtDnsTs(ts) {
    if (!ts) return "";
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return String(ts).slice(11, 19) || String(ts);
      return d.toLocaleTimeString();
    } catch (_) {
      return String(ts);
    }
  }
  const chipDns = document.getElementById("chip-dns");
  const chipHelper = document.getElementById("chip-helper");
  const btnEnableDns = document.getElementById("btn-enable-dns");
  const dnsRecentBody = document.getElementById("dns-recent-body");
  const dnsEmpty = document.getElementById("dns-empty");
  const dnsTable = document.getElementById("dns-table");

  function renderDnsPanel(snap) {
    const d = (snap && snap.dns_log) || {};
    const h = d.helper || {};
    const live = !!d.live || (!!h.connected && !!h.dns);
    if (chipHelper) {
      const tcpOn = !!(h.tcp);
      const tcpLim = !!(h.tcp_limited);
      let helperLabel = "Live DNS: not running";
      if (live || h.connected) {
        if (tcpOn && !tcpLim) helperLabel = "Live DNS+TCP: on";
        else if (tcpOn && tcpLim) helperLabel = "Live DNS+TCP: limited";
        else helperLabel = "Live DNS: on";
      }
      chipHelper.textContent = helperLabel;
      chipHelper.classList.toggle("helper-on", !!(live || h.connected));
      chipHelper.classList.toggle("helper-off", !(live || h.connected));
      const tipBits = [h.last_error, h.tcp_error, d.message, h.tcp_source ? ("tcp=" + h.tcp_source) : ""].filter(Boolean);
      chipHelper.title = tipBits.join(" | ") || (live ? "elevated helper connected" : "helper not running");
    }
    if (btnEnableDns) {
      btnEnableDns.disabled = !!(live || h.connected);
      btnEnableDns.textContent = (live || h.connected) ? "Live DNS on" : "Enable live DNS (admin)";
    }
    const rows = Array.isArray(d.queries) ? d.queries.slice(-80) : [];
    if (dnsRecentBody) {
      dnsRecentBody.textContent = "";
      const frag = document.createDocumentFragment();
      // ux44: group identical Live DNS rows (proc+name+result) with count
      const grouped = [];
      const gmap = new Map();
      for (const q of rows.slice().reverse()) {
        const proc = q.proc || (q.pid != null ? ("pid " + q.pid) : "") || "-";
        const name = q.name || "-";
        let res;
        if (q.nxdomain) res = "NXDOMAIN";
        else res = (q.results && q.results.length) ? q.results.join(", ") : (q.ip || "-");
        const gk = proc + "|" + name + "|" + res;
        if (gmap.has(gk)) {
          const g = gmap.get(gk);
          g.count += 1;
          if (q.ts && (!g.ts || q.ts > g.ts)) g.ts = q.ts;
        } else {
          const g = { ts: q.ts, proc, name, res, nx: !!q.nxdomain, count: 1 };
          gmap.set(gk, g);
          grouped.push(g);
        }
      }
      for (const g of grouped.slice(0, 80)) {
        const tr = document.createElement("tr");
        const tdT = document.createElement("td");
        const tdP = document.createElement("td");
        const tdN = document.createElement("td");
        const tdR = document.createElement("td");
        tdT.textContent = fmtDnsTs(g.ts) + (g.count > 1 ? (" x" + g.count) : "");
        tdP.textContent = g.proc || "-";
        tdN.textContent = g.name || "-";
        if (g.nx) {
          tdR.textContent = "NXDOMAIN";
          tdR.className = "dns-nx";
        } else {
          tdR.textContent = g.res;
        }
        tr.appendChild(tdT);
        tr.appendChild(tdP);
        tr.appendChild(tdN);
        tr.appendChild(tdR);
        frag.appendChild(tr);
      }
      dnsRecentBody.appendChild(frag);
    }
    const empty = rows.length === 0;
    if (dnsEmpty) dnsEmpty.classList.toggle("hidden", !empty);
    if (dnsTable) dnsTable.classList.toggle("hidden", empty);
    if (!live && d.limited) {
      showToast(
        "DNS limited",
        "Live DNS helper is not running. Settings: Enable live DNS (admin), or stay on the 20s poll.",
        { key: "dns-limited-session", sev: "info", ttl: 9000 }
      );
    }
    if (h.storm_trips > 0) {
      // Helper paused packet-level capture because it was loading the CPU (#69).
      showToast(
        "Capture paused to protect this PC",
        h.tcp_error || "Live packet capture was using too much CPU and was paused. Connections still update from the normal poll.",
        { key: "storm|" + h.storm_trips, sev: "info", ttl: 15000 }
      );
    } else if (h.connected && h.tcp_limited) {
      showToast(
        "TCP limited",
        "Helper TCP bytes limited (" + (h.tcp_source || "none") + "). Direction may stay guess for some rows; Enable live DNS restarts helper.",
        { key: "tcp-limited-session", sev: "info", ttl: 9000 }
      );
    }
    if (!h.connected) {
      showToast(
        "TCP helper off",
        "No live TCP direction/bytes until Settings -> Enable live DNS (admin).",
        { key: "tcp-helper-off-session", sev: "info", ttl: 9000 }
      );
    }
  }
  let dnsEnableBusy = false;
  async function enableLiveDns() {
    if (dnsEnableBusy) return;
    dnsEnableBusy = true;
    if (btnEnableDns) btnEnableDns.disabled = true;
    showToast("Live DNS", "Waiting for admin consent (UAC)...", {
      sev: "info",
      key: "dns-enable-wait|" + Date.now(),
      ttl: 6000,
    });
    try {
      const r = await twFetch("/api/helper/enable", { method: "POST" });
      const j = await r.json().catch(() => ({}));
      if (j && j.declined) {
        showToast("Live DNS", "Not enabled; using 20s poll.", {
          sev: "info",
          key: "dns-enable-no|" + Date.now(),
        });
      } else if (j && j.cancelled) {
        showToast("Live DNS", "UAC cancelled.", {
          sev: "info",
          key: "dns-enable-uac|" + Date.now(),
        });
      } else if (j && j.ok) {
        showToast("Live DNS", j.already ? "Helper already running." : "Helper started.", {
          sev: "info",
          key: "dns-enable-ok|" + Date.now(),
        });
      } else {
        showToast("Live DNS failed", (j && j.error) || "could not start helper", {
          sev: "high",
          key: "dns-enable-fail|" + Date.now(),
        });
      }
    } catch (_) {
      showToast("Live DNS failed", "request failed", {
        sev: "high",
        key: "dns-enable-err|" + Date.now(),
      });
    } finally {
      dnsEnableBusy = false;
      if (btnEnableDns) btnEnableDns.disabled = false;
    }
  }
  if (btnEnableDns) {
    btnEnableDns.addEventListener("click", () => { enableLiveDns(); });
  }

  function considerToasts(snap) {
    const rows = (snap && snap.connections) || [];
    for (const c of rows) {
      if (c.private_remote) continue;
      if (c.direction === "listen") {
        const hotListen = (c.signals || []).some((s) => s.id === "new_listener" && s.severity === "high");
        if (!hotListen) continue; // skip listen noise
      }
      const intel = c.intel || {};
      if (intel.hit && intel.severity === "high" && c.remote_ip) {
        showToast(
          "Intel hit (high)",
          (c.process || "?") + " → " + c.remote_ip + (c.remote_port != null ? ":" + c.remote_port : "") +
            " · " + ((intel.lists || []).slice(0, 2).join(",") || "list"),
          { key: alertIdentity(c, "intel"), sev: "high" }
        );
      }
      for (const s of c.signals || []) {
        if (s.id === "public_inbound" && (s.severity === "high" || s.severity === "medium")) {
          showToast(
            "Public inbound",
            (c.process || "?") + " <- " + (c.remote_ip || "?") + " : " + (c.local_port ?? "?") + " - " + (s.detail || ""),
            { key: alertIdentity(c, "public_inbound"), sev: s.severity === "high" ? "high" : "info" }
          );
          continue;
        }
        if (s.severity !== "high") continue;
        if (s.id === "new_listener") {
          showToast(
            "New unexpected listener",
            (c.process || "?") + " LISTEN :" + (c.local_port ?? "?") + " - " + (s.detail || ""),
            { key: alertIdentity(c, "new_listener"), sev: "high" }
          );
        } else {
          showToast(
            s.label || s.id || "High signal",
            (c.process || "?") + " · " + (s.detail || ""),
            { key: alertIdentity(c, s.id), sev: "high" }
          );
        }
      }
    }
  }

  const LS_HOME = "tw_home_v2";
  const LS_FILTERS = "tw_filters_v2";
  const LS_SIDEBAR = "tw_sidebar_open_v2";
  const LS_PROC_OPEN = "tw_proc_open_v3";
  const LS_TRUST = "tw_trust_pids"; // legacy PID-only
  const LS_TRUST_KEYS = "tw_trust_keys"; // Review 4: [{exe, signer}]
  const LS_MUTE = "tw_mute_keys";
  const LS_LAYOUT = "tw_layout";
  const LS_GUIDE = "tw_seen_guide";
  const LS_LIST_TAB = "tw_list_tab";

  const connList = document.getElementById("conn-list");
  const body = connList; // alias used by select-scroll helpers
  const statCount = document.getElementById("stat-count");
  const statMapped = document.getElementById("stat-mapped");
  const statStatus = document.getElementById("stat-status");
  const statSysIn = document.getElementById("stat-sys-in");
  const statSysOut = document.getElementById("stat-sys-out");
  const chipTalkers = document.getElementById("chip-talkers");
  const chipIntel = document.getElementById("chip-intel");
  const chipHistory = document.getElementById("chip-history");
  const chipBaseline = document.getElementById("chip-baseline");
  const listMeta = document.getElementById("list-meta");
  const statusBanner = document.getElementById("status-banner");
  const statusVerdict = document.getElementById("status-verdict");
  const statusVerdictDetail = document.getElementById("status-verdict-detail");
  const alertsList = document.getElementById("alerts-list");
  const alertCountEl = document.getElementById("alert-count");
  const tabLive = document.getElementById("tab-live");
  const tabAlerts = document.getElementById("tab-alerts");
  const tabStatus = document.getElementById("tab-status");
  const statusPanel = document.getElementById("status-panel");
  const statusEmpty = document.getElementById("status-empty");
  const statusSections = document.getElementById("status-sections");
  const listTabs = document.getElementById("list-tabs");
  const mainLayout = document.getElementById("main-layout");
  const sidebarToggle = document.getElementById("sidebar-toggle");
  const bootSplash = document.getElementById("boot-splash");
  const bootTitle = document.getElementById("boot-title");
  const bootSub = document.getElementById("boot-sub");

  const fProcess = document.getElementById("filter-process");
  const fCountry = document.getElementById("filter-country");
  const fPort = document.getElementById("filter-port");
  const fEstablished = document.getElementById("filter-established");
  const fMapped = document.getElementById("filter-mapped");
  const fHidePrivate = document.getElementById("filter-hide-private");
  const dirFilterEl = document.getElementById("dir-filter");
  const filterHint = document.getElementById("filter-hint");
  let dirFilter = "all"; // all | outbound | inbound | listen


  const homePanel = document.getElementById("home-panel");
  const homeLat = document.getElementById("home-lat");
  const homeLon = document.getElementById("home-lon");
  const homeLabelInput = document.getElementById("home-label-input");

  let latest = [];
  let topTalkers = [];
  let selectedKey = null;
  let focusProc = null; // process name focused on globe, or null = all traffic
  let listPointerInside = false; // pause Live list DOM rebuild while hovering / Inspect open
  let alertsPointerInside = false; // ux44: pause Alerts list rebuild under pointer / alert modal
  let displayRates = new Map(); // key -> {in, out} EMA on client too
  let splashDone = false;
  let openProcs = loadOpenProcs();
  let activeTab = "live"; // live | alerts | status
  let sawSnapshot = false;

  // --- Boot splash ---------------------------------------------------------
  function dismissSplash() {
    if (splashDone || !bootSplash) return;
    splashDone = true;
    bootSplash.classList.add("fade-out");
    setTimeout(() => {
      bootSplash.classList.add("hidden");
      bootSplash.classList.remove("fade-out");
      // Globe may have been sized under splash - force resize
      try {
        window.dispatchEvent(new Event("resize"));
      } catch (err) {
        console.warn("TrafficWatch: dismissSplash resize failed", err);
      }
      try {
        if (window.__twHideBoot) window.__twHideBoot();
      } catch (err) {
        console.warn("TrafficWatch: __twHideBoot failed", err);
      }
      withMap((M) => { if (M.resize) M.resize(); });
    }, 280);
  }

  // Soft nudge only; do NOT hide into empty chrome. boot.js owns ~10s error state.
  setTimeout(() => {
    if (splashDone || sawSnapshot) return;
    if (bootTitle) bootTitle.textContent = "Still loading.";
    if (bootSub) bootSub.textContent = "Waiting for first live snapshot.";
  }, 9000);


  // --- Sidebar accordion ---------------------------------------------------
  function loadSidebarOpen() {
    try {
      const raw = localStorage.getItem(LS_SIDEBAR);
      if (raw === "0" || raw === "false") return false;
      if (raw === "1" || raw === "true") return true;
    } catch (_) {}
    return false; // default collapsed so globe fills on first launch
  }
  function saveSidebarOpen(open) {
    try {
      localStorage.setItem(LS_SIDEBAR, open ? "1" : "0");
    } catch (_) {}
  }
  function applySidebar(open) {
    if (!mainLayout || !sidebarToggle) return;
    mainLayout.classList.toggle("sidebar-collapsed", !open);
    sidebarToggle.setAttribute("aria-expanded", open ? "true" : "false");
    sidebarToggle.title = open ? "Collapse Live connections" : "Expand Live connections";
    const listBody = document.getElementById("list-body");
    if (listBody) listBody.style.display = open ? "" : "none";
    if (listTabs) listTabs.style.display = open ? "" : "none";
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        try { window.dispatchEvent(new Event("resize")); } catch (_) {}
      });
    });
  }
  let sidebarOpen = loadSidebarOpen();
  applySidebar(sidebarOpen);
  if (sidebarToggle) {
    sidebarToggle.addEventListener("pointerdown", (e) => {
      if (e.button != null && e.button !== 0) return;
      e.preventDefault();
      e.stopPropagation();
      sidebarOpen = !sidebarOpen;
      saveSidebarOpen(sidebarOpen);
      applySidebar(sidebarOpen);
    });
  }

  
  // --- Sidebar width drag -------------------------------------------------
  const LS_SIDEBAR_W = "tw_sidebar_w";
  const SIDEBAR_MIN = 280;
  const SIDEBAR_MAX = 720;
  function applySidebarWidth(px) {
    const w = Math.max(SIDEBAR_MIN, Math.min(SIDEBAR_MAX, Math.round(px)));
    document.documentElement.style.setProperty("--sidebar-w", w + "px");
    try { localStorage.setItem(LS_SIDEBAR_W, String(w)); } catch (_) {}
    requestAnimationFrame(() => {
      try { window.dispatchEvent(new Event("resize")); } catch (_) {}
    });
    return w;
  }
  try {
    const savedW = parseInt(localStorage.getItem(LS_SIDEBAR_W) || "", 10);
    if (savedW >= SIDEBAR_MIN && savedW <= SIDEBAR_MAX) applySidebarWidth(savedW);
  } catch (_) {}
  const sidebarResizer = document.getElementById("sidebar-resizer");
  if (sidebarResizer && mainLayout) {
    let dragging = false;
    const onMove = (e) => {
      if (!dragging) return;
      const rect = mainLayout.getBoundingClientRect();
      const x = e.clientX != null ? e.clientX : (e.touches && e.touches[0] && e.touches[0].clientX);
      if (x == null) return;
      applySidebarWidth(rect.right - x);
    };
    const onUp = () => {
      if (!dragging) return;
      dragging = false;
      sidebarResizer.classList.remove("dragging");
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
    sidebarResizer.addEventListener("pointerdown", (e) => {
      if (e.button != null && e.button !== 0) return;
      e.preventDefault();
      e.stopPropagation();
      dragging = true;
      sidebarResizer.classList.add("dragging");
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
    });
  }

  
  // --- Expand / collapse all process groups -------------------------------
  const procFoldBtn = document.getElementById("proc-fold-all");
  const btnClearFocus = document.getElementById("btn-clear-focus");

  function clearGlobeFocus() {
    focusProc = null;
    selectedKey = null;
    withMap((M) => {
      M.setSelected(null);
      if (M.setProcessFilter) M.setProcessFilter(null);
    });
  }

  function updateClearFocusBtn() {
    if (!btnClearFocus) return;
    btnClearFocus.hidden = !focusProc;
  }

  if (btnClearFocus) {
    btnClearFocus.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      clearGlobeFocus();
      render();
    });
  }
  let procsExpanded = false;
  function setAllProcGroups(open) {
    procsExpanded = !!open;
    const groups = connList ? connList.querySelectorAll(".proc-group") : [];
    groups.forEach((group) => {
      const name = group.dataset.proc;
      if (!name) return;
      group.classList.toggle("collapsed", !procsExpanded);
      if (procsExpanded) {
        openProcs.delete("!" + name);
        openProcs.add(name);
      } else {
        openProcs.delete(name);
        openProcs.add("!" + name);
      }
    });
    saveOpenProcs();
    if (procFoldBtn) {
      procFoldBtn.textContent = procsExpanded ? "Collapse all" : "Expand all";
      procFoldBtn.setAttribute("aria-expanded", procsExpanded ? "true" : "false");
      procFoldBtn.title = procsExpanded
        ? "Collapse all process groups"
        : "Expand all process groups";
    }
  }
  if (procFoldBtn) {
    procFoldBtn.textContent = "Expand all";
    procFoldBtn.setAttribute("aria-expanded", "false");
    procFoldBtn.title = "Expand all process groups";
    procFoldBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      setAllProcGroups(!procsExpanded);
    });
  }

  // Live | Alerts | Status tabs
  function loadListTab() {
    try {
      const v = localStorage.getItem(LS_LIST_TAB);
      if (v === "live" || v === "alerts" || v === "status") return v;
    } catch (_) {}
    return "live";
  }
  function saveListTab(tab) {
    try { localStorage.setItem(LS_LIST_TAB, tab); } catch (_) {}
  }
  function onTabClick(e) {
    const btn = e.currentTarget;
    const tab = btn && btn.dataset ? btn.dataset.tab : "live";
    setActiveTab(tab);
  }
  if (tabLive) tabLive.addEventListener("click", onTabClick);
  if (tabAlerts) tabAlerts.addEventListener("click", onTabClick);
  if (tabStatus) tabStatus.addEventListener("click", onTabClick);
  setActiveTab(loadListTab());

  function loadOpenProcs() {
    try {
      const raw = localStorage.getItem(LS_PROC_OPEN);
      if (!raw) return new Set();
      const arr = JSON.parse(raw);
      return new Set(Array.isArray(arr) ? arr : []);
    } catch (_) {
      return new Set();
    }
  }
  function saveOpenProcs() {
    try {
      localStorage.setItem(LS_PROC_OPEN, JSON.stringify([...openProcs]));
    } catch (_) {}
  }

  // Map wiring: app.js is last (ux35); still listen for tw-map-ready + poll backup.
  let mapWired = false;
  function wireMap() {
    if (mapWired || !mapOk()) return;
    mapWired = true;
    try { window.TWMap.init("globe"); } catch (err) {
      console.warn("TrafficWatch: TWMap.init failed", err);
    }
    const spinEl = document.getElementById("btn-spin");
    if (spinEl) {
      try { spinEl.checked = window.TWMap.getSpin(); } catch (err) {
        console.warn("TrafficWatch: getSpin failed", err);
      }
      spinEl.addEventListener("change", () => {
        withMap((M) => M.setSpin(spinEl.checked));
      });
    }
    const globeModeEl = document.getElementById("globe-mode");
    if (globeModeEl && window.TWMap.setGlobeMode) {
      const paintMode = (mode) => {
        withMap((M) => M.setGlobeMode(mode));
        globeModeEl.querySelectorAll("[data-mode]").forEach((b) => {
          b.classList.toggle("active", b.getAttribute("data-mode") === mode);
        });
      };
      try { paintMode(window.TWMap.getGlobeMode()); } catch (_) { paintMode("daynight"); }
      globeModeEl.addEventListener("click", (e) => {
        const b = e.target.closest("[data-mode]");
        if (!b) return;
        paintMode(b.getAttribute("data-mode"));
      });
    }
    withMap((M) => {
      if (typeof M.onHover === "function") {
        M.onHover((obj) => {
          if (!obj) return hideTip();
          const html = obj.tip || (obj.conn ? M.tipHtml(obj.conn) : escapeHtml(obj.label || ""));
          const globeEl = document.getElementById("globe");
          const r = globeEl ? globeEl.getBoundingClientRect() : { left: 40, top: 80, width: 400, height: 400 };
          showTipHtml(html, r.left + r.width * 0.62, r.top + r.height * 0.28);
        });
      }
      if (typeof M.onSelect === "function") {
        M.onSelect((key) => {
          selectedKey = key;
          render();
          const row = connList && connList.querySelector(`.conn-row[data-key="${cssEscape(key)}"]`);
          if (row) {
            const group = row.closest(".proc-group");
            if (group) {
              const name = group.dataset.proc;
              if (name) {
                openProcs.add(name);
                saveOpenProcs();
                group.classList.remove("collapsed");
              }
            }
            if (!sidebarOpen) {
              sidebarOpen = true;
              saveSidebarOpen(true);
              applySidebar(true);
            }
            row.scrollIntoView({ block: "nearest", behavior: "smooth" });
          }
        });
      }
    });
    try { window.dispatchEvent(new Event("resize")); } catch (_) {}
    withMap((M) => { if (M.resize) M.resize(); });
    try { render(); } catch (_) {}
  }
  window.__twOnMapReady = function () {
    wireMap();
  };
  window.addEventListener("tw-map-ready", function () {
    wireMap();
  });
  if (window.TWMap) {
    wireMap();
  }
  (function waitMap(n) {
    if (mapOk()) return wireMap();
    if (n >= 80) {
      console.warn("TrafficWatch: TWMap never ready after ~4s");
      return;
    }
    setTimeout(function () { waitMap(n + 1); }, 50);
  })(0);

  // Review 4: Settings menu (layout / globe / Home). Spin stays on globe legend.
  (function setupSettingsMenu() {
    const btn = document.getElementById("btn-settings");
    const pop = document.getElementById("settings-pop");
    const wrap = document.getElementById("settings-wrap");
    if (!btn || !pop) return;
    const setOpen = (open) => {
      pop.classList.toggle("hidden", !open);
      if (open) pop.removeAttribute("hidden");
      else pop.setAttribute("hidden", "");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    };
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      setOpen(pop.classList.contains("hidden") || pop.hasAttribute("hidden"));
    });
    document.addEventListener("click", (e) => {
      if (!wrap) return setOpen(false);
      if (!wrap.contains(e.target)) setOpen(false);
    });
  })();

  // ux44: tipEl resolved at call time so early setActiveTab/hideTip is TDZ-safe
  function tipElRef() {
    return document.getElementById("tw-tooltip");
  }
  function hideTip() {
    const tipEl = tipElRef();
    if (tipEl) tipEl.classList.add("hidden");
  }
  function showTipHtml(html, x, y) {
    const tipEl = tipElRef();
    if (!tipEl || !html) return hideTip();
    tipEl.innerHTML = html;
    tipEl.classList.remove("hidden");
    const pad = 14;
    let left = x + pad;
    let top = y + pad;
    const rect = tipEl.getBoundingClientRect();
    if (left + rect.width > window.innerWidth - 8) left = x - rect.width - pad;
    if (top + rect.height > window.innerHeight - 8) top = y - rect.height - pad;
    tipEl.style.left = Math.max(8, left) + "px";
    tipEl.style.top = Math.max(8, top) + "px";
  }


  document.addEventListener("mousemove", (e) => {
    const tipEl = tipElRef();
    if (tipEl && !tipEl.classList.contains("hidden") && tipEl.dataset.follow === "1") {
      showTipHtml(tipEl.innerHTML, e.clientX, e.clientY);
    }
  });


  function cssEscape(s) {
    if (window.CSS && CSS.escape) return CSS.escape(s);
    return String(s).replace(/"/g, '\\"');
  }

  function fmtRate(n) {
    if (n == null || Number.isNaN(n)) return "—";
    if (n < 1024) return `${n.toFixed(0)} B/s`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB/s`;
    return `${(n / (1024 * 1024)).toFixed(2)} MB/s`;
  }

  function rowKey(c) {
    return `${c.proto}|${c.pid}|${c.local_ip}:${c.local_port}|${c.remote_ip}:${c.remote_port}|${c.status}`;
  }

  function smoothRate(key, inn, out) {
    const prev = displayRates.get(key) || { in: inn || 0, out: out || 0 };
    const a = 0.4;
    const next = {
      in: inn == null ? prev.in : a * inn + (1 - a) * prev.in,
      out: out == null ? prev.out : a * out + (1 - a) * prev.out,
    };
    displayRates.set(key, next);
    return next;
  }

  function passes(c) {
    const procQ = (fProcess.value || "").trim().toLowerCase();
    const countryQ = (fCountry.value || "").trim().toLowerCase();
    const portQ = (fPort.value || "").trim();
    if (procQ && !(c.process || "").toLowerCase().includes(procQ) && !String(c.pid || "").includes(procQ)) {
      return false;
    }
    if (countryQ) {
      const blob = `${c.country || ""} ${c.country_code || ""} ${c.city || ""} ${c.hostname || ""}`.toLowerCase();
      if (!blob.includes(countryQ)) return false;
    }
    if (portQ) {
      const p = portQ.replace(/^:/, "");
      const match =
        String(c.remote_port || "") === p ||
        String(c.local_port || "") === p ||
        String(c.remote_port || "").includes(p) ||
        String(c.local_port || "").includes(p);
      if (!match) return false;
    }
    // Direction filter; Inbound/Listening auto-ignore Hide private + Established
    const dirMode = dirFilter || "all";
    const relaxPrivateEst = dirMode === "inbound" || dirMode === "listen";
    if (dirMode === "outbound" && c.direction !== "outbound") return false;
    if (dirMode === "inbound" && c.direction !== "inbound") return false;
    if (dirMode === "listen" && c.direction !== "listen" && (c.status || "").toUpperCase() !== "LISTEN") return false;

    const useEstablished = fEstablished.checked && !relaxPrivateEst;
    const useHidePrivate = fHidePrivate.checked && !relaxPrivateEst;
    if (useEstablished) {
      const st = (c.status || "").toUpperCase();
      if (c.proto === "TCP" && st !== "ESTABLISHED") return false;
      if (c.proto === "UDP" && !c.remote_ip) return false;
    }
    if (fMapped.checked && (c.lat == null || c.lon == null)) return false;
    if (useHidePrivate && c.private_remote) return false;
    if (useHidePrivate && c.direction === "listen") return false;
    return true;
  }

  function dirLabel(d) {
    if (d === "inbound") return "IN";
    if (d === "listen") return "LISTEN";
    return "OUT";
  }

  function directionBasisText(c) {
    const d = (c && c.direction) || "outbound";
    const b = (c && c.direction_basis) || "guess";
    if (d === "listen") return "Direction: listening";
    if (d === "inbound") {
      if (b === "confirmed") {
        if (c && c.helper_tcp) return "Direction: inbound (confirmed - helper TCP accept)";
        const lp = c.local_port != null ? ":" + c.local_port : "";
        return "Direction: inbound (confirmed - listener on " + lp + ")";
      }
      return "Direction: inbound (guess from ports)";
    }
    if (b === "confirmed") {
      return c && c.helper_tcp
        ? "Direction: outbound (confirmed - helper TCP connect)"
        : "Direction: outbound (confirmed)";
    }
    return "Direction: outbound (guess from ports)";
  }

  function dirChipHtml(c) {
    const d = (c && c.direction) || "outbound";
    const b = (c && c.direction_basis) || "guess";
    const cls = d === "inbound" ? "in" : d === "listen" ? "listen" : "out";
    const guess = b === "guess" && d !== "listen" ? " dir-guess" : "";
    const title = escapeHtml(directionBasisText(c));
    return `<span class="dir ${cls}${guess}" title="${title}">${dirLabel(d)}</span>`;
  }

  function saveFilters() {
    try {
      localStorage.setItem(
        LS_FILTERS,
        JSON.stringify({
          process: fProcess.value,
          country: fCountry.value,
          port: fPort.value,
          established: fEstablished.checked,
          mapped: fMapped.checked,
          hidePrivate: fHidePrivate.checked,
          direction: dirFilter || "all",
        })
      );
    } catch (_) {}
  }

  function loadFilters() {
    try {
      const raw = localStorage.getItem(LS_FILTERS);
      if (!raw) return;
      const o = JSON.parse(raw);
      if (o.process != null) fProcess.value = o.process;
      if (o.country != null) fCountry.value = o.country;
      if (o.port != null) fPort.value = o.port;
      if (typeof o.established === "boolean") fEstablished.checked = o.established;
      if (typeof o.mapped === "boolean") fMapped.checked = o.mapped;
      if (typeof o.hidePrivate === "boolean") fHidePrivate.checked = o.hidePrivate;
      if (o.direction && ["all","outbound","inbound","listen"].includes(o.direction)) {
        dirFilter = o.direction;
        applyDirFilterButtons();
      }
    } catch (_) {}
  }

  function applyDirFilterButtons() {
    if (!dirFilterEl) return;
    dirFilterEl.querySelectorAll(".dir-f").forEach((btn) => {
      const on = btn.getAttribute("data-dir") === dirFilter;
      btn.classList.toggle("active", on);
    });
  }

  function loadHomeFromLS() {
    try {
      const raw = localStorage.getItem(LS_HOME);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch (_) {
      return null;
    }
  }

  function saveHomeLS(h) {
    try {
      localStorage.setItem(LS_HOME, JSON.stringify(h));
    } catch (_) {}
  }

  function groupByProcess(rows) {
    const map = new Map();
    for (const c of rows) {
      const name = c.process || "?";
      if (!map.has(name)) map.set(name, []);
      map.get(name).push(c);
    }
    // Sort groups by max risk desc, then aggregate rate, then name
    const entries = [...map.entries()];
    entries.sort((a, b) => {
      const arisk = Math.max(0, ...a[1].map(riskRank));
      const brisk = Math.max(0, ...b[1].map(riskRank));
      if (brisk !== arisk) return brisk - arisk;
      const ar = a[1].reduce((s, c) => s + (c.bytes_in_rate || 0) + (c.bytes_out_rate || 0), 0);
      const br = b[1].reduce((s, c) => s + (c.bytes_in_rate || 0) + (c.bytes_out_rate || 0), 0);
      if (br !== ar) return br - ar;
      return a[0].localeCompare(b[0]);
    });
    // Within each group: risk first
    for (const ent of entries) {
      ent[1].sort((a, b) => {
        const d = riskRank(b) - riskRank(a);
        if (d) return d;
        const ar = (a.bytes_in_rate || 0) + (a.bytes_out_rate || 0);
        const br = (b.bytes_in_rate || 0) + (b.bytes_out_rate || 0);
        return br - ar;
      });
    }
    return entries;
  }



  // --- Review 3 Step 2: risk 0–100 + trust/mute + alerts + banner ----------
  const ACTIONABLE_SIG_IDS = new Set(["beacon", "new_listener", "suspicious_path", "baseline_depart", "exfil_ish", "dns_rare", "dns_burst", "public_inbound", "new_binary_network", "hash_changed_same_publisher", "doh_unusual", "net_context_change", "config_drift", "asn_rotating", "combined_threat"]);

  function normExe(exe) {
    return String(exe || "").trim().toLowerCase();
  }
  function normSigner(signer) {
    return String(signer || "").trim().toLowerCase();
  }
  function normHash(h) {
    return String(h || "").trim().toLowerCase();
  }
  function trustKeyOf(exe, signer, hash) {
    const e = normExe(exe);
    if (!e) return "";
    const s = normSigner(signer);
    const h = normHash(hash);
    // Tier 0: path + signer + hash when hash known; else path|signer (compat)
    return h ? (e + "|" + s + "|" + h) : (e + "|" + s);
  }
  function loadTrustKeys() {
    try {
      const raw = localStorage.getItem(LS_TRUST_KEYS);
      const arr = raw ? JSON.parse(raw) : [];
      const out = [];
      for (const it of arr || []) {
        if (!it || typeof it !== "object") continue;
        const exe = normExe(it.exe);
        if (!exe) continue;
        out.push({ exe, signer: normSigner(it.signer), hash: normHash(it.hash) });
      }
      return out;
    } catch (_) {
      return [];
    }
  }
  function saveTrustKeys(list) {
    try {
      localStorage.setItem(LS_TRUST_KEYS, JSON.stringify(list || []));
    } catch (_) {}
  }
  // One-time migrate: if old PID trust matches a live row, rewrite as exe+signer
  function migrateTrustPidsOnce(conns) {
    try {
      if (localStorage.getItem("tw_trust_migrated_v4") === "1") return;
      const raw = localStorage.getItem(LS_TRUST);
      const arr = raw ? JSON.parse(raw) : [];
      const pids = new Set((arr || []).map((x) => Number(x)).filter((n) => Number.isFinite(n)));
      if (!pids.size) {
        localStorage.setItem("tw_trust_migrated_v4", "1");
        return;
      }
      const keys = loadTrustKeys();
      const have = new Set(keys.map((k) => trustKeyOf(k.exe, k.signer, k.hash)));
      for (const c of conns || []) {
        if (!pids.has(Number(c.pid))) continue;
        const exe = c.exe || "";
        const signer = (c.authenticode && c.authenticode.publisher) || c.publisher_hint || "";
        const hash = c.exe_sha256 || "";
        const tk = trustKeyOf(exe, signer, hash);
        if (tk && !have.has(tk)) {
          keys.push({ exe: normExe(exe), signer: normSigner(signer), hash: normHash(hash) });
          have.add(tk);
        }
      }
      saveTrustKeys(keys);
      localStorage.removeItem(LS_TRUST);
      localStorage.setItem("tw_trust_migrated_v4", "1");
    } catch (_) {}
  }
  function loadTrustPids() {
    // legacy no-op set retained for demotion path during migration window
    try {
      const raw = localStorage.getItem(LS_TRUST);
      const arr = raw ? JSON.parse(raw) : [];
      return new Set((arr || []).map((x) => Number(x)).filter((n) => Number.isFinite(n)));
    } catch (_) {
      return new Set();
    }
  }
  function saveTrustPids(set) {
    try {
      localStorage.setItem(LS_TRUST, JSON.stringify([...set]));
    } catch (_) {}
  }
  function loadMuteKeys() {
    try {
      const raw = localStorage.getItem(LS_MUTE);
      const arr = raw ? JSON.parse(raw) : [];
      return new Set(arr || []);
    } catch (_) {
      return new Set();
    }
  }
  function saveMuteKeys(set) {
    try {
      localStorage.setItem(LS_MUTE, JSON.stringify([...set]));
    } catch (_) {}
  }
  let trustPids = loadTrustPids();
  let trustKeys = loadTrustKeys();
  let muteKeys = loadMuteKeys();

  // --- Alert store (stable identity; not snapshot-row identity) ------------
  const ALERT_LINGER_SEC = 10 * 60; // stay listed 10 min after last_seen
  const alertStore = new Map(); // id -> alert
  let alertsSeeded = false;
  let _alertPersistTimer = null;
  const _alertDirty = new Set();

  function alertIdentity(c, sigId) {
    const sid = String(sigId || "intel");
    // Machine-wide signals: stable system identity (not under unrelated app rows)
    if (sid === "net_context_change" || sid === "config_drift") {
      return "(system)|0|-|" + sid;
    }
    // Exe identity path/name — NOT per PID (restarts must coalesce)
    const proc = String((c && (c.exe || c.process)) || "?").trim().toLowerCase();
    const isListen =
      (c && c.direction === "listen") ||
      (c && String(c.status || "").toUpperCase() === "LISTEN") ||
      (c && c.direction === "system");
    let classKey;
    if (isListen && c && c.direction === "system") {
      classKey = "-";
    } else if (isListen) {
      const lp = c && c.local_port != null ? Number(c.local_port) : null;
      const lip = String((c && c.local_ip) || "").toLowerCase();
      const loop = lip === "127.0.0.1" || lip === "::1" || lip === "localhost";
      const anyIf =
        !lip || lip === "0.0.0.0" || lip === "::" || lip === "*" || lip === "[::]";
      const validSigned =
        !!(c && c.authenticode && c.authenticode.signed === true);
      // ux42: ephemeral loopback listens coalesce (matches signals skip for Valid-signed)
      if (lp != null && lp >= 49152 && loop) {
        classKey = "listen:ephemeral";
      } else if (lp != null && lp >= 49152 && anyIf && validSigned) {
        // ux44: Valid-signed short-lived all-interface high ports -> one alert per app
        classKey = "listen:ephemeral-any";
      } else {
        classKey = "listen:" + (c.local_port != null ? String(c.local_port) : "");
      }
    } else {
      const asn =
        (c && (c.asn || (c.geo && c.geo.asn))) != null
          ? String(c.asn || (c.geo && c.geo.asn))
          : "";
      if (asn) {
        classKey = "asn:" + asn;
      } else {
        const rp = c && c.remote_port != null ? Number(c.remote_port) : null;
        if (rp != null && (rp === 80 || rp === 443 || rp === 8080 || rp === 8443 || rp <= 1024)) {
          classKey = "port:" + rp;
        } else if (rp != null && rp >= 49152) {
          classKey = "portclass:ephemeral";
        } else if (rp != null) {
          classKey = "portclass:high";
        } else {
          classKey = "remote:-";
        }
      }
    }
    // pid slot kept empty on purpose — same signal for same app/ASN coalesces
    return proc + "||" + classKey + "|" + sid;
  }

  function portClassKey(c) {
    if (!c) return "remote:-";
    const isListen =
      c.direction === "listen" ||
      String(c.status || "").toUpperCase() === "LISTEN" ||
      c.direction === "system";
    if (isListen && c.direction === "system") return "-";
    if (isListen) {
      const lp = c.local_port != null ? Number(c.local_port) : null;
      const lip = String(c.local_ip || "").toLowerCase();
      const loop = lip === "127.0.0.1" || lip === "::1" || lip === "localhost";
      const anyIf =
        !lip || lip === "0.0.0.0" || lip === "::" || lip === "*" || lip === "[::]";
      const validSigned = !!(c.authenticode && c.authenticode.signed === true);
      if (lp != null && lp >= 49152 && loop) return "listen:ephemeral";
      if (lp != null && lp >= 49152 && anyIf && validSigned) return "listen:ephemeral-any";
      return "listen:" + (c.local_port != null ? String(c.local_port) : "");
    }
    const asn =
      (c.asn || (c.geo && c.geo.asn)) != null
        ? String(c.asn || (c.geo && c.geo.asn))
        : "";
    if (asn) return "asn:" + asn;
    const rp = c.remote_port != null ? Number(c.remote_port) : null;
    if (rp != null && (rp === 80 || rp === 443 || rp === 8080 || rp === 8443 || rp <= 1024)) {
      return "port:" + rp;
    }
    if (rp != null && rp >= 49152) return "portclass:ephemeral";
    if (rp != null) return "portclass:high";
    return "remote:-";
  }

  function alertMuteKeyFromPayload(p) {
    if (!p) return "";
    // ux44: exe identity + port class (NOT PID) so mute survives restart
    const proc = String((p.exe || p.process) || "?").trim().toLowerCase();
    return "mute|" + proc + "|" + portClassKey(p);
  }

  function queueAlertPersist(id) {
    if (id) _alertDirty.add(id);
    if (_alertPersistTimer) return;
    _alertPersistTimer = setTimeout(() => {
      _alertPersistTimer = null;
      const ids = [..._alertDirty];
      _alertDirty.clear();
      const alerts = ids
        .map((i) => alertStore.get(i))
        .filter(Boolean)
        .map((a) => ({
          id: a.id,
          first_seen: a.first_seen,
          last_seen: a.last_seen,
          count: a.count,
          state: a.state,
          payload: a.payload,
        }));
      if (!alerts.length) return;
      twFetch("/api/alerts/upsert", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alerts }),
      }).catch(() => {});
    }, 1200);
  }

  function upsertStoreAlert(id, fields) {
    const now = Date.now() / 1000;
    let a = alertStore.get(id);
    if (!a) {
      a = {
        id,
        first_seen: now,
        last_seen: now,
        count: 1,
        state: "active",
        payload: fields.payload || {},
        summary: fields.summary || "Alert",
        risk: fields.risk || 0,
        intelHit: !!fields.intelHit,
        connKey: fields.connKey || "",
      };
      alertStore.set(id, a);
    } else {
      if (a.state === "ack" || a.state === "muted") {
        // Still refresh last_seen/count but keep terminal state until user undoes
        a.last_seen = now;
        a.count = (a.count || 0) + 1;
        a.payload = fields.payload || a.payload;
        a.summary = fields.summary || a.summary;
        a.risk = fields.risk != null ? fields.risk : a.risk;
        a.intelHit = !!fields.intelHit || !!a.intelHit;
        a.connKey = fields.connKey || a.connKey;
        queueAlertPersist(id);
        return a;
      }
      a.last_seen = now;
      a.count = (a.count || 0) + 1;
      a.state = "active";
      a.payload = fields.payload || a.payload;
      a.summary = fields.summary || a.summary;
      a.risk = fields.risk != null ? fields.risk : a.risk;
      a.intelHit = !!fields.intelHit || !!a.intelHit;
      a.connKey = fields.connKey || a.connKey;
    }
    queueAlertPersist(id);
    return a;
  }

  function ingestAlertsFromRows(rows) {
    const now = Date.now() / 1000;
    const seen = new Set();
    for (const c of rows || []) {
      if (!c) continue;
      // Prefer mute prefs: muted connections do not create/refresh alerts
      if (isMutedConn(c)) continue;
      const payloadBase = {
        process: c.process,
        exe: c.exe,
        pid: c.pid,
        remote_ip: c.remote_ip,
        remote_port: c.remote_port,
        local_port: c.local_port,
        local_ip: c.local_ip,
        private_remote: !!c.private_remote,
        direction: c.direction,
        status: c.status,
        proto: c.proto,
        risk: riskScore(c),
        intel: c.intel || null,
        signals: c.signals || [],
        lat: c.lat,
        lon: c.lon,
        country: c.country,
        city: c.city,
        hostname: c.hostname,
        authenticode: c.authenticode || null,
        publisher_hint: c.publisher_hint || null,
        _row_key: rowKey(c),
      };
      if (c.intel && c.intel.hit) {
        const id = alertIdentity(c, "intel");
        seen.add(id);
        upsertStoreAlert(id, {
          payload: Object.assign({}, payloadBase, { signal_id: "intel" }),
          summary: alertSummary(c),
          risk: riskScore(c),
          intelHit: true,
          connKey: rowKey(c),
        });
      }
      for (const s of c.signals || []) {
        if (!s) continue;
        if (!(s.severity === "high" || ACTIONABLE_SIG_IDS.has(s.id))) continue;
        const id = alertIdentity(c, s.id);
        seen.add(id);
        upsertStoreAlert(id, {
          payload: Object.assign({}, payloadBase, {
            signal_id: s.id,
            signal_label: s.label,
            signal_detail: s.detail,
            signal_severity: s.severity,
          }),
          summary: (s.label || s.id) + (c.intel && c.intel.hit ? " · intel" : ""),
          risk: riskScore(c),
          intelHit: !!(c.intel && c.intel.hit),
          connKey: rowKey(c),
        });
      }
    }
    // Lifecycle: active -> stale when not in this snapshot; drop after linger / terminal
    for (const [id, a] of [...alertStore.entries()]) {
      if (a.state === "ack" || a.state === "muted") {
        // Keep terminal briefly for persist, then drop from memory after linger
        if (now - (a.last_seen || 0) > ALERT_LINGER_SEC) {
          alertStore.delete(id);
        }
        continue;
      }
      if (!seen.has(id)) {
        if (a.state === "active") a.state = "stale";
      }
      if (now - (a.last_seen || 0) > ALERT_LINGER_SEC) {
        alertStore.delete(id);
        queueAlertPersist(id); // last write may no-op; ok
      }
    }
  }

  function visibleAlerts() {
    const out = [];
    for (const a of alertStore.values()) {
      if (a.state === "active" || a.state === "stale") out.push(a);
    }
    out.sort((x, y) => (y.risk || 0) - (x.risk || 0) || (y.last_seen || 0) - (x.last_seen || 0));
    return out;
  }

  function ackAlert(id) {
    const a = alertStore.get(id);
    if (!a) return;
    a.state = "ack";
    queueAlertPersist(id);
    twFetch("/api/alerts/ack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    }).catch(() => {});
    renderAlerts();
    updateStatusBannerFromStore();
  }

  function muteAlert(id) {
    const a = alertStore.get(id);
    if (!a) return;
    a.state = "muted";
    const mKey = alertMuteKeyFromPayload(a.payload);
    if (mKey) {
      muteKeys.add(mKey);
      saveMuteKeys(muteKeys);
    }
    queueAlertPersist(id);
    twFetch("/api/alerts/mute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    }).catch(() => {});
    renderAlerts();
    updateStatusBannerFromStore();
    render();
  }

  async function seedAlertsFromServer() {
    if (alertsSeeded) return;
    alertsSeeded = true;
    try {
      const r = await fetch("/api/alerts");
      const j = await r.json();
      for (const row of (j && j.alerts) || []) {
        if (!row || !row.id) continue;
        if (alertStore.has(row.id)) continue;
        alertStore.set(row.id, {
          id: row.id,
          first_seen: row.first_seen,
          last_seen: row.last_seen,
          count: row.count || 1,
          state: row.state || "stale",
          payload: row.payload || {},
          summary: (row.payload && (row.payload.signal_label || row.payload.signal_id)) || "Alert",
          risk: (row.payload && row.payload.risk) || 0,
          intelHit: !!(row.payload && row.payload.intel && row.payload.intel.hit),
          connKey: (row.payload && row.payload._row_key) || "",
        });
      }
      renderAlerts();
      updateStatusBannerFromStore();
    } catch (_) {}
  }

  function muteKeyFor(c) {
    if (!c) return "";
    // ux44: exe identity + port class (NOT PID)
    const proc = String((c.exe || c.process) || "?").trim().toLowerCase();
    return "mute|" + proc + "|" + portClassKey(c);
  }
  function isTrustedConn(c) {
    if (!c) return false;
    const exe = c.exe || "";
    const signer = (c.authenticode && c.authenticode.publisher) || "";
    const hash = c.exe_sha256 || "";
    const tk = trustKeyOf(exe, signer, hash);
    if (tk && trustKeys.some((k) => trustKeyOf(k.exe, k.signer, k.hash) === tk)) return true;
    // compat: path+signer without hash
    const tk2 = trustKeyOf(exe, signer, "");
    if (tk2 && trustKeys.some((k) => trustKeyOf(k.exe, k.signer, "") === tk2 && !k.hash)) return true;
    const e = normExe(exe);
    if (e && trustKeys.some((k) => k.exe === e && !k.signer && !normSigner(signer) && !k.hash)) return true;
    return c.pid != null && trustPids.has(Number(c.pid));
  }
  function isTrustedPid(pid) {
    // Prefer conn-based trust; PID-only kept for group headers that only have pid lists
    if (pid == null) return false;
    if (trustPids.has(Number(pid))) return true;
    const rows = (latest && latest.connections) || [];
    return rows.some((c) => Number(c.pid) === Number(pid) && isTrustedConn(c));
  }
  function toggleTrustFor(d) {
    const exe = (d && d.exe) || "";
    const signer =
      (d && d.authenticode && d.authenticode.publisher) ||
      (d && d.publisher_hint) ||
      "";
    const hash = (d && d.exe_sha256) || "";
    const tk = trustKeyOf(exe, signer, hash);
    if (!tk) return;
    const idx = trustKeys.findIndex((k) => trustKeyOf(k.exe, k.signer, k.hash) === tk);
    if (idx >= 0) trustKeys.splice(idx, 1);
    else trustKeys.push({ exe: normExe(exe), signer: normSigner(signer), hash: normHash(hash) });
    saveTrustKeys(trustKeys);
    // drop legacy pid entry if present
    if (d && d.pid != null && trustPids.has(Number(d.pid))) {
      trustPids.delete(Number(d.pid));
      saveTrustPids(trustPids);
    }
  }
  function isMutedConn(c) {
    return muteKeys.has(muteKeyFor(c));
  }

  function riskScore(c) {
    // Server snapshot includes numeric risk 0–100; fall back to 0.
    const n = c && c.risk != null ? Number(c.risk) : 0;
    return Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : 0;
  }

  function riskRank(c) {
    // Sort key: higher = worse. Trusted PIDs sort lower (display rank demotion).
    let score = riskScore(c);
    if (isTrustedConn(c)) score = Math.max(0, score - 40);
    // Mild intel tie-break so equal scores still prefer intel hits
    if (c && c.intel && c.intel.hit) score += 0.5;
    return score;
  }


  function annotateRemoteGroups(conns) {
    const counts = new Map();
    for (const c of conns || []) {
      if (!c || !c.remote_ip) continue;
      const rk = String(c.remote_ip) + "|" + String(c.remote_port ?? "") + "|" + String(c.direction || "");
      counts.set(rk, (counts.get(rk) || 0) + 1);
    }
    for (const c of conns || []) {
      if (!c || !c.remote_ip) {
        c._remote_group_count = 1;
        continue;
      }
      const rk = String(c.remote_ip) + "|" + String(c.remote_port ?? "") + "|" + String(c.direction || "");
      c._remote_group_count = counts.get(rk) || 1;
    }
    return conns;
  }

  function riskBadgeHtml(score) {
    const s = Math.max(0, Math.min(100, Number(score) || 0));
    if (s <= 0) return ""; // Review 4: hide risk badge when score is 0
    const cls = s >= 70 ? "risk-hot" : s >= 40 ? "risk-warm" : "risk-low";
    return `<span class="risk-badge ${cls}" title="Risk score 0-100">${s}</span>`;
  }

  function isActionableAlert(c) {
    if (!c) return false;
    if (isMutedConn(c)) return false;
    if (c.intel && c.intel.hit) return true;
    for (const s of c.signals || []) {
      if (s.severity === "high") return true;
      if (ACTIONABLE_SIG_IDS.has(s.id)) return true;
    }
    return false;
  }

  function alertSummary(c) {
    const parts = [];
    if (c.intel && c.intel.hit) {
      const lists = (c.intel.lists || []).slice(0, 2).join(",") || "list";
      parts.push("Intel: " + lists);
    }
    for (const s of c.signals || []) {
      if (s.severity === "high" || ACTIONABLE_SIG_IDS.has(s.id)) {
        parts.push(s.label || s.id);
      }
    }
    return parts.slice(0, 4).join(" · ") || "Alert";
  }

  function computeVerdict(rows) {
    let intelHits = 0;
    let highSignals = 0;
    let watchSignals = 0;
    for (const c of rows || []) {
      if (c.intel && c.intel.hit) intelHits += 1;
      for (const s of c.signals || []) {
        if (s.severity === "high") highSignals += 1;
        if (ACTIONABLE_SIG_IDS.has(s.id)) watchSignals += 1;
      }
    }
    if (intelHits > 0) {
      return {
        verdict: "Hits",
        cls: "verdict-hits",
        detail: intelHits + " intel hit" + (intelHits === 1 ? "" : "s")
          + (highSignals ? " · " + highSignals + " high signal" + (highSignals === 1 ? "" : "s") : ""),
      };
    }
    if (highSignals > 0 || watchSignals > 0) {
      const n = highSignals + watchSignals;
      return {
        verdict: "Watch",
        cls: "verdict-watch",
        detail: n + " actionable signal" + (n === 1 ? "" : "s")
          + (highSignals ? " (" + highSignals + " high)" : ""),
      };
    }
    return {
      verdict: "Clear",
      cls: "verdict-clear",
      detail: "No intel hits or high signals",
    };
  }

  function updateStatusBanner(rows) {
    // Prefer alert store so banner does not flash 0-1-0 with one-poll edges.
    if (alertStore && alertStore.size) {
      updateStatusBannerFromStore();
      return;
    }
    const v = computeVerdict(rows);
    let detail = v.detail;
    let maxR = 0;
    for (const c of rows || []) {
      const r = riskScore(c);
      if (r > maxR) maxR = r;
    }
    if (maxR > 0) detail += " · max risk " + maxR;
    if (statusBanner) {
      statusBanner.classList.remove("verdict-clear", "verdict-watch", "verdict-hits");
      statusBanner.classList.add(v.cls);
    }
    if (statusVerdict) statusVerdict.textContent = v.verdict;
    if (statusVerdictDetail) statusVerdictDetail.textContent = detail;
  }

  function updateStatusBannerFromStore() {
    const vis = visibleAlerts();
    let intelHits = 0;
    let highSignals = 0;
    let watchSignals = 0;
    let maxR = 0;
    for (const a of vis) {
      if (a.intelHit) intelHits += 1;
      const sid = a.payload && a.payload.signal_id;
      const sev = a.payload && a.payload.signal_severity;
      if (sev === "high") highSignals += 1;
      if (sid && ACTIONABLE_SIG_IDS.has(sid)) watchSignals += 1;
      if ((a.risk || 0) > maxR) maxR = a.risk || 0;
    }
    let verdict, cls, detail;
    if (intelHits > 0) {
      verdict = "Hits";
      cls = "verdict-hits";
      detail =
        intelHits +
        " intel hit" +
        (intelHits === 1 ? "" : "s") +
        (highSignals ? " · " + highSignals + " high signal" + (highSignals === 1 ? "" : "s") : "");
    } else if (highSignals > 0 || watchSignals > 0 || vis.length > 0) {
      const n = Math.max(vis.length, highSignals + watchSignals);
      verdict = "Watch";
      cls = "verdict-watch";
      detail = n + " open alert" + (n === 1 ? "" : "s");
    } else {
      verdict = "Clear";
      cls = "verdict-clear";
      detail = "No intel hits or high signals";
    }
    if (maxR > 0) detail += " · max risk " + maxR;
    if (statusBanner) {
      statusBanner.classList.remove("verdict-clear", "verdict-watch", "verdict-hits");
      statusBanner.classList.add(cls);
    }
    if (statusVerdict) statusVerdict.textContent = verdict;
    if (statusVerdictDetail) statusVerdictDetail.textContent = detail;
  }

  function setActiveTab(tab) {
    activeTab = (tab === "alerts" || tab === "status") ? tab : "live";
    hideTip(); // ux44: sticky hover tooltip off on tab change
    saveListTab(activeTab);
    if (tabLive) {
      tabLive.classList.toggle("active", activeTab === "live");
      tabLive.setAttribute("aria-selected", activeTab === "live" ? "true" : "false");
    }
    if (tabAlerts) {
      tabAlerts.classList.toggle("active", activeTab === "alerts");
      tabAlerts.setAttribute("aria-selected", activeTab === "alerts" ? "true" : "false");
    }
    if (tabStatus) {
      tabStatus.classList.toggle("active", activeTab === "status");
      tabStatus.setAttribute("aria-selected", activeTab === "status" ? "true" : "false");
    }
    if (connList) {
      connList.classList.toggle("hidden", activeTab !== "live");
      if (activeTab === "live") connList.removeAttribute("hidden");
      else connList.setAttribute("hidden", "");
    }
    if (alertsList) {
      alertsList.classList.toggle("hidden", activeTab !== "alerts");
      if (activeTab === "alerts") alertsList.removeAttribute("hidden");
      else alertsList.setAttribute("hidden", "");
    }
    if (statusPanel) {
      statusPanel.classList.toggle("hidden", activeTab !== "status");
      if (activeTab === "status") statusPanel.removeAttribute("hidden");
      else statusPanel.setAttribute("hidden", "");
    }
    if (procFoldBtn) {
      procFoldBtn.style.display = activeTab === "live" ? "" : "none";
    }
  }

  function focusConnection(c) {
    if (!c) return;
    const key = rowKey(c);
    selectedKey = key;
    withMap((M) => {
      M.setSelected(key);
      if (c.lat != null) M.focusLatLng(c.lat, c.lon);
    });
    // Ensure Live tab + expanded group + sidebar open so row is visible
    setActiveTab("live");
    if (!sidebarOpen) {
      sidebarOpen = true;
      saveSidebarOpen(true);
      applySidebar(true);
    }
    const name = c.process || "?";
    openProcs.delete("!" + name);
    openProcs.add(name);
    saveOpenProcs();
    render();
    requestAnimationFrame(() => {
      const row = connList && connList.querySelector(`.conn-row[data-key="${cssEscape(key)}"]`);
      if (row) row.scrollIntoView({ block: "nearest", behavior: "smooth" });
    });
  }

  function renderAlerts() {
    if (!alertsList) return;
    hideTip(); // ux44: sticky tip off on alerts list rebuild
    const alerts = visibleAlerts();
    // Banner + count use active+stale (unacked, unmuted) — no 0-1-0 flash
    if (alertCountEl) alertCountEl.textContent = String(alerts.length);
    if (!alerts.length) {
      alertsList.innerHTML = `<p class="alerts-empty">No alerts</p>`;
      return;
    }
    const now = Date.now() / 1000;
    const frag = document.createDocumentFragment();
    for (const a of alerts.slice(0, 200)) {
      const p = a.payload || {};
      const el = document.createElement("div");
      const connKey = a.connKey || p._row_key || "";
      el.className =
        "alert-row" +
        (connKey && connKey === selectedKey ? " active" : "") +
        (a.intelHit ? " intel-hit" : "") +
        (a.state === "stale" ? " alert-stale" : "");
      el.dataset.key = connKey;
      el.dataset.alertId = a.id;
      const remote = p.remote_ip
        ? `${p.remote_ip}${p.remote_port != null ? ":" + p.remote_port : ""}`
        : p.direction === "listen" || String(p.status || "").toUpperCase() === "LISTEN"
          ? `LISTEN :${p.local_port ?? "?"}`
          : "—";
      const agoSec = Math.max(0, now - (a.last_seen || now));
      const agoMin = Math.max(1, Math.round(agoSec / 60));
      const staleBit =
        a.state === "stale"
          ? `<span class="alert-stale-label">last seen ${agoMin}m ago</span>`
          : `<span class="alert-count-label">x${a.count || 1}</span>`;
      const fakeConn = {
        intel: p.intel,
        signals: p.signals || [],
        process: p.process,
        pid: p.pid,
        remote_ip: p.remote_ip,
        remote_port: p.remote_port,
        local_port: p.local_port,
        local_ip: p.local_ip,
        private_remote: p.private_remote,
        direction: p.direction,
        status: p.status,
        proto: p.proto,
        risk: p.risk,
        lat: p.lat,
        lon: p.lon,
        exe: p.exe,
        authenticode: p.authenticode,
        publisher_hint: p.publisher_hint,
        _row_key: connKey,
      };
      const canBlock = isPublicRemoteIp(p.remote_ip, p.private_remote);
      el.innerHTML = `
        <div class="alert-main">
          ${riskBadgeHtml(a.risk != null ? a.risk : riskScore(fakeConn))}
          <span class="alert-proc">${escapeHtml(p.process || "?")}</span>
          <span class="alert-pid">PID ${p.pid ?? "—"}</span>
          <span class="alert-remote">${escapeHtml(remote)}</span>
          ${staleBit}
        </div>
        <div class="alert-why">${escapeHtml(a.summary || alertSummary(fakeConn))}</div>
        <div class="alert-badges">${intelBadge(fakeConn)}${signalChips(fakeConn)}</div>
        <div class="alert-actions">
          <button type="button" class="btn btn-xs" data-alert-open="${escapeHtml(a.id)}">Open</button>
          <button type="button" class="btn btn-xs" data-alert-inspect="${p.pid ?? ""}" ${p.pid == null ? "disabled" : ""}>Inspect</button>
          <button type="button" class="btn btn-xs warn" data-alert-block="${escapeHtml(a.id)}" ${canBlock ? "" : "disabled"}>Block</button>
          <button type="button" class="btn btn-xs" data-alert-copy="${escapeHtml(a.id)}">Copy</button>
          <button type="button" class="btn btn-xs" data-alert-ack="${escapeHtml(a.id)}">Acknowledge</button>
          <button type="button" class="btn btn-xs" data-alert-mute="${escapeHtml(a.id)}">Mute</button>
        </div>
      `;
      el.addEventListener("click", (e) => {
        if (e.target.closest(".alert-actions")) return;
        openAlertDetail(a);
        highlightConnectionQuiet(fakeConn);
      });
      el.querySelector("[data-alert-open]")?.addEventListener("click", (e) => {
        e.stopPropagation();
        openAlertDetail(a);
        highlightConnectionQuiet(fakeConn);
      });
      el.querySelector("[data-alert-inspect]")?.addEventListener("click", (e) => {
        e.stopPropagation();
        if (p.pid != null) openInspect(p.pid);
      });
      el.querySelector("[data-alert-block]")?.addEventListener("click", (e) => {
        e.stopPropagation();
        if (!canBlock) return;
        openFwConfirm(p.remote_ip, "block", null, { process: p.process || "", pid: p.pid });
      });
      el.querySelector("[data-alert-copy]")?.addEventListener("click", (e) => {
        e.stopPropagation();
        copyAlertFields(a);
      });
      el.querySelector("[data-alert-ack]")?.addEventListener("click", (e) => {
        e.stopPropagation();
        ackAlert(a.id);
      });
      el.querySelector("[data-alert-mute]")?.addEventListener("click", (e) => {
        e.stopPropagation();
        muteAlert(a.id);
      });
      frag.appendChild(el);
    }
    alertsList.innerHTML = "";
    alertsList.appendChild(frag);
  }

  function intelBadge(c) {
    if (!c || !c.intel || !c.intel.hit) return "";
    const lists = (c.intel.lists || []).slice(0, 3).join(",");
    return `<span class="badge-intel" title="Threat intel: ${escapeHtml(lists)} · ${escapeHtml(c.intel.severity || "")}">INTEL</span>`;
  }

  function signalChips(c) {
    const sigs = (c && c.signals) || [];
    if (!sigs.length) return "";
    // Cap chips in list to avoid flood
    return (
      `<div class="sig-chips">` +
      sigs
        .slice(0, 3)
        .map((s) => {
          const sev = s.severity === "medium" || s.severity === "high" ? "sev-medium" : s.severity === "info" ? "sev-info" : "";
          return `<span class="sig-chip ${sev}" title="${escapeHtml(s.detail || s.label || "")}">${escapeHtml(s.label || s.id)}</span>`;
        })
        .join("") +
      `</div>`
    );
  }

  function pubHintHtml(c) {
    // Prefer live authenticode status when present; fall back to publisher_hint.
    // checking while queued/running/retrying; unverified only after real failure;
    // no exe / system -> unknown|system (never fake unverified).
    const auth = c && c.authenticode;
    let h = (c && c.publisher_hint) || "";
    if (auth) {
      const st = String(auth.status || "").toLowerCase();
      if (st === "pending" || st === "checking") h = "checking";
      else if (st === "timeout" || st === "error") h = "unverified";
      else if (st === "unknown" || st === "missing" || st === "unsupported" || st === "skipped") h = "unknown";
      else if (st === "system") h = "system";
    }
    if (!h) h = "unknown";
    if (h === "…" || h === "checking") {
      return `<span class="pub-hint checking" title="Authenticode checking">checking</span>`;
    }
    if (h === "unverified") {
      return `<span class="pub-hint unverified" title="Authenticode unverified">unverified</span>`;
    }
    if (h === "unknown" || h === "system") {
      return `<span class="pub-hint muted" title="No executable path">${escapeHtml(h)}</span>`;
    }
    const cls = h === "unsigned" ? "unsigned" : h === "Microsoft" ? "microsoft" : "";
    return `<span class="pub-hint ${cls}" title="Authenticode / publisher">${escapeHtml(h)}</span>`;
  }

  function authInspectHtml(auth) {
    if (!auth) return `<span class="muted">unknown</span>`;
    const st = String(auth.status || "").toLowerCase();
    if (st === "pending" || st === "checking") return `<span class="pub-hint checking">checking</span>`;
    if (st === "timeout" || st === "error") {
      return `<span class="pub-hint unverified">unverified</span>`;
    }
    if (st === "notsigned") {
      return `<span class="pub-hint unsigned">unsigned</span>`;
    }
    if (st === "unknown" || st === "missing" || st === "unsupported" || st === "skipped" || st === "system") {
      return `<span class="muted">${escapeHtml(st === "system" ? "system" : "unknown")}</span>`;
    }
    if (auth.signed === false) {
      return `<span class="pub-hint unverified">unverified</span>`;
    }
    if (auth.signed === true) {
      const pub = (auth.publisher || "").trim() || "signed";
      return `<span class="pub-hint microsoft">${escapeHtml(pub)}</span> <span class="muted">(${escapeHtml(auth.status || "Valid")})</span>`;
    }
    return `<span class="muted">${escapeHtml(st || "unknown")}</span>`;
  }


  function updateFilterHint(filtered) {
    if (!filterHint) return;
    const dirMode = dirFilter || "all";
    // Auto-ignore already applied for inbound/listen; still explain quiet empty views
    if (dirMode === "inbound" && filtered.length === 0) {
      const rawIn = latest.filter((c) => c.direction === "inbound").length;
      filterHint.classList.remove("hidden");
      if (rawIn === 0) {
        filterHint.innerHTML = `<span>No inbound connections right now (quiet).</span>`;
      } else {
        filterHint.innerHTML = `<span>Inbound rows exist but other filters hid them.</span>
          <button type="button" class="btn btn-xs" id="filter-hint-fix">Show all filters off for In</button>`;
        filterHint.querySelector("#filter-hint-fix")?.addEventListener("click", () => {
          fEstablished.checked = false;
          fHidePrivate.checked = false;
          fMapped.checked = false;
          saveFilters();
          render();
        });
      }
      return;
    }
    if (dirMode === "listen" && filtered.length === 0) {
      const rawL = latest.filter((c) => c.direction === "listen" || (c.status || "").toUpperCase() === "LISTEN").length;
      filterHint.classList.remove("hidden");
      if (rawL === 0) {
        filterHint.innerHTML = `<span>No listening sockets in this snapshot.</span>`;
      } else {
        filterHint.innerHTML = `<span>Listening rows exist but other filters hid them.</span>
          <button type="button" class="btn btn-xs" id="filter-hint-fix">Clear Mapped / search</button>`;
        filterHint.querySelector("#filter-hint-fix")?.addEventListener("click", () => {
          fMapped.checked = false;
          fProcess.value = "";
          fCountry.value = "";
          fPort.value = "";
          saveFilters();
          render();
        });
      }
      return;
    }
    // Established + Hide private can wipe Live when all ESTABLISHED remotes are private
    if (
      filtered.length === 0 &&
      latest.length > 0 &&
      (dirMode === "all" || dirMode === "outbound") &&
      fEstablished.checked &&
      fHidePrivate.checked
    ) {
      filterHint.classList.remove("hidden");
      filterHint.innerHTML =
        `<span>Many of ${latest.length} rows are hidden by Established + Hide private.</span>
        <button type="button" class="btn btn-xs" id="filter-hint-show-private">Show private remotes</button>
        <button type="button" class="btn btn-xs" id="filter-hint-clear-est">Clear Established</button>`;
      const btnP = filterHint.querySelector("#filter-hint-show-private");
      if (btnP) {
        btnP.addEventListener("click", () => {
          fHidePrivate.checked = false;
          saveFilters();
          render();
        });
      }
      const btnE = filterHint.querySelector("#filter-hint-clear-est");
      if (btnE) {
        btnE.addEventListener("click", () => {
          fEstablished.checked = false;
          saveFilters();
          render();
        });
      }
      return;
    }
    // When All/Out with hide-private hiding listen/inbound interest — optional one-line
    if ((dirMode === "all" || dirMode === "outbound") && fHidePrivate.checked) {
      const hiddenListen = latest.some((c) => c.direction === "listen");
      const hiddenIn = latest.some((c) => c.direction === "inbound" && c.private_remote);
      // Keep quiet unless user selected inbound/listen (handled above)
    }
    filterHint.classList.add("hidden");
    filterHint.innerHTML = "";
  }

  if (connList && !connList.dataset.twHoverWired) {
    connList.dataset.twHoverWired = "1";
    connList.addEventListener("pointerenter", () => { listPointerInside = true; });
    connList.addEventListener("pointerleave", () => {
      listPointerInside = false;
      hideTip(); // ux44: sticky tooltip off on list-container pointerleave
    });
  }
  if (alertsList && !alertsList.dataset.twHoverWired) {
    alertsList.dataset.twHoverWired = "1";
    alertsList.addEventListener("pointerenter", () => { alertsPointerInside = true; });
    alertsList.addEventListener("pointerleave", () => {
      alertsPointerInside = false;
      hideTip();
    });
  }

  function listDomRebuildPaused() {
    if (listPointerInside) return true;
    const im = document.getElementById("inspect-modal");
    if (im && !im.classList.contains("hidden") && im.getAttribute("aria-hidden") !== "true") return true;
    return false;
  }

  function alertsDomRebuildPaused() {
    if (alertsPointerInside) return true;
    const am = document.getElementById("alert-modal");
    if (am && !am.classList.contains("hidden") && am.getAttribute("aria-hidden") !== "true") return true;
    const im = document.getElementById("inspect-modal");
    if (im && !im.classList.contains("hidden") && im.getAttribute("aria-hidden") !== "true") return true;
    return false;
  }

  function render(opts) {
    const fromSnapshot = !!(opts && opts.fromSnapshot);
    try {
      migrateTrustPidsOnce(Array.isArray(latest) ? latest : (latest && latest.connections) || []);
      trustKeys = loadTrustKeys();
    } catch (_) {}

    const filtered = latest.filter(passes);
    const mapped = filtered.filter((c) => c.lat != null && c.lon != null);
    const nIn = latest.filter((c) => c.direction === "inbound").length;
    const nListen = latest.filter((c) => c.direction === "listen" || (c.status || "").toUpperCase() === "LISTEN").length;
    const nInPublic = latest.filter((c) => c.direction === "inbound" && c.remote_ip && !c.private_remote).length;
    // e.g. "19 conns · 2 in · 5 listening"
    const chipCount = document.getElementById("chip-count");
    if (chipCount) {
      chipCount.textContent = `${filtered.length} conns · ${nIn} in · ${nListen} listening`;
      chipCount.classList.toggle("chip-inbound-public", nInPublic > 0);
      chipCount.title = nInPublic > 0
        ? (`${nInPublic} inbound from public IP` + (nInPublic === 1 ? "" : "s"))
        : "Connection counts (filtered list length · all inbound · listening)";
    } else if (statCount) {
      statCount.textContent = String(filtered.length);
    }
    statMapped.textContent = String(mapped.length);
    if (focusProc) {
      listMeta.textContent = `${filtered.length} / ${latest.length} · globe: ${focusProc}`;
    } else {
      listMeta.textContent = `${filtered.length} / ${latest.length}`;
    }
    updateClearFocusBtn();
    updateFilterHint(filtered);

    for (const c of mapped) c._key = rowKey(c);
    withMap((M) => {
      if (M.setProcessFilter) M.setProcessFilter(focusProc);
      M.upsert(mapped);
      M.setSelected(selectedKey);
    });

    if (topTalkers && topTalkers.length) {
      chipTalkers.textContent =
        "top: " +
        topTalkers
          .slice(0, 3)
          .map((t) => `${t.process} (${fmtRate((t.bytes_in_rate || 0) + (t.bytes_out_rate || 0))})`)
          .join(" · ");
    } else if (window.__twRatesHelperNeeded) {
      chipTalkers.textContent = "rates: helper needed";
      chipTalkers.title = "Per-connection rates need Settings -> Enable live DNS (admin) for helper TCP bytes";
    } else {
      chipTalkers.textContent = "rates: —";
    }

    // Risk / severity first (intel > high signals > rest); mapped as tie-break
    filtered.sort((a, b) => {
      const d = riskRank(b) - riskRank(a);
      if (d) return d;
      const am = a.lat != null ? 0 : 1;
      const bm = b.lat != null ? 0 : 1;
      if (am !== bm) return am - bm;
      const ar = (a.bytes_in_rate || 0) + (a.bytes_out_rate || 0);
      const br = (b.bytes_in_rate || 0) + (b.bytes_out_rate || 0);
      if (br !== ar) return br - ar;
      return (a.process || "").localeCompare(b.process || "");
    });

    const capped = filtered.slice(0, 400);
    const groups = groupByProcess(capped);
    if (!groups.length) {
      const empty = document.createElement("p");
      empty.className = "list-empty";
      if ((dirFilter || "all") === "inbound") {
        empty.textContent = "No inbound connections to show (quiet, or filtered).";
      } else if ((dirFilter || "all") === "listen") {
        empty.textContent = "No listening sockets to show.";
      } else {
        empty.textContent = "No connections match the current filters (Established + Hide private may hide all).";
      }
      const pauseLiveEmpty = fromSnapshot && listDomRebuildPaused();
      if (activeTab === "live" && connList && !pauseLiveEmpty) {
        hideTip();
        connList.innerHTML = "";
        connList.appendChild(empty);
      }
      ingestAlertsFromRows(latest);
      if (!(fromSnapshot && alertsDomRebuildPaused())) {
        renderAlerts();
      } else if (alertCountEl) {
        alertCountEl.textContent = String(visibleAlerts().length);
      }
      updateStatusBannerFromStore();
      return;
    }
    // Default: first visit expands nothing stored → expand groups that have selected, else first 6
    const frag = document.createDocumentFragment();

    for (const [procName, conns] of groups) {
      const group = document.createElement("div");
      group.className = "proc-group" + (focusProc === procName ? " proc-focused" : "");
      group.dataset.proc = procName;

      const pids = [...new Set(conns.map((c) => c.pid).filter((p) => p != null))];
      const hasSelected = conns.some((c) => rowKey(c) === selectedKey);
      let isOpen;
      if (focusProc === procName) isOpen = true;
      else if (openProcs.has(procName)) isOpen = true;
      else if (openProcs.has("!" + procName)) isOpen = false;
      else isOpen = false; // default collapsed; only explicit name stays open

      if (!isOpen) group.classList.add("collapsed");

      const head = document.createElement("button");
      head.type = "button";
      head.className = "proc-group-head";
      const maxRisk = Math.max(0, ...conns.map(riskScore));
      const riskCls = maxRisk >= 70 ? "risk-hot" : maxRisk >= 40 ? "risk-warm" : "";
      const anyTrusted = pids.some((pid) => isTrustedPid(pid));
      head.innerHTML = `
        <span class="acc-chevron" aria-hidden="true">▾</span>
        <span class="proc-group-title" title="Click process name to filter globe (Clear focus to reset)">${escapeHtml(procName)}</span>
        ${anyTrusted ? '<span class="trust-badge" title="Trusted PID">trusted</span>' : ""}
        <span class="proc-group-meta ${riskCls}">${riskBadgeHtml(maxRisk)} · ${conns.length} · PID ${pids.slice(0, 3).map(String).join(",")}${pids.length > 3 ? "…" : ""}</span>
      `;
      head.addEventListener("click", (e) => {
        e.stopPropagation();
        // Process name only: toggle globe process filter (Clear focus stays visible)
        if (e.target.closest(".proc-group-title")) {
          if (focusProc === procName) {
            clearGlobeFocus();
            render();
            return;
          }
          focusProc = procName;
          updateClearFocusBtn();
          const firstMapped = conns.find((c) => c.lat != null && c.lon != null);
          if (firstMapped) {
            selectedKey = rowKey(firstMapped);
            withMap((M) => M.setSelected(selectedKey));
          } else {
            selectedKey = null;
            withMap((M) => M.setSelected(null));
          }
          withMap((M) => { if (M.setProcessFilter) M.setProcessFilter(focusProc); });
          render();
          withMap((M) => { if (firstMapped) M.focusLatLng(firstMapped.lat, firstMapped.lon); });
          return;
        }
        // Chevron / meta / rest of header: expand/collapse only (does NOT filter globe)
        const nowCollapsed = !group.classList.contains("collapsed");
        group.classList.toggle("collapsed", nowCollapsed);
        if (nowCollapsed) {
          openProcs.delete(procName);
          openProcs.add("!" + procName);
        } else {
          openProcs.delete("!" + procName);
          openProcs.add(procName);
        }
        saveOpenProcs();
      });

      const bodyEl = document.createElement("div");
      bodyEl.className = "proc-group-body";
      const colHead = document.createElement("div");
      colHead.className = "conn-cols-head";
      colHead.innerHTML = `<span>PID</span><span>Remote</span><span>Dir</span><span>Risk / signals</span><span></span><span>Rate</span>`;
      bodyEl.appendChild(colHead);

      annotateRemoteGroups(conns);
      for (const c of conns) {
        const row = document.createElement("div");
        const key = rowKey(c);
        const isIntel = !!(c.intel && c.intel.hit);
        row.className = "conn-row" + (key === selectedKey ? " active" : "") + (isIntel ? " intel-hit" : "");
        row.dataset.key = key;
        const host = c.hostname ? `<div class="host">${escapeHtml(c.hostname)}</div>` : "";
        const remote = c.remote_ip
          ? `${c.remote_ip}${c.remote_port != null ? ":" + c.remote_port : ""}`
          : (c.direction === "listen" || String(c.status || "").toUpperCase() === "LISTEN"
              ? `LISTEN`
              : "—");
        const localBit =
          c.local_port != null
            ? `<span class="remote-local" title="Local port">:${c.local_port}</span>`
            : "";
        const dupCount = c._remote_group_count && c._remote_group_count > 1
          ? `<span class="remote-count" title="Identical remotes">${c._remote_group_count}x</span>`
          : "";
        const place = [c.city, c.country].filter(Boolean).join(", ") || "—";
        const sm = smoothRate(
          key,
          c.bytes_in_rate_share != null ? c.bytes_in_rate_share : c.bytes_in_rate,
          c.bytes_out_rate_share != null ? c.bytes_out_rate_share : c.bytes_out_rate
        );
        const rate =
          c.bytes_in_rate != null || c.bytes_out_rate != null
            ? `↓${fmtRate(sm.in)} ↑${fmtRate(sm.out)}`
            : "—";
        const risk = riskScore(c);
        const trusted = isTrustedConn(c);
        if (trusted) row.classList.add("trusted");
        row.innerHTML = `
          <div class="c-pid" title="PID">${c.pid ?? "—"}</div>
          <div class="c-remote" title="${escapeHtml(place)}">
            <span class="remote">${escapeHtml(remote)}</span>${dupCount}${localBit}${host}
          </div>
          <div class="c-dir">${dirChipHtml(c)}</div>
          <div class="c-sigs">${riskBadgeHtml(risk)}${trusted ? '<span class="trust-badge">trusted</span>' : ""}${intelBadge(c)}${signalChips(c)}${pubHintHtml(c)}</div>
          <div class="c-actions row-actions">
            <button type="button" class="btn btn-xs" data-inspect="${c.pid ?? ""}" title="Inspect process">Inspect</button>
          </div>
          <div class="c-rate rate" title="${escapeHtml((c.rate_source === "helper_tcp") ? ("Helper TCP" + (c.duration_ms != null ? (" - " + Math.round(c.duration_ms/1000) + "s") : "") + (c.conn_bytes_out != null ? (" out " + c.conn_bytes_out + "B") : "") + (c.conn_bytes_in != null ? (" in " + c.conn_bytes_in + "B") : "")) : "Per-process network EMA / share")}">${rate}</div>
        `;
        row.dataset.risk = String(risk);
        const tip = mapOk() ? window.TWMap.tipHtml(c) : "";
        row.addEventListener("mouseenter", (e) => {
          const tipEl = tipElRef();
          if (tipEl) tipEl.dataset.follow = "1";
          showTipHtml(tip, e.clientX, e.clientY);
        });
        row.addEventListener("mousemove", (e) => {
          const tipEl = tipElRef();
          if (tipEl) tipEl.dataset.follow = "1";
          showTipHtml(tip, e.clientX, e.clientY);
        });
        row.addEventListener("mouseleave", () => {
          const tipEl = tipElRef();
          if (tipEl) tipEl.dataset.follow = "0";
          hideTip();
        });
        row.addEventListener("click", (e) => {
          if (e.target.closest("[data-inspect]")) return;
          const proc = c.process || "?";
          // Same already-active row again: deselect + full globe
          if (selectedKey === key && focusProc === proc) {
            clearGlobeFocus();
            render();
            return;
          }
          focusProc = proc;
          selectedKey = key;
          withMap((M) => {
            M.setSelected(key);
            if (M.setProcessFilter) M.setProcessFilter(focusProc);
            if (c.lat != null) M.focusLatLng(c.lat, c.lon);
          });
          render();
        });
        bodyEl.appendChild(row);
      }

      group.appendChild(head);
      group.appendChild(bodyEl);
      frag.appendChild(group);
    }

    const pauseLive = fromSnapshot && listDomRebuildPaused();
    if (connList && !pauseLive) {
      hideTip(); // ux44: hide sticky tip on list rebuild
      connList.innerHTML = "";
      connList.appendChild(frag);
    }
    ingestAlertsFromRows(latest);
    if (!(fromSnapshot && alertsDomRebuildPaused())) {
      renderAlerts();
    } else if (alertCountEl) {
      alertCountEl.textContent = String(visibleAlerts().length);
    }
    updateStatusBannerFromStore();
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function copyTextFallback(text, done) {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      if (done) done();
    } catch (_) {
      showToast("Copy failed", "", { key: "copy-fail|" + Date.now(), sev: "info", ttl: 2500 });
    }
  }

  function copyText(value, label) {
    const text = value == null ? "" : String(value);
    if (!text || text === "—") {
      showToast("Nothing to copy", label || "", { key: "copy-empty|" + Date.now(), sev: "info", ttl: 2500 });
      return;
    }
    const nice = label || "value";
    const done = () =>
      showToast(
        "Copied " + nice,
        text.length > 90 ? text.slice(0, 87) + "..." : text,
        { key: "copy|" + Date.now(), sev: "info", ttl: 2500 }
      );
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(() => copyTextFallback(text, done));
    } else {
      copyTextFallback(text, done);
    }
  }

  function copyableHtml(label, value) {
    const v = value == null || value === "" ? "—" : String(value);
    const empty = v === "—";
    return (
      '<div class="copy-field">' +
      '<span class="copy-label">' +
      escapeHtml(label) +
      "</span>" +
      '<code class="copy-value" tabindex="0">' +
      escapeHtml(v) +
      "</code>" +
      '<button type="button" class="btn btn-xs copy-btn" data-copy="' +
      escapeHtml(empty ? "" : v) +
      '" data-copy-label="' +
      escapeHtml(label) +
      '"' +
      (empty ? " disabled" : "") +
      ">Copy</button></div>"
    );
  }

  function copyableDd(value, label) {
    const v = value == null || value === "" ? "—" : String(value);
    const empty = v === "—";
    return (
      '<span class="copy-value" tabindex="0">' +
      escapeHtml(v) +
      "</span>" +
      (empty
        ? ""
        : ' <button type="button" class="btn btn-xs copy-btn" data-copy="' +
          escapeHtml(v) +
          '" data-copy-label="' +
          escapeHtml(label) +
          '">Copy</button>')
    );
  }

  function isPublicRemoteIp(ip, privateFlag) {
    if (privateFlag) return false;
    if (!ip) return false;
    const s = String(ip).trim().toLowerCase();
    if (!s || s === "—" || s === "*" || s === "::" || s === "0.0.0.0") return false;
    if (s === "::1" || s === "localhost") return false;
    if (s.startsWith("127.") || s.startsWith("10.") || s.startsWith("192.168.") || s.startsWith("169.254.")) return false;
    if (s.startsWith("fe80:") || s.startsWith("fc") || s.startsWith("fd")) return false;
    const m = /^172\.(\d+)\./.exec(s);
    if (m) {
      const n = Number(m[1]);
      if (n >= 16 && n <= 31) return false;
    }
    return true;
  }

  function highlightConnectionQuiet(c) {
    if (!c) return;
    const key = c._row_key || rowKey(c);
    if (!key) return;
    selectedKey = key;
    withMap((M) => {
      M.setSelected(key);
      if (c.lat != null) M.focusLatLng(c.lat, c.lon);
    });
  }

  [fProcess, fCountry, fPort, fEstablished, fMapped, fHidePrivate].forEach((el) => {
    el.addEventListener("input", () => {
      saveFilters();
      render();
    });
    el.addEventListener("change", () => {
      saveFilters();
      render();
    });
  });


  function setStatLine(text, cls) {
    if (!statStatus) return;
    statStatus.textContent = text;
    if (cls === "warn") statStatus.classList.add("warn");
    if (cls === "bad") statStatus.classList.add("bad");
  }

  // --- Threat intel modal (ux29): header opens view; Refresh lives inside ---
  const intelModal = document.getElementById("intel-modal");
  const intelStatusStrip = document.getElementById("intel-status-strip");
  const intelHitsEl = document.getElementById("intel-hits");
  const btnIntel = document.getElementById("btn-intel");
  const btnIntelRefresh = document.getElementById("intel-refresh");
  const btnIntelOpenCache = document.getElementById("intel-open-cache");
  let intelCacheDir = "";
  let intelRefreshingUi = false;

  function closeIntelModal() {
    if (!intelModal) return;
    intelModal.classList.add("hidden");
    intelModal.setAttribute("aria-hidden", "true");
  }

  function fmtIntelTs(ts) {
    if (ts == null || ts === "") return "—";
    const n = Number(ts);
    if (!Number.isFinite(n) || n <= 0) return "—";
    try {
      return new Date(n * 1000).toLocaleString();
    } catch (_) {
      return "—";
    }
  }

  function renderIntelStatus(j) {
    if (!intelStatusStrip) return;
    if (!j || j.ok === false) {
      intelStatusStrip.innerHTML =
        '<span class="intel-chip warn">' + escapeHtml((j && j.error) || "Failed to load status") + "</span>";
      if (intelHitsEl) intelHitsEl.innerHTML = '<p class="intel-hits-empty">No intel hits right now.</p>';
      return;
    }
    intelCacheDir = j.cache_dir || "";
    if (j && j.refreshing === false) intelRefreshingUi = false;
    const refreshing = !!(j.refreshing);
    const counts = j.counts || {};
    const total =
      (Number(counts.ips) || 0) + (Number(counts.cidrs) || 0) + (Number(counts.domains) || 0);
    const lists = j.lists || [];
    let chips =
      '<span class="intel-chip">' +
      (refreshing
        ? "<strong>Refreshing…</strong>"
        : "<strong>" + lists.length + "</strong> lists") +
      "</span>" +
      '<span class="intel-chip muted-chip">~' +
      total +
      " entries</span>" +
      '<span class="intel-chip muted-chip">Last refresh: ' +
      escapeHtml(fmtIntelTs(j.last_refresh)) +
      "</span>";
    if (j.hit_count != null) {
      chips +=
        '<span class="intel-chip">' +
        "<strong>" +
        Number(j.hit_count) +
        "</strong> snapshot hit" +
        (Number(j.hit_count) === 1 ? "" : "s") +
        "</span>";
    }
    const listMeta =
      '<ul class="intel-list-meta">' +
      lists
        .map((L) => {
          const err = L.error ? ' · <span class="kill-error">' + escapeHtml(String(L.error).slice(0, 80)) + "</span>" : "";
          return (
            "<li><span class=\"il-name\">" +
            escapeHtml(L.name || L.id || "list") +
            "</span><span>" +
            (L.entries != null ? L.entries : 0) +
            " entries</span><span>" +
            escapeHtml(fmtIntelTs(L.updated_at)) +
            "</span>" +
            err +
            "</li>"
          );
        })
        .join("") +
      "</ul>";
    intelStatusStrip.innerHTML = chips + listMeta;

    const hits = j.hits || [];
    if (!intelHitsEl) return;
    if (!hits.length) {
      intelHitsEl.innerHTML = '<p class="intel-hits-empty">No intel hits right now.</p>';
      return;
    }
    const rows = hits
      .map((h) => {
        const ip = h.remote_ip || "—";
        const proc =
          (h.process || "—") + (h.pid != null ? " · PID " + h.pid : "");
        const listsTxt = (h.lists || []).slice(0, 4).join(", ") || "—";
        const sev = (h.severity || "—").toLowerCase();
        return (
          "<tr>" +
          "<td>" +
          copyableHtml("IP", ip === "—" ? "" : ip).replace(
            'class="copy-field"',
            'class="copy-field intel-ip-field"'
          ) +
          "</td>" +
          "<td>" +
          escapeHtml(proc) +
          "</td>" +
          "<td>" +
          escapeHtml(listsTxt) +
          "</td>" +
          '<td><span class="intel-sev ' +
          escapeHtml(sev) +
          '">' +
          escapeHtml(h.severity || "—") +
          "</span></td>" +
          "</tr>"
        );
      })
      .join("");
    intelHitsEl.innerHTML =
      '<table class="intel-hits-table"><thead><tr>' +
      "<th>Remote IP</th><th>Process / PID</th><th>List(s)</th><th>Severity</th>" +
      "</tr></thead><tbody>" +
      rows +
      "</tbody></table>" +
      (j.hits_capped
        ? '<p class="muted" style="margin-top:0.45rem;font-size:0.7rem">Showing first 200 snapshot hits.</p>'
        : "");
  }

  async function loadIntelStatus() {
    try {
      const r = await twFetch("/api/intel/status");
      const j = await r.json();
      renderIntelStatus(j);
      return j;
    } catch (_) {
      renderIntelStatus({ ok: false, error: "Request failed" });
      return null;
    }
  }

  async function openIntelModal() {
    if (!intelModal) return;
    intelModal.classList.remove("hidden");
    intelModal.setAttribute("aria-hidden", "false");
    if (intelStatusStrip) intelStatusStrip.textContent = "Loading…";
    if (intelHitsEl) intelHitsEl.innerHTML = "";
    await loadIntelStatus();
  }

  async function refreshIntelLists() {
    if (intelRefreshingUi) return;
    intelRefreshingUi = true;
    if (btnIntelRefresh) {
      btnIntelRefresh.disabled = true;
      btnIntelRefresh.textContent = "…";
    }
    showToast("Intel", "Refreshing threat-intel lists...", {
      sev: "info",
      key: "intel-go|" + Date.now(),
      ttl: 5000,
    });
    try {
      const r = await twFetch("/api/intel/refresh", { method: "POST" });
      const j = await r.json();
      if (!r.ok) {
        setStatLine(j.error || "intel refresh denied", "warn");
        showToast("Intel failed", j.error || "refresh denied", {
          sev: "high",
          key: "intel-fail|" + Date.now(),
        });
      } else {
        setStatLine("intel refreshing...", "warn");
        await loadIntelStatus();
        let n = 0;
        for (let i = 0; i < 8; i++) {
          await new Promise((res) => setTimeout(res, 700));
          try {
            const s = await twFetch("/api/intel/status").then((x) => x.json());
            renderIntelStatus(s);
            n =
              (s.counts && s.counts.ips + s.counts.cidrs + s.counts.domains) ||
              0;
            if (!s.refreshing) break;
          } catch (_) {}
        }
        setStatLine("intel lists ~" + n + " entries", "warn");
        showToast("Intel lists updated", "~" + n + " entries in local cache", {
          sev: "info",
          key: "intel-ok|" + Date.now(),
          ttl: 7000,
        });
        await loadIntelStatus();
      }
    } catch (_) {
      setStatLine("intel refresh failed", "bad");
      showToast("Intel failed", "Request failed", {
        sev: "high",
        key: "intel-err|" + Date.now(),
      });
    } finally {
      intelRefreshingUi = false;
      if (btnIntelRefresh) {
        btnIntelRefresh.disabled = false;
        btnIntelRefresh.textContent = "Refresh";
      }
    }
  }

  btnIntel?.addEventListener("click", () => {
    openIntelModal();
  });
  btnIntelRefresh?.addEventListener("click", () => {
    refreshIntelLists();
  });
  document.getElementById("intel-modal-close")?.addEventListener("click", closeIntelModal);
    intelModal?.addEventListener("click", (e) => {
    if (e.target === intelModal) closeIntelModal();
  });
  btnIntelOpenCache?.addEventListener("click", async () => {
    const path = intelCacheDir;
    if (!path) {
      showToast("Cache folder unknown", "Status has no cache_dir yet", {
        sev: "info",
        key: "intel-cache-miss|" + Date.now(),
        ttl: 4000,
      });
      return;
    }
    try {
      if (window.pywebview && window.pywebview.api && window.pywebview.api.reveal) {
        const ok = await window.pywebview.api.reveal(path);
        if (!ok) {
          showToast("Open cache failed", "reveal blocked or path missing", {
            sev: "info",
            key: "intel-cache-fail|" + Date.now(),
            ttl: 4000,
          });
        }
      } else {
        showToast("Open cache", path, {
          sev: "info",
          key: "intel-cache-path|" + Date.now(),
          ttl: 8000,
        });
      }
    } catch (_) {
      showToast("Open cache failed", "", {
        sev: "info",
        key: "intel-cache-err|" + Date.now(),
        ttl: 4000,
      });
    }
  });

  const btnExport = document.getElementById("btn-export");
  if (btnExport) {
    btnExport.addEventListener("click", async () => {
      btnExport.disabled = true;
      try {
        const r = await twFetch("/api/export/save", { method: "POST" });
        const j = await r.json();
        if (!r.ok || !j.ok) {
          showToast("CSV failed", (j && j.error) || "export denied", { sev: "high", key: "csv-fail|" + Date.now() });
        } else {
          showToast("CSV saved", j.path || j.filename, { sev: "info", key: "csv-ok|" + Date.now(), ttl: 10000 });
          setStatLine("CSV: " + (j.filename || "saved"), "warn");
          try {
            if (window.pywebview && window.pywebview.api && window.pywebview.api.reveal) {
              await window.pywebview.api.reveal(j.path);
            }
          } catch (_) {}
          try {
            const g = await twFetch("/api/export.csv");
            if (g.ok) {
              const blob = await g.blob();
              const a = document.createElement("a");
              a.href = URL.createObjectURL(blob);
              a.download = j.filename || "trafficwatch-snapshot.csv";
              document.body.appendChild(a);
              a.click();
              a.remove();
              setTimeout(() => URL.revokeObjectURL(a.href), 2000);
            }
          } catch (_) {}
        }
      } catch (_) {
        showToast("CSV failed", "Request failed", { sev: "high", key: "csv-err|" + Date.now() });
      } finally {
        btnExport.disabled = false;
      }
    });
  }


  document.getElementById("btn-home").addEventListener("click", () => {
    // Close Settings popover so Home Reset/Close are clickable
    try {
      const pop = document.getElementById("settings-pop");
      const sbtn = document.getElementById("btn-settings");
      if (pop) {
        pop.classList.add("hidden");
        pop.setAttribute("hidden", "");
      }
      if (sbtn) sbtn.setAttribute("aria-expanded", "false");
    } catch (_) {}
    const h = mapOk() ? window.TWMap.getHome() : null;
    homeLat.value = h.lat;
    homeLon.value = h.lon;
    homeLabelInput.value = h.label || "";
    const err = document.getElementById("home-error");
    if (err) { err.textContent = ""; err.classList.add("hidden"); }
    homePanel.classList.remove("hidden");
  });
  document.getElementById("home-close").addEventListener("click", () => {
    homePanel.classList.add("hidden");
  });
  document.getElementById("home-save").addEventListener("click", async () => {
    const lat = parseFloat(homeLat.value);
    const lon = parseFloat(homeLon.value);
    let errEl = document.getElementById("home-error");
    if (!errEl && homePanel) {
      errEl = document.createElement("span");
      errEl.id = "home-error";
      errEl.className = "kill-error hidden";
      errEl.style.marginLeft = "0.5rem";
      homePanel.appendChild(errEl);
    }
    const showErr = (msg) => {
      if (!errEl) return;
      errEl.textContent = msg || "";
      errEl.classList.toggle("hidden", !msg);
    };
    if (Number.isNaN(lat) || Number.isNaN(lon)) {
      showErr("lat/lon required");
      return;
    }
    if (lat < -90 || lat > 90 || lon < -180 || lon > 180) {
      showErr("lat must be -90..90 and lon -180..180");
      return;
    }
    const home = {
      lat,
      lon,
      label: homeLabelInput.value || `Custom home (${lat.toFixed(4)}, ${lon.toFixed(4)})`,
      source: "user_override",
    };
    try {
      const r = await twFetch("/api/home", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(home),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || (j && j.ok === false)) {
        showErr((j && j.error) || ("Save failed (" + (r.status || "?") + ")"));
        return;
      }
      withMap((M) => M.setHome(home));
      saveHomeLS(home);
      try { socket.emit("set_home", home); } catch (_) {}
      showErr("");
      homePanel.classList.add("hidden");
      render();
    } catch (_) {
      showErr("Save failed (network)");
    }
  });
  document.getElementById("home-detect")?.addEventListener("click", () => {
    twFetch("/api/home/detect", { method: "POST" })
      .then((r) => r.json())
      .then((j) => {
        if (j && j.ok && j.home) {
          withMap((M) => M.setHome(j.home));
          render();
        }
      })
      .catch(() => {});
  });
  document.getElementById("btn-clear-history")?.addEventListener("click", async () => {
    const yes = await twConfirm(
      "Clear history",
      "Delete persisted history on this PC? This cannot be undone.",
      "Delete history"
    );
    if (!yes) return;
    twFetch("/api/history/clear", { method: "POST" })
      .then((r) => r.json())
      .then((j) => {
        if (j && j.ok) {
          if (chipHistory) chipHistory.textContent = "hist: 0r / 0p";
        }
      })
      .catch(() => {});
  });
  document.getElementById("home-reset").addEventListener("click", () => {
    try {
      localStorage.removeItem(LS_HOME);
    } catch (_) {}
    twFetch("/api/home/reset", { method: "POST" })
      .then((r) => r.json())
      .then((j) => {
        if (j.home) withMap((M) => M.setHome(j.home));
        render();
      })
      .catch(() => {});
    homePanel.classList.add("hidden");
  });

  document.getElementById("btn-uninstall")?.addEventListener("click", async () => {
    const yes = await twConfirm(
      "Uninstall TrafficWatch",
      "Open the uninstaller? It asks for admin approval, lets you choose whether to delete your data, and closes TrafficWatch when it runs. Nothing is removed until you confirm there.",
      "Open uninstaller"
    );
    if (!yes) return;
    try {
      const r = await twFetch("/api/uninstall", { method: "POST" });
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.ok) {
        showToast("Uninstaller opened", "Follow the Uninstall TrafficWatch window (it may be behind this one).", { key: "uninstall|" + Date.now(), sev: "info", ttl: 8000 });
      } else {
        showToast("Uninstall failed", (j && j.error) || "could not start the uninstaller", { key: "uninstall-fail|" + Date.now(), ttl: 8000 });
      }
    } catch (_) {
      showToast("Uninstall failed", "request failed", { key: "uninstall-fail|" + Date.now(), ttl: 8000 });
    }
  });
  const btnQuit = document.getElementById("btn-quit");
  if (btnQuit) {
    async function doQuit() {
      if (statStatus) {
        statStatus.textContent = "Quitting...";
        statStatus.classList.remove("bad");
      }
      const hasBridge = !!(
        window.pywebview &&
        window.pywebview.api &&
        typeof window.pywebview.api.quit === "function"
      );
      if (hasBridge) {
        try {
          await Promise.race([
            Promise.resolve(window.pywebview.api.quit()),
            new Promise(function (_, reject) {
              setTimeout(function () { reject(new Error("quit bridge timeout")); }, 1500);
            }),
          ]);
          return;
        } catch (err) {
          console.warn("TrafficWatch: pywebview quit failed, trying /api/quit", err);
        }
      }
      try {
        const r = await twFetch("/api/quit", { method: "POST" });
        if (r && r.ok) {
          if (statStatus) statStatus.textContent = "quitting.";
          return;
        }
        console.warn("TrafficWatch: /api/quit returned", r && r.status);
      } catch (err) {
        console.warn("TrafficWatch: /api/quit failed", err);
      }
      if (statStatus) {
        statStatus.textContent = "close the window to quit";
        statStatus.classList.add("warn");
      }
    }
    btnQuit.addEventListener("click", () => {
      doQuit();
    });
  }


  // --- Layout toggle: globe-first (default) | list-first --------------------
  function loadLayout() {
    try {
      const v = localStorage.getItem(LS_LAYOUT);
      if (v === "list" || v === "globe") return v;
    } catch (_) {}
    return "globe";
  }
  function saveLayout(mode) {
    try { localStorage.setItem(LS_LAYOUT, mode); } catch (_) {}
  }
  // ux43: never dispatch synthetic resize here - that re-entered applyLayout via the
  // window resize listener and blew the stack (RangeError at forceGlobeResize kick).
  let _globeResizeBusy = false;
  function forceGlobeResize() {
    if (_globeResizeBusy) return;
    _globeResizeBusy = true;
    const kick = () => {
      withMap((M) => { if (M.resize) M.resize(); });
    };
    try {
      kick();
      requestAnimationFrame(() => {
        try {
          kick();
          setTimeout(kick, 80);
          setTimeout(kick, 250);
        } finally {
          setTimeout(() => { _globeResizeBusy = false; }, 300);
        }
      });
    } catch (_) {
      _globeResizeBusy = false;
    }
  }

  // ux42 compact: short viewports get a real list-first height split (CSS) + resize
  function layoutCompactHeight() {
    try { return window.innerHeight <= 720; } catch (_) { return false; }
  }
  // Titles/classes only - safe for window resize listener (no forceGlobeResize).
  function applyLayoutClasses(mode) {
    if (!mainLayout) return;
    const m = mode === "list" ? "list" : "globe";
    mainLayout.classList.toggle("layout-list", m === "list");
    mainLayout.classList.toggle("layout-globe", m !== "list");
    const btn = document.getElementById("btn-layout");
    if (btn) {
      const compact = layoutCompactHeight();
      btn.textContent = m === "list" ? "Globe-first" : "List-first";
      if (compact) {
        btn.title = m === "list"
          ? "Switch to globe-first (short window: list-first uses a shorter globe)"
          : "Switch to list-first (short window: globe height capped ~28vh)";
      } else {
        btn.title = m === "list" ? "Switch to globe-first layout" : "Switch to list-first (smaller globe)";
      }
      btn.setAttribute("aria-pressed", m === "list" ? "true" : "false");
      btn.classList.toggle("btn-layout-disabled", false);
      btn.disabled = false;
    }
  }
  function applyLayout(mode) {
    applyLayoutClasses(mode);
    forceGlobeResize();
  }
  let layoutMode = loadLayout();
  applyLayout(layoutMode);
  forceGlobeResize(); // init
  document.getElementById("btn-layout")?.addEventListener("click", () => {
    layoutMode = layoutMode === "list" ? "globe" : "list";
    saveLayout(layoutMode);
    applyLayout(layoutMode);
  });
  // Debounced: titles/classes only - must NOT call applyLayout/forceGlobeResize
  // (other paths still dispatchEvent("resize"); that must not re-enter forced resize).
  let _layoutResizeTimer = null;
  window.addEventListener("resize", () => {
    if (_layoutResizeTimer) clearTimeout(_layoutResizeTimer);
    _layoutResizeTimer = setTimeout(() => {
      _layoutResizeTimer = null;
      applyLayoutClasses(layoutMode);
    }, 150);
  });

  // Alert detail modal ------------------------------------------------------
  let currentAlert = null;
  const alertModal = document.getElementById("alert-modal");
  const alertModalTitle = document.getElementById("alert-modal-title");
  const alertModalBody = document.getElementById("alert-modal-body");

  function closeAlertDetail() {
    if (alertModal) {
      alertModal.classList.add("hidden");
      alertModal.setAttribute("aria-hidden", "true");
    }
    currentAlert = null;
  }

  function copyAlertFields(a) {
    const p = (a && a.payload) || {};
    const lines = [
      "process: " + (p.process || ""),
      "pid: " + (p.pid != null ? String(p.pid) : ""),
      "remote_ip: " + (p.remote_ip || ""),
      "remote_port: " + (p.remote_port != null ? String(p.remote_port) : ""),
      "local_port: " + (p.local_port != null ? String(p.local_port) : ""),
      "path: " + (p.exe || ""),
    ];
    copyText(lines.join("\n"), "alert fields");
  }

  function openAlertDetail(alert) {
    hideTip(); // ux44
    if (!alert) return;
    currentAlert = alert;
    const p = alert.payload || {};
    const canBlock = isPublicRemoteIp(p.remote_ip, p.private_remote);
    if (alertModalTitle) {
      alertModalTitle.textContent = (alert.summary || "Alert") + (p.process ? " · " + p.process : "");
    }
    const firstIso = alert.first_seen
      ? new Date(alert.first_seen * 1000).toLocaleString()
      : "—";
    const lastIso = alert.last_seen
      ? new Date(alert.last_seen * 1000).toLocaleString()
      : "—";
    const sigBits = ((p.signals || [])
      .slice(0, 8)
      .map((s) => escapeHtml(s.label || s.id || ""))
      .filter(Boolean)
      .join(", ")) || "—";
    const intelBits =
      p.intel && p.intel.hit
        ? escapeHtml(((p.intel.lists || []).slice(0, 4).join(", ")) || "hit") +
          (p.intel.severity ? " · " + escapeHtml(p.intel.severity) : "")
        : "—";
    if (alertModalBody) {
      alertModalBody.innerHTML =
        `<p class="alert-detail-summary">${escapeHtml(alert.summary || "Alert")}</p>` +
        `<div class="alert-detail-meta">state ${escapeHtml(alert.state || "active")} · count ${alert.count || 1} · risk ${alert.risk != null ? alert.risk : (p.risk != null ? p.risk : "—")}</div>` +
        `<div class="alert-detail-fields">` +
        copyableHtml("Process", p.process || "—") +
        copyableHtml("PID", p.pid != null ? String(p.pid) : "—") +
        copyableHtml("Remote IP", p.remote_ip || "—") +
        copyableHtml("Remote port", p.remote_port != null ? String(p.remote_port) : "—") +
        copyableHtml("Local port", p.local_port != null ? String(p.local_port) : "—") +
        copyableHtml("Path", p.exe || "—") +
        `</div>` +
        `<dl class="inspect-meta">` +
        `<dt>Why</dt><dd>${escapeHtml(alert.summary || "—")}</dd>` +
        `<dt>Signals</dt><dd>${sigBits}</dd>` +
        `<dt>Intel</dt><dd>${intelBits}</dd>` +
        `<dt>First seen</dt><dd>${escapeHtml(firstIso)}</dd>` +
        `<dt>Last seen</dt><dd>${escapeHtml(lastIso)}</dd>` +
        `<dt>Direction</dt><dd>${escapeHtml(p.direction || p.status || "—")}</dd>` +
        `</dl>`;
    }
    const blockIpBtn = document.getElementById("alert-act-block-ip");
    const blockProcBtn = document.getElementById("alert-act-block-proc");
    if (blockIpBtn) {
      blockIpBtn.disabled = !canBlock;
      blockIpBtn.title = canBlock ? "Block this public remote IP" : "No public remote IP to block";
    }
    if (blockProcBtn) {
      blockProcBtn.disabled = !canBlock;
      blockProcBtn.textContent = p.process
        ? "Block for " + p.process
        : "Block for this process";
      blockProcBtn.title = canBlock
        ? "Block the known remote IP (shown with process name)"
        : "No public remote IP to block";
    }
    if (alertModal) {
      alertModal.classList.remove("hidden");
      alertModal.setAttribute("aria-hidden", "false");
    }
  }

  // Inspect / Kill ----------------------------------------------------------
  let inspectPid = null;
  let killForce = false;
  const inspectModal = document.getElementById("inspect-modal");
  const inspectBody = document.getElementById("inspect-body");
  const inspectTitle = document.getElementById("inspect-title");
  const killModal = document.getElementById("kill-modal");
  const killNameEl = document.getElementById("kill-name");
  const killPidEl = document.getElementById("kill-pid");
  const killWarn = document.getElementById("kill-warn");
  const killInput = document.getElementById("kill-confirm-input");
  const killError = document.getElementById("kill-error");
  const killConfirmBtn = document.getElementById("kill-confirm-btn");

  function closeInspect() {
    if (inspectModal) {
      inspectModal.classList.add("hidden");
      inspectModal.setAttribute("aria-hidden", "true");
    }
    // ux44: clear revealed cmdline from hidden Inspect DOM on close
    if (inspectBody) inspectBody.innerHTML = "";
  }
  function closeKill() {
    if (killModal) {
      killModal.classList.add("hidden");
      killModal.setAttribute("aria-hidden", "true");
    }
    if (killError) killError.classList.add("hidden");
    if (killInput) killInput.value = "";
  }

  async function openInspect(pid) {
    if (!pid) return;
    inspectPid = Number(pid);
    hideTip(); // ux44
    if (inspectModal) {
      inspectModal.classList.remove("hidden");
      inspectModal.setAttribute("aria-hidden", "false");
    }
    if (inspectTitle) inspectTitle.textContent = `Process PID ${inspectPid}`;
    if (inspectBody) inspectBody.innerHTML = "<p>Loading…</p>";
    try {
      const r = await twFetch(`/api/process/${inspectPid}`);
      const d = await r.json();
      renderInspect(d);
    } catch (e) {
      if (inspectBody) inspectBody.innerHTML = `<p class="kill-error">Failed to load process details.</p>`;
    }
  }

  function renderInspect(d) {
    if (!inspectBody) return;
    if (!d || (d.ok === false && d.error && !d.name)) {
      inspectBody.innerHTML = `<p class="kill-error">${escapeHtml((d && d.error) || "error")}</p>`;
      return;
    }
    if (inspectTitle) inspectTitle.textContent = `${d.name || "Process"} · PID ${d.pid}`;
    const crit = d.critical
      ? `<div class="critical-banner">Protected: ${escapeHtml(d.critical_reason || "critical system process")}. Kill is blocked.</div>`
      : "";
    const risk = d.risk != null ? Number(d.risk) : riskScore(
      (latest.find((c) => c.pid === d.pid) || {})
    );
    const trusted = isTrustedConn(d) || isTrustedPid(d.pid);
    // Mute applies to selected connection if any for this pid, else first public remote
    const selConn =
      (selectedKey && latest.find((c) => rowKey(c) === selectedKey && c.pid === d.pid)) ||
      latest.find((c) => c.pid === d.pid) ||
      null;
    const mKey = selConn ? muteKeyFor(selConn) : "";
    const muted = mKey ? muteKeys.has(mKey) : false;
    const sigChips =
      ((d.signals || []).length
        ? `<div class="sig-chips">` +
          (d.signals || [])
            .slice(0, 6)
            .map((s) => {
              const sev =
                s.severity === "medium" || s.severity === "high"
                  ? "sev-medium"
                  : s.severity === "info"
                    ? "sev-info"
                    : "";
              return `<span class="sig-chip ${sev}" title="${escapeHtml(s.detail || s.label || "")}">${escapeHtml(
                s.label || s.id
              )}</span>`;
            })
            .join("") +
          `</div>`
        : `<span class="muted">No local signals</span>`);
    const trustLead = `
      <div class="inspect-trust-lead">
        <div class="inspect-trust-row">
          ${riskBadgeHtml(risk)}
          <span class="inspect-trust-label">Risk</span>
          ${trusted ? '<span class="trust-badge">trusted</span>' : '<span class="muted">not trusted</span>'}
          ${muted ? '<span class="mute-badge">muted</span>' : ""}
        </div>
        <dl class="inspect-meta inspect-meta-lead">
          <dt>Publisher</dt><dd>${escapeHtml(d.company || "—")}${d.description ? " · " + escapeHtml(d.description) : ""}</dd>
          <dt>Authenticode</dt><dd>${authInspectHtml(d.authenticode)}</dd>
          <dt>Path</dt><dd>${copyableDd(d.exe || "—", "path")}</dd>
          <dt>SHA-256</dt><dd>${copyableDd(d.exe_sha256 || d.exe_sha256_short || "—", "SHA-256")}</dd>
          <dt>Signals</dt><dd>${sigChips}</dd>
        </dl>
        <div class="inspect-trust-actions">
          <button type="button" class="btn btn-xs" id="inspect-trust-btn">${trusted ? "Untrust" : "Trust"} app</button>
          <button type="button" class="btn btn-xs" id="inspect-mute-btn" ${mKey ? "" : "disabled"}>${muted ? "Unmute" : "Mute"} alert</button>
        </div>
      </div>`;
    const meta = `
      ${crit}
      ${trustLead}
      <dl class="inspect-meta">
        <dt>Name</dt><dd>${copyableDd(d.name || "—", "process name")}</dd>
        <dt>PID</dt><dd>${copyableDd(d.pid != null ? String(d.pid) : "—", "PID")}</dd>
        <dt>User</dt><dd>${escapeHtml(d.username || "—")}</dd>
        <dt>Started</dt><dd>${escapeHtml(d.create_time_iso || "—")}</dd>
        <dt>Parent</dt><dd>${escapeHtml(d.parent_process || "—")}</dd>
        <dt>Direction</dt><dd>${selConn ? escapeHtml(directionBasisText(selConn)) : '<span class="muted">select a row</span>'}</dd>
        <dt>Remote</dt><dd>${selConn && selConn.remote_ip ? copyableDd(selConn.remote_ip + (selConn.remote_port != null ? ":" + selConn.remote_port : ""), "remote IP") : '<span class="muted">select a row</span>'}</dd>
        <dt>ASN / org</dt><dd>${selConn ? escapeHtml([selConn.asn || (selConn.geo && selConn.geo.asn), selConn.org || (selConn.geo && selConn.geo.org)].filter(Boolean).join(' · ') || '—') : '—'}</dd>
        <dt>Rates</dt><dd>↓${fmtRate(d.bytes_in_rate)} ↑${fmtRate(d.bytes_out_rate)}${selConn && selConn.rate_source ? (" - " + escapeHtml(selConn.rate_source)) : ""}</dd>
        <dt>Conn bytes</dt><dd>${selConn && (selConn.conn_bytes_in != null || selConn.conn_bytes_out != null) ? ("in " + (selConn.conn_bytes_in != null ? selConn.conn_bytes_in : "?") + "B out " + (selConn.conn_bytes_out != null ? selConn.conn_bytes_out : "?") + "B") : '<span class="muted">need live helper</span>'}${selConn && selConn.duration_ms != null ? (" - " + Math.round(selConn.duration_ms/1000) + "s") : ""}</dd>
        <dt>Status</dt><dd>${escapeHtml(d.status || "—")}${d.error ? " · " + escapeHtml(d.error) : ""}</dd>
      </dl>
      <details class="inspect-cmdline">
        <summary>Command line${d.cmdline_redacted ? " (redacted)" : ""}</summary>
        <pre class="inspect-cmdline-pre" id="inspect-cmdline-pre">${escapeHtml((d.cmdline || []).join(" ") || "—")}</pre>
        ${d.cmdline_can_reveal ? '<button type="button" class="btn btn-xs" id="inspect-cmdline-reveal">Reveal</button>' : ""}
      </details>`;
    const destRows = (d.destinations || [])
      .slice(0, 40)
      .map(
        (x) =>
          `<tr><td>${escapeHtml(x.remote_ip || "—")}</td><td>${escapeHtml(x.hostname || "")}</td><td>${escapeHtml(
            [x.city, x.country].filter(Boolean).join(", ")
          )}</td><td>${escapeHtml((x.ports || []).slice(0, 8).join(", "))}</td><td>${x.count}</td></tr>`
      )
      .join("");
    const connRows = (d.connections || [])
      .slice(0, 80)
      .map((c) => {
        const remote = c.remote_ip
          ? `${c.remote_ip}${c.remote_port != null ? ":" + c.remote_port : ""}`
          : "—";
        const rr = c.risk != null ? riskBadgeHtml(c.risk) : "";
        return `<tr><td>${rr}</td><td>${escapeHtml(c.direction || "")}</td><td>${escapeHtml(remote)}</td><td>${escapeHtml(
          c.country || ""
        )}</td><td>${escapeHtml((c.proto_label || c.proto || ""))} ${escapeHtml(c.status || "")}</td></tr>`;
      })
      .join("");
    inspectBody.innerHTML =
      meta +
      `<div class="inspect-section"><h3>Remote destinations</h3>
        <table class="inspect-table"><thead><tr><th>IP</th><th>Host</th><th>Place</th><th>Ports</th><th>N</th></tr></thead>
        <tbody>${destRows || "<tr><td colspan=5>—</td></tr>"}</tbody></table></div>` +
      `<div class="inspect-section"><h3>Related connections (${(d.connections || []).length})</h3>
        <table class="inspect-table"><thead><tr><th>Risk</th><th>Dir</th><th>Remote</th><th>Country</th><th>Proto</th></tr></thead>
        <tbody>${connRows || "<tr><td colspan=5>—</td></tr>"}</tbody></table></div>`;

    const killBtn = document.getElementById("inspect-kill");
    const forceBtn = document.getElementById("inspect-kill-force");
    if (killBtn) killBtn.disabled = !!d.critical;
    if (forceBtn) forceBtn.disabled = !!d.critical;
    inspectBody.dataset.name = d.name || "";
    inspectBody.dataset.critical = d.critical ? "1" : "0";
    inspectBody.dataset.pid = String(d.pid || "");
    inspectBody.dataset.muteKey = mKey || "";

    const trustBtn = document.getElementById("inspect-trust-btn");
    const muteBtn = document.getElementById("inspect-mute-btn");
    if (trustBtn) {
      trustBtn.addEventListener("click", () => {
        toggleTrustFor(d);
        renderInspect(d);
        render();
      });
    }
    if (muteBtn && mKey) {
      muteBtn.addEventListener("click", () => {
        if (muteKeys.has(mKey)) muteKeys.delete(mKey);
        else muteKeys.add(mKey);
        saveMuteKeys(muteKeys);
        renderInspect(d);
        render();
      });
    }
    const revealBtn = document.getElementById("inspect-cmdline-reveal");
    if (revealBtn) {
      revealBtn.addEventListener("click", async () => {
        try {
          const r = await twFetch("/api/process/" + encodeURIComponent(d.pid) + "/cmdline/reveal", { method: "POST" });
          const jrev = await r.json();
          const pre = document.getElementById("inspect-cmdline-pre");
          if (pre && jrev && jrev.ok && jrev.cmdline) {
            pre.textContent = (jrev.cmdline || []).join(" ") || "—";
            const sum = pre.closest("details") && pre.closest("details").querySelector("summary");
            if (sum) sum.textContent = "Command line (revealed)";
          }
        } catch (_) {}
      });
    }
  }

  function openKillConfirm(force) {
    if (!inspectPid) return;
    if (inspectBody && inspectBody.dataset.critical === "1") {
      showToast("Protected process", "This process is protected and cannot be killed from TrafficWatch.", { key: "kill-protected|" + Date.now(), sev: "info", ttl: 5000 });
      return;
    }
    killForce = !!force;
    const name = (inspectBody && inspectBody.dataset.name) || "?";
    if (killNameEl) killNameEl.textContent = name;
    if (killPidEl) killPidEl.textContent = String(inspectPid);
    if (killWarn) {
      killWarn.textContent = force
        ? "Force kill (SIGKILL / TerminateProcess). Prefer Terminate first when possible."
        : "Graceful terminate first. Use Force kill only if the process ignores terminate.";
    }
    if (killConfirmBtn) killConfirmBtn.textContent = force ? "Force kill" : "Terminate";
    if (killError) {
      killError.textContent = "";
      killError.classList.add("hidden");
    }
    if (killModal) {
      killModal.classList.remove("hidden");
      killModal.setAttribute("aria-hidden", "false");
    }
    hideTip();
    if (killInput) {
      killInput.value = "";
      killInput.focus();
    }
  }

  async function doKill() {
    const name = (killNameEl && killNameEl.textContent) || "";
    const typed = ((killInput && killInput.value) || "").trim();
    if (!typed || typed.toLowerCase() !== name.toLowerCase()) {
      if (killError) {
        killError.textContent = "Name does not match — type the process name exactly to confirm.";
        killError.classList.remove("hidden");
      }
      return;
    }
    try {
      const r = await twFetch(`/api/process/${inspectPid}/kill`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          force: killForce,
          confirm_pid: inspectPid,
          confirm_name: typed,
        }),
      });
      const j = await r.json();
      if (!j.ok) {
        if (killError) {
          killError.textContent = j.error || "Kill failed";
          killError.classList.remove("hidden");
        }
        return;
      }
      closeKill();
      closeInspect();
      // ux44: LIVE LINK shows link state, not last action message
      showToast(
        "Process",
        j.gone ? ("ended PID " + inspectPid) : ((j.action || "action") + " PID " + inspectPid + " (still running?)"),
        { key: "kill|" + inspectPid + "|" + Date.now(), sev: "info", ttl: 5000 }
      );
    } catch (e) {
      if (killError) {
        killError.textContent = "Request failed";
        killError.classList.remove("hidden");
      }
    }
  }

  if (connList) {
    connList.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-inspect]");
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      openInspect(btn.getAttribute("data-inspect"));
    });
  }
  document.getElementById("inspect-close")?.addEventListener("click", closeInspect);
  document.getElementById("inspect-kill")?.addEventListener("click", () => openKillConfirm(false));
  document.getElementById("inspect-kill-force")?.addEventListener("click", () => openKillConfirm(true));
  document.getElementById("kill-cancel")?.addEventListener("click", closeKill);
  document.getElementById("kill-name-copy")?.addEventListener("click", () => {
    copyText((killNameEl && killNameEl.textContent) || "", "process name");
  });
  killConfirmBtn?.addEventListener("click", () => {
    doKill();
  });
  inspectModal?.addEventListener("click", (e) => {
    if (e.target === inspectModal) closeInspect();
  });
  killModal?.addEventListener("click", (e) => {
    if (e.target === killModal) closeKill();
  });

  // Alert detail modal actions
  document.getElementById("alert-modal-close")?.addEventListener("click", closeAlertDetail);
  alertModal?.addEventListener("click", (e) => {
    if (e.target === alertModal) closeAlertDetail();
  });
  document.getElementById("alert-act-ack")?.addEventListener("click", () => {
    if (!currentAlert) return;
    ackAlert(currentAlert.id);
    closeAlertDetail();
  });
  document.getElementById("alert-act-mute")?.addEventListener("click", () => {
    if (!currentAlert) return;
    muteAlert(currentAlert.id);
    closeAlertDetail();
  });
  document.getElementById("alert-act-inspect")?.addEventListener("click", () => {
    if (!currentAlert) return;
    const pid = currentAlert.payload && currentAlert.payload.pid;
    if (pid != null) openInspect(pid);
  });
  document.getElementById("alert-act-globe")?.addEventListener("click", () => {
    if (!currentAlert) return;
    const p = currentAlert.payload || {};
    focusConnection({
      process: p.process,
      pid: p.pid,
      remote_ip: p.remote_ip,
      remote_port: p.remote_port,
      local_port: p.local_port,
      direction: p.direction,
      status: p.status,
      proto: p.proto,
      lat: p.lat,
      lon: p.lon,
      exe: p.exe,
      _row_key: currentAlert.connKey || p._row_key,
    });
  });
  document.getElementById("alert-act-block-ip")?.addEventListener("click", () => {
    if (!currentAlert) return;
    const p = currentAlert.payload || {};
    if (!isPublicRemoteIp(p.remote_ip, p.private_remote)) return;
    openFwConfirm(p.remote_ip, "block", null, { process: p.process || "", pid: p.pid });
  });
  document.getElementById("alert-act-block-proc")?.addEventListener("click", () => {
    if (!currentAlert) return;
    const p = currentAlert.payload || {};
    if (!isPublicRemoteIp(p.remote_ip, p.private_remote)) return;
    openFwConfirm(p.remote_ip, "block", null, { process: p.process || "", pid: p.pid });
  });
  document.getElementById("alert-act-copy-all")?.addEventListener("click", () => {
    if (!currentAlert) return;
    copyAlertFields(currentAlert);
  });

  // Click-to-copy for data-copy buttons (alert/inspect/fw)
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-copy]");
    if (!btn || btn.disabled) return;
    e.preventDefault();
    e.stopPropagation();
    copyText(btn.getAttribute("data-copy") || "", btn.getAttribute("data-copy-label") || "value");
  });

  loadFilters();

  const socket = io({ transports: ["websocket", "polling"], withCredentials: true });

  let socketSnapshotSeen = false;

  function applySnapshot(snap) {
    latest = (snap && snap.connections) || [];
    topTalkers = (snap && snap.top_talkers) || [];
    if (snap && snap.home && !loadHomeFromLS()) withMap((M) => M.setHome(snap.home));
    if (snap && snap.rates) {
      statSysIn.textContent = fmtRate(snap.rates.system_in);
      statSysOut.textContent = fmtRate(snap.rates.system_out);
    }
    if (chipIntel) {
      const n = snap && typeof snap.intel_hits === "number"
        ? snap.intel_hits
        : (latest.filter((c) => c.intel && c.intel.hit).length);
      chipIntel.innerHTML = `intel: <span>${n}</span>`;
      chipIntel.classList.toggle("intel-hot", n > 0);
    }
    if (chipDns && snap && snap.dns_log) {
      const d = snap.dns_log;
      const live = !!d.live;
      chipDns.textContent = live ? "DNS log: live" : (d.limited ? "DNS log: limited" : (d.message || "DNS log: ok"));
      chipDns.classList.toggle("dns-limited", !live && !!d.limited);
      chipDns.classList.toggle("dns-live", live);
      chipDns.title = d.message || "";
    }
    try { renderDnsPanel(snap); } catch (_) {}
    if (snap && snap.admin_limited) {
      statStatus.textContent = "live · limited (no admin)";
      statStatus.classList.add("warn");
    }
    try { considerToasts(snap); } catch (_) {}
    try { seedAlertsFromServer(); } catch (_) {}
    if (!sawSnapshot) {
      sawSnapshot = true;
      if (statusEmpty) statusEmpty.classList.add("hidden");
      if (statusSections) statusSections.classList.remove("hidden");
    }
    render({ fromSnapshot: true });
    dismissSplash();
  }

  function httpPollSnapshot() {
    if (socketSnapshotSeen) return;
    twFetch("/api/snapshot")
      .then((r) => (r && r.ok ? r.json() : null))
      .then((snap) => {
        if (!snap || socketSnapshotSeen) return;
        applySnapshot(snap);
      })
      .catch(() => {});
  }
  setTimeout(httpPollSnapshot, 2000);
  const httpPollIv = setInterval(() => {
    if (socketSnapshotSeen) {
      clearInterval(httpPollIv);
      return;
    }
    httpPollSnapshot();
  }, 4000);

  socket.on("connect", () => {
    statStatus.textContent = "live";
    statStatus.classList.remove("warn", "bad");
    dismissSplash();
    try { window.dispatchEvent(new Event("resize")); } catch (_) {}
    withMap((M) => { if (M.resize) M.resize(); });
  });
  socket.on("disconnect", () => {
    statStatus.textContent = "disconnected";
    statStatus.classList.add("bad");
  });
  socket.on("hello", (msg) => {
    const lsHome = loadHomeFromLS();
    if (lsHome && lsHome.lat != null) {
      withMap((M) => M.setHome(lsHome));
      socket.emit("set_home", lsHome);
    } else if (msg && msg.home) {
      withMap((M) => M.setHome(msg.home));
    }
    if (msg && msg.geo && !msg.geo.mmdb_ok) {
      statStatus.textContent = "live · no geo db";
      statStatus.classList.add("warn");
    }
  });
  socket.on("home", (h) => {
    if (h) withMap((M) => M.setHome(h));
    render();
  });
  socket.on("snapshot", (snap) => {
    socketSnapshotSeen = true;
    try { clearInterval(httpPollIv); } catch (_) {}
    applySnapshot(snap);
  });
  socket.on("error", (e) => {
    console.warn("TrafficWatch error", e);
    statStatus.textContent = "error";
    statStatus.classList.add("bad");
  });


  // Phase C — firewall confirm + history chip --------------------------------
  let fwIp = null;
  let fwMode = "block"; // block | unblock | timed
  let fwMinutes = null;
  let fwCtx = {};
  const fwModal = document.getElementById("fw-modal");
  const fwIpEl = document.getElementById("fw-ip");
  const fwProcEl = document.getElementById("fw-proc");
  const fwProcWrap = document.getElementById("fw-proc-wrap");
  const fwInput = document.getElementById("fw-confirm-input");
  const fwError = document.getElementById("fw-error");
  const fwTitle = document.getElementById("fw-title");
  const fwWarn = document.getElementById("fw-warn");
  const fwConfirmBtn = document.getElementById("fw-confirm-btn");
  const fwUnblockBtn = document.getElementById("fw-unblock-btn");

  function closeFw() {
    if (fwModal) {
      fwModal.classList.add("hidden");
      fwModal.setAttribute("aria-hidden", "true");
    }
    if (fwError) fwError.classList.add("hidden");
    if (fwInput) fwInput.value = "";
    fwIp = null;
    fwCtx = {};
  }
  function openFwConfirm(ip, mode, minutes, ctx) {
    fwIp = ip;
    fwMode = mode || "block";
    fwMinutes = minutes != null ? minutes : null;
    fwCtx = ctx || fwCtx || {};
    const proc = (fwCtx && fwCtx.process) || "";
    if (fwIpEl) fwIpEl.textContent = ip;
    if (fwProcEl && fwProcWrap) {
      if (proc) {
        fwProcEl.textContent = proc;
        fwProcWrap.classList.remove("hidden");
      } else {
        fwProcEl.textContent = "";
        fwProcWrap.classList.add("hidden");
      }
    }
    if (fwTitle) {
      const procBit = proc ? (" for " + proc) : "";
      fwTitle.textContent =
        fwMode === "unblock"
          ? "Unblock " + ip + "?"
          : fwMode === "timed"
            ? "Block " + ip + procBit + " for 10 minutes?"
            : "Block " + ip + procBit + "?";
    }
    if (fwConfirmBtn) {
      fwConfirmBtn.textContent =
        fwMode === "unblock"
          ? "Remove block rule"
          : fwMode === "timed"
            ? "Block for 10 minutes"
            : "Create block rule";
    }
    if (fwWarn) {
      if (fwMode === "unblock") {
        fwWarn.textContent = "This removes TrafficWatch-created Windows Firewall rules for this IP only.";
      } else if (fwMode === "timed") {
        fwWarn.textContent =
          "Creates a temporary Windows Firewall block. Expiry is stored in the rule description; " +
          "TrafficWatch removes it after ~10 minutes even if the app restarted. Permanent Block remains available.";
      } else {
        fwWarn.innerHTML =
          "This creates a <strong>local Windows Firewall</strong> outbound (and inbound) block rule " +
          "for this IP only. It does <strong>not</strong> enable a default-deny policy.";
      }
    }
    if (fwModal) {
      fwModal.classList.remove("hidden");
      fwModal.setAttribute("aria-hidden", "false");
    }
    if (fwInput) {
      fwInput.value = ip || "";
      fwInput.focus();
      try { fwInput.select(); } catch (_) {}
    }
    if (fwError) fwError.classList.add("hidden");
  }
  async function doFwAction() {
    let typed = ((fwInput && fwInput.value) || "").trim();
    if (!fwIp) return;
    // One-click: empty input means confirm the known IP (prefilled / known fields)
    if (!typed) typed = fwIp;
    if (typed !== fwIp) {
      if (fwError) {
        fwError.textContent = "IP does not match — edit back to the known address, or clear the field for one-click.";
        fwError.classList.remove("hidden");
      }
      return;
    }
    const url = fwMode === "unblock" ? "/api/firewall/unblock" : "/api/firewall/block";
    try {
      const body = { ip: fwIp, confirm_ip: typed };
      if (fwMode === "timed") body.minutes = fwMinutes || 10;
      const r = await twFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = await r.json();
      if (!j.ok) {
        if (fwError) {
          fwError.textContent = j.error || "Firewall action failed";
          fwError.classList.remove("hidden");
        }
        return;
      }
      closeFw();
      showToast(
        fwMode === "unblock" ? "Firewall unblocked" : "Firewall blocked",
        fwIp + (j.rules ? " · " + (j.rules || []).join(", ") : j.removed ? " · removed" : ""),
        { key: "fw|" + fwMode + "|" + fwIp + "|" + Date.now(), sev: "info", ttl: 6000 }
      );
      rememberToast("fw|" + fwMode + "|" + fwIp); // allow re-toast next time with timestamp key above
      statStatus.textContent = fwMode === "unblock" ? "firewall unblocked " + fwIp : "firewall blocked " + fwIp;
      statStatus.classList.add("warn");
    } catch (_) {
      if (fwError) {
        fwError.textContent = "Request failed";
        fwError.classList.remove("hidden");
      }
    }
  }
  document.getElementById("fw-cancel")?.addEventListener("click", closeFw);
  fwConfirmBtn?.addEventListener("click", () => doFwAction());
  fwUnblockBtn?.addEventListener("click", () => {
    if (fwIp) openFwConfirm(fwIp, "unblock", null, fwCtx);
  });
  document.getElementById("fw-timed-btn")?.addEventListener("click", () => {
    if (fwIp) openFwConfirm(fwIp, "timed", 10, fwCtx);
  });
  document.getElementById("fw-ip-copy")?.addEventListener("click", () => {
    copyText(fwIp || (fwIpEl && fwIpEl.textContent) || "", "IP");
  });
  fwModal?.addEventListener("click", (e) => {
    if (e.target === fwModal) closeFw();
  });
  document.getElementById("inspect-fw-block")?.addEventListener("click", () => {
    // Prefer selected connection remote from latest for this inspect pid
    const rows = latest.filter((c) => c.pid === inspectPid && c.remote_ip && !c.private_remote);
    if (!rows.length) {
      showToast("Nothing to block", "No public remote IP on this process to block.", { key: "fw-none|" + Date.now(), sev: "info", ttl: 5000 });
      return;
    }
    // If multiple, pick the currently selected row's remote if it matches pid, else first
    let ip = rows[0].remote_ip;
    if (selectedKey) {
      const hit = rows.find((c) => rowKey(c) === selectedKey);
      if (hit) ip = hit.remote_ip;
    }
    openFwConfirm(ip, "block", null, {
      process: (inspectBody && inspectBody.dataset.name) || "",
      pid: inspectPid,
    });
  });
  // Per-row Block removed (Review 3 Step 2) — Block only in Inspect


  async function setNetTrust(state) {
    try {
      const cur = await twFetch("/api/net-context").then((r) => r.json());
      const h = cur && cur.primary_hash;
      if (!h) return;
      await twFetch("/api/net-context/trust", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name_hash: h, state }),
      });
      refreshNetCtxChip();
      const lab = document.getElementById("net-trust-label");
      if (lab) lab.textContent = state;
    } catch (_) {}
  }
  document.getElementById("net-trust-trusted")?.addEventListener("click", () => setNetTrust("trusted"));
  document.getElementById("net-trust-untrusted")?.addEventListener("click", () => setNetTrust("untrusted"));

  async function refreshHistoryChip() {
    if (!chipHistory) return;
    try {
      const j = await twFetch("/api/history/summary").then((r) => r.json());
      if (!j || !j.ok) {
        chipHistory.textContent = "hist: —";
        return;
      }
      const c = j.counts || {};
      chipHistory.textContent = `hist: ${c.remotes || 0}r / ${c.processes || 0}p`;
      chipHistory.title =
        `Persisted history — remotes ${c.remotes}, processes ${c.processes}, listens ${c.listens}, events ${c.events}` +
        (j.oldest_first_seen ? ` · oldest ${new Date(j.oldest_first_seen * 1000).toLocaleString()}` : "");
    } catch (_) {}
  }
  async function refreshNetCtxChip() {
    const el = document.getElementById("chip-netctx");
    if (!el) return;
    try {
      const j = await twFetch("/api/net-context").then((r) => r.json());
      if (!j || j.ok === false) {
        el.textContent = "net: —";
        return;
      }
      const bits = [];
      if (j.wifi_ssid) bits.push(j.wifi_ssid);
      if (j.trust) bits.push(j.trust);
      if ((j.vpn_ifaces || []).length) bits.push("vpn");
      el.textContent = "net: " + (bits.join(" · ") || "ok");
      el.title = "Network context (names shown in UI only; stored hashed)";
      const lab = document.getElementById("net-trust-label");
      if (lab) lab.textContent = j.trust ? ("marked " + j.trust) : "(unmarked)";
    } catch (_) {}
  }
  async function refreshIpinfoChip() {
    const el = document.getElementById("chip-ipinfo");
    if (!el) return;
    try {
      const sample = (latest || []).find((c) => c && c.asn);
      const attr = document.getElementById("ipinfo-attr");
      if (sample && sample.asn) {
        el.textContent = "ASN: live";
        el.title = "IPinfo Lite ASN on rows. Attribution: CC BY-SA 4.0 (ipinfo.io/lite)";
        if (attr) attr.textContent = "ASN data: IPinfo Lite (CC BY-SA 4.0) https://ipinfo.io/lite";
      } else {
        el.textContent = "ASN: —";
        el.title = "No ASN on current rows (MMDB may still be loading)";
      }
    } catch (_) {}
  }
  async function refreshBaselineChip() {
    if (!chipBaseline) return;
    try {
      const j = await twFetch("/api/baseline/summary").then((r) => r.json());
      if (!j || !j.ok) {
        chipBaseline.textContent = "baseline: -";
        return;
      }
      const st = j.state || "learning";
      const c = j.counts || {};
      const label = st === "ready" ? "ready" : st === "mixed" ? "mixed" : "learning";
      chipBaseline.textContent = `baseline: ${label}`;
      chipBaseline.title =
        `Per-program baseline (~7d AND samples) - ${label}` +
        ` | procs ${c.processes || 0} (ready ${c.ready || 0}, learning ${c.learning || 0})` +
        ` | dests ${c.dests || 0}, upload samples ${c.upload_samples || 0}` +
        (j.asn_weak ? " | ASN weak (country+/24)" : "") +
        " | upload=process io_counters EMA (not per-TCP)";
      chipBaseline.classList.toggle("baseline-ready", st === "ready");
      chipBaseline.classList.toggle("baseline-learning", st === "learning" || st === "mixed");
    } catch (_) {
      chipBaseline.textContent = "baseline: -";
    }
  }
  refreshHistoryChip();
  setInterval(refreshHistoryChip, 15000);
  refreshNetCtxChip();
  refreshIpinfoChip();
  setInterval(() => { refreshNetCtxChip(); refreshIpinfoChip(); }, 15000);
  refreshBaselineChip();
  setInterval(refreshBaselineChip, 15000);


  // --- Direction filter ---
  if (dirFilterEl) {
    dirFilterEl.querySelectorAll(".dir-f").forEach((btn) => {
      btn.addEventListener("click", () => {
        dirFilter = btn.getAttribute("data-dir") || "all";
        applyDirFilterButtons();
        saveFilters();
        render();
      });
    });
    applyDirFilterButtons();
  }

  // --- Weekly summary modal ---
  const weeklyModal = document.getElementById("weekly-modal");
  const weeklyBody = document.getElementById("weekly-body");
  const btnWeekly = document.getElementById("btn-weekly");
  function closeWeekly() {
    if (!weeklyModal) return;
    weeklyModal.classList.add("hidden");
    weeklyModal.setAttribute("aria-hidden", "true");
  }
  async function openWeekly() {
    if (!weeklyModal) return;
    weeklyModal.classList.remove("hidden");
    weeklyModal.setAttribute("aria-hidden", "false");
    if (weeklyBody) weeklyBody.innerHTML = "<p>Loading weekly summary.</p>";
    try {
      const j = await twFetch("/api/summary/weekly").then((r) => r.json());
      if (!weeklyBody) return;
      if (!j || !j.ok) {
        weeklyBody.innerHTML = `<p class="kill-error">${escapeHtml((j && j.error) || "Failed")}</p>`;
        return;
      }
      if (j.young) {
        weeklyBody.innerHTML = `<p class="weekly-empty">${escapeHtml(j.empty_hint || "History is still young.")}</p>
          <p class="muted">Age ~${escapeHtml(String(j.age_hours || 0))} hours. Keep TrafficWatch running to fill this view.</p>`;
        return;
      }
      const top = (j.top_processes_outbound || [])
        .slice(0, 8)
        .map((p) => `<li><code>${escapeHtml(p.proc_key || "")}</code> — avg ${escapeHtml(String(Math.round(p.avg_out_bps || 0)))} B/s (${p.samples || 0} samples)${(p.stale_disk_era || p.label === "stale (disk-era)") ? ' <span class="muted">stale (disk-era)</span>' : ""}</li>`)
        .join("") || '<li class="muted">No upload samples yet</li>';
      const kinds = Object.entries(j.events_by_kind || {})
        .map(([k, v]) => `<li>${escapeHtml(k)}: ${v}</li>`)
        .join("") || '<li class="muted">No events</li>';
      weeklyBody.innerHTML = `
        <div class="weekly-grid">
          <div class="weekly-stat"><strong>${j.unique_remotes || 0}</strong><span>Unique remotes (7d)</span></div>
          <div class="weekly-stat"><strong>${j.new_remotes || 0}</strong><span>New remotes</span></div>
          <div class="weekly-stat"><strong>${j.intel_hits || 0}</strong><span>Intel hit events</span></div>
          <div class="weekly-stat"><strong>${j.new_listeners || 0}</strong><span>New listeners</span></div>
          <div class="weekly-stat"><strong>${j.baseline_departures || 0}</strong><span>Baseline departures</span></div>
          <div class="weekly-stat"><strong>${j.dns_flags || 0}</strong><span>DNS flags</span></div>
        </div>
        <h3>Top processes by outbound</h3>
        <ul class="weekly-list">${top}</ul>
        <h3>Events by kind</h3>
        <ul class="weekly-list">${kinds}</ul>
        <p class="muted footnote-inline">${escapeHtml(j.note || "")}</p>`;
    } catch (e) {
      if (weeklyBody) weeklyBody.innerHTML = `<p class="kill-error">Request failed</p>`;
    }
  }
  btnWeekly?.addEventListener("click", openWeekly);
  document.getElementById("weekly-close")?.addEventListener("click", closeWeekly);
  weeklyModal?.addEventListener("click", (e) => { if (e.target === weeklyModal) closeWeekly(); });

  // --- First-run guide (localStorage tw_seen_guide) ---
  const guideModal = document.getElementById("guide-modal");
  let guideStep = 0;
  function setGuideStep(n) {
    guideStep = Math.max(0, Math.min(5, n));
    const steps = guideModal?.querySelectorAll(".guide-steps li") || [];
    steps.forEach((li) => {
      li.classList.toggle("active", Number(li.getAttribute("data-step")) === guideStep);
    });
    const num = document.getElementById("guide-step-num");
    if (num) num.textContent = String(guideStep + 1);
    const next = document.getElementById("guide-next");
    if (next) next.textContent = guideStep >= 5 ? "Done" : "Next";
  }
  function closeGuide(save) {
    if (save) {
      try { localStorage.setItem(LS_GUIDE, "1"); } catch (_) {}
    }
    if (!guideModal) return;
    guideModal.classList.add("hidden");
    guideModal.setAttribute("aria-hidden", "true");
  }
  function openGuide() {
    if (!guideModal) return;
    guideModal.classList.remove("hidden");
    guideModal.setAttribute("aria-hidden", "false");
    setGuideStep(0);
  }
  document.getElementById("guide-skip")?.addEventListener("click", () => closeGuide(true));
  document.getElementById("guide-back")?.addEventListener("click", () => setGuideStep(guideStep - 1));
  document.getElementById("guide-next")?.addEventListener("click", () => {
    if (guideStep >= 5) closeGuide(true);
    else setGuideStep(guideStep + 1);
  });
  try {
    const seenRaw = (localStorage.getItem(LS_GUIDE) || "").trim().toLowerCase();
    const seenGuide = seenRaw === "1" || seenRaw === "true" || seenRaw === "yes";
    if (!seenGuide) {
      setTimeout(openGuide, 900);
    }
  } catch (_) {}



  // Escape closes top-most modal/popover (Weekly, Intel, Inspect, Alert, Home, Settings, Kill/FW)
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    const isOpen = (el) => el && !el.classList.contains("hidden") && el.getAttribute("aria-hidden") !== "true";
    const weeklyModalEl = document.getElementById("weekly-modal");
    const intelModalEl = document.getElementById("intel-modal");
    const inspectModalEl = document.getElementById("inspect-modal");
    const alertModalEl = document.getElementById("alert-modal");
    const killModalEl = document.getElementById("kill-modal");
    const fwModalEl = document.getElementById("fw-modal");
    const homePanelEl = document.getElementById("home-panel");
    const settingsPopEl = document.getElementById("settings-pop");
    if (isOpen(fwModalEl)) { document.getElementById("fw-cancel")?.click(); e.preventDefault(); return; }
    if (isOpen(killModalEl)) { document.getElementById("kill-cancel")?.click(); e.preventDefault(); return; }
    if (isOpen(alertModalEl)) { closeAlertDetail(); e.preventDefault(); return; }
    if (isOpen(inspectModalEl)) { document.getElementById("inspect-close")?.click(); e.preventDefault(); return; }
    if (isOpen(intelModalEl)) { closeIntelModal(); e.preventDefault(); return; }
    if (isOpen(weeklyModalEl)) { closeWeekly(); e.preventDefault(); return; }
    if (homePanelEl && !homePanelEl.classList.contains("hidden")) {
      homePanelEl.classList.add("hidden");
      e.preventDefault();
      return;
    }
    if (settingsPopEl && !settingsPopEl.classList.contains("hidden") && !settingsPopEl.hasAttribute("hidden")) {
      settingsPopEl.classList.add("hidden");
      settingsPopEl.setAttribute("hidden", "");
      document.getElementById("btn-settings")?.setAttribute("aria-expanded", "false");
      e.preventDefault();
    }
  });

})();
