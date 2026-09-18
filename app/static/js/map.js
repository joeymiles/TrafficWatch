/* TrafficWatch v2 map: globe.gl 3D globe + thin arcs (local vendor assets) */

window.TWMap = (() => {
  /** Default globe.pointOfView altitude (lower = closer / Earth fills more). */
  const DEFAULT_ALTITUDE = 1.35;
  const IMG_NIGHT = "/static/vendor/imgs/earth-night.jpg";
  const IMG_DAY = "/static/vendor/imgs/earth-blue-marble.jpg";
  const IMG_TOPO = "/static/vendor/imgs/earth-topology.png";
  const IMG_SKY = "/static/vendor/imgs/night-sky.png";
  const LS_SPIN = "tw_spin_v2";
  const LS_MODE = "tw_globe_mode";
  const MODES = ["night", "daynight", "day"];
  const SUN_MS = 60 * 1000;

  let globe = null;
  let mapEl = null;
  let resizeFn = null;
  let inited = false;
  let home = { lat: 39.8283, lon: -98.5795, label: "Home (set in UI)", source: "assumed_home" };
  let selectedKey = null;
  let onSelectCb = null;
  let onHoverCb = null;
  let lastArcs = [];
  let lastPoints = [];
  const ARC_LINGER_MS = 8000;
  const arcObjs = new Map(); // connection key -> stable arc object
  const pointObjs = new Map(); // remote_ip -> stable point object
  let homePointObj = null;
  let centeredOnHome = false;
  let userMovedView = false;
  let processFilter = null; // process name string or null (full globe)
  let arcsMembershipSig = "";
  let pointsMembershipSig = "";
  let spinEnabled = true;
  let globeMode = "daynight";
  let defaultMaterial = null;
  let dayReady = false;
  let sunTimer = null;
  let canvasFallback = false;
  let dayNightWarnOnce = false;
  let dayImage = null;
  let nightImage = null;

  function colorFor(dir, highlight, intelHit) {
    if (highlight) return "#fbbf24";
    if (intelHit) return "#fb7185";
    if (dir === "inbound") return "#f472b6";
    if (dir === "listen") return "#a78bfa";
    return "#38bdf8";
  }

  function loadSpinPref() {
    try {
      const raw = localStorage.getItem(LS_SPIN);
      if (raw === "0" || raw === "false") return false;
      if (raw === "1" || raw === "true") return true;
    } catch (_) {}
    return true;
  }

  function saveSpinPref(on) {
    try {
      localStorage.setItem(LS_SPIN, on ? "1" : "0");
    } catch (_) {}
  }

  function normalizeMode(raw) {
    if (raw === "day-night" || raw === "day_night") return "daynight";
    if (MODES.indexOf(raw) !== -1) return raw;
    return null;
  }

  function loadModePref() {
    try {
      const got = normalizeMode(localStorage.getItem(LS_MODE));
      if (got) return got;
    } catch (_) {}
    return "daynight";
  }

  function saveModePref(mode) {
    try {
      localStorage.setItem(LS_MODE, mode);
    } catch (_) {}
  }

  function applySpin() {
    const ctrl = globe && globe.controls && globe.controls();
    if (!ctrl) return;
    ctrl.autoRotate = !!spinEnabled;
    ctrl.autoRotateSpeed = 0.28;
  }

  function setSpin(on) {
    spinEnabled = !!on;
    saveSpinPref(spinEnabled);
    applySpin();
    return spinEnabled;
  }

  function getSpin() {
    return spinEnabled;
  }

  function toggleSpin() {
    return setSpin(!spinEnabled);
  }

  function setGlobeMode(mode) {
    const next = normalizeMode(mode) || "daynight";
    globeMode = next;
    saveModePref(next);
    applyMode();
    return globeMode;
  }

  function getGlobeMode() {
    return globeMode;
  }

  function radians(d) {
    return (Math.PI * d) / 180;
  }

  function degrees(r) {
    return (180 * r) / Math.PI;
  }

  // solar-calculator (mbostock) — J2000 century, equation of time, declination.
  function solarCentury(date) {
    return (date - Date.UTC(2000, 0, 1, 12)) / 315576e7;
  }

  function meanLongitude(t) {
    let l = (280.46646 + t * (36000.76983 + t * 0.0003032)) % 360;
    return l < 0 ? l + 360 : l;
  }

  function meanAnomaly(t) {
    return 357.52911 + t * (35999.05029 - 0.0001537 * t);
  }

  function equationOfCenter(t) {
    const m = radians(meanAnomaly(t));
    return (
      Math.sin(m) * (1.914602 - t * (0.004817 + 0.000014 * t)) +
      Math.sin(m * 2) * (0.019993 - 0.000101 * t) +
      Math.sin(m * 3) * 0.000289
    );
  }

  function apparentLongitude(t) {
    return meanLongitude(t) + equationOfCenter(t) - 0.00569 - 0.00478 * Math.sin(radians(125.04 - 1934.136 * t));
  }

  function obliquityOfEcliptic(t) {
    const e0 = 23 + (26 + (21.448 - t * (46.815 + t * (0.00059 - t * 0.001813))) / 60) / 60;
    return e0 + 0.00256 * Math.cos(radians(125.04 - 1934.136 * t));
  }

  function declination(t) {
    return degrees(Math.asin(Math.sin(radians(obliquityOfEcliptic(t))) * Math.sin(radians(apparentLongitude(t)))));
  }

  function orbitEccentricity(t) {
    return 0.016708634 - t * (0.000042037 + 0.0000001267 * t);
  }

  function equationOfTime(t) {
    const epsilon = obliquityOfEcliptic(t);
    const l0 = meanLongitude(t);
    const e = orbitEccentricity(t);
    const m = meanAnomaly(t);
    const y = Math.pow(Math.tan(radians(epsilon) / 2), 2);
    const Etime =
      y * Math.sin(2 * radians(l0)) -
      2 * e * Math.sin(radians(m)) +
      4 * e * y * Math.sin(radians(m)) * Math.cos(2 * radians(l0)) -
      0.5 * y * y * Math.sin(4 * radians(l0)) -
      1.25 * e * e * Math.sin(2 * radians(m));
    return degrees(Etime) * 4;
  }

  /** Subsolar [lng, lat] from UTC instant (globe.gl day-night-cycle formula). */
  function sunPosAt(dt) {
    const day = new Date(+dt).setUTCHours(0, 0, 0, 0);
    const t = solarCentury(dt);
    let longitude = ((day - dt) / 864e5) * 360 - 180;
    longitude -= equationOfTime(t) / 4;
    while (longitude > 180) longitude -= 360;
    while (longitude < -180) longitude += 360;
    return [longitude, declination(t)];
  }

  function loadImage(url) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error("texture failed: " + url));
      img.src = url;
    });
  }

  function tintDefault(dim) {
    const mat = defaultMaterial;
    if (!mat || !mat.color || typeof mat.color.setHex !== "function") return;
    mat.color.setHex(dim ? 0xb4bcc8 : 0xffffff);
  }

  function useNightTexture() {
    if (!globe) return;
    if (defaultMaterial) globe.globeMaterial(defaultMaterial);
    globe.globeImageUrl(IMG_NIGHT);
    tintDefault(false);
  }

  function blendCanvas(sunLng, sunLat) {
    if (!dayImage || !nightImage) return null;
    const w = Math.min(dayImage.naturalWidth || dayImage.width || 2048, 2048);
    const h = Math.min(dayImage.naturalHeight || dayImage.height || 1024, 1024);
    const c = document.createElement("canvas");
    c.width = w;
    c.height = h;
    const ctx = c.getContext("2d", { willReadFrequently: true });
    if (!ctx) return null;
    ctx.drawImage(nightImage, 0, 0, w, h);
    const nightData = ctx.getImageData(0, 0, w, h);
    ctx.drawImage(dayImage, 0, 0, w, h);
    const dayData = ctx.getImageData(0, 0, w, h);
    const out = ctx.createImageData(w, h);
    const sl = radians(sunLng);
    const sb = radians(sunLat);
    const sunX = Math.cos(sb) * Math.cos(sl);
    const sunY = Math.sin(sb);
    const sunZ = Math.cos(sb) * Math.sin(sl);
    for (let y = 0; y < h; y++) {
      const lat = radians(90 - ((y + 0.5) / h) * 180);
      const cosLat = Math.cos(lat);
      const sinLat = Math.sin(lat);
      for (let x = 0; x < w; x++) {
        const lon = radians(((x + 0.5) / w) * 360 - 180);
        const nx = cosLat * Math.cos(lon);
        const ny = sinLat;
        const nz = cosLat * Math.sin(lon);
        const intensity = nx * sunX + ny * sunY + nz * sunZ;
        let t = (intensity + 0.12) / 0.24;
        if (t < 0) t = 0;
        else if (t > 1) t = 1;
        t = t * t * (3 - 2 * t);
        const i = (y * w + x) * 4;
        out.data[i] = nightData.data[i] * (1 - t) + dayData.data[i] * t * 0.78;
        out.data[i + 1] = nightData.data[i + 1] * (1 - t) + dayData.data[i + 1] * t * 0.8;
        out.data[i + 2] = nightData.data[i + 2] * (1 - t) + dayData.data[i + 2] * t * 0.86;
        out.data[i + 3] = 255;
      }
    }
    ctx.putImageData(out, 0, 0);
    return c;
  }

  function applyCanvasDayNight() {
    try {
      if (!globe) return false;
      if (!dayImage || !nightImage) return false;
      const [lng, lat] = sunPosAt(Date.now());
      const canvas = blendCanvas(lng, lat);
      if (!canvas) return false;
      const dataUrl = canvas.toDataURL("image/jpeg", 0.82);
      if (defaultMaterial) {
        try {
          globe.globeMaterial(defaultMaterial);
        } catch (_) {}
      }
      globe.globeImageUrl(dataUrl);
      tintDefault(false);
      return true;
    } catch (err) {
      console.warn("TrafficWatch applyCanvasDayNight failed", err);
      return false;
    }
  }

  function updateSun() {
    if (globeMode === "daynight" && canvasFallback && dayReady) {
      applyCanvasDayNight();
    }
  }

  function applyMode() {
    if (!globe) return;
    if (globeMode === "daynight") {
      canvasFallback = false;
      if (dayReady && applyCanvasDayNight()) {
        canvasFallback = true;
        return;
      }
      // Before images load: night silently. Warn only after dayReady if canvas fails
      // (setupLighting also warns on image load failure).
      useNightTexture();
      if (dayReady && !dayNightWarnOnce) {
        dayNightWarnOnce = true;
        console.warn("TrafficWatch day/night unavailable; using night");
      }
      return;
    }
    canvasFallback = false;
    if (globeMode === "day" && dayReady) {
      if (defaultMaterial) globe.globeMaterial(defaultMaterial);
      globe.globeImageUrl(IMG_DAY);
      tintDefault(true);
      return;
    }
    useNightTexture();
  }

  function whenMapReady(cb) {
    let n = 0;
    const tick = () => {
      const mat = globe && globe.globeMaterial && globe.globeMaterial();
      if (mat && mat.map && mat.map.constructor) {
        cb(mat);
        return;
      }
      if (n++ > 80) {
        cb(mat || defaultMaterial);
        return;
      }
      setTimeout(tick, 50);
    };
    tick();
  }

  function setupLighting() {
    Promise.all([loadImage(IMG_DAY), loadImage(IMG_NIGHT)])
      .then(([dayImg, nightImg]) => {
        dayImage = dayImg;
        nightImage = nightImg;
        dayReady = true;
        whenMapReady((mat) => {
          defaultMaterial = defaultMaterial || mat;
          applyMode();
        });
      })
      .catch((err) => {
        console.warn("TrafficWatch day texture failed; staying on night", err);
        dayReady = false;
        useNightTexture();
      });
  }

  function startSunTimer() {
    updateSun();
    if (sunTimer) clearInterval(sunTimer);
    sunTimer = setInterval(updateSun, SUN_MS);
  }

  function tipHtml(c) {
    if (!c) return "";
    const remote = c.remote_ip
      ? `${c.remote_ip}${c.remote_port != null ? ":" + c.remote_port : ""}`
      : "—";
    const host = c.hostname ? `<div class="tt-host">${esc(c.hostname)}</div>` : "";
    const place = [c.city, c.country].filter(Boolean).join(", ") || "—";
    const rate =
      c.bytes_in_rate != null || c.bytes_out_rate != null
        ? `↓${fmt(c.bytes_in_rate_share ?? c.bytes_in_rate)} ↑${fmt(c.bytes_out_rate_share ?? c.bytes_out_rate)}`
        : "—";
    const intel = c.intel && c.intel.hit
      ? `<div class="tt-intel">INTEL · ${(c.intel.lists || []).join(", ") || "list"} · ${esc(c.intel.severity || "")}</div>`
      : "";
    const sigs = (c.signals || []).length
      ? `<div class="tt-sig">${(c.signals || []).slice(0, 4).map((s) => esc(s.label || s.id)).join(" · ")}</div>`
      : "";
    let dirLine = (c.direction || "out").toUpperCase();
    const basis = c.direction_basis || "guess";
    if (c.direction === "inbound" && basis === "confirmed") {
      dirLine = "INBOUND (confirmed - listener on :" + (c.local_port ?? "?") + ")";
    } else if (c.direction === "inbound") {
      dirLine = "INBOUND (guess from ports)";
    } else if (c.direction === "listen") {
      dirLine = "LISTENING";
    } else if (basis === "guess") {
      dirLine = "OUTBOUND (guess from ports)";
    } else {
      dirLine = "OUTBOUND";
    }
    return (
      `<div class="tt">` +
      `<div class="tt-title">${esc(c.process || "?")} <span class="tt-pid">PID ${c.pid ?? "—"}</span></div>` +
      `<div><b>${esc(dirLine)}</b> · ${esc(c.proto || "")} ${esc(c.status || "")}</div>` +
      `<div>Remote: ${esc(remote)}</div>${host}` +
      `<div>${esc(place)}</div>` +
      `<div>Local :${c.local_port ?? "—"} · Rate ${esc(rate)}</div>` +
      intel + sigs +
      `</div>`
    );
  }

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function fmt(n) {
    if (n == null || Number.isNaN(n)) return "—";
    if (n < 1024) return `${n.toFixed(0)} B/s`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB/s`;
    return `${(n / (1024 * 1024)).toFixed(2)} MB/s`;
  }

  function resize() {
    if (typeof resizeFn === "function") {
      try { resizeFn(); } catch (_) {}
      return;
    }
    if (!globe || !mapEl) return;
    try {
      const w = mapEl.clientWidth || 600;
      const h = mapEl.clientHeight || 400;
      globe.width(w);
      globe.height(h);
    } catch (_) {}
  }

  function init(elId) {
    const el = document.getElementById(elId);
    mapEl = el || mapEl;
    if (inited && globe) {
      resize();
      return globe;
    }
    if (!el || typeof Globe !== "function") {
      console.error("globe.gl not loaded");
      el && (el.innerHTML = '<div class="globe-fallback">globe.gl failed to load (local vendor). Check static/vendor/globe.gl.min.js.</div>');
      return null;
    }

    spinEnabled = loadSpinPref();
    globeMode = loadModePref();

    try {
      globe = Globe()(el)
        .globeImageUrl(IMG_NIGHT)
        .bumpImageUrl(IMG_TOPO)
        .backgroundImageUrl(IMG_SKY)
        .showAtmosphere(true)
        .atmosphereColor("#4b7bec")
        .atmosphereAltitude(0.18)
        .arcsData([])
        .arcColor((d) => d.color)
        .arcAltitude((d) => d.alt || 0.12)
        .arcStroke((d) => (d.highlight ? 0.55 : 0.18))
        .arcDashLength(0.4)
        .arcDashGap(0.55)
        .arcDashAnimateTime(3200)
        .arcsTransitionDuration(0)
        .pointsTransitionDuration(0)
        .arcLabel(() => null)
        .onArcClick((arc) => {
          if (!arc) return;
          selectedKey = arc.key;
          if (onSelectCb) onSelectCb(arc.key, arc);
          _refreshHighlight();
        })
        .onArcHover((arc) => {
          if (onHoverCb) onHoverCb(arc || null, "arc");
        })
        .pointsData([])
        .pointAltitude(0.008)
        .pointRadius((d) => (d.isHome ? 0.38 : d.highlight ? 0.22 : 0.12))
        .pointColor((d) => d.color)
        .pointLabel(() => null)
        .onPointClick((p) => {
          if (!p || p.isHome) return;
          selectedKey = p.key || selectedKey;
          if (p.key && onSelectCb) onSelectCb(p.key, p);
          if (p.lat != null) focusLatLng(p.lat, p.lng);
          _refreshHighlight();
        })
        .onPointHover((p) => {
          if (onHoverCb) onHoverCb(p && !p.isHome ? p : null, "point");
        });
    } catch (err) {
      console.error("Globe init failed", err);
      el.innerHTML = '<div class="globe-fallback">WebGL/globe.gl failed to initialize (local vendor). Check WebGL and static/vendor.</div>';
      globe = null;
      return null;
    }

    defaultMaterial = globe.globeMaterial && globe.globeMaterial();

    // GPU budget (#69): cap render resolution on high-DPI screens and stop rendering
    // entirely while the window is hidden/minimized, so the globe never loads the
    // GPU driver (seen as "System interrupts") when nobody is looking at it.
    try {
      const r = globe.renderer && globe.renderer();
      if (r && r.setPixelRatio) r.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.25));
    } catch (_) {}
    document.addEventListener("visibilitychange", () => {
      if (!globe) return;
      try {
        if (document.hidden) {
          if (globe.pauseAnimation) globe.pauseAnimation();
        } else if (globe.resumeAnimation) {
          globe.resumeAnimation();
        }
      } catch (_) {}
    });

    resizeFn = () => {
      if (!globe || !el) return;
      const w = el.clientWidth || 600;
      const h = el.clientHeight || 400;
      try {
        globe.width(w);
        globe.height(h);
      } catch (_) {}
    };

    let tries = 0;
    const trySize = () => {
      if (!globe || !el) return;
      const w0 = el.clientWidth;
      const h0 = el.clientHeight;
      if ((w0 === 0 || h0 === 0) && tries < 20) {
        tries += 1;
        try {
          requestAnimationFrame(trySize);
        } catch (_) {
          setTimeout(trySize, 50);
        }
        return;
      }
      resizeFn();
    };
    trySize();
    for (let i = 1; i <= 20; i++) {
      setTimeout(trySize, i * 100);
    }
    window.addEventListener("resize", resizeFn);

    const ctrl = globe.controls();
    if (ctrl) {
      ctrl.enableDamping = true;
      applySpin();
      // A real drag/zoom by the user: stop auto-centering on home for this session.
      ctrl.addEventListener("start", () => { userMovedView = true; });
    }

    setHome(home);
    globe.pointOfView({ lat: home.lat, lng: home.lon, altitude: DEFAULT_ALTITUDE }, 0);
    setupLighting();
    startSunTimer();
    inited = true;
    return globe;
  }

  function onSelect(cb) {
    onSelectCb = cb;
  }

  function onHover(cb) {
    onHoverCb = cb;
  }

  function setHome(h) {
    const prev = home;
    home = h || home;
    const label = document.getElementById("home-label");
    if (label) label.textContent = `Home: ${home.label || "set in UI"}`;
    _paint();
    // #68: the camera was only pointed once at init (the US-center fallback), so a
    // saved/detected home that arrived a moment later never moved the view. Center on
    // a real home when it first arrives or when its coordinates change, unless the
    // user has already dragged the globe this session.
    const real = home && home.source !== "assumed_home" && home.lat != null && home.lon != null;
    const moved = !prev || prev.lat !== home.lat || prev.lon !== home.lon;
    if (globe && real && (moved || !centeredOnHome) && !userMovedView) {
      try {
        globe.pointOfView({ lat: home.lat, lng: home.lon, altitude: DEFAULT_ALTITUDE }, centeredOnHome && !document.hidden ? 900 : 0);
        centeredOnHome = true;
      } catch (_) {}
    }
  }

  function getHome() {
    return home;
  }

  function setSelected(key) {
    selectedKey = key;
    _refreshHighlight();
  }

  function setProcessFilter(name) {
    const n = name != null && String(name).trim() !== "" ? String(name) : null;
    if (n === processFilter) {
      _rebuildVisible();
      return;
    }
    processFilter = n;
    _rebuildVisible();
    _pushGlobeData(false);
    _refreshHighlight();
  }

  function getProcessFilter() {
    return processFilter;
  }

  function _arcMatchesFilter(a) {
    if (!processFilter) return true;
    return a.process === processFilter;
  }

  function _rebuildVisible() {
    if (!processFilter) {
      lastArcs = Array.from(arcObjs.values());
      lastPoints = [_ensureHomePoint(), ...pointObjs.values()];
      return;
    }
    // Non-matching arcs must NOT linger while filtered — omit from lastArcs immediately.
    lastArcs = Array.from(arcObjs.values()).filter(_arcMatchesFilter);
    const ips = new Set(lastArcs.map((a) => a.ip).filter(Boolean));
    lastPoints = [
      _ensureHomePoint(),
      ...[...pointObjs.values()].filter(
        (p) => p.process === processFilter || (p.ip && ips.has(p.ip))
      ),
    ];
  }

  function _dimColor(hex, fade) {
    // fade 0..1 (1 = full). Soften linger arcs without rebuilding objects.
    if (!fade || fade >= 0.99) return hex;
    const h = String(hex || "#38bdf8").replace("#", "");
    if (h.length !== 6) return hex;
    const r = parseInt(h.slice(0, 2), 16);
    const g = parseInt(h.slice(2, 4), 16);
    const b = parseInt(h.slice(4, 6), 16);
    const mix = (c) => Math.round(c * fade + 30 * (1 - fade));
    const to = (n) => n.toString(16).padStart(2, "0");
    return "#" + to(mix(r)) + to(mix(g)) + to(mix(b));
  }

  function _ensureHomePoint() {
    if (!homePointObj) {
      homePointObj = {
        lat: home.lat,
        lng: home.lon,
        color: "#5eead4",
        isHome: true,
        label: home.label || "Home",
        tip: `<div class="tt"><div class="tt-title">${esc(home.label || "Home")}</div></div>`,
        key: "__home__",
      };
    } else {
      homePointObj.lat = home.lat;
      homePointObj.lng = home.lon;
      homePointObj.label = home.label || "Home";
      homePointObj.tip = `<div class="tt"><div class="tt-title">${esc(home.label || "Home")}</div></div>`;
    }
    return homePointObj;
  }

  function _pushGlobeData(force) {
    if (!globe) return;
    const arcSig = lastArcs.map((a) => a.key).join("\0");
    const pointSig = lastPoints.map((p) => p.key || (p.isHome ? "__home__" : p.ip)).join("\0");
    const arcChanged = force || arcSig !== arcsMembershipSig;
    const pointChanged = force || pointSig !== pointsMembershipSig;
    if (arcChanged) {
      arcsMembershipSig = arcSig;
      globe.arcsData(lastArcs);
    }
    if (pointChanged) {
      pointsMembershipSig = pointSig;
      globe.pointsData(lastPoints);
    }
  }

  function _refreshHighlight() {
    // Mutate colors in place; do not resend arcsData/pointsData (avoids dash restart).
    for (const a of lastArcs) {
      a.highlight = a.key === selectedKey;
      const base = colorFor(a.direction, a.highlight, !!a.intelHit);
      a.color = a.lingering ? _dimColor(base, 0.35) : base;
    }
    for (const p of lastPoints) {
      if (p.isHome) continue;
      p.highlight = p.key === selectedKey || (selectedKey && p.ip && selectedKey.includes(p.ip));
      const base = p.highlight ? "#fbbf24" : colorFor(p.direction, false, !!p.intelHit);
      p.color = p.lingering ? _dimColor(base, 0.35) : base;
    }
    if (!globe) return;
    const ctrl = globe.controls && globe.controls();
    if (ctrl && selectedKey) {
      ctrl.autoRotate = false;
      clearTimeout(_refreshHighlight._t);
      _refreshHighlight._t = setTimeout(() => {
        applySpin();
      }, 8000);
    }
  }

  function upsert(connections) {
    const now = Date.now();
    const seenKeys = new Set();
    const seenIps = new Set();
    const capped = connections.slice(0, 280);

    if (!globe) {
      // Still keep object maps warm so first paint is stable
    } else {
      globe
        .arcStartLat("startLat")
        .arcStartLng("startLng")
        .arcEndLat("endLat")
        .arcEndLng("endLng");
    }

    for (const c of capped) {
      if (c.lat == null || c.lon == null) continue;
      if (c.direction === "listen") continue;
      if (!c.remote_ip) continue;

      const key =
        c._key ||
        `${c.proto}|${c.pid}|${c.local_ip}:${c.local_port}|${c.remote_ip}:${c.remote_port}|${c.status}`;
      const highlight = key === selectedKey;
      const dist = Math.abs(c.lat - home.lat) + Math.abs(c.lon - home.lon);
      const alt = Math.min(0.4, 0.06 + dist / 400);
      const intelHit = !!(c.intel && c.intel.hit);
      // Inbound: animate toward home (remote -> home); outbound: away (home -> remote)
      const inbound = c.direction === "inbound";
      const startLat = inbound ? c.lat : home.lat;
      const startLng = inbound ? c.lon : home.lon;
      const endLat = inbound ? home.lat : c.lat;
      const endLng = inbound ? home.lon : c.lon;
      const color = colorFor(c.direction, highlight, intelHit);

      let arc = arcObjs.get(key);
      if (!arc) {
        arc = {
          key,
          startLat,
          startLng,
          endLat,
          endLng,
          color,
          direction: c.direction,
          intelHit,
          alt,
          highlight,
          tip: tipHtml(c),
          conn: c,
          ip: c.remote_ip,
          process: c.process,
          pid: c.pid,
          lat: c.lat,
          lng: c.lon,
          lingering: false,
          closedAt: null,
        };
        arcObjs.set(key, arc);
      } else {
        arc.startLat = startLat;
        arc.startLng = startLng;
        arc.endLat = endLat;
        arc.endLng = endLng;
        arc.direction = c.direction;
        arc.intelHit = intelHit;
        arc.alt = alt;
        arc.highlight = highlight;
        arc.tip = tipHtml(c);
        arc.conn = c;
        arc.ip = c.remote_ip;
        arc.process = c.process;
        arc.pid = c.pid;
        arc.lat = c.lat;
        arc.lng = c.lon;
        arc.lingering = false;
        arc.closedAt = null;
        arc.color = color;
      }
      seenKeys.add(key);

      if (!seenIps.has(c.remote_ip)) {
        seenIps.add(c.remote_ip);
        let pt = pointObjs.get(c.remote_ip);
        if (!pt) {
          pt = {
            lat: c.lat,
            lng: c.lon,
            color,
            direction: c.direction,
            intelHit,
            highlight,
            ip: c.remote_ip,
            process: c.process,
            key,
            conn: c,
            tip: tipHtml(c),
            lingering: false,
            closedAt: null,
          };
          pointObjs.set(c.remote_ip, pt);
        } else {
          pt.lat = c.lat;
          pt.lng = c.lon;
          pt.direction = c.direction;
          pt.intelHit = intelHit;
          pt.highlight = highlight;
          pt.key = key;
          pt.conn = c;
          pt.process = c.process;
          pt.tip = tipHtml(c);
          pt.lingering = false;
          pt.closedAt = null;
          pt.color = color;
        }
      }
    }

    for (const [key, arc] of [...arcObjs.entries()]) {
      if (seenKeys.has(key)) continue;
      if (!arc.closedAt) arc.closedAt = now;
      const age = now - arc.closedAt;
      if (age >= ARC_LINGER_MS) {
        arcObjs.delete(key);
        continue;
      }
      arc.lingering = true;
      arc.highlight = arc.key === selectedKey;
      arc.color = _dimColor(colorFor(arc.direction, arc.highlight, !!arc.intelHit), 0.35);
    }

    for (const [ip, pt] of [...pointObjs.entries()]) {
      if (seenIps.has(ip)) continue;
      if (!pt.closedAt) pt.closedAt = now;
      const age = now - pt.closedAt;
      if (age >= ARC_LINGER_MS) {
        pointObjs.delete(ip);
        continue;
      }
      pt.lingering = true;
      pt.highlight = pt.key === selectedKey || (selectedKey && pt.ip && selectedKey.includes(pt.ip));
      pt.color = _dimColor(pt.highlight ? "#fbbf24" : colorFor(pt.direction, false, !!pt.intelHit), 0.35);
    }

    _rebuildVisible();
    _pushGlobeData(false);
  }

  function focusLatLng(lat, lon) {
    if (!globe || lat == null || lon == null) return;
    globe.pointOfView({ lat, lng: lon, altitude: 1.25 }, 800);
  }

  function focusIp(ip, lat, lon) {
    focusLatLng(lat, lon);
  }

  function _paint() {
    _ensureHomePoint();
    // Home moved: mutate outbound starts / inbound ends that use home; keep object identity.
    for (const a of arcObjs.values()) {
      const inbound = a.direction === "inbound";
      if (inbound) {
        a.endLat = home.lat;
        a.endLng = home.lon;
      } else {
        a.startLat = home.lat;
        a.startLng = home.lon;
      }
    }
    _rebuildVisible();
    if (globe) {
      // Membership unchanged; still poke once so home point coords refresh.
      arcsMembershipSig = "";
      pointsMembershipSig = "";
      _pushGlobeData(true);
    }
  }

  return {
    init,
    resize,
    setHome,
    getHome,
    getView: () => (globe && globe.pointOfView ? globe.pointOfView() : null),
    upsert,
    focusIp,
    focusLatLng,
    setSelected,
    setProcessFilter,
    getProcessFilter,
    onSelect,
    onHover,
    setSpin,
    getSpin,
    toggleSpin,
    setGlobeMode,
    getGlobeMode,
    tipHtml,
  };
})();

/* Auto-init #globe when Globe is ready; notify app.js via event + callback. */
(function () {
  try {
    if (typeof Globe === "function" && window.TWMap && typeof window.TWMap.init === "function") {
      window.TWMap.init("globe");
    }
  } catch (err) {
    console.error("TWMap auto-init failed", err);
  }
  try {
    window.dispatchEvent(new Event("tw-map-ready"));
  } catch (err) {
    console.warn("TrafficWatch: tw-map-ready dispatch failed", err);
  }
  try {
    if (typeof window.__twOnMapReady === "function") window.__twOnMapReady();
  } catch (err) {
    console.warn("TrafficWatch: __twOnMapReady failed", err);
  }
})();
