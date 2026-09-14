/* Boot splash: hide on live snapshot; error at ~10s. ASCII only. */
(function () {
  var hidden = false;
  var snapshotOk = false;

  function afterHide() {
    try { window.dispatchEvent(new Event("resize")); } catch (err) {
      console.warn("TrafficWatch: boot resize dispatch failed", err);
    }
    try {
      if (window.TWMap && typeof window.TWMap.resize === "function") window.TWMap.resize();
    } catch (err) {
      console.warn("TrafficWatch: boot TWMap.resize failed", err);
    }
  }

  function hide() {
    var el = document.getElementById("boot-splash");
    if (!el || el.classList.contains("hidden")) {
      hidden = true;
      return;
    }
    hidden = true;
    el.classList.add("hidden");
    afterHide();
  }

  window.__twHideBoot = hide;

  function showError(details) {
    if (hidden || snapshotOk) return;
    var el = document.getElementById("boot-splash");
    if (!el) return;
    el.classList.add("boot-error");
    var title = document.getElementById("boot-title");
    var sub = document.getElementById("boot-sub");
    if (title) title.textContent = "Could not load the live view";
    if (sub) {
      sub.textContent = details || "Session or snapshot failed. Click to dismiss and inspect chrome.";
    }
    var spin = el.querySelector(".boot-spin");
    if (spin) spin.style.display = "none";
  }

  try {
    fetch("/api/snapshot", { credentials: "include" }).then(function (r) {
      if (r && r.ok) {
        snapshotOk = true;
        hide();
      }
    }).catch(function (err) {
      console.warn("TrafficWatch: boot snapshot fetch failed", err);
    });
  } catch (err) {
    console.warn("TrafficWatch: boot snapshot fetch error", err);
  }

  setTimeout(function () {
    if (hidden || snapshotOk) return;
    showError("Session or snapshot failed after 10s. Click to dismiss so you can see chrome.");
  }, 10000);

  document.addEventListener("click", function (e) {
    if (e.target && e.target.closest && e.target.closest("#boot-splash")) hide();
  });
})();
