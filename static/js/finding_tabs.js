/* Client-side tab switching for the finding detail page.
 *
 * Server already renders the active tab via ?tab=X (deep-linkable on its
 * own). This script enhances the experience by switching tabs without a
 * page reload + updating the URL via History API. If JS fails to load,
 * tab links still work as plain GETs.
 *
 * Also handles data-confirm on forms (replaces missing window.confirm
 * styling — we use a native confirm dialog).
 */
(function () {
  "use strict";

  function activateTab(name) {
    var tabs = document.querySelectorAll("[data-tab-link]");
    var panels = document.querySelectorAll("[data-tab-panel]");
    tabs.forEach(function (t) {
      t.classList.toggle("active", t.getAttribute("data-tab-link") === name);
    });
    panels.forEach(function (p) {
      p.classList.toggle("active", p.getAttribute("data-tab-panel") === name);
    });
  }

  function bindTabs() {
    var container = document.querySelector("[data-finding-tabs]");
    if (!container) return;
    container.addEventListener("click", function (ev) {
      var link = ev.target.closest("[data-tab-link]");
      if (!link) return;
      ev.preventDefault();
      var name = link.getAttribute("data-tab-link");
      activateTab(name);
      var url = new URL(window.location.href);
      url.searchParams.set("tab", name);
      window.history.replaceState({}, "", url.toString());
    });
  }

  function bindConfirms() {
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (ev) {
        var msg = form.getAttribute("data-confirm") || "Are you sure?";
        if (!window.confirm(msg)) ev.preventDefault();
      });
    });
  }

  function init() {
    bindTabs();
    bindConfirms();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
