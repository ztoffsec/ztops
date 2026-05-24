/* Edit/Preview toggle for the Finding description textarea.
 *
 * Markup contract:
 *
 *   <div data-md-preview data-endpoint="/findings/preview-markdown/">
 *     <div class="md-tabs">
 *       <button type="button" data-md-tab="edit">Edit</button>
 *       <button type="button" data-md-tab="preview">Preview</button>
 *     </div>
 *     <div data-md-edit>      <!-- textarea here --></div>
 *     <div data-md-preview-body class="markdown-body"></div>
 *   </div>
 *
 * On "Preview" the wrapped textarea's current value is POSTed to the
 * endpoint and the returned HTML is dropped into the preview-body
 * container. CSRF token is read from the page cookie.
 */
(function () {
  "use strict";

  function getCookie(name) {
    var match = document.cookie.match(new RegExp("(^|;\\s*)" + name + "=([^;]+)"));
    return match ? decodeURIComponent(match[2]) : null;
  }

  function bind(root) {
    var endpoint = root.getAttribute("data-endpoint");
    var editPane = root.querySelector("[data-md-edit]");
    var previewPane = root.querySelector("[data-md-preview-body]");
    var editTab = root.querySelector('[data-md-tab="edit"]');
    var previewTab = root.querySelector('[data-md-tab="preview"]');
    if (!endpoint || !editPane || !previewPane || !editTab || !previewTab) return;

    function showEdit() {
      editPane.style.display = "";
      previewPane.style.display = "none";
      editTab.classList.add("active");
      previewTab.classList.remove("active");
    }
    function showPreview() {
      editPane.style.display = "none";
      previewPane.style.display = "";
      editTab.classList.remove("active");
      previewTab.classList.add("active");
    }

    async function fetchPreview() {
      var ta = editPane.querySelector("textarea");
      var body = ta ? ta.value : "";
      previewPane.innerHTML = '<p class="subtle">Rendering…</p>';
      showPreview();
      try {
        var form = new FormData();
        form.append("body", body);
        var res = await fetch(endpoint, {
          method: "POST",
          headers: { "X-CSRFToken": getCookie("csrftoken") || "" },
          body: form,
          credentials: "same-origin",
        });
        if (!res.ok) throw new Error("preview failed");
        var html = await res.text();
        previewPane.innerHTML = html || '<p class="subtle">Nothing to preview yet.</p>';
      } catch (err) {
        previewPane.innerHTML = '<p class="status error">Preview failed: ' +
          String(err.message || err) + '</p>';
      }
    }

    editTab.addEventListener("click", showEdit);
    previewTab.addEventListener("click", fetchPreview);
    showEdit();
  }

  function init() {
    document.querySelectorAll("[data-md-preview]").forEach(bind);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
