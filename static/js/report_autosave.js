/* Server-side draft autosave for report edit forms.
 *
 * A container with data-autosave-url / data-autosave-pk / data-autosave-model
 * / data-autosave-fields (comma-separated field names) wires those fields to
 * save, debounced, to the report autosave endpoint as the user types. A
 * [data-autosave-status] element shows "Saving…" / "Saved HH:MM:SS" / failure.
 *
 * Text fields only; selects, contacts, and brand-new (unsaved) objects save
 * on explicit submit.
 */
(function () {
  function csrfToken() {
    var m = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  document.querySelectorAll("[data-autosave-url]").forEach(function (wrap) {
    var url = wrap.getAttribute("data-autosave-url");
    var pk = wrap.getAttribute("data-autosave-pk");
    var model = wrap.getAttribute("data-autosave-model");
    var fields = (wrap.getAttribute("data-autosave-fields") || "")
      .split(",")
      .map(function (s) { return s.trim(); })
      .filter(Boolean);
    var status = wrap.querySelector("[data-autosave-status]")
      || document.querySelector("[data-autosave-status]");

    function setStatus(text) { if (status) status.textContent = text; }

    fields.forEach(function (field) {
      var el = wrap.querySelector('[name="' + field + '"]');
      if (!el) return;
      var timer = null;

      function save() {
        setStatus("Saving…");
        fetch(url, {
          method: "POST",
          headers: { "X-CSRFToken": csrfToken(), "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ model: model, pk: pk, field: field, value: el.value }),
        })
          .then(function (r) {
            if (!r.ok) throw new Error("autosave failed");
            return r.json();
          })
          .then(function (data) { setStatus("Saved " + (data.saved_at || "")); })
          .catch(function () { setStatus("Save failed — your text is still on screen"); });
      }

      el.addEventListener("input", function () {
        if (timer) clearTimeout(timer);
        timer = setTimeout(save, 1500);
      });
    });
  });
})();
