/* Chip-style tag input with a fully-styled, JS-driven autocomplete popup.
 *
 * Native <datalist> is unstyleable across browsers, so this widget rolls
 * its own suggestion list (.tag-input-suggestions) that the CSS in
 * base.html / form.html takes responsibility for.
 *
 * Two modes (data-mode):
 *
 * - "cwe":  loads a JSON list of {id, name} from data-source. Typing
 *           filters the popup by name/id substring; arrow keys navigate;
 *           Enter / click commits a chip carrying just the CWE id.
 * - "url":  free-form text; Enter or comma commits a chip.
 *
 * The component owns a hidden <input name=...> whose value is the JSON
 * array of currently-added tags. The form submits that as the JSON
 * payload Finding.cwe_ids / Finding.references expect.
 *
 * Markup contract:
 *
 *   <div data-tag-input data-mode="cwe" data-source="/static/data/cwes.json">
 *     <input type="hidden" name="cwe_ids" data-tag-input-value value="[]">
 *     <span data-tag-input-chips></span>
 *     <input type="text" data-tag-input-entry placeholder="…">
 *     <ul data-tag-input-suggestions class="tag-input-suggestions"></ul>
 *   </div>
 */
(function () {
  "use strict";

  var MAX_SUGGESTIONS = 12;

  function parseInitial(hidden) {
    try {
      var v = JSON.parse(hidden.value || "[]");
      return Array.isArray(v) ? v.map(String) : [];
    } catch (e) {
      return [];
    }
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function bind(root) {
    var mode = root.getAttribute("data-mode") || "url";
    var source = root.getAttribute("data-source");
    var hidden = root.querySelector("[data-tag-input-value]");
    var chips = root.querySelector("[data-tag-input-chips]");
    var entry = root.querySelector("[data-tag-input-entry]");
    var popup = root.querySelector("[data-tag-input-suggestions]");
    if (!hidden || !chips || !entry) return;

    var tags = parseInitial(hidden);
    var dataset = [];          // [{id, name, haystack}]
    var labelMap = {};          // id → name
    var visible = [];           // currently rendered suggestion rows
    var highlight = -1;
    var open = false;

    function sync() {
      hidden.value = JSON.stringify(tags);
      renderChips();
    }

    function renderChips() {
      chips.innerHTML = "";
      tags.forEach(function (tag, idx) {
        var label = labelMap[tag] ? tag + " — " + labelMap[tag] : tag;
        var chip = document.createElement("span");
        chip.className = "tag-chip";
        var text = document.createElement("span");
        text.textContent = label;
        chip.appendChild(text);
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "tag-chip-x";
        btn.setAttribute("aria-label", "Remove " + label);
        btn.textContent = "×";
        btn.addEventListener("click", function () {
          tags.splice(idx, 1);
          sync();
        });
        chip.appendChild(btn);
        chips.appendChild(chip);
      });
    }

    function addTag(raw) {
      if (!raw) return false;
      var tag = String(raw).trim();
      if (!tag) return false;

      if (mode === "cwe") {
        var m = tag.match(/CWE-\d+/i);
        if (m) tag = m[0].toUpperCase();
        if (!/^CWE-\d+$/i.test(tag)) return false;
      } else if (mode === "url") {
        if (tag.length < 3) return false;
      }

      if (tags.indexOf(tag) !== -1) {
        entry.classList.add("dup");
        setTimeout(function () { entry.classList.remove("dup"); }, 350);
        return false;
      }
      tags.push(tag);
      sync();
      return true;
    }

    // ---- autocomplete popup (CWE mode) --------------------------------

    function showPopup() {
      if (!popup) return;
      popup.classList.add("open");
      open = true;
    }
    function hidePopup() {
      if (!popup) return;
      popup.classList.remove("open");
      open = false;
      highlight = -1;
    }
    function setHighlight(idx) {
      if (!popup) return;
      var rows = popup.querySelectorAll(".tag-input-suggestion");
      rows.forEach(function (r, i) {
        r.classList.toggle("active", i === idx);
      });
      var active = rows[idx];
      if (active && active.scrollIntoView) active.scrollIntoView({ block: "nearest" });
      highlight = idx;
    }

    function renderPopup(items) {
      if (!popup) return;
      visible = items;
      if (items.length === 0) { hidePopup(); return; }
      var html = "";
      for (var i = 0; i < items.length; i++) {
        var it = items[i];
        html +=
          '<li class="tag-input-suggestion" data-idx="' + i + '">' +
            '<span class="tag-input-suggestion-id">' + escapeHtml(it.id) + '</span>' +
            '<span class="tag-input-suggestion-name">' + escapeHtml(it.name) + '</span>' +
          '</li>';
      }
      popup.innerHTML = html;
      showPopup();
      setHighlight(items.length > 0 ? 0 : -1);
    }

    function filterDataset(q) {
      q = q.trim().toLowerCase();
      if (q === "") return dataset.slice(0, MAX_SUGGESTIONS);
      var hits = [];
      for (var i = 0; i < dataset.length && hits.length < MAX_SUGGESTIONS; i++) {
        if (dataset[i].haystack.indexOf(q) !== -1) hits.push(dataset[i]);
      }
      return hits;
    }

    // ---- event wiring -------------------------------------------------

    entry.addEventListener("focus", function () {
      if (mode === "cwe" && dataset.length > 0) {
        renderPopup(filterDataset(entry.value));
      }
    });

    entry.addEventListener("input", function () {
      if (mode === "cwe") {
        renderPopup(filterDataset(entry.value));
      }
    });

    entry.addEventListener("keydown", function (ev) {
      if (mode === "cwe" && open && visible.length > 0) {
        if (ev.key === "ArrowDown") {
          ev.preventDefault();
          setHighlight((highlight + 1) % visible.length);
          return;
        }
        if (ev.key === "ArrowUp") {
          ev.preventDefault();
          setHighlight((highlight - 1 + visible.length) % visible.length);
          return;
        }
        if (ev.key === "Escape") {
          ev.preventDefault();
          hidePopup();
          return;
        }
        if (ev.key === "Enter" || ev.key === "Tab") {
          if (highlight >= 0 && highlight < visible.length) {
            ev.preventDefault();
            if (addTag(visible[highlight].id)) entry.value = "";
            hidePopup();
            return;
          }
        }
      }

      if (ev.key === "Enter" || ev.key === ",") {
        ev.preventDefault();
        if (mode === "cwe") {
          if (addTag(entry.value)) entry.value = "";
        } else {
          if (addTag(entry.value)) entry.value = "";
        }
        hidePopup();
      } else if (ev.key === "Backspace" && entry.value === "" && tags.length > 0) {
        tags.pop();
        sync();
      }
    });

    entry.addEventListener("blur", function () {
      // Defer so a mousedown on a suggestion still registers as a click.
      setTimeout(hidePopup, 120);
    });

    if (popup) {
      popup.addEventListener("mousedown", function (ev) {
        var row = ev.target.closest(".tag-input-suggestion");
        if (!row) return;
        ev.preventDefault(); // keep focus on the entry
        var idx = parseInt(row.getAttribute("data-idx"), 10);
        if (!isNaN(idx) && visible[idx]) {
          if (addTag(visible[idx].id)) entry.value = "";
          hidePopup();
          entry.focus();
        }
      });
      popup.addEventListener("mousemove", function (ev) {
        var row = ev.target.closest(".tag-input-suggestion");
        if (!row) return;
        var idx = parseInt(row.getAttribute("data-idx"), 10);
        if (!isNaN(idx)) setHighlight(idx);
      });
    }

    // Multi-paste (URL mode): split on whitespace/comma so dropping a
    // wall of links adds them all at once.
    entry.addEventListener("paste", function (ev) {
      if (mode !== "url") return;
      var clip = (ev.clipboardData || window.clipboardData);
      if (!clip) return;
      var text = clip.getData("text") || "";
      if (!/\s|,/.test(text)) return;
      ev.preventDefault();
      var parts = text.split(/[\s,]+/).filter(Boolean);
      parts.forEach(addTag);
      entry.value = "";
    });

    // Load CWE list (CWE mode).
    if (mode === "cwe" && source) {
      fetch(source, { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (items) {
          if (!Array.isArray(items)) return;
          dataset = items
            .filter(function (it) { return it && it.id; })
            .map(function (it) {
              labelMap[it.id] = it.name || "";
              return {
                id: it.id,
                name: it.name || "",
                haystack: (it.id + " " + (it.name || "")).toLowerCase(),
              };
            });
          renderChips();
        })
        .catch(function () { /* fail-soft */ });
    }

    renderChips();
  }

  function init() {
    document.querySelectorAll("[data-tag-input]").forEach(bind);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
