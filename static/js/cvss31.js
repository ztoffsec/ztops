/* CVSS 3.1 base-score calculator.
 *
 * Reference: https://www.first.org/cvss/v3.1/specification-document
 *
 * Wires to a DOM hierarchy of:
 *   - one <input type="text" data-cvss31-score>     ← score field
 *   - one <input type="text" data-cvss31-vector>    ← vector string field
 *   - eight <select data-cvss31-metric="AV|AC|PR|UI|S|C|I|A">
 *
 * Changing any dropdown rebuilds the vector + score. Pasting a vector
 * into the vector field parses it back into the dropdowns and re-runs
 * the score. CVSS 3.0 vectors are accepted (formula is identical).
 */
(function () {
  "use strict";

  var WEIGHTS = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    PR: {
      U: { N: 0.85, L: 0.62, H: 0.27 }, // scope unchanged
      C: { N: 0.85, L: 0.68, H: 0.5 },  // scope changed
    },
    UI: { N: 0.85, R: 0.62 },
    S: { U: 1, C: 1 }, // not actually a weight — just the allowed set for validation
    C: { N: 0, L: 0.22, H: 0.56 },
    I: { N: 0, L: 0.22, H: 0.56 },
    A: { N: 0, L: 0.22, H: 0.56 },
  };

  var METRICS_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

  function roundUp(n) {
    // CVSS 3.1 "Roundup" function — round to one decimal, always up.
    var x = Math.round(n * 100000);
    if (x % 10000 === 0) return x / 100000;
    return Math.floor(x / 10000 + 1) / 10;
  }

  function computeScore(m) {
    var iss = 1 - (1 - WEIGHTS.C[m.C]) * (1 - WEIGHTS.I[m.I]) * (1 - WEIGHTS.A[m.A]);
    var impact;
    if (m.S === "U") {
      impact = 6.42 * iss;
    } else {
      impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    }
    if (impact <= 0) return 0.0;

    var prScope = m.S === "U" ? "U" : "C";
    var prVal = WEIGHTS.PR[prScope][m.PR];
    var exploitability = 8.22 * WEIGHTS.AV[m.AV] * WEIGHTS.AC[m.AC] * prVal * WEIGHTS.UI[m.UI];

    var base;
    if (m.S === "U") {
      base = Math.min(impact + exploitability, 10);
    } else {
      base = Math.min(1.08 * (impact + exploitability), 10);
    }
    return roundUp(base);
  }

  function severityBand(score) {
    if (score <= 0) return "None";
    if (score < 4.0) return "Low";
    if (score < 7.0) return "Medium";
    if (score < 9.0) return "High";
    return "Critical";
  }

  function buildVector(m) {
    return (
      "CVSS:3.1" +
      "/AV:" + m.AV +
      "/AC:" + m.AC +
      "/PR:" + m.PR +
      "/UI:" + m.UI +
      "/S:" + m.S +
      "/C:" + m.C +
      "/I:" + m.I +
      "/A:" + m.A
    );
  }

  function parseVector(s) {
    if (!s) return null;
    s = s.trim();
    // Drop the CVSS:3.x prefix and split.
    var parts = s.split("/").filter(function (p) { return p.length > 0; });
    if (parts.length === 0) return null;
    if (!/^CVSS:3\.[01]$/.test(parts[0])) return null;
    var m = {};
    for (var i = 1; i < parts.length; i++) {
      var kv = parts[i].split(":");
      if (kv.length !== 2) return null;
      m[kv[0]] = kv[1];
    }
    // Must carry the 8 base metrics.
    for (var j = 0; j < METRICS_ORDER.length; j++) {
      if (!Object.prototype.hasOwnProperty.call(m, METRICS_ORDER[j])) return null;
    }
    return m;
  }

  function readSelects(root) {
    var m = {};
    for (var i = 0; i < METRICS_ORDER.length; i++) {
      var key = METRICS_ORDER[i];
      var el = root.querySelector('[data-cvss31-metric="' + key + '"]');
      if (!el) return null;
      m[key] = el.value;
    }
    return m;
  }

  function writeSelects(root, m) {
    for (var i = 0; i < METRICS_ORDER.length; i++) {
      var key = METRICS_ORDER[i];
      var el = root.querySelector('[data-cvss31-metric="' + key + '"]');
      if (el && m[key] != null) el.value = m[key];
    }
  }

  function isComplete(m) {
    if (!m) return false;
    for (var i = 0; i < METRICS_ORDER.length; i++) {
      var key = METRICS_ORDER[i];
      var v = m[key];
      if (v === "" || v == null) return false;
      var allowed = WEIGHTS[key];
      if (key === "PR") allowed = WEIGHTS.PR.U; // any of {N,L,H}
      if (!allowed || !Object.prototype.hasOwnProperty.call(allowed, v)) return false;
    }
    return true;
  }

  function applyMetrics(root, m, opts) {
    opts = opts || {};
    var scoreEl = root.querySelector("[data-cvss31-score]");
    var vectorEl = root.querySelector("[data-cvss31-vector]");
    var bandEl = root.querySelector("[data-cvss31-band]");

    if (!isComplete(m)) {
      if (bandEl) bandEl.textContent = "—";
      return;
    }
    var score = computeScore(m);
    var band = severityBand(score);

    if (scoreEl && opts.score !== false) scoreEl.value = score.toFixed(1);
    if (vectorEl && opts.vector !== false) vectorEl.value = buildVector(m);
    if (bandEl) bandEl.textContent = score.toFixed(1) + " (" + band + ")";
  }

  function bind(root) {
    var selects = root.querySelectorAll("[data-cvss31-metric]");
    selects.forEach(function (sel) {
      sel.addEventListener("change", function () {
        var m = readSelects(root);
        applyMetrics(root, m);
      });
    });

    var vectorEl = root.querySelector("[data-cvss31-vector]");
    if (vectorEl) {
      var handle = function () {
        var parsed = parseVector(vectorEl.value);
        if (parsed) {
          writeSelects(root, parsed);
          // Re-write vector in canonical 3.1 form, recompute score.
          applyMetrics(root, parsed);
        }
      };
      vectorEl.addEventListener("paste", function () {
        // Run after the paste actually mutates the value.
        setTimeout(handle, 0);
      });
      vectorEl.addEventListener("change", handle);
      vectorEl.addEventListener("blur", handle);
    }

    // If the form is preloaded with a vector (edit mode), parse on init.
    if (vectorEl && vectorEl.value.trim().length > 0) {
      var initial = parseVector(vectorEl.value);
      if (initial) {
        writeSelects(root, initial);
        applyMetrics(root, initial);
      }
    } else {
      var m = readSelects(root);
      applyMetrics(root, m, { score: false, vector: false });
    }
  }

  function init() {
    var roots = document.querySelectorAll("[data-cvss31-root]");
    roots.forEach(bind);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
