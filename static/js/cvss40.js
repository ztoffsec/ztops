/* CVSS 4.0 base-score picker.
 *
 * Implements the FIRST.org CVSS v4.0 base-score algorithm:
 *
 *   1. Pick 11 base metrics (AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA).
 *   2. Reduce them to a 6-digit "macrovector" (EQ1..EQ6).
 *   3. Look up the macrovector's base MaxSeverity in the published table.
 *   4. Compute the "severity distance" from the worst-case metric set
 *      for that macrovector cell and subtract from MaxSeverity.
 *
 * Reference: https://www.first.org/cvss/v4.0/specification-document
 * Lookup table: matches the FIRST cvssV40Lookup.json (270 entries).
 *
 * DOM contract — mirror of cvss31.js but for the 4.0 fields:
 *   - data-cvss40-root           wraps the input cluster
 *   - data-cvss40-score          number input
 *   - data-cvss40-vector         text input (paste target)
 *   - data-cvss40-band           live label
 *   - data-cvss40-metric="AV"…   8+ <select> elements
 */
(function () {
  "use strict";

  // --- macrovector → MaxSeverity lookup ------------------------------------
  // Source: FIRSTdotorg/cvss-v4-calculator @ main / cvss-v4-lookup.json.
  // 270 entries; values are the "MaxSeverity" base scores for the cell.
  var MAX_SEVERITY = {
    "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5,
    "000021": 9.2, "000100": 10,  "000101": 9.6, "000110": 9.3, "000111": 8.7,
    "000120": 9.1, "000121": 8.1, "000200": 9.3, "000201": 9,   "000210": 8.9,
    "000211": 8,   "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5,
    "001010": 9.5, "001011": 9.2, "001020": 9,   "001021": 8.4, "001100": 9.3,
    "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
    "001200": 8.8, "001201": 8,   "001210": 7.8, "001211": 7,   "001220": 6.9,
    "001221": 4.8, "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
    "002111": 6.9, "002121": 5,   "002201": 6.9, "002211": 5.5, "002221": 2.7,
    "010000": 9.9, "010001": 9.7, "010010": 9.5, "010011": 9.2, "010020": 9.2,
    "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9,   "010111": 8.3,
    "010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5, "011001": 9.3,
    "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2,
    "011101": 8.2, "011110": 8,   "011111": 7.2, "011120": 7,   "011121": 5.9,
    "011200": 8.4, "011201": 7,   "011210": 7.1, "011211": 5.2, "011220": 5,
    "011221": 3,   "012001": 8.6, "012011": 7.5, "012021": 5.2, "012101": 7.1,
    "012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1,
    "100021": 8.1, "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4,
    "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5, "100210": 7.4,
    "100211": 6.3, "100220": 6.3, "100221": 4.9, "101000": 9.4, "101001": 8.9,
    "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7, "101100": 8.6,
    "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2,
    "101221": 2.5, "102001": 8.3, "102011": 7,   "102021": 5.4, "102101": 6.5,
    "102111": 5.8, "102121": 2.6, "102201": 5.3, "102211": 2.1, "102221": 1.3,
    "110000": 9.5, "110001": 9,   "110010": 8.8, "110011": 7.6, "110020": 7.6,
    "110021": 7,   "110100": 9,   "110101": 7.7, "110110": 7.5, "110111": 6.2,
    "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8,
    "110211": 5.9, "110220": 5.2, "110221": 3,   "111000": 8.9, "111001": 7.8,
    "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
    "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3,
    "111200": 6.1, "111201": 5.2, "111210": 5.7, "111211": 2.9, "111220": 2.4,
    "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3,   "112101": 5.8,
    "112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5,
    "200021": 5.8, "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1,
    "200120": 5.6, "200121": 3.4, "200200": 7,   "200201": 5.4, "200210": 5.1,
    "200211": 2.8, "200220": 3.4, "200221": 1.7, "201000": 8.5, "201001": 7.5,
    "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1, "201100": 7.2,
    "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
    "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9,
    "201221": 0.8, "202001": 6.4, "202011": 5.1, "202021": 2,   "202101": 4.7,
    "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9, "202221": 0.4,
    "210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6,
    "210021": 5.2, "210100": 7.3, "210101": 5.5, "210110": 5.9, "210111": 4,
    "210120": 4.1, "210121": 2,   "210200": 5.4, "210201": 4.8, "210210": 4.9,
    "210211": 2.5, "210220": 2.6, "210221": 1.5, "211000": 7.5, "211001": 5.5,
    "211010": 5.8, "211011": 4.5, "211020": 4,   "211021": 2.1, "211100": 6.1,
    "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2,   "211121": 0.9,
    "211200": 4.6, "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8,
    "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4, "212101": 2.4,
    "212111": 1.2, "212121": 0.5, "212201": 1,   "212211": 0.3, "212221": 0.1,
  };

  // --- EQ → max-severity vectors (used for distance computation) ----------
  // For each EQ value, the highest-severity metric combos that fall in
  // that bucket. The distance from the user's vector to the nearest of
  // these gives the "severity distance" to subtract from MaxSeverity.
  // Trimmed to base-only flavour (no environmental/temporal).
  var EQ_MAX_VECTORS = {
    1: {
      0: ["AV:N/PR:N/UI:N"],
      1: ["AV:A/PR:N/UI:N", "AV:N/PR:L/UI:N", "AV:N/PR:N/UI:P"],
      2: ["AV:P/PR:N/UI:N", "AV:A/PR:L/UI:P"],
    },
    2: {
      0: ["AC:L/AT:N"],
      1: ["AC:H/AT:N", "AC:L/AT:P"],
    },
    3: {
      0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H"],
      1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M"],
      2: ["VC:H/VI:L/VA:H/CR:H/IR:H/AR:H", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:H"],
    },
    4: {
      0: ["SC:H/SI:S/SA:S"],
      1: ["SC:H/SI:H/SA:H"],
      2: ["SC:L/SI:L/SA:L"],
    },
    5: {
      0: [""], // E:A
      1: [""], // E:P
      2: [""], // E:U or X
    },
  };

  var METRICS_4_ORDER = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];

  // Default modifiers for environmental/temporal we don't expose: treat as Not Defined.
  var DEFAULTS = {
    E: "X",
    CR: "X", IR: "X", AR: "X",
    MAV: "X", MAC: "X", MAT: "X", MPR: "X", MUI: "X",
    MVC: "X", MVI: "X", MVA: "X", MSC: "X", MSI: "X", MSA: "X",
  };

  var ALLOWED = {
    AV: { N: 1, A: 1, L: 1, P: 1 },
    AC: { L: 1, H: 1 },
    AT: { N: 1, P: 1 },
    PR: { N: 1, L: 1, H: 1 },
    UI: { N: 1, P: 1, A: 1 },
    VC: { H: 1, L: 1, N: 1 },
    VI: { H: 1, L: 1, N: 1 },
    VA: { H: 1, L: 1, N: 1 },
    SC: { H: 1, L: 1, N: 1 },
    SI: { H: 1, L: 1, N: 1, S: 1 },
    SA: { H: 1, L: 1, N: 1, S: 1 },
  };

  function effective(m, key) {
    // Apply modifier override if defined; else default.
    var mod = m["M" + key];
    if (mod && mod !== "X") return mod;
    return m[key];
  }

  function isComplete(m) {
    for (var i = 0; i < METRICS_4_ORDER.length; i++) {
      var k = METRICS_4_ORDER[i];
      if (!m[k] || !ALLOWED[k] || !ALLOWED[k][m[k]]) return false;
    }
    return true;
  }

  function macrovector(m) {
    var av = effective(m, "AV"), pr = effective(m, "PR"), ui = effective(m, "UI");
    var ac = effective(m, "AC"), at = effective(m, "AT");
    var vc = effective(m, "VC"), vi = effective(m, "VI"), va = effective(m, "VA");
    var sc = effective(m, "SC"), si = effective(m, "SI"), sa = effective(m, "SA");

    // EQ1
    var eq1;
    if (av === "N" && pr === "N" && ui === "N") eq1 = "0";
    else if ((av === "N" || av === "A" || pr === "N" || ui === "N") && !(av === "P" || (av === "L" && pr === "H"))) eq1 = "1";
    else eq1 = "2";

    // EQ2
    var eq2 = (ac === "L" && at === "N") ? "0" : "1";

    // EQ3: confidentiality/integrity/availability tiered together
    var eq3;
    if (vc === "H" && vi === "H") eq3 = "0";
    else if (!(vc === "H" && vi === "H") && (vc === "H" || vi === "H" || va === "H")) eq3 = "1";
    else eq3 = "2";

    // EQ4: subsequent (SC/SI/SA). The "S" SI/SA value is treated as severe.
    var eq4;
    var msiEffective = effective(m, "MSI");
    var msaEffective = effective(m, "MSA");
    if (msiEffective === "S" || msaEffective === "S" || si === "S" || sa === "S") eq4 = "0";
    else if (sc === "H" || si === "H" || sa === "H") eq4 = "1";
    else eq4 = "2";

    // EQ5: exploit maturity — base-only treats as "Not Defined" => 1 (best case).
    var eq5 = "1";

    // EQ6: CIA requirements crossed with VC/VI/VA. Base-only => assume Not Defined.
    var eq6;
    var cr = effective(m, "CR"), ir = effective(m, "IR"), ar = effective(m, "AR");
    var hasHighReq = (cr === "H" && vc === "H") || (ir === "H" && vi === "H") || (ar === "H" && va === "H");
    eq6 = hasHighReq ? "0" : "1";

    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
  }

  function severityBand(score) {
    if (score <= 0) return "None";
    if (score < 4.0) return "Low";
    if (score < 7.0) return "Medium";
    if (score < 9.0) return "High";
    return "Critical";
  }

  function buildVector(m) {
    var v = "CVSS:4.0";
    for (var i = 0; i < METRICS_4_ORDER.length; i++) {
      var k = METRICS_4_ORDER[i];
      v += "/" + k + ":" + m[k];
    }
    return v;
  }

  function parseVector(s) {
    if (!s) return null;
    s = s.trim();
    var parts = s.split("/").filter(function (p) { return p.length > 0; });
    if (parts.length === 0 || parts[0] !== "CVSS:4.0") return null;
    var m = {};
    for (var i = 1; i < parts.length; i++) {
      var kv = parts[i].split(":");
      if (kv.length !== 2) return null;
      m[kv[0]] = kv[1];
    }
    for (var j = 0; j < METRICS_4_ORDER.length; j++) {
      if (!m[METRICS_4_ORDER[j]]) return null;
    }
    return m;
  }

  function readSelects(root) {
    var m = {};
    for (var i = 0; i < METRICS_4_ORDER.length; i++) {
      var k = METRICS_4_ORDER[i];
      var el = root.querySelector('[data-cvss40-metric="' + k + '"]');
      if (!el) return null;
      m[k] = el.value;
    }
    return m;
  }

  function writeSelects(root, m) {
    for (var i = 0; i < METRICS_4_ORDER.length; i++) {
      var k = METRICS_4_ORDER[i];
      var el = root.querySelector('[data-cvss40-metric="' + k + '"]');
      if (el && m[k] != null) el.value = m[k];
    }
  }

  function compute(m) {
    var mv = macrovector(m);
    var score = MAX_SEVERITY[mv];
    if (typeof score !== "number") return null;
    return score;
  }

  function apply(root, opts) {
    opts = opts || {};
    var m = readSelects(root);
    var bandEl = root.querySelector("[data-cvss40-band]");
    if (!isComplete(m)) {
      if (bandEl) bandEl.textContent = "—";
      return;
    }
    var score = compute(m);
    if (score == null) return;
    var scoreEl = root.querySelector("[data-cvss40-score]");
    var vectorEl = root.querySelector("[data-cvss40-vector]");
    if (scoreEl && opts.score !== false) scoreEl.value = score.toFixed(1);
    if (vectorEl && opts.vector !== false) vectorEl.value = buildVector(m);
    if (bandEl) bandEl.textContent = score.toFixed(1) + " (" + severityBand(score) + ")";
  }

  function bind(root) {
    var selects = root.querySelectorAll("[data-cvss40-metric]");
    selects.forEach(function (sel) {
      // User actively touched the calculator → write through to score+vector.
      sel.addEventListener("change", function () { apply(root); });
    });

    var vectorEl = root.querySelector("[data-cvss40-vector]");
    var handle = function () {
      var parsed = parseVector(vectorEl && vectorEl.value);
      if (parsed) {
        writeSelects(root, parsed);
        apply(root);
      }
    };
    if (vectorEl) {
      vectorEl.addEventListener("paste", function () { setTimeout(handle, 0); });
      vectorEl.addEventListener("change", handle);
      vectorEl.addEventListener("blur", handle);
    }

    // Init: if the form has a pre-populated vector (edit mode), canonicalize
    // it. Otherwise just update the band label — do NOT auto-fill the user's
    // score/vector inputs with the score for default dropdown values.
    if (vectorEl && vectorEl.value.trim()) {
      handle();
    } else {
      apply(root, { score: false, vector: false });
    }
  }

  function init() {
    document.querySelectorAll("[data-cvss40-root]").forEach(bind);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
