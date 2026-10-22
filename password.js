/* PasswordLab Random Password Generator — all computation is local. No network requests, no tracking.
   Entropy model: each character is a uniform random pick from the selected pool.
   - Without "require each class": bits = length * log2(pool size).
   - With "require each class": the output is rejection-sampled until every selected class appears
     at least once, so the distribution is uniform over exactly those strings, and bits =
     log2(count) where count is computed by inclusion-exclusion over the classes.
   Crack time assumes an offline attack at 10 billion guesses/sec — the same documented model
   as the strength checker. Symbols set is counted from the literal string below, never hardcoded. */
(function (root) {
  "use strict";

  var SETS = {
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.<>?/|~"
  };
  var AMBIGUOUS = "0O1lI|"; // removed from every class when "exclude ambiguous" is on
  var GUESSES_PER_SEC = 10000000000;

  function buildPool(opts) {
    var classes = [];
    ["lower", "upper", "digits", "symbols"].forEach(function (key) {
      if (!opts[key]) return;
      var chars = SETS[key];
      if (opts.ambiguous) {
        chars = chars.split("").filter(function (c) { return AMBIGUOUS.indexOf(c) === -1; }).join("");
      }
      classes.push({ key: key, chars: chars });
    });
    var pool = classes.map(function (c) { return c.chars; }).join("");
    return { classes: classes, pool: pool };
  }

  // Exact count of strings of length L over the pool that contain every class at least once,
  // by inclusion-exclusion. Returns 0 when impossible (L < number of classes).
  function countWithAllClasses(length, classes, poolSize) {
    var n = classes.length, total = 0, mask;
    for (mask = 0; mask < (1 << n); mask++) {
      var excluded = 0, bits = 0, i;
      for (i = 0; i < n; i++) {
        if (mask & (1 << i)) { excluded += classes[i].chars.length; bits++; }
      }
      var term = Math.pow(poolSize - excluded, length);
      total += (bits % 2 === 0) ? term : -term;
    }
    return total;
  }

  function entropyBits(length, built, requireAll) {
    var poolSize = built.pool.length;
    if (poolSize === 0) return null;
    if (!requireAll) return length * Math.log(poolSize) / Math.log(2);
    var count = countWithAllClasses(length, built.classes, poolSize);
    if (count <= 0) return null;
    return Math.log(count) / Math.log(2);
  }

  // rng: function returning a uniform integer in [0, max). Defaults to crypto.getRandomValues
  // with rejection sampling (no modulo bias).
  function defaultRng(max) {
    var buf = new Uint16Array(1);
    var limit = 65536 - (65536 % max);
    var v;
    do {
      (root.crypto || window.crypto).getRandomValues(buf);
      v = buf[0];
    } while (v >= limit);
    return v % max;
  }

  function drawOnce(length, pool, rng) {
    var out = "";
    for (var i = 0; i < length; i++) out += pool[rng(pool.length)];
    return out;
  }

  function hasAllClasses(pw, classes) {
    return classes.every(function (c) {
      for (var i = 0; i < pw.length; i++) {
        if (c.chars.indexOf(pw[i]) !== -1) return true;
      }
      return false;
    });
  }

  // Rejection sampling: uniform over the pool, retried until the constraint holds.
  // Because every accepted string was drawn uniformly, the result is uniform over the
  // accepted set — which is exactly what entropyBits(requireAll=true) counts.
  function generate(length, built, requireAll, rng) {
    rng = rng || defaultRng;
    if (built.pool.length === 0) return null;
    if (requireAll && length < built.classes.length) return null;
    for (var attempt = 0; attempt < 10000; attempt++) {
      var pw = drawOnce(length, built.pool, rng);
      if (!requireAll || hasAllClasses(pw, built.classes)) return pw;
    }
    return null;
  }

  function crackSeconds(bits) {
    return Math.pow(2, bits) / GUESSES_PER_SEC;
  }

  function formatDuration(seconds) {
    if (!isFinite(seconds)) return "effectively forever";
    if (seconds < 1) return "instantly";
    var units = [
      [31557600, "year"], [86400, "day"], [3600, "hour"], [60, "minute"], [1, "second"]
    ];
    for (var i = 0; i < units.length; i++) {
      if (seconds >= units[i][0] * 0.95) {
        var v = seconds / units[i][0];
        var shown = v >= 100 ? Math.round(v).toString() : v.toFixed(1);
        return shown + " " + units[i][1] + (shown === "1.0" || shown === "1" ? "" : "s");
      }
    }
    return seconds.toFixed(2) + " seconds";
  }

  function formatCombinations(bits) {
    return "~2^" + bits.toFixed(1) + " (" + Math.pow(2, bits).toExponential(1).replace("e+", " × 10^") + ")";
  }

  function verdict(bits) {
    if (bits < 45) return ["weak", "weak"];
    if (bits < 70) return ["moderate", "fair"];
    if (bits < 90) return ["strong", "strong"];
    return ["very strong", "strong"];
  }

  // ---- DOM wiring (browser only) ----
  function init() {
    var $ = function (id) { return document.getElementById(id); };
    if (!$("genBtn")) return;
    var len = $("lenRange"), lenLabel = $("lenLabel");
    function syncLabel() { lenLabel.textContent = len.value; }
    len.addEventListener("input", syncLabel); syncLabel();

    function readOpts() {
      return {
        lower: $("lowerCheck").checked, upper: $("upperCheck").checked,
        digits: $("digitsCheck").checked, symbols: $("symbolsCheck").checked,
        ambiguous: $("ambiguousCheck").checked, requireAll: $("requireCheck").checked
      };
    }

    function run() {
      var opts = readOpts();
      var built = buildPool(opts);
      var length = parseInt(len.value, 10);
      var err = $("error");
      if (built.classes.length === 0) {
        err.textContent = "Select at least one character class.";
        err.hidden = false; $("result").hidden = true; return;
      }
      if (opts.requireAll && length < built.classes.length) {
        err.textContent = "Length must be at least " + built.classes.length +
          " to include one of each selected class.";
        err.hidden = false; $("result").hidden = true; return;
      }
      err.hidden = true;
      var pw = generate(length, built, opts.requireAll);
      if (pw === null) {
        err.textContent = "Could not generate a password with these settings. Try a longer length.";
        err.hidden = false; $("result").hidden = true; return;
      }
      var bits = entropyBits(length, built, opts.requireAll);
      var v = verdict(bits);
      $("output").textContent = pw;
      $("output").setAttribute("data-hidden", "false");
      $("showBtn").textContent = "Hide";
      $("result").hidden = false;
      $("entropy").textContent = bits.toFixed(1) + " bits";
      $("combos").textContent = formatCombinations(bits);
      $("poolSize").textContent = built.pool.length + " characters";
      $("bignum").textContent = formatDuration(crackSeconds(bits));
      var ve = $("verdict");
      ve.textContent = v[0].toUpperCase();
      ve.className = "verdict " + v[1];
      var chips = $("classChips");
      chips.innerHTML = "";
      built.classes.forEach(function (c) {
        var s = document.createElement("span");
        s.className = "chip on";
        s.textContent = c.key + " (" + c.chars.length + ")";
        chips.appendChild(s);
      });
    }
    $("genBtn").addEventListener("click", run);
    ["lowerCheck", "upperCheck", "digitsCheck", "symbolsCheck", "ambiguousCheck", "requireCheck"]
      .forEach(function (id) { $(id).addEventListener("change", run); });
    len.addEventListener("input", run);
    $("showBtn").addEventListener("click", function () {
      var out = $("output");
      var hidden = out.getAttribute("data-hidden") === "true";
      if (hidden) { out.textContent = out.getAttribute("data-pw"); out.setAttribute("data-hidden", "false"); $("showBtn").textContent = "Hide"; }
      else { out.setAttribute("data-pw", out.textContent); out.textContent = "•".repeat(out.textContent.length); out.setAttribute("data-hidden", "true"); $("showBtn").textContent = "Show"; }
    });
    $("copyBtn").addEventListener("click", function () {
      var out = $("output");
      var text = out.getAttribute("data-hidden") === "true" ? out.getAttribute("data-pw") : out.textContent;
      navigator.clipboard.writeText(text).then(function () {
        $("copyHint").hidden = false;
        setTimeout(function () { $("copyHint").hidden = true; }, 2500);
      });
    });
    run();
  }
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
  }

  var api = {
    SETS: SETS, AMBIGUOUS: AMBIGUOUS, buildPool: buildPool,
    countWithAllClasses: countWithAllClasses, entropyBits: entropyBits,
    generate: generate, hasAllClasses: hasAllClasses,
    crackSeconds: crackSeconds, formatDuration: formatDuration,
    formatCombinations: formatCombinations, verdict: verdict
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PwGen = api;
})(typeof self !== "undefined" ? self : this);
