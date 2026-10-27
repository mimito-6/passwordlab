/* PasswordLab Secure PIN Generator — all computation is local. No network requests, no tracking.
   Model: each digit is a uniform random pick from 0-9, drawn with crypto.getRandomValues
   and rejection sampling (no modulo bias).
   - Leading zero allowed: combinations = 10^n, bits = n * log2(10).
   - Leading zero disallowed: combinations = 9 * 10^(n-1), bits = log2 of that.
   Offline crack time uses the same documented model as the rest of PasswordLab:
   10 billion guesses/sec. That model is deliberately brutal for PINs — and honest:
   a 6-digit PIN has only 1,000,000 combinations, so offline it falls in a fraction of a
   second. The page therefore also shows the online-attack math: with a lockout after
   10 wrong tries, an attacker's chance is 10 / combinations. PINs are only safe
   behind a lockout (or as a second factor), never as a sole secret on a leaked hash. */
(function (root) {
  "use strict";

  var GUESSES_PER_SEC = 10000000000;
  var LOCKOUT_TRIES = 10;

  function combinations(length, allowLeadingZero) {
    if (allowLeadingZero) return Math.pow(10, length);
    return 9 * Math.pow(10, length - 1);
  }

  function entropyBits(length, allowLeadingZero) {
    return Math.log(combinations(length, allowLeadingZero)) / Math.log(2);
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

  function formatCombinations(combos) {
    if (combos < 1000000) return combos.toLocaleString("en-US");
    return combos.toExponential(1).replace("e+", " × 10^");
  }

  function formatChance(combos) {
    var p = LOCKOUT_TRIES / combos * 100;
    if (p >= 0.01) return p.toFixed(3).replace(/0+$/, "").replace(/\.$/, "") + "%";
    return p.toExponential(1) + "%";
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

  function generate(length, allowLeadingZero, rng) {
    rng = rng || defaultRng;
    var out = "";
    for (var i = 0; i < length; i++) {
      var max = (i === 0 && !allowLeadingZero) ? 9 : 10;
      var d = rng(max);
      out += (i === 0 && !allowLeadingZero) ? String(d + 1) : String(d);
    }
    return out;
  }

  // Verdicts are PIN-relative, not password-relative: every PIN is weak offline,
  // so the scale judges length against real-world PIN use (lockout-protected device).
  function verdict(length) {
    if (length <= 4) return ["short — lockout only", "weak"];
    if (length <= 6) return ["standard phone PIN", "fair"];
    return ["strong for a PIN", "strong"];
  }

  // ---- DOM wiring (browser only) ----
  function init() {
    var $ = function (id) { return document.getElementById(id); };
    if (!$("genBtn")) return;
    var len = $("pinLenRange"), lenLabel = $("pinLenLabel");
    function syncLabel() { lenLabel.textContent = len.value; }
    len.addEventListener("input", syncLabel); syncLabel();

    function run() {
      var length = parseInt(len.value, 10);
      var allowLeadingZero = $("leadingZeroCheck").checked;
      var pin = generate(length, allowLeadingZero);
      var combos = combinations(length, allowLeadingZero);
      var bits = entropyBits(length, allowLeadingZero);
      var v = verdict(length);
      $("output").textContent = pin;
      $("output").setAttribute("data-hidden", "false");
      $("showBtn").textContent = "Hide";
      $("result").hidden = false;
      $("entropy").textContent = bits.toFixed(1) + " bits";
      $("combos").textContent = formatCombinations(combos);
      $("avgGuesses").textContent = formatCombinations(combos / 2) + " guesses on average";
      $("lockoutChance").textContent = formatChance(combos) + " (10 tries)";
      $("bignum").textContent = formatDuration(crackSeconds(bits));
      var ve = $("verdict");
      ve.textContent = v[0].toUpperCase();
      ve.className = "verdict " + v[1];
    }
    $("genBtn").addEventListener("click", run);
    $("leadingZeroCheck").addEventListener("change", run);
    len.addEventListener("input", run);
    $("showBtn").addEventListener("click", function () {
      var out = $("output");
      var hidden = out.getAttribute("data-hidden") === "true";
      if (hidden) { out.textContent = out.getAttribute("data-pin"); out.setAttribute("data-hidden", "false"); $("showBtn").textContent = "Hide"; }
      else { out.setAttribute("data-pin", out.textContent); out.textContent = "•".repeat(out.textContent.length); out.setAttribute("data-hidden", "true"); $("showBtn").textContent = "Show"; }
    });
    $("copyBtn").addEventListener("click", function () {
      var out = $("output");
      var text = out.getAttribute("data-hidden") === "true" ? out.getAttribute("data-pin") : out.textContent;
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
    combinations: combinations, entropyBits: entropyBits,
    crackSeconds: crackSeconds, formatDuration: formatDuration,
    formatCombinations: formatCombinations, formatChance: formatChance,
    generate: generate, verdict: verdict
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PinGen = api;
})(typeof self !== "undefined" ? self : this);
