/* PasswordLab Password Length Calculator — all computation is local. No network requests.
   This is the inverse of the Strength Checker: instead of "how long will this password
   survive?", it answers "how long must a random password be to survive this long?"
   Model (same as the rest of PasswordLab): a uniform random password over the selected
   character classes, attacked offline at 10 billion guesses/sec, worst case = full
   search space (pool^length / rate). Minimum length = the smallest L with
   pool^L >= targetSeconds * rate, i.e. ceil(log2(targetSeconds*rate) / log2(pool)).
   The "one shorter" figure is shown deliberately: it is the cliff — one character
   less multiplies the attacker's job by only pool, and usually drops below target. */
(function (root) {
  "use strict";

  var GUESSES_PER_SEC = 10000000000;
  var YEAR_SECONDS = 31557600; // 365.25 days, same constant as the other PasswordLab pages
  var CLASS_SIZES = { lower: 26, upper: 26, digits: 10, symbols: 32 };

  function poolSize(flags) {
    var pool = 0;
    if (flags.lower) pool += CLASS_SIZES.lower;
    if (flags.upper) pool += CLASS_SIZES.upper;
    if (flags.digits) pool += CLASS_SIZES.digits;
    if (flags.symbols) pool += CLASS_SIZES.symbols;
    return pool;
  }

  // Returns null when pool < 2 (no usable character set) or target <= 0.
  function minLength(pool, targetSeconds) {
    if (!pool || pool < 2 || !targetSeconds || targetSeconds <= 0) return null;
    var bitsNeeded = Math.log2(targetSeconds * GUESSES_PER_SEC);
    // Subtract a tiny epsilon so an exact power (e.g. pool^L == target*rate) is not
    // bumped to L+1 by floating-point dust.
    return Math.max(1, Math.ceil(bitsNeeded / Math.log2(pool) - 1e-12));
  }

  function bitsNeeded(targetSeconds) {
    return Math.log2(targetSeconds * GUESSES_PER_SEC);
  }

  function crackSeconds(pool, length) {
    return Math.pow(pool, length) / GUESSES_PER_SEC;
  }

  function formatDuration(seconds) {
    if (!isFinite(seconds)) return "effectively forever";
    if (seconds < 1) return "instantly";
    var units = [
      [YEAR_SECONDS, "year"], [86400, "day"], [3600, "hour"], [60, "minute"], [1, "second"]
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

  function verdict(length) {
    if (length <= 8) return ["short — fine only for low-value accounts", "weak"];
    if (length <= 12) return ["solid everyday length", "fair"];
    return ["long — use a password manager", "strong"];
  }

  // ---- DOM wiring (browser only) ----
  function init() {
    var $ = function (id) { return document.getElementById(id); };
    if (!$("calcBtn")) return;
    function run() {
      var flags = {
        lower: $("lowerCheck").checked,
        upper: $("upperCheck").checked,
        digits: $("digitCheck").checked,
        symbols: $("symbolCheck").checked
      };
      var pool = poolSize(flags);
      var targetSeconds = parseFloat($("targetSelect").value);
      var length = minLength(pool, targetSeconds);
      $("result").hidden = false;
      if (length === null) {
        $("verdict").textContent = "PICK AT LEAST ONE CHARACTER CLASS";
        $("verdict").className = "verdict weak";
        $("bignum").textContent = "–";
        $("poolSize").textContent = "–";
        $("bitsNeeded").textContent = "–";
        $("crackAtMin").textContent = "–";
        $("crackOneShorter").textContent = "–";
        return;
      }
      var v = verdict(length);
      $("verdict").textContent = v[0].toUpperCase();
      $("verdict").className = "verdict " + v[1];
      $("bignum").textContent = length + (length === 1 ? " character" : " characters");
      $("poolSize").textContent = pool + " characters in the pool";
      $("bitsNeeded").textContent = bitsNeeded(targetSeconds).toFixed(1) + " bits needed";
      $("crackAtMin").textContent = formatDuration(crackSeconds(pool, length));
      $("crackOneShorter").textContent = length > 1
        ? formatDuration(crackSeconds(pool, length - 1)) + " (one character shorter)"
        : "n/a";
    }
    $("calcBtn").addEventListener("click", run);
    ["lowerCheck", "upperCheck", "digitCheck", "symbolCheck", "targetSelect"].forEach(function (id) {
      $(id).addEventListener("change", run);
    });
    run();
  }
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
  }

  var api = {
    poolSize: poolSize, minLength: minLength, bitsNeeded: bitsNeeded,
    crackSeconds: crackSeconds, formatDuration: formatDuration, verdict: verdict,
    GUESSES_PER_SEC: GUESSES_PER_SEC, YEAR_SECONDS: YEAR_SECONDS
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.LengthCalc = api;
})(typeof self !== "undefined" ? self : this);
